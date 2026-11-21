package node

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DecodeState upgrades schema 1–9 in memory only. A meaningful write creates
// a schema 10 generation and retains the original generation unchanged.
// Future schemas must add an explicit decoder and migration here;
// unknown fields must never be discarded to make a newer state look compatible.
// Decoding has no filesystem or service effects. Validate remains a separate step
// so structurally readable expired certificates can still be backed up/repaired.
func DecodeState(data []byte) (State, error) {
	var st State
	if len(data) > maxStateBytes {
		return st, errors.New("状态文件超过 8 MiB 上限")
	}
	if err := rejectStateDuplicateFields(data); err != nil {
		return st, err
	}
	var header struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return st, err
	}
	switch header.Schema {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, Schema:
		if err := unmarshalStrictStruct(data, &st); err != nil {
			return st, err
		}
		if header.Schema < Schema {
			if header.Schema < 10 && st.Firewall == "nftables" {
				return st, errors.New("旧状态不能声明nftables受管模式；请使用版本10")
			}
			if header.Schema < 9 && st.Firewall == "firewalld" {
				return st, errors.New("旧状态不能声明firewalld受管模式；请使用版本9")
			}
			// Presence, including explicit null, must match its schema. Do not
			// silently accept an extension which an old binary cannot understand.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				return st, err
			}
			for key := range raw {
				if header.Schema < 7 && (stateFieldEqual(key, "observability") || stateFieldEqual(key, "credential_expirations")) {
					return st, errors.New("旧状态不能包含观测或到期设置；请使用版本7")
				}
				if header.Schema < 6 && stateFieldEqual(key, "certificates") {
					return st, errors.New("旧状态不能包含证书资源；请使用版本6")
				}
				if header.Schema < 5 && stateFieldEqual(key, "devices") {
					return st, errors.New("旧状态不能包含设备扩展；请使用版本5")
				}
				if header.Schema == 1 && stateFieldEqual(key, "dns") {
					return st, errors.New("状态版本1不能包含DNS扩展；请使用版本2")
				}
				if header.Schema < 4 && (stateFieldEqual(key, "egresses") || stateFieldEqual(key, "egress_policies") || stateFieldEqual(key, "forwards")) {
					return st, fmt.Errorf("状态版本%d不能包含拓扑扩展；请使用版本4", header.Schema)
				}
			}
			if header.Schema < 10 {
				if err := rejectLegacyPre10Raw(raw); err != nil {
					return st, err
				}
			}
			for key, rawNodes := range raw {
				// encoding/json accepts case-insensitive struct field names. Inspect
				// the same spellings here so Nodes cannot hide a null extension.
				if !stateFieldEqual(key, "nodes") {
					continue
				}
				var nodes []map[string]json.RawMessage
				if err := json.Unmarshal(rawNodes, &nodes); err != nil {
					return st, err
				}
				for _, n := range nodes {
					for key, value := range n {
						if header.Schema < 8 && (stateFieldEqual(key, "anytls") || stateFieldEqual(key, "tuic") || stateFieldEqual(key, "transport")) {
							return st, errors.New("旧状态不能包含新协议设置；请使用版本8")
						}
						if header.Schema < 8 && stateFieldEqual(key, "protocol") {
							var protocol string
							_ = json.Unmarshal(value, &protocol)
							if p, ok := Protocol(protocol); ok && p.MinSchema >= 8 {
								return st, errors.New("旧状态不能声明新协议；请使用版本8")
							}
						}
					}
					for key := range n {
						if header.Schema < 6 && stateFieldEqual(key, "certificate_id") {
							return st, errors.New("旧状态不能包含证书引用；请使用版本6")
						}
						if stateFieldEqual(key, "certificate") {
							if header.Schema >= 6 {
								return st, errors.New("版本6及以上节点仅允许certificate_id")
							}
							var certificate map[string]json.RawMessage
							if err := json.Unmarshal(n[key], &certificate); err != nil {
								return st, err
							}
							for field := range certificate {
								if stateFieldEqual(field, "acme") || stateFieldEqual(field, "certificate_path") || stateFieldEqual(field, "key_path") {
									return st, errors.New("旧状态不能包含新证书设置；请使用版本6")
								}
							}
						}
						if header.Schema < 5 && stateFieldEqual(key, "tags") {
							return st, errors.New("旧状态不能包含节点标签；请使用版本5")
						}
						if header.Schema == 1 && stateFieldEqual(key, "hysteria2") {
							return st, errors.New("状态版本1不能包含Hysteria2性能扩展；请使用版本2")
						}
						if header.Schema < 3 && (stateFieldEqual(key, "connect_port") || stateFieldEqual(key, "additional_endpoints")) {
							return st, fmt.Errorf("状态版本%d不能包含连接端点扩展；请使用版本3", header.Schema)
						}
						if header.Schema < 4 && stateFieldEqual(key, "egress_id") {
							return st, fmt.Errorf("状态版本%d不能包含出口引用；请使用版本4", header.Schema)
						}
					}
				}
			}
		} else {
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(data, &raw)
			for key, value := range raw {
				if stateFieldEqual(key, "nodes") {
					var nodes []map[string]json.RawMessage
					_ = json.Unmarshal(value, &nodes)
					for _, n := range nodes {
						for field := range n {
							if stateFieldEqual(field, "certificate") {
								return st, errors.New("版本6节点仅允许certificate_id，私钥须存放证书资源")
							}
						}
					}
				}
			}
		}
		return MigrateState(st)
	default:
		return st, fmt.Errorf("不支持状态版本 %d（当前 %d），请使用匹配的管理器迁移", header.Schema, Schema)
	}
}

func legacyRealityFingerprint(fp string) bool {
	switch fp {
	case "", "chrome", "firefox", "safari", "ios", "edge":
		return true
	default:
		return false
	}
}

func rejectLegacyPre10TransportRaw(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var tr map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tr); err != nil {
		return err
	}
	for field, value := range tr {
		if stateFieldEqual(field, "max_early_data") || stateFieldEqual(field, "early_data_header_name") {
			return errors.New("旧状态不能包含版本10 WebSocket Early Data 设置；请使用版本10")
		}
		if stateFieldEqual(field, "type") {
			var kind string
			_ = json.Unmarshal(value, &kind)
			if kind == "http" {
				return errors.New("旧状态不能包含版本10 HTTP/2 传输设置；请使用版本10")
			}
		}
	}
	return nil
}

func rejectLegacyPre10HY2PerfRaw(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var hy2 map[string]json.RawMessage
	if err := json.Unmarshal(raw, &hy2); err != nil {
		return err
	}
	for field := range hy2 {
		if stateFieldEqual(field, "obfs") || stateFieldEqual(field, "hop_ports") || stateFieldEqual(field, "hop_interval") || stateFieldEqual(field, "hop_mode") {
			return errors.New("旧状态不能包含版本10 Hysteria2 混淆或端口跳跃设置；请使用版本10")
		}
	}
	return nil
}

func rejectLegacyPre10Raw(raw map[string]json.RawMessage) error {
	for key := range raw {
		if stateFieldEqual(key, "traffic_quotas") {
			return errors.New("旧状态不能包含版本10流量配额设置；请使用版本10")
		}
	}
	for key, rawDevices := range raw {
		if !stateFieldEqual(key, "devices") {
			continue
		}
		var devices []map[string]json.RawMessage
		if err := json.Unmarshal(rawDevices, &devices); err != nil {
			return err
		}
		for _, d := range devices {
			for field, value := range d {
				if stateFieldEqual(field, "default_subscription_format") || stateFieldEqual(field, "tun") || stateFieldEqual(field, "controller") {
					return errors.New("旧状态不能包含版本10设备导出或默认订阅设置；请使用版本10")
				}
				if stateFieldEqual(field, "routing") {
					var routing string
					_ = json.Unmarshal(value, &routing)
					if routing == "cn-direct" || routing == "global-secure-dns" {
						return errors.New("旧状态不能声明新分流预设；请使用版本10")
					}
				}
			}
		}
	}
	for key, rawNodes := range raw {
		if !stateFieldEqual(key, "nodes") {
			continue
		}
		var nodes []map[string]json.RawMessage
		if err := json.Unmarshal(rawNodes, &nodes); err != nil {
			return err
		}
		for _, n := range nodes {
			var protocol string
			for field, value := range n {
				if stateFieldEqual(field, "protocol") {
					_ = json.Unmarshal(value, &protocol)
				}
			}
			for field, value := range n {
				if stateFieldEqual(field, "multiplex") {
					return errors.New("旧状态不能包含版本10多路复用设置；请使用版本10")
				}
				if stateFieldEqual(field, "transport") {
					if protocol == "reality" {
						return errors.New("旧状态不能包含版本10 REALITY传输扩展；请使用版本10")
					}
					if err := rejectLegacyPre10TransportRaw(value); err != nil {
						return err
					}
				}
				if stateFieldEqual(field, "hysteria2") {
					if err := rejectLegacyPre10HY2PerfRaw(value); err != nil {
						return err
					}
				}
				if stateFieldEqual(field, "reality") && string(value) != "null" {
					var r map[string]json.RawMessage
					if err := json.Unmarshal(value, &r); err != nil {
						return err
					}
					for rf, rv := range r {
						if stateFieldEqual(rf, "short_ids") {
							return errors.New("旧状态不能包含版本10 REALITY多short_id设置；请使用版本10")
						}
						if stateFieldEqual(rf, "fingerprint") {
							var fp string
							_ = json.Unmarshal(rv, &fp)
							if !legacyRealityFingerprint(fp) {
								return errors.New("旧状态不能包含版本10新增REALITY指纹；请使用版本10")
							}
						}
					}
				}
				if protocol == "ss2022" && stateFieldEqual(field, "shadowsocks") && string(value) != "null" {
					var ss map[string]json.RawMessage
					if err := json.Unmarshal(value, &ss); err != nil {
						return err
					}
					for sf, sv := range ss {
						if stateFieldEqual(sf, "method") {
							var m string
							_ = json.Unmarshal(sv, &m)
							if m != "" && m != SS2022Method {
								return errors.New("旧状态不能包含版本10新增SS2022加密方法；请使用版本10")
							}
						}
					}
				}
			}
		}
	}
	for key, rawEgresses := range raw {
		if !stateFieldEqual(key, "egresses") || string(rawEgresses) == "null" {
			continue
		}
		var egresses []map[string]json.RawMessage
		if err := json.Unmarshal(rawEgresses, &egresses); err != nil {
			return err
		}
		for _, e := range egresses {
			var protocol string
			for field, value := range e {
				if stateFieldEqual(field, "protocol") {
					_ = json.Unmarshal(value, &protocol)
				}
			}
			if spec, ok := egressProtocol(protocol); ok && spec.MinSchema >= 10 {
				return errors.New("旧状态不能声明版本10新增远程出口协议；请使用版本10")
			}
			for field, value := range e {
				for _, v10Field := range []string{"transport", "multiplex", "http", "trojan", "vless", "vmess", "anytls", "tuic"} {
					if stateFieldEqual(field, v10Field) {
						return errors.New("旧状态不能包含版本10远程出口扩展字段；请使用版本10")
					}
				}
				if stateFieldEqual(field, "reality") && string(value) != "null" {
					var r map[string]json.RawMessage
					if err := json.Unmarshal(value, &r); err != nil {
						return err
					}
					for rf, rv := range r {
						if stateFieldEqual(rf, "fingerprint") {
							var fp string
							_ = json.Unmarshal(rv, &fp)
							if !legacyRealityFingerprint(fp) {
								return errors.New("旧状态不能包含版本10新增远程REALITY指纹；请使用版本10")
							}
						}
					}
				}
				if protocol == "ss2022" && stateFieldEqual(field, "shadowsocks") && string(value) != "null" {
					var ss map[string]json.RawMessage
					if err := json.Unmarshal(value, &ss); err != nil {
						return err
					}
					for sf, sv := range ss {
						if stateFieldEqual(sf, "method") {
							var m string
							_ = json.Unmarshal(sv, &m)
							if m != "" && m != SS2022Method {
								return errors.New("旧状态不能包含版本10新增远程SS2022加密方法；请使用版本10")
							}
						}
					}
				}
				if stateFieldEqual(field, "hysteria2") && string(value) != "null" {
					var hy map[string]json.RawMessage
					if err := json.Unmarshal(value, &hy); err != nil {
						return err
					}
					for hf, hv := range hy {
						if stateFieldEqual(hf, "performance") {
							if err := rejectLegacyPre10HY2PerfRaw(hv); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func rejectLegacyPre10State(st State) error {
	if st.Firewall == "nftables" {
		return errors.New("旧状态不能声明nftables受管模式")
	}
	if st.TrafficQuotas != nil {
		return errors.New("旧状态不能包含版本10流量配额设置")
	}
	for _, d := range st.Devices {
		if d.DefaultSubscriptionFormat != "" || d.TUN || d.Controller != nil || d.Routing == "cn-direct" || d.Routing == "global-secure-dns" {
			return errors.New("旧状态不能包含版本10设备导出或分流设置")
		}
	}
	for _, n := range st.Nodes {
		if n.Multiplex != nil {
			return errors.New("旧状态不能包含版本10多路复用设置")
		}
		if n.Transport != nil {
			if n.Protocol == "reality" || n.Transport.Type == "http" || n.Transport.MaxEarlyData != 0 || n.Transport.EarlyDataHeaderName != "" {
				return errors.New("旧状态不能包含版本10传输扩展设置")
			}
		}
		if n.HY2 != nil && (n.HY2.Obfs != nil || n.HY2.HopPorts != "" || n.HY2.HopInterval != "" || n.HY2.HopMode != "") {
			return errors.New("旧状态不能包含版本10 Hysteria2 混淆或端口跳跃设置")
		}
		if n.Reality != nil && (len(n.Reality.ShortIDs) > 0 || !legacyRealityFingerprint(n.Reality.Fingerprint)) {
			return errors.New("旧状态不能包含版本10 REALITY 扩展设置")
		}
		if n.Protocol == "ss2022" && n.Shadowsocks != nil && n.Shadowsocks.Method != "" && n.Shadowsocks.Method != SS2022Method {
			return errors.New("旧状态不能包含版本10 SS2022 新增加密方法")
		}
	}
	for _, e := range st.Egresses {
		if spec, ok := egressProtocol(e.Protocol); ok && spec.MinSchema >= 10 {
			return errors.New("旧状态不能声明版本10新增远程出口协议")
		}
		if e.Transport != nil || e.Multiplex != nil || e.HTTP != nil || e.Trojan != nil || e.VLESS != nil || e.VMess != nil || e.AnyTLS != nil || e.TUIC != nil {
			return errors.New("旧状态不能包含版本10远程出口扩展设置")
		}
		if e.Reality != nil && !legacyRealityFingerprint(e.Reality.Fingerprint) {
			return errors.New("旧状态不能包含版本10远程REALITY新增指纹")
		}
		if e.Protocol == "ss2022" && e.Shadowsocks != nil && e.Shadowsocks.Method != "" && e.Shadowsocks.Method != SS2022Method {
			return errors.New("旧状态不能包含版本10远程SS2022新增加密方法")
		}
		if e.HY2 != nil && e.HY2.Performance != nil && (e.HY2.Performance.Obfs != nil || e.HY2.Performance.HopPorts != "" || e.HY2.Performance.HopInterval != "" || e.HY2.Performance.HopMode != "") {
			return errors.New("旧状态不能包含版本10远程Hysteria2混淆或端口跳跃设置")
		}
	}
	return nil
}

// MigrateState is deterministic and has no disk, identity or runtime effects.
// The caller must retain original bytes when persisting a newly migrated state.
func MigrateState(st State) (State, error) {
	if st.Schema < 10 {
		if err := rejectLegacyPre10State(st); err != nil {
			return State{}, err
		}
	}
	if st.Schema < 9 && st.Firewall == "firewalld" {
		return State{}, errors.New("旧状态不能声明firewalld受管模式")
	}
	if st.Schema < 8 {
		for _, n := range st.Nodes {
			p, ok := Protocol(n.Protocol)
			if n.AnyTLS != nil || n.TUIC != nil || n.Transport != nil || (ok && p.MinSchema >= 8) {
				return State{}, errors.New("旧状态不能包含新协议字段或类型")
			}
		}
	}
	switch st.Schema {
	case Schema:
		return CanonicalCertificates(st)
	case 7, 8, 9:
		st = st.Clone()
		st.Schema = Schema
		return CanonicalCertificates(st)
	case 6:
		if st.Observability != nil || st.CredentialExpirations != nil {
			return State{}, errors.New("旧状态不能包含观测或到期设置")
		}
		st = st.Clone()
		st.Schema = Schema
		return CanonicalCertificates(st)
	case 1, 2, 3, 4, 5:
		if st.Observability != nil || st.CredentialExpirations != nil {
			return State{}, errors.New("旧状态不能包含观测或到期设置")
		}
		if st.Certificates != nil {
			return State{}, errors.New("旧状态不能包含证书资源")
		}
		if st.Schema < 5 && st.Devices != nil {
			return State{}, errors.New("旧状态不能包含设备扩展")
		}
		if st.Schema < 4 && (st.Egresses != nil || st.EgressPolicies != nil || st.Forwards != nil) {
			return State{}, fmt.Errorf("状态版本%d不能包含拓扑扩展", st.Schema)
		}
		if st.Schema == 1 && st.DNS != nil {
			return State{}, errors.New("状态版本1不能包含DNS扩展")
		}
		for _, n := range st.Nodes {
			if n.CertificateID != "" || n.Certificate != nil && (n.Certificate.ACME != nil || n.Certificate.CertificatePath != "" || n.Certificate.KeyPath != "") {
				return State{}, errors.New("旧状态不能包含新证书设置")
			}
			if st.Schema < 5 && n.Tags != nil {
				return State{}, errors.New("旧状态不能包含节点标签")
			}
			if st.Schema == 1 && n.HY2 != nil {
				return State{}, errors.New("状态版本1不能包含Hysteria2性能扩展")
			}
			if st.Schema < 3 && (n.ConnectPort != nil || n.AdditionalEndpoints != nil) {
				return State{}, fmt.Errorf("状态版本%d不能包含连接端点扩展", st.Schema)
			}
			if st.Schema < 4 && n.EgressID != "" {
				return State{}, fmt.Errorf("状态版本%d不能包含出口引用", st.Schema)
			}
		}
		st = st.Clone()
		for i := range st.Nodes {
			if st.Schema < 3 {
				port := st.Nodes[i].Port
				st.Nodes[i].ConnectPort = &port
			}
		}
		st.Schema = Schema
		return CanonicalCertificates(st)
	default:
		return State{}, fmt.Errorf("不支持状态版本 %d（当前 %d），请使用匹配的管理器迁移", st.Schema, Schema)
	}
}

func rejectStateDuplicateFields(data []byte) error {
	return validateStrictJSON(data, stateJSONPolicy)
}
