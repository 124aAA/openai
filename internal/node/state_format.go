package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// DecodeState upgrades schema 1–8 in memory only. A meaningful write creates
// a schema 9 generation and retains the original generation unchanged.
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
	case 1, 2, 3, 4, 5, 6, 7, 8, Schema:
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&st); err != nil {
			return st, err
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return st, errors.New("状态文件含多余数据")
		}
		if header.Schema < Schema {
			if st.Firewall == "firewalld" {
				return st, errors.New("旧状态不能声明firewalld受管模式；请使用版本9")
			}
			// Presence, including explicit null, must match its schema. Do not
			// silently accept an extension which an old binary cannot understand.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				return st, err
			}
			for key := range raw {
				if header.Schema < 7 && (strings.EqualFold(key, "observability") || strings.EqualFold(key, "credential_expirations")) {
					return st, errors.New("旧状态不能包含观测或到期设置；请使用版本7")
				}
				if header.Schema < 6 && strings.EqualFold(key, "certificates") {
					return st, errors.New("旧状态不能包含证书资源；请使用版本6")
				}
				if header.Schema < 5 && strings.EqualFold(key, "devices") {
					return st, errors.New("旧状态不能包含设备扩展；请使用版本5")
				}
				if header.Schema == 1 && strings.EqualFold(key, "dns") {
					return st, errors.New("状态版本1不能包含DNS扩展；请使用版本2")
				}
				if header.Schema < 4 && (strings.EqualFold(key, "egresses") || strings.EqualFold(key, "egress_policies") || strings.EqualFold(key, "forwards")) {
					return st, fmt.Errorf("状态版本%d不能包含拓扑扩展；请使用版本4", header.Schema)
				}
			}
			for key, rawNodes := range raw {
				// encoding/json accepts case-insensitive struct field names. Inspect
				// the same spellings here so Nodes cannot hide a null extension.
				if !strings.EqualFold(key, "nodes") {
					continue
				}
				var nodes []map[string]json.RawMessage
				if err := json.Unmarshal(rawNodes, &nodes); err != nil {
					return st, err
				}
				for _, n := range nodes {
					for key, value := range n {
						if header.Schema < 8 && (strings.EqualFold(key, "anytls") || strings.EqualFold(key, "tuic")) {
							return st, errors.New("旧状态不能包含新协议设置；请使用版本8")
						}
						if header.Schema < 8 && strings.EqualFold(key, "protocol") {
							var protocol string
							_ = json.Unmarshal(value, &protocol)
							if protocol == "anytls" || protocol == "trojan" || protocol == "ss-aead" || protocol == "tuic" {
								return st, errors.New("旧状态不能声明新协议；请使用版本8")
							}
						}
					}
					for key := range n {
						if header.Schema < 6 && strings.EqualFold(key, "certificate_id") {
							return st, errors.New("旧状态不能包含证书引用；请使用版本6")
						}
						if strings.EqualFold(key, "certificate") {
							if header.Schema >= 6 {
								return st, errors.New("版本6及以上节点仅允许certificate_id")
							}
							var certificate map[string]json.RawMessage
							if err := json.Unmarshal(n[key], &certificate); err != nil {
								return st, err
							}
							for field := range certificate {
								if strings.EqualFold(field, "acme") || strings.EqualFold(field, "certificate_path") || strings.EqualFold(field, "key_path") {
									return st, errors.New("旧状态不能包含新证书设置；请使用版本6")
								}
							}
						}
						if header.Schema < 5 && strings.EqualFold(key, "tags") {
							return st, errors.New("旧状态不能包含节点标签；请使用版本5")
						}
						if header.Schema == 1 && strings.EqualFold(key, "hysteria2") {
							return st, errors.New("状态版本1不能包含Hysteria2性能扩展；请使用版本2")
						}
						if header.Schema < 3 && (strings.EqualFold(key, "connect_port") || strings.EqualFold(key, "additional_endpoints")) {
							return st, fmt.Errorf("状态版本%d不能包含连接端点扩展；请使用版本3", header.Schema)
						}
						if header.Schema < 4 && strings.EqualFold(key, "egress_id") {
							return st, fmt.Errorf("状态版本%d不能包含出口引用；请使用版本4", header.Schema)
						}
					}
				}
			}
		} else {
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(data, &raw)
			for key, value := range raw {
				if strings.EqualFold(key, "nodes") {
					var nodes []map[string]json.RawMessage
					_ = json.Unmarshal(value, &nodes)
					for _, n := range nodes {
						for field := range n {
							if strings.EqualFold(field, "certificate") {
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

// MigrateState is deterministic and has no disk, identity or runtime effects.
// The caller must retain original bytes when persisting a newly migrated state.
func MigrateState(st State) (State, error) {
	if st.Schema < 9 && st.Firewall == "firewalld" {
		return State{}, errors.New("旧状态不能声明firewalld受管模式")
	}
	if st.Schema < 8 {
		for _, n := range st.Nodes {
			if n.AnyTLS != nil || n.TUIC != nil || n.Protocol == "anytls" || n.Protocol == "trojan" || n.Protocol == "ss-aead" || n.Protocol == "tuic" {
				return State{}, errors.New("旧状态不能包含新协议字段或类型")
			}
		}
	}
	switch st.Schema {
	case Schema:
		return CanonicalCertificates(st)
	case 7, 8:
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

// encoding/json otherwise accepts the last spelling of a duplicate field.
// Case folding matches its struct-field behavior and prevents hidden schema or
// secret replacement. This is validation only and never rewrites source bytes.
func rejectStateDuplicateFields(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok {
						return errors.New("状态对象字段无效")
					}
					name = stateFieldKey(name)
					if seen[name] {
						return errors.New("状态对象含重复字段")
					}
					seen[name] = true
					if err = value(); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err = value(); err != nil {
						return err
					}
				}
			default:
				return errors.New("状态JSON结构无效")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("状态文件含多余数据")
	}
	return nil
}

// encoding/json compares struct field names using Unicode SimpleFold, which
// includes aliases such as long s and Kelvin sign. Lowercasing alone misses
// those duplicate spellings. A canonical member of each fold cycle gives the
// same equivalence relation in linear key length; no normalization or scan of
// previously seen keys is needed.
func stateFieldKey(name string) string {
	return strings.Map(func(r rune) rune {
		canonical := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		return canonical
	}, name)
}
