package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// This built-in ruleset has no network updater or mutable cache. These four
// ranges are RFC 1918 private IPv4 and RFC 4193 unique-local IPv6, not a
// geographic, ad-blocking or comprehensive special-use address database.
var devicePrivateCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

type DeviceRuleSource struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	CacheStatus string `json:"cache_status"`
}

type DeviceExportResult struct {
	Content    []byte           `json:"-"`
	Warnings   []string         `json:"warnings,omitempty"`
	NodeIDs    []string         `json:"node_ids"`
	RuleSource DeviceRuleSource `json:"rule_source"`
}

func deviceExportName(n Node, u User, b DeviceBinding) string {
	return n.Name + " / " + u.Name + " [" + b.NodeID + "/" + b.UserID + "/" + deviceEndpoint(b.EndpointID) + "]"
}

func deviceExportTag(b DeviceBinding) string {
	return "node-" + b.NodeID + "-user-" + b.UserID + "-" + deviceEndpoint(b.EndpointID)
}

// ExportDeviceProfile serializes local entrance authentication only. A node's
// EgressID, remote egress secrets, server TLS private keys and other users are
// never copied into the exported client graph.
func ExportDeviceProfile(st State, p DeviceProfile, format, clientVersion string, allowLossy bool) (DeviceExportResult, error) {
	r := DeviceExportResult{NodeIDs: []string{}, RuleSource: DeviceRuleSource{ID: "global-v1", Source: "all destinations use the selected entrance", CacheStatus: "embedded; no external update"}}
	if err := ValidateDeviceProfile(st, p); err != nil {
		return r, err
	}
	if p.Disabled {
		return r, errors.New("设备 Profile 已停用，不能导出或下载")
	}
	switch format {
	case "uri", "base64":
	case "sing-box", "sing-box-outbounds":
		if clientVersion != "1.14.0" && clientVersion != "1.14.3" {
			return r, errors.New("批量 sing-box 导出仅核验 1.14.0 与 1.14.3；不会猜测其他版本字段")
		}
		if deviceStrategy(p) == "fallback" {
			return r, errors.New("sing-box 1.14.0/1.14.3 没有等价的有序 fallback 出站；请选择 manual/auto，或导出 Mihomo 完整配置")
		}
		if format == "sing-box" && deviceStrategy(p) == "auto" && p.TimeoutMS != 0 {
			return r, errors.New("sing-box 1.14 URLTest 没有可配置 timeout 字段（核心固定 15 秒）；请清除 timeout_ms，或导出 Mihomo")
		}
	case "mihomo", "provider":
		if clientVersion != "1.19.30" {
			return r, errors.New("批量 Mihomo 导出仅核验 1.19.30；不会猜测其他版本字段")
		}
		if format == "mihomo" && deviceStrategy(p) == "auto" {
			if !p.AllowDegradedAuto {
				return r, errors.New("Mihomo 1.19.30 已实测存在首成员容差缺陷：选中第一项时可能在容差内切换；完整 auto 配置默认拒绝，请改用 manual/fallback，或明确设置 allow_degraded_auto 接受此缺陷")
			}
			r.Warnings = append(r.Warnings, "已明确接受 Mihomo 1.19.30 首成员容差缺陷：仍输出真实 tolerance 字段，但选中第一项时不能保证容差防抖；HTTPS 健康检测不证明 UDP 可用")
		}
	default:
		return r, errors.New("设备导出格式为 uri、base64、sing-box、sing-box-outbounds、mihomo 或 provider")
	}
	if deviceRouting(p) == "basic" {
		r.RuleSource = DeviceRuleSource{ID: "private-rfc1918-rfc4193-v1", Source: "RFC1918: 10/8, 172.16/12, 192.168/16; RFC4193: fc00::/7", CacheStatus: "embedded-v1; no external update or network cache"}
	}
	collectionOnly := format == "uri" || format == "base64" || format == "provider" || format == "sing-box-outbounds"
	if collectionOnly {
		r.Warnings = append(r.Warnings, "此格式仅包含节点集合，不能表达设备选择策略、分流、监听与 DNS；请用完整 sing-box/Mihomo 配置保留这些设置")
	}
	if deviceStrategy(p) != "manual" {
		r.Warnings = append(r.Warnings, "自动 HTTPS 探测只判断该测试 URL 的 TCP/HTTP 可用性与延迟；UDP 未经此测试验证，切换不能迁移已建立的会话")
	}
	bindings := selectedDeviceBindings(st, p)
	if len(bindings) == 0 {
		return r, errors.New("设备标签筛选后没有明确绑定的节点；不会导出空组或改用直连")
	}
	outbounds, proxies, tags, names, uris := []any{}, []any{}, []string{}, []string{}, []string{}
	nodeSeen := map[string]bool{}
	for _, b := range bindings {
		n, u, err := deviceBinding(st, b)
		if err != nil {
			return r, err
		}
		if !n.Enabled {
			return r, fmt.Errorf("设备选中的节点 %s 已停用", n.ID)
		}
		if err = ValidateProtocolClient(n, format, clientVersion, nil); err != nil {
			return r, err
		}
		adapter, ok := Protocol(n.Protocol)
		if !ok {
			return r, fmt.Errorf("节点 %s 的协议不受支持", n.ID)
		}
		if err = adapter.Validate(n); err != nil {
			return r, fmt.Errorf("节点 %s 的协议配置无效", n.ID)
		}
		if err = ValidateHY2ClientCertificate(n, format); err != nil {
			return r, fmt.Errorf("节点 %s：%w", n.ID, err)
		}
		if n.HY2 != nil {
			version := DefaultCore
			if format == "sing-box" || format == "sing-box-outbounds" {
				version = clientVersion
			}
			if err = ValidateHY2Capabilities(n, version, nil); err != nil {
				return r, fmt.Errorf("节点 %s 的 Hysteria2 设置无效", n.ID)
			}
		}
		capabilityFormat := format
		if format == "sing-box-outbounds" {
			capabilityFormat = "sing-box"
		}
		warnings := HY2ExportWarnings(n, capabilityFormat)
		if notes := ProtocolExportWarnings(n, format); len(notes) > 0 {
			return r, errors.New(strings.Join(notes, "；"))
		}
		for _, warning := range warnings {
			r.Warnings = append(r.Warnings, fmt.Sprintf("节点 %s：%s", n.ID, warning))
		}
		if capabilityFormat != "sing-box" && len(warnings) > 0 && !allowLossy {
			return r, errors.New("批量导出会丢失 Hysteria2 性能设置；请使用完整 sing-box 配置，或明确允许降级并查看 warnings")
		}
		if !nodeSeen[n.ID] {
			r.NodeIDs = append(r.NodeIDs, n.ID)
			nodeSeen[n.ID] = true
		}
		tag, name := deviceExportTag(b), deviceExportName(n, u, b)
		out := Outbound(n, u)
		out["tag"] = tag
		outbounds, tags = append(outbounds, out), append(tags, tag)
		proxy := MihomoProxy(n, u)
		proxy["name"] = name
		proxies, names = append(proxies, proxy), append(names, name)
		if format == "uri" || format == "base64" {
			raw := URI(n, u)
			if raw == "" {
				return r, errors.New("该协议或高级设置不支持分享URI；请导出完整配置")
			}
			parsed, err := url.Parse(raw)
			if err != nil {
				return r, errors.New("无法编码节点分享链接")
			}
			parsed.Fragment = name
			uris = append(uris, parsed.String())
		}
	}
	var err error
	switch format {
	case "uri":
		r.Content = []byte(strings.Join(uris, "\n") + "\n")
	case "base64":
		r.Content = []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(uris, "\n")+"\n")) + "\n")
	case "sing-box-outbounds":
		r.Content, err = json.MarshalIndent(M{"outbounds": outbounds}, "", "  ")
	case "provider":
		r.Content, err = yaml.Marshal(M{"proxies": proxies})
	case "sing-box":
		group := M{"type": "selector", "tag": "PROXY", "outbounds": tags, "default": tags[0], "interrupt_exist_connections": false}
		if deviceStrategy(p) == "auto" {
			interval, tolerance, _ := deviceTestSettings(p)
			group = M{"type": "urltest", "tag": "PROXY", "outbounds": tags, "url": p.TestURL, "interval": fmt.Sprintf("%ds", interval), "tolerance": tolerance, "idle_timeout": fmt.Sprintf("%ds", max(1800, interval*2)), "interrupt_exist_connections": false}
			r.Warnings = append(r.Warnings, "sing-box 1.14 URLTest 采用核心固定 15 秒单项超时；配置没有 timeout 字段")
		} else {
			r.Warnings = append(r.Warnings, "sing-box 手动组默认选择稳定排序后的第一项；切换由客户端界面或其已有 Clash API 完成，本配置不额外开放控制端口")
		}
		outbounds = append(outbounds, group)
		route := M{"final": "PROXY", "default_domain_resolver": "system"}
		if deviceRouting(p) == "basic" {
			outbounds = append(outbounds, M{"type": "direct", "tag": "DIRECT"})
			route["rules"] = []any{M{"ip_cidr": devicePrivateCIDRs, "action": "route", "outbound": "DIRECT"}}
		}
		r.Content, err = json.MarshalIndent(M{"log": M{"level": "warn"}, "dns": M{"servers": []any{M{"type": "local", "tag": "system"}}}, "inbounds": []any{M{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": 2080}}, "outbounds": outbounds, "route": route}, "", "  ")
	case "mihomo":
		group := M{"name": "PROXY", "type": "select", "proxies": names, "empty-fallback": "REJECT"}
		if deviceStrategy(p) != "manual" {
			interval, tolerance, timeout := deviceTestSettings(p)
			group["type"], group["url"], group["interval"], group["timeout"], group["lazy"] = "url-test", p.TestURL, interval, timeout, true
			group["max-failed-times"] = 3
			if deviceStrategy(p) == "auto" {
				group["tolerance"] = tolerance
			} else {
				group["type"] = "fallback"
			}
		}
		rules := []string{}
		if deviceRouting(p) == "basic" {
			for _, cidr := range devicePrivateCIDRs {
				typ := "IP-CIDR"
				if strings.Contains(cidr, ":") {
					typ = "IP-CIDR6"
				}
				rules = append(rules, typ+","+cidr+",DIRECT,no-resolve")
			}
		}
		rules = append(rules, "MATCH,PROXY")
		r.Content, err = yaml.Marshal(M{"mixed-port": 7890, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning", "proxies": proxies, "proxy-groups": []any{group}, "rules": rules})
	}
	return r, err
}

func deviceTestSettings(p DeviceProfile) (interval, tolerance, timeout int) {
	interval, tolerance, timeout = p.IntervalSeconds, p.ToleranceMS, p.TimeoutMS
	if interval == 0 {
		interval = 300
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if timeout == 0 {
		timeout = 5000
	}
	return
}
