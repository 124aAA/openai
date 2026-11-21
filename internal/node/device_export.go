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

// Built-in private/special-use direct CIDRs covering IPv4/IPv6 loopback,
// RFC 1918, RFC 6598 CGNAT, link-local, and RFC 4193 unique-local ranges.
var devicePrivateCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

const (
	singBoxGeositeCNSRS = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
	singBoxGeoipCNSRS   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
	mihomoGeositeCNMRS  = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
	mihomoGeoipCNMRS    = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
)

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

func ruleSourceForRouting(routing string) DeviceRuleSource {
	switch clientRouting(routing) {
	case "basic":
		return DeviceRuleSource{
			ID:          "private-special-cidrs-v2",
			Source:      "sing-box ip_is_private + special-use CIDRs (127/8, 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, ::1/128, fc00::/7, fe80::/10)",
			CacheStatus: "embedded-v2; no external update or network cache",
		}
	case "global-secure-dns":
		return DeviceRuleSource{
			ID:          "global-secure-dns-v1",
			Source:      "all traffic via proxy with encrypted remote DoH DNS",
			CacheStatus: "embedded-v1; no external rule-set download",
		}
	case "cn-direct":
		return DeviceRuleSource{
			ID:          "cn-direct-ruleset-v1",
			Source:      "geosite-cn + geoip-cn (.srs/.mrs) + private IP direct + split encrypted DoH DNS",
			CacheStatus: "remote rule-set fetched by client via proxy",
		}
	default:
		return DeviceRuleSource{
			ID:          "global-v1",
			Source:      "all destinations use the selected entrance",
			CacheStatus: "embedded; no external update",
		}
	}
}

func buildSingBoxClientDoc(outbounds []any, proxyTag string, localPort int, opts ClientOptions) (M, error) {
	if err := ValidateClientOptions(opts); err != nil {
		return nil, err
	}
	routing := clientRouting(opts.Routing)
	inbounds := []any{M{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": localPort}}
	if opts.TUN {
		inbounds = append(inbounds, M{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route":   true,
			"strict_route": true,
		})
	}
	var dns M
	var route M
	switch routing {
	case "basic":
		outbounds = append(outbounds, M{"type": "direct", "tag": "DIRECT"})
		dns = M{"servers": []any{M{"type": "local", "tag": "system"}}}
		route = M{
			"rules": []any{
				M{"ip_is_private": true, "action": "route", "outbound": "DIRECT"},
				M{"ip_cidr": devicePrivateCIDRs, "action": "route", "outbound": "DIRECT"},
			},
			"final":                   proxyTag,
			"default_domain_resolver": "system",
		}
	case "global-secure-dns":
		dns = M{
			"servers": []any{
				M{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": proxyTag},
				M{"type": "local", "tag": "dns-bootstrap"},
			},
			"final": "dns-remote",
		}
		route = M{
			"rules": []any{
				M{"action": "sniff"},
				M{"protocol": "dns", "action": "hijack-dns"},
			},
			"final":                   proxyTag,
			"default_domain_resolver": "dns-bootstrap",
		}
	case "cn-direct":
		outbounds = append(outbounds, M{"type": "direct", "tag": "DIRECT"})
		dns = M{
			"servers": []any{
				M{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": proxyTag},
				M{"type": "https", "tag": "dns-direct", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query"},
				M{"type": "local", "tag": "dns-bootstrap"},
			},
			"rules": []any{
				M{"rule_set": []string{"geosite-cn"}, "server": "dns-direct"},
			},
			"final": "dns-remote",
		}
		route = M{
			"rules": []any{
				M{"action": "sniff"},
				M{"protocol": "dns", "action": "hijack-dns"},
				M{"ip_is_private": true, "action": "route", "outbound": "DIRECT"},
				M{"ip_cidr": devicePrivateCIDRs, "action": "route", "outbound": "DIRECT"},
				M{"rule_set": []string{"geosite-cn", "geoip-cn"}, "action": "route", "outbound": "DIRECT"},
			},
			"rule_set": []any{
				M{"tag": "geosite-cn", "type": "remote", "format": "binary", "url": singBoxGeositeCNSRS, "download_detour": proxyTag},
				M{"tag": "geoip-cn", "type": "remote", "format": "binary", "url": singBoxGeoipCNSRS, "download_detour": proxyTag},
			},
			"final":                   proxyTag,
			"default_domain_resolver": "dns-bootstrap",
		}
	default:
		dns = M{"servers": []any{M{"type": "local", "tag": "system"}}}
		route = M{"final": proxyTag, "default_domain_resolver": "system"}
	}
	if opts.TUN {
		route["auto_detect_interface"] = true
	}
	doc := M{
		"log":       M{"level": "warn"},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
	}
	if opts.Controller != nil && opts.Controller.Enabled {
		port := opts.Controller.Port
		if port == 0 {
			port = 9090
		}
		doc["experimental"] = M{
			"clash_api": M{
				"external_controller": fmt.Sprintf("127.0.0.1:%d", port),
				"secret":              opts.Controller.Secret,
			},
		}
	}
	return doc, nil
}

func mihomoPrivateRules() []string {
	rules := make([]string, 0, len(devicePrivateCIDRs))
	for _, cidr := range devicePrivateCIDRs {
		typ := "IP-CIDR"
		if strings.Contains(cidr, ":") {
			typ = "IP-CIDR6"
		}
		rules = append(rules, typ+","+cidr+",DIRECT,no-resolve")
	}
	return rules
}

func buildMihomoClientDoc(proxies []any, group M, localPort int, opts ClientOptions) (M, error) {
	if err := ValidateClientOptions(opts); err != nil {
		return nil, err
	}
	routing := clientRouting(opts.Routing)
	rules := []string{}
	doc := M{
		"mixed-port":   localPort,
		"allow-lan":    false,
		"bind-address": "127.0.0.1",
		"mode":         "rule",
		"log-level":    "warning",
		"proxies":      proxies,
		"proxy-groups": []any{group},
	}
	switch routing {
	case "basic":
		rules = append(rules, mihomoPrivateRules()...)
	case "global-secure-dns":
		doc["dns"] = M{
			"enable":                  true,
			"ipv6":                    false,
			"enhanced-mode":           "fake-ip",
			"fake-ip-range":           "198.18.0.1/16",
			"default-nameserver":      []string{"223.5.5.5", "119.29.29.29"},
			"proxy-server-nameserver": []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
			"nameserver":              []string{"https://1.1.1.1/dns-query#PROXY", "https://8.8.8.8/dns-query#PROXY"},
		}
	case "cn-direct":
		doc["dns"] = M{
			"enable":                  true,
			"ipv6":                    false,
			"enhanced-mode":           "fake-ip",
			"fake-ip-range":           "198.18.0.1/16",
			"default-nameserver":      []string{"223.5.5.5", "119.29.29.29"},
			"proxy-server-nameserver": []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
			"nameserver":              []string{"https://1.1.1.1/dns-query#PROXY", "https://8.8.8.8/dns-query#PROXY"},
			"nameserver-policy": M{
				"rule-set:geosite-cn": []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
			},
		}
		doc["rule-providers"] = M{
			"geosite-cn": M{
				"type":     "http",
				"behavior": "domain",
				"format":   "mrs",
				"url":      mihomoGeositeCNMRS,
				"path":     "./ruleset/geosite-cn.mrs",
				"interval": 86400,
			},
			"geoip-cn": M{
				"type":     "http",
				"behavior": "ipcidr",
				"format":   "mrs",
				"url":      mihomoGeoipCNMRS,
				"path":     "./ruleset/geoip-cn.mrs",
				"interval": 86400,
			},
		}
		rules = append(rules, mihomoPrivateRules()...)
		rules = append(rules, "RULE-SET,geosite-cn,DIRECT", "RULE-SET,geoip-cn,DIRECT,no-resolve")
	}
	rules = append(rules, "MATCH,PROXY")
	doc["rules"] = rules
	if opts.TUN {
		doc["tun"] = M{
			"enable":                true,
			"stack":                 "mixed",
			"auto-route":            true,
			"auto-detect-interface": true,
			"dns-hijack":            []string{"any:53", "tcp://any:53"},
		}
	}
	if opts.Controller != nil && opts.Controller.Enabled {
		port := opts.Controller.Port
		if port == 0 {
			port = 9090
		}
		doc["external-controller"] = fmt.Sprintf("127.0.0.1:%d", port)
		doc["secret"] = opts.Controller.Secret
	}
	return doc, nil
}

// ExportDeviceProfile serializes local entrance authentication only. A node's
// EgressID, remote egress secrets, server TLS private keys and other users are
// never copied into the exported client graph.
func ExportDeviceProfile(st State, p DeviceProfile, format, clientVersion string, allowLossy bool) (DeviceExportResult, error) {
	r := DeviceExportResult{NodeIDs: []string{}, RuleSource: ruleSourceForRouting("global")}
	if err := ValidateDeviceProfile(st, p); err != nil {
		return r, err
	}
	if p.Disabled {
		return r, errors.New("设备 Profile 已停用，不能导出或下载")
	}
	switch format {
	case "uri", "base64":
	case "sing-box", "sing-box-outbounds":
		if !SupportedVersion(clientVersion) {
			return r, errors.New("批量 sing-box 导出要求 1.14.x 正式版本；不会猜测其他主次版本字段")
		}
		if deviceStrategy(p) == "fallback" {
			return r, errors.New("sing-box 1.14.x 没有等价的有序 fallback 出站；请选择 manual/auto，或导出 Mihomo 完整配置")
		}
		if format == "sing-box" && deviceStrategy(p) == "auto" && p.TimeoutMS != 0 {
			return r, errors.New("sing-box 1.14 URLTest 没有可配置 timeout 字段（核心固定 15 秒）；请清除 timeout_ms，或导出 Mihomo")
		}
	case "mihomo", "provider":
		if !SupportedMihomoVersion(clientVersion) {
			return r, errors.New("批量 Mihomo 导出要求 >= 1.19.0 正式版本；不会猜测更旧或非标准版本字段")
		}
		if format == "mihomo" && deviceStrategy(p) == "auto" {
			if !p.AllowDegradedAuto {
				return r, errors.New("Mihomo 1.19.x 已实测存在首成员容差缺陷：选中第一项时可能在容差内切换；完整 auto 配置默认拒绝，请改用 manual/fallback，或明确设置 allow_degraded_auto 接受此缺陷")
			}
			r.Warnings = append(r.Warnings, "已明确接受 Mihomo 首成员容差缺陷：仍输出真实 tolerance 字段，但选中第一项时不能保证容差防抖；HTTPS 健康检测不证明 UDP 可用")
		}
	default:
		return r, errors.New("设备导出格式为 uri、base64、sing-box、sing-box-outbounds、mihomo 或 provider")
	}
	r.RuleSource = ruleSourceForRouting(deviceRouting(p))
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
			if format == "base64" && n.Protocol == "vmess-tls" {
				if notes := ProtocolExportWarnings(n, "vmess-v2rayn"); len(notes) > 0 {
					return r, errors.New(strings.Join(notes, "；"))
				}
				uris = append(uris, VMessV2RayNURIWithName(n, u, name))
				continue
			}
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
	opts := ClientOptions{Routing: p.Routing, TUN: p.TUN, Controller: p.Controller}
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
		} else if p.Controller != nil && p.Controller.Enabled {
			r.Warnings = append(r.Warnings, "sing-box 手动组默认选择稳定排序后的第一项；已配置仅本机 127.0.0.1 的 Clash API 控制端口供客户端切换节点")
		} else {
			r.Warnings = append(r.Warnings, "sing-box 手动组默认选择稳定排序后的第一项；切换由客户端界面或其已有 Clash API 完成，本配置不额外开放控制端口")
		}
		outbounds = append(outbounds, group)
		var doc M
		doc, err = buildSingBoxClientDoc(outbounds, "PROXY", 2080, opts)
		if err == nil {
			r.Content, err = json.MarshalIndent(doc, "", "  ")
		}
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
		var doc M
		doc, err = buildMihomoClientDoc(proxies, group, 7890, opts)
		if err == nil {
			r.Content, err = yaml.Marshal(doc)
		}
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
