package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
	"gopkg.in/yaml.v3"
)

type M = map[string]any

func Server(s State, root string) ([]byte, error) {
	var resolveErr error
	s, resolveErr = CanonicalCertificates(s)
	if resolveErr != nil {
		return nil, resolveErr
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	in := []any{}
	providers := []any{}
	providerSeen := map[string]bool{}
	for _, n := range s.Nodes {
		if !n.Enabled {
			continue
		}
		adapter, _ := Protocol(n.Protocol)
		config := adapter.Inbound(n, root)
		if n.Certificate != nil && n.Certificate.Mode == "acme" && n.Certificate.ACME != nil {
			tag := "certificate-" + n.CertificateID
			if !providerSeen[tag] {
				provider := certificateACMEProvider(n, root)
				resource, _ := s.FindCertificate(n.CertificateID)
				provider["data_directory"] = CertificateACMEDirectory(root, *resource)
				provider["tag"] = tag
				providers = append(providers, provider)
				providerSeen[tag] = true
			}
			config["tls"].(M)["certificate_provider"] = tag
		}
		config["tag"] = n.ID
		config["listen"] = n.Listen
		config["listen_port"] = n.Port
		in = append(in, config)
	}
	for _, f := range s.Forwards {
		if f.Enabled {
			in = append(in, forwardInbound(f))
		}
	}
	route := M{"final": "direct", "default_domain_resolver": "system"}
	out, endpoints, err := topologyServerConfig(s, in, route)
	if err != nil {
		return nil, err
	}
	config := M{"log": M{"level": "warn", "timestamp": true}, "dns": ProjectDNS(s.DNS), "inbounds": in, "outbounds": out, "route": route}
	if api := s.Observability; api != nil && api.Enabled {
		config["services"] = []any{M{"type": "api", "tag": "qingnode-api", "listen": api.Listen, "listen_port": api.Port, "secret": api.Secret}}
	}
	if len(providers) > 0 {
		config["certificate_providers"] = providers
	}
	if len(endpoints) != 0 {
		config["endpoints"] = endpoints
	}
	return json.MarshalIndent(config, "", "  ")
}
func SelectUser(n Node, id string) (User, error) {
	if id == "" {
		if len(n.Users) != 1 {
			return User{}, errors.New("此节点有多个凭据，请用 --user 指定")
		}
		return n.Users[0], nil
	}
	for _, u := range n.Users {
		if u.ID == id {
			return u, nil
		}
	}
	for _, u := range n.Users {
		if u.Name == id {
			return u, nil
		}
	}
	return User{}, errors.New("凭据不存在")
}
func URI(n Node, u User) string {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return ""
	}
	return p.URI(n, u)
}
func Outbound(n Node, u User) M {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	out := p.Outbound(n, u)
	out["tag"] = "proxy"
	out["server"] = n.Host
	if _, hasHopPorts := out["server_ports"]; !hasHopPorts {
		out["server_port"] = EffectiveConnectPort(n)
	}
	return out
}
func Client(n Node, u User, port int) M {
	doc, _ := ClientWithOptions(n, u, port, ClientOptions{})
	return doc
}
func ClientWithOptions(n Node, u User, port int, opts ClientOptions) (M, error) {
	return buildSingBoxClientDoc([]any{Outbound(n, u)}, "proxy", port, opts)
}
func MihomoProxy(n Node, u User) M {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	out := p.Mihomo(n, u)
	out["name"] = n.Name + " / " + u.Name
	out["server"] = n.Host
	out["port"] = EffectiveConnectPort(n)
	return out
}
func Export(n Node, u User, format string) ([]byte, error) {
	if warnings := ProtocolExportWarnings(n, format); len(warnings) > 0 {
		return nil, errors.New(strings.Join(warnings, "；"))
	}
	if n.HY2 != nil && n.Protocol != "hysteria2" {
		return nil, errors.New("Hysteria2性能设置不能用于其他协议")
	}
	if err := validateHY2Performance(n.HY2); err != nil {
		return nil, err
	}
	if format != "sing-box" {
		if warnings := HY2ExportWarnings(n, format); len(warnings) > 0 {
			return nil, fmt.Errorf("导出将丢失性能选择：%s", strings.Join(warnings, "；"))
		}
	}
	return exportUnchecked(n, u, format)
}

func exportUnchecked(n Node, u User, format string) ([]byte, error) {
	return exportUncheckedWithOptions(n, u, format, ClientOptions{})
}

func exportUncheckedWithOptions(n Node, u User, format string, opts ClientOptions) ([]byte, error) {
	if err := ValidateClientOptions(opts); err != nil {
		return nil, err
	}
	hasClientOptions := clientRouting(opts.Routing) != "global" || opts.TUN || (opts.Controller != nil && opts.Controller.Enabled)
	if hasClientOptions && format != "sing-box" && format != "mihomo" {
		return nil, errors.New("客户端分流预设、TUN 入站与本地控制端口仅适用于 sing-box 或 mihomo 完整配置")
	}
	if err := ValidateHY2ClientCertificate(n, format); err != nil {
		return nil, err
	}
	if p, ok := Protocol(n.Protocol); !ok {
		return nil, errors.New("不支持该协议")
	} else if p.MinSchema >= 8 {
		if err := p.Validate(n); err != nil {
			return nil, err
		}
	}
	if !n.Enabled {
		return nil, errors.New("节点已停用，启用后才能导出")
	}
	if (format == "uri" || format == "base64" || format == "qr") && URI(n, u) == "" {
		return nil, errors.New("该协议或高级设置不支持分享URI，请导出完整配置")
	}
	switch format {
	case "uri":
		return []byte(URI(n, u) + "\n"), nil
	case "vmess-v2rayn":
		if n.Protocol != "vmess-tls" {
			return nil, errors.New("vmess-v2rayn 导出格式仅适用于 VMess 节点")
		}
		return []byte(VMessV2RayNURI(n, u) + "\n"), nil
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString([]byte(URI(n, u)+"\n")) + "\n"), nil
	case "qr":
		q, e := qrcode.New(URI(n, u), qrcode.Medium)
		if e != nil {
			return nil, e
		}
		return []byte(q.ToSmallString(false)), nil
	case "sing-box":
		doc, e := ClientWithOptions(n, u, 2080, opts)
		if e != nil {
			return nil, e
		}
		return json.MarshalIndent(doc, "", "  ")
	case "mihomo":
		p := MihomoProxy(n, u)
		group := M{"name": "PROXY", "type": "select", "proxies": []string{p["name"].(string)}}
		doc, e := buildMihomoClientDoc([]any{p}, group, 7890, opts)
		if e != nil {
			return nil, e
		}
		return yaml.Marshal(doc)
	case "provider":
		return yaml.Marshal(M{"proxies": []any{MihomoProxy(n, u)}})
	default:
		return nil, fmt.Errorf("未知格式 %q；支持 %s", format, strings.Join([]string{"uri", "vmess-v2rayn", "qr", "base64", "mihomo", "provider", "sing-box"}, ", "))
	}
}
