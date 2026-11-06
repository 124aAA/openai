package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// V2RayTransport is an optional transport on a TLS protocol, not a protocol or
// a separate listener. An absent transport preserves the existing TCP format.
type V2RayTransport struct {
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

func NormalizeV2RayTransport(p *V2RayTransport) *V2RayTransport {
	if p == nil {
		return nil
	}
	t := *p
	switch t.Type {
	case "", "tcp":
		if t.Path == "" && t.Host == "" && t.ServiceName == "" {
			return nil
		}
		t.Type = "tcp"
	case "ws", "httpupgrade":
		if t.Path == "" {
			t.Path = "/"
		}
	case "grpc":
		if t.ServiceName == "" {
			t.ServiceName = "qingnode"
		}
	}
	return &t
}

var grpcServiceNameRE = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func ValidateV2RayTransport(protocol string, p *V2RayTransport) error {
	if p == nil {
		return nil
	}
	if protocol != "vless" && protocol != "vmess" && protocol != "trojan" {
		return errors.New("传输设置仅适用于 VLESS、VMess 和 Trojan")
	}
	t := NormalizeV2RayTransport(p)
	if t == nil {
		return nil
	}
	switch t.Type {
	case "ws", "httpupgrade":
		if t.Type == "httpupgrade" && protocol != "vless" {
			return errors.New("HTTPUpgrade 当前仅支持 VLESS；其他协议请选择 TCP、WebSocket 或 gRPC")
		}
		if t.ServiceName != "" {
			return errors.New("WebSocket/HTTPUpgrade 不使用 gRPC service name，请清除该参数")
		}
		if !utf8.ValidString(t.Path) || len(t.Path) > 2048 || !strings.HasPrefix(t.Path, "/") || strings.ContainsAny(t.Path, "?#%") || strings.IndexFunc(t.Path, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return errors.New("传输路径须以 / 开头，不能含空白、控制字符、?、# 或百分号编码；请填写原始路径")
		}
		if t.Host != "" {
			u, err := url.Parse("https://" + t.Host)
			if err != nil || u.Host != t.Host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !ValidHost(u.Hostname()) {
				return errors.New("传输 Host 须为域名或 IP，可带端口；IPv6 请使用方括号")
			}
			if port := u.Port(); port != "" {
				v, err := strconv.Atoi(port)
				if err != nil || v < 1 || v > 65535 {
					return errors.New("传输 Host 端口须为 1–65535")
				}
			}
		}
	case "grpc":
		if t.Path != "" || t.Host != "" {
			return errors.New("gRPC 使用 service name 和证书名称，不使用 WebSocket 的 path/Host")
		}
		if len(t.ServiceName) > 128 || !grpcServiceNameRE.MatchString(t.ServiceName) {
			return errors.New("gRPC service name 须为 1–128 个字母、数字、点、横线或下划线")
		}
	case "tcp":
		return errors.New("TCP 直连不使用 path、Host 或 service name，请清除这些参数")
	default:
		return errors.New("不支持该传输方式；请选择 tcp、ws、grpc，或 VLESS 的 httpupgrade")
	}
	return nil
}

func transportALPN(t *V2RayTransport) []string {
	if t != nil {
		switch t.Type {
		case "grpc":
			return []string{"h2"}
		case "ws", "httpupgrade":
			return []string{"http/1.1"}
		}
	}
	return nil
}

func withV2RayTransport(config M, p *V2RayTransport) M {
	t := NormalizeV2RayTransport(p)
	if t == nil {
		return config
	}
	transport := M{"type": t.Type}
	switch t.Type {
	case "ws":
		transport["path"] = t.Path
		if t.Host != "" {
			transport["headers"] = M{"Host": t.Host}
		}
	case "httpupgrade":
		transport["path"] = t.Path
		if t.Host != "" {
			transport["host"] = t.Host
		}
	case "grpc":
		transport["service_name"] = t.ServiceName
	}
	config["transport"] = transport
	return config
}

func withMihomoTransport(config M, p *V2RayTransport) M {
	t := NormalizeV2RayTransport(p)
	if t == nil {
		return config
	}
	config["network"] = t.Type
	config["alpn"] = transportALPN(t)
	switch t.Type {
	case "ws", "httpupgrade":
		opts := M{"path": t.Path}
		if t.Host != "" {
			opts["headers"] = M{"Host": t.Host}
		}
		if t.Type == "httpupgrade" {
			config["network"] = "ws"
			opts["v2ray-http-upgrade"] = true
		}
		config["ws-opts"] = opts
	case "grpc":
		config["grpc-opts"] = M{"grpc-service-name": t.ServiceName}
	}
	return config
}

func addTransportQuery(q url.Values, p *V2RayTransport) {
	t := NormalizeV2RayTransport(p)
	if t == nil {
		return
	}
	q.Set("security", "tls")
	q.Set("type", t.Type)
	q.Set("alpn", strings.Join(transportALPN(t), ","))
	switch t.Type {
	case "ws", "httpupgrade":
		q.Set("path", t.Path)
		if t.Host != "" {
			q.Set("host", t.Host)
		}
	case "grpc":
		q.Set("serviceName", t.ServiceName)
	}
}

func v2rayCredential(u *User) {
	u.Password = ""
	realityCredential(u)
}

func validateV2RayTLS(n Node) error { return validateTLSNode(n, true) }

func v2rayInbound(n Node, root string) M {
	users := make([]any, 0, len(n.Users))
	for _, u := range n.Users {
		user := M{"name": u.ID, "uuid": u.UUID}
		if n.Protocol == "vmess" {
			user["alterId"] = 0
		}
		users = append(users, user)
	}
	return withV2RayTransport(M{"type": n.Protocol, "users": users, "tls": tlsInbound(n, root)}, n.Transport)
}

func v2rayOutbound(n Node, u User) M {
	out := M{"type": n.Protocol, "uuid": u.UUID, "tls": tlsOutbound(n)}
	if n.Protocol == "vmess" {
		out["security"], out["alter_id"] = "auto", 0
	}
	return withV2RayTransport(out, n.Transport)
}

func v2rayMihomo(n Node, u User) M {
	out := M{"type": n.Protocol, "uuid": u.UUID, "tls": true, "servername": n.Certificate.ServerName, "skip-cert-verify": false, "network": "tcp", "udp": true}
	if n.Protocol == "vmess" {
		out["cipher"], out["alterId"] = "auto", 0
	}
	return withMihomoTransport(out, n.Transport)
}

func vlessURI(n Node, u User) string {
	if n.Transport != nil && n.Transport.Type == "httpupgrade" {
		return ""
	}
	q := url.Values{"encryption": {"none"}, "security": {"tls"}, "type": {"tcp"}, "sni": {n.Certificate.ServerName}}
	addTransportQuery(q, n.Transport)
	x := url.URL{Scheme: "vless", User: url.User(u.UUID), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), RawQuery: q.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}

// The widely supported v2rayN JSON form preserves names and IPv6 without URL
// authority ambiguity. gRPC uses path as service name in this sharing format.
func vmessURI(n Node, u User) string {
	return vmessNamedURI(n, u, n.Name+" / "+u.Name)
}

func vmessNamedURI(n Node, u User, name string) string {
	share := M{"v": "2", "ps": name, "add": n.Host, "port": strconv.Itoa(EffectiveConnectPort(n)), "id": u.UUID, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "tls": "tls", "sni": n.Certificate.ServerName}
	if t := NormalizeV2RayTransport(n.Transport); t != nil {
		share["net"] = t.Type
		share["alpn"] = strings.Join(transportALPN(t), ",")
		if t.Type == "grpc" {
			share["path"] = t.ServiceName
		} else {
			share["path"], share["host"] = t.Path, t.Host
		}
	}
	raw, _ := json.Marshal(share)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}
