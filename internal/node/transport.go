package node

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TransportOptions models V2Ray-compatible application-layer transports over TLS
// (TCP, WebSocket, gRPC, HTTPUpgrade) without treating transports as separate
// underlying proxy protocols.
type TransportOptions struct {
	Type        string `json:"type,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

var grpcServiceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ProtocolSupportsTransport(protocol string) bool {
	return protocol == "vless-tls" || protocol == "vmess-tls" || protocol == "trojan"
}

func EffectiveTransport(n Node) string {
	if n.Transport == nil || n.Transport.Type == "" || n.Transport.Type == "tcp" {
		return "tcp"
	}
	return n.Transport.Type
}

func TransportName(kind string) string {
	switch kind {
	case "", "tcp":
		return "TCP"
	case "ws":
		return "WebSocket"
	case "grpc":
		return "gRPC"
	case "httpupgrade":
		return "HTTPUpgrade"
	default:
		return kind
	}
}

func ProtocolDisplaySummary(n Node) string {
	tr := EffectiveTransport(n)
	switch n.Protocol {
	case "reality":
		return "VLESS + REALITY + Vision"
	case "vless-tls":
		if tr == "tcp" {
			return "VLESS + TLS"
		}
		return "VLESS + " + TransportName(tr) + " + TLS"
	case "vmess-tls":
		if tr == "tcp" {
			return "VMess + TLS"
		}
		return "VMess + " + TransportName(tr) + " + TLS"
	case "trojan":
		if tr == "tcp" {
			return "Trojan + TLS"
		}
		return "Trojan + " + TransportName(tr) + " + TLS"
	case "ss2022":
		return "Shadowsocks 2022"
	case "ss-aead":
		return "Shadowsocks AEAD"
	case "hysteria2":
		return "Hysteria2"
	case "anytls":
		return "AnyTLS"
	case "tuic":
		return "TUIC v5"
	default:
		return n.Protocol
	}
}

// NormalizeProtocolAndTransport resolves shorthand protocol+transport aliases
// (such as vless-ws-tls, vmess-grpc-tls, trojan-ws-tls) into the canonical base
// protocol and TransportOptions, applying safe defaults when transport is chosen.
func NormalizeProtocolAndTransport(rawProtocol, rawTransport, path, host, serviceName string) (string, *TransportOptions, error) {
	p := strings.ToLower(strings.TrimSpace(rawProtocol))
	tr := strings.ToLower(strings.TrimSpace(rawTransport))
	if tr == "websocket" {
		tr = "ws"
	}
	impliedTr := ""
	switch p {
	case "vless":
		p = "vless-tls"
	case "vless-ws", "vless-ws-tls":
		p, impliedTr = "vless-tls", "ws"
	case "vless-grpc", "vless-grpc-tls":
		p, impliedTr = "vless-tls", "grpc"
	case "vless-httpupgrade", "vless-httpupgrade-tls":
		p, impliedTr = "vless-tls", "httpupgrade"
	case "vmess":
		p = "vmess-tls"
	case "vmess-ws", "vmess-ws-tls":
		p, impliedTr = "vmess-tls", "ws"
	case "vmess-grpc", "vmess-grpc-tls":
		p, impliedTr = "vmess-tls", "grpc"
	case "vmess-httpupgrade", "vmess-httpupgrade-tls":
		p, impliedTr = "vmess-tls", "httpupgrade"
	case "trojan-tls":
		p = "trojan"
	case "trojan-ws", "trojan-ws-tls":
		p, impliedTr = "trojan", "ws"
	case "trojan-grpc", "trojan-grpc-tls":
		p, impliedTr = "trojan", "grpc"
	case "trojan-httpupgrade", "trojan-httpupgrade-tls":
		p, impliedTr = "trojan", "httpupgrade"
	}
	if impliedTr != "" {
		if tr != "" && tr != impliedTr {
			return "", nil, fmt.Errorf("协议缩写 %s 与 --transport %s 冲突", rawProtocol, rawTransport)
		}
		tr = impliedTr
	}
	path = strings.TrimSpace(path)
	host = strings.TrimSpace(host)
	serviceName = strings.TrimSpace(serviceName)
	if host != "" {
		normalizedHost, err := NormalizeEndpointHost(host)
		if err != nil {
			return "", nil, fmt.Errorf("传输层 Host 无效：%w", err)
		}
		host = normalizedHost
	}
	if tr == "" && path == "" && host == "" && serviceName == "" {
		return p, nil, nil
	}
	if !ProtocolSupportsTransport(p) {
		return "", nil, fmt.Errorf("%s 不支持 WebSocket/gRPC/HTTPUpgrade 传输层参数", p)
	}
	if tr == "" {
		if serviceName != "" && path == "" && host == "" {
			tr = "grpc"
		} else if path != "" || host != "" {
			tr = "ws"
		} else {
			tr = "tcp"
		}
	}
	switch tr {
	case "tcp":
		if path != "" || host != "" || serviceName != "" {
			return "", nil, errors.New("TCP 传输层不使用 path、host 或 service-name 参数")
		}
		return p, nil, nil
	case "ws":
		if serviceName != "" {
			return "", nil, errors.New("WebSocket 传输层不使用 gRPC service-name 参数")
		}
		if path == "" {
			path = "/ws"
		}
		opts := &TransportOptions{Type: "ws", Path: path, Host: host}
		if err := validateTransportOptions(opts); err != nil {
			return "", nil, err
		}
		return p, opts, nil
	case "httpupgrade":
		if serviceName != "" {
			return "", nil, errors.New("HTTPUpgrade 传输层不使用 gRPC service-name 参数")
		}
		if path == "" {
			path = "/upgrade"
		}
		opts := &TransportOptions{Type: "httpupgrade", Path: path, Host: host}
		if err := validateTransportOptions(opts); err != nil {
			return "", nil, err
		}
		return p, opts, nil
	case "grpc":
		if path != "" || host != "" {
			return "", nil, errors.New("gRPC 传输层不使用 WebSocket path 或 host 参数")
		}
		if serviceName == "" {
			serviceName = "grpc"
		}
		opts := &TransportOptions{Type: "grpc", ServiceName: serviceName}
		if err := validateTransportOptions(opts); err != nil {
			return "", nil, err
		}
		return p, opts, nil
	default:
		return "", nil, fmt.Errorf("不支持传输方式 %q（可选：tcp、ws、grpc、httpupgrade）", tr)
	}
}

func validateTransport(n Node) error {
	if !ProtocolSupportsTransport(n.Protocol) {
		if n.Transport != nil {
			return fmt.Errorf("%s 不支持传输层参数", n.Protocol)
		}
		return nil
	}
	return validateTransportOptions(n.Transport)
}

func validateTransportOptions(t *TransportOptions) error {
	if t == nil {
		return nil
	}
	switch t.Type {
	case "", "tcp":
		if t.Path != "" || t.Host != "" || t.ServiceName != "" {
			return errors.New("TCP 传输层不能包含 path、host 或 service_name")
		}
		return nil
	case "ws", "httpupgrade":
		if t.ServiceName != "" {
			return fmt.Errorf("%s 传输层不能包含 service_name", TransportName(t.Type))
		}
		if !validTransportPath(t.Path) {
			return fmt.Errorf("%s 路径须以 / 开头、长度 1–256 字节且不含空白、?、# 或控制字符", TransportName(t.Type))
		}
		if t.Host != "" && !ValidHost(t.Host) {
			return fmt.Errorf("%s Host 头须为有效域名或 IP", TransportName(t.Type))
		}
		return nil
	case "grpc":
		if t.Path != "" || t.Host != "" {
			return errors.New("gRPC 传输层不能包含 path 或 host")
		}
		if !grpcServiceNameRE.MatchString(t.ServiceName) {
			return errors.New("gRPC service_name 须为 1–128 位字母、数字、点、下划线或连字符")
		}
		return nil
	default:
		return fmt.Errorf("不支持传输层类型 %q", t.Type)
	}
}

func validTransportPath(p string) bool {
	if p == "" || len(p) > 256 || !strings.HasPrefix(p, "/") || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '?' || r == '#' {
			return false
		}
	}
	return true
}

func tlsInboundWithTransport(n Node, root string) M {
	tls := tlsInbound(n, root)
	switch EffectiveTransport(n) {
	case "ws", "httpupgrade":
		tls["alpn"] = []string{"http/1.1"}
	case "grpc":
		tls["alpn"] = []string{"h2"}
	}
	return tls
}

func tlsOutboundWithTransport(n Node) M {
	tls := tlsOutbound(n)
	switch EffectiveTransport(n) {
	case "ws", "httpupgrade":
		tls["alpn"] = []string{"http/1.1"}
	case "grpc":
		tls["alpn"] = []string{"h2"}
	}
	return tls
}

func transportInbound(n Node) M {
	if n.Transport == nil {
		return nil
	}
	switch n.Transport.Type {
	case "", "tcp":
		return nil
	case "ws":
		out := M{"type": "ws", "path": n.Transport.Path}
		if n.Transport.Host != "" {
			out["headers"] = M{"Host": n.Transport.Host}
		}
		return out
	case "grpc":
		return M{"type": "grpc", "service_name": n.Transport.ServiceName}
	case "httpupgrade":
		out := M{"type": "httpupgrade", "path": n.Transport.Path}
		if n.Transport.Host != "" {
			out["host"] = n.Transport.Host
		}
		return out
	default:
		return nil
	}
}

func transportOutbound(n Node) M {
	return transportInbound(n)
}

func applyTransportMihomo(out M, n Node) {
	switch EffectiveTransport(n) {
	case "ws":
		out["network"] = "ws"
		out["alpn"] = []string{"http/1.1"}
		wsOpts := M{"path": n.Transport.Path}
		if n.Transport.Host != "" {
			wsOpts["headers"] = M{"Host": n.Transport.Host}
		}
		out["ws-opts"] = wsOpts
	case "grpc":
		out["network"] = "grpc"
		out["alpn"] = []string{"h2"}
		out["grpc-opts"] = M{"grpc-service-name": n.Transport.ServiceName}
	case "httpupgrade":
		out["network"] = "ws"
		out["alpn"] = []string{"http/1.1"}
		wsOpts := M{
			"path":                         n.Transport.Path,
			"v2ray-http-upgrade":           true,
			"v2ray-http-upgrade-fast-open": false,
		}
		if n.Transport.Host != "" {
			wsOpts["headers"] = M{"Host": n.Transport.Host}
		}
		out["ws-opts"] = wsOpts
	default:
		out["network"] = "tcp"
	}
}

func applyTransportURIQuery(q url.Values, n Node) {
	switch EffectiveTransport(n) {
	case "ws":
		q.Set("type", "ws")
		q.Set("path", n.Transport.Path)
		q.Set("alpn", "http/1.1")
		if n.Transport.Host != "" {
			q.Set("host", n.Transport.Host)
		}
	case "grpc":
		q.Set("type", "grpc")
		q.Set("serviceName", n.Transport.ServiceName)
		q.Set("mode", "gun")
		q.Set("alpn", "h2")
	case "httpupgrade":
		q.Set("type", "httpupgrade")
		q.Set("path", n.Transport.Path)
		q.Set("alpn", "http/1.1")
		if n.Transport.Host != "" {
			q.Set("host", n.Transport.Host)
		}
	default:
		q.Set("type", "tcp")
	}
}
