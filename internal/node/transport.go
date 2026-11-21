package node

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const DefaultWSEarlyDataHeader = "Sec-WebSocket-Protocol"

// TransportOptions models V2Ray-compatible application-layer transports
// (TCP, WebSocket, gRPC, HTTPUpgrade, HTTP/2) without treating transports as
// separate underlying proxy protocols.
type TransportOptions struct {
	Type                string `json:"type,omitempty"`
	Path                string `json:"path,omitempty"`
	Host                string `json:"host,omitempty"`
	ServiceName         string `json:"service_name,omitempty"`
	MaxEarlyData        int    `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string `json:"early_data_header_name,omitempty"`
}

// MultiplexOptions configures sing-mux stream multiplexing for compatible TCP
// proxy protocols (mutually exclusive with XTLS Vision, QUIC, and built-in mux).
type MultiplexOptions struct {
	Enabled        bool   `json:"enabled"`
	Protocol       string `json:"protocol,omitempty"`
	MaxConnections int    `json:"max_connections,omitempty"`
	MinStreams     int    `json:"min_streams,omitempty"`
	Padding        bool   `json:"padding,omitempty"`
}

var grpcServiceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var httpHeaderTokenRE = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]{1,64}$`)

func ProtocolSupportsTransport(protocol string) bool {
	p, ok := Protocol(protocol)
	return ok && p.SupportsTransport
}

func ProtocolSupportsMultiplex(protocol string) bool {
	p, ok := Protocol(protocol)
	return ok && p.SupportsMultiplex
}

func EffectiveTransport(n Node) string {
	if n.Transport == nil || n.Transport.Type == "" || n.Transport.Type == "tcp" {
		return "tcp"
	}
	return n.Transport.Type
}

func EffectiveWSEarlyDataHeader(t *TransportOptions) string {
	if t == nil || t.MaxEarlyData <= 0 {
		return ""
	}
	if t.EarlyDataHeaderName != "" {
		return t.EarlyDataHeaderName
	}
	return DefaultWSEarlyDataHeader
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
	case "http":
		return "HTTP/2"
	default:
		return kind
	}
}

func ProtocolDisplaySummary(n Node) string {
	if p, ok := Protocol(n.Protocol); ok && p.DisplaySummary != nil {
		return p.DisplaySummary(n)
	}
	return n.Protocol
}

type protocolAlias struct {
	protocol  string
	transport string
}

var protocolShorthandAliases = map[string]protocolAlias{
	"reality-grpc":           {"reality", "grpc"},
	"vless":                  {"vless-tls", ""},
	"vless-ws":               {"vless-tls", "ws"},
	"vless-ws-tls":           {"vless-tls", "ws"},
	"vless-grpc":             {"vless-tls", "grpc"},
	"vless-grpc-tls":         {"vless-tls", "grpc"},
	"vless-httpupgrade":      {"vless-tls", "httpupgrade"},
	"vless-httpupgrade-tls":  {"vless-tls", "httpupgrade"},
	"vless-http":             {"vless-tls", "http"},
	"vless-http-tls":         {"vless-tls", "http"},
	"vless-h2":               {"vless-tls", "http"},
	"vless-h2-tls":           {"vless-tls", "http"},
	"vmess":                  {"vmess-tls", ""},
	"vmess-ws":               {"vmess-tls", "ws"},
	"vmess-ws-tls":           {"vmess-tls", "ws"},
	"vmess-grpc":             {"vmess-tls", "grpc"},
	"vmess-grpc-tls":         {"vmess-tls", "grpc"},
	"vmess-httpupgrade":      {"vmess-tls", "httpupgrade"},
	"vmess-httpupgrade-tls":  {"vmess-tls", "httpupgrade"},
	"vmess-http":             {"vmess-tls", "http"},
	"vmess-http-tls":         {"vmess-tls", "http"},
	"vmess-h2":               {"vmess-tls", "http"},
	"vmess-h2-tls":           {"vmess-tls", "http"},
	"trojan-tls":             {"trojan", ""},
	"trojan-ws":              {"trojan", "ws"},
	"trojan-ws-tls":          {"trojan", "ws"},
	"trojan-grpc":            {"trojan", "grpc"},
	"trojan-grpc-tls":        {"trojan", "grpc"},
	"trojan-httpupgrade":     {"trojan", "httpupgrade"},
	"trojan-httpupgrade-tls": {"trojan", "httpupgrade"},
	"trojan-http":            {"trojan", "http"},
	"trojan-http-tls":        {"trojan", "http"},
	"trojan-h2":              {"trojan", "http"},
	"trojan-h2-tls":          {"trojan", "http"},
}

// NormalizeProtocolAndTransport resolves shorthand protocol+transport aliases
// (such as vless-ws-tls, vmess-grpc-tls, trojan-h2-tls, reality-grpc) into the
// canonical base protocol and TransportOptions, applying safe defaults.
func NormalizeProtocolAndTransport(rawProtocol, rawTransport, path, host, serviceName string) (string, *TransportOptions, error) {
	p := strings.ToLower(strings.TrimSpace(rawProtocol))
	tr := strings.ToLower(strings.TrimSpace(rawTransport))
	switch tr {
	case "websocket":
		tr = "ws"
	case "h2":
		tr = "http"
	}
	if alias, ok := protocolShorthandAliases[p]; ok {
		p = alias.protocol
		if alias.transport != "" {
			if tr != "" && tr != alias.transport {
				return "", nil, fmt.Errorf("协议缩写 %s 与 --transport %s 冲突", rawProtocol, rawTransport)
			}
			tr = alias.transport
		}
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
	if p == "reality" {
		if tr == "" && serviceName != "" && path == "" && host == "" {
			tr = "grpc"
		}
		if tr == "tcp" {
			if path != "" || host != "" || serviceName != "" {
				return "", nil, errors.New("TCP 传输层不使用 path、host 或 service-name 参数")
			}
			return p, nil, nil
		}
		if tr != "grpc" {
			return "", nil, errors.New("REALITY 仅支持默认 TCP (Vision) 或 gRPC 传输层")
		}
		if path != "" || host != "" {
			return "", nil, errors.New("REALITY gRPC 传输层不使用 path 或 host 参数")
		}
		if serviceName == "" {
			serviceName = "grpc"
		}
		opts := &TransportOptions{Type: "grpc", ServiceName: serviceName}
		if err := validateTransportOptions(opts); err != nil {
			return "", nil, err
		}
		return p, opts, nil
	}
	if !ProtocolSupportsTransport(p) {
		return "", nil, fmt.Errorf("%s 不支持 WebSocket/gRPC/HTTPUpgrade/HTTP2 传输层参数", p)
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
	case "http":
		if serviceName != "" {
			return "", nil, errors.New("HTTP/2 传输层不使用 gRPC service-name 参数")
		}
		if path == "" {
			path = "/"
		}
		opts := &TransportOptions{Type: "http", Path: path, Host: host}
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
		return "", nil, fmt.Errorf("不支持传输方式 %q（可选：tcp、ws、grpc、httpupgrade、http）", tr)
	}
}

func validateTransport(n Node) error {
	if n.Protocol == "reality" {
		if n.Transport == nil {
			return nil
		}
		if n.Transport.Type != "" && n.Transport.Type != "tcp" && n.Transport.Type != "grpc" {
			return errors.New("REALITY 仅支持默认 TCP (Vision) 或 gRPC 传输层")
		}
		return validateTransportOptions(n.Transport)
	}
	if !ProtocolSupportsTransport(n.Protocol) {
		if n.Transport != nil {
			return fmt.Errorf("%s 不支持传输层参数", n.Protocol)
		}
		return nil
	}
	return validateTransportOptions(n.Transport)
}

func validEarlyDataHeaderName(h string) bool {
	if !httpHeaderTokenRE.MatchString(h) {
		return false
	}
	switch strings.ToLower(h) {
	case "host", "connection", "upgrade", "content-length", "transfer-encoding":
		return false
	}
	return true
}

func ValidateTransportOptions(t *TransportOptions) error {
	return validateTransportOptions(t)
}

func ValidateMultiplexOptions(m *MultiplexOptions) error {
	return validateMultiplexOptions(m)
}

func validateTransportOptions(t *TransportOptions) error {
	if t == nil {
		return nil
	}
	switch t.Type {
	case "", "tcp":
		if t.Path != "" || t.Host != "" || t.ServiceName != "" || t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return errors.New("TCP 传输层不能包含 path、host、service_name 或 early data 参数")
		}
		return nil
	case "ws":
		if t.ServiceName != "" {
			return errors.New("WebSocket 传输层不能包含 service_name")
		}
		if !validTransportPath(t.Path) {
			return errors.New("WebSocket 路径须以 / 开头、长度 1–256 字节且不含空白、?、# 或控制字符")
		}
		if t.Host != "" && !ValidHost(t.Host) {
			return errors.New("WebSocket Host 头须为有效域名或 IP")
		}
		if t.MaxEarlyData < 0 || t.MaxEarlyData > 65536 {
			return errors.New("WebSocket max_early_data 须为 0 或 1–65536")
		}
		if t.MaxEarlyData == 0 && t.EarlyDataHeaderName != "" {
			return errors.New("WebSocket early_data_header_name 仅在开启 max_early_data (>0) 时有效")
		}
		if t.EarlyDataHeaderName != "" && !validEarlyDataHeaderName(t.EarlyDataHeaderName) {
			return errors.New("WebSocket early_data_header_name 须为合法的 HTTP 头名称（1–64 字节，不能使用 Host/Upgrade/Connection 等保留头）")
		}
		return nil
	case "httpupgrade", "http":
		if t.ServiceName != "" || t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return fmt.Errorf("%s 传输层不能包含 service_name 或 WebSocket early data 参数", TransportName(t.Type))
		}
		if !validTransportPath(t.Path) {
			return fmt.Errorf("%s 路径须以 / 开头、长度 1–256 字节且不含空白、?、# 或控制字符", TransportName(t.Type))
		}
		if t.Host != "" && !ValidHost(t.Host) {
			return fmt.Errorf("%s Host 头须为有效域名或 IP", TransportName(t.Type))
		}
		return nil
	case "grpc":
		if t.Path != "" || t.Host != "" || t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return errors.New("gRPC 传输层不能包含 path、host 或 WebSocket early data 参数")
		}
		if !grpcServiceNameRE.MatchString(t.ServiceName) {
			return errors.New("gRPC service_name 须为 1–128 位字母、数字、点、下划线或连字符")
		}
		return nil
	default:
		return fmt.Errorf("不支持传输层类型 %q", t.Type)
	}
}

func validateNodeMultiplex(n Node) error {
	if !ProtocolSupportsMultiplex(n.Protocol) {
		if n.Multiplex != nil {
			return fmt.Errorf("%s 不支持 sing-mux 多路复用（与 XTLS Vision、QUIC 或内置会话复用互斥）", n.Protocol)
		}
		return nil
	}
	return validateMultiplexOptions(n.Multiplex)
}

func validateMultiplexOptions(m *MultiplexOptions) error {
	if m == nil {
		return nil
	}
	if !m.Enabled {
		return errors.New("多路复用（multiplex）开启时 enabled 必须为 true；停用请清除 multiplex 配置")
	}
	switch m.Protocol {
	case "", "h2mux", "smux", "yamux":
	default:
		return errors.New("多路复用协议仅支持 h2mux、smux 或 yamux")
	}
	if m.MaxConnections < 0 || m.MaxConnections > 64 {
		return errors.New("多路复用 max_connections 须为 0–64")
	}
	if m.MinStreams < 0 || m.MinStreams > 256 {
		return errors.New("多路复用 min_streams 须为 0–256")
	}
	return nil
}

func multiplexInbound(m *MultiplexOptions) M {
	if m == nil || !m.Enabled {
		return nil
	}
	out := M{"enabled": true}
	if m.Padding {
		out["padding"] = true
	}
	return out
}

func multiplexOutbound(m *MultiplexOptions) M {
	if m == nil || !m.Enabled {
		return nil
	}
	proto := m.Protocol
	if proto == "" {
		proto = "h2mux"
	}
	out := M{"enabled": true, "protocol": proto}
	if m.MaxConnections > 0 {
		out["max_connections"] = m.MaxConnections
	}
	if m.MinStreams > 0 {
		out["min_streams"] = m.MinStreams
	}
	if m.Padding {
		out["padding"] = true
	}
	return out
}

func applyMultiplexMihomo(out M, m *MultiplexOptions) {
	if m == nil || !m.Enabled {
		return
	}
	proto := m.Protocol
	if proto == "" {
		proto = "h2mux"
	}
	smux := M{"enabled": true, "protocol": proto}
	if m.MaxConnections > 0 {
		smux["max-connections"] = m.MaxConnections
	}
	if m.MinStreams > 0 {
		smux["min-streams"] = m.MinStreams
	}
	if m.Padding {
		smux["padding"] = true
	}
	out["smux"] = smux
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

func transportALPN(t *TransportOptions) []string {
	if t == nil {
		return nil
	}
	switch t.Type {
	case "ws", "httpupgrade":
		return []string{"http/1.1"}
	case "grpc", "http":
		return []string{"h2"}
	default:
		return nil
	}
}

func tlsInboundWithTransport(n Node, root string) M {
	tls := tlsInbound(n, root)
	if alpn := transportALPN(n.Transport); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	return tls
}

func tlsOutboundWithTransport(n Node) M {
	tls := tlsOutbound(n)
	if alpn := transportALPN(n.Transport); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	return tls
}

func transportOptionsToSingBox(t *TransportOptions) M {
	if t == nil {
		return nil
	}
	switch t.Type {
	case "", "tcp":
		return nil
	case "ws":
		out := M{"type": "ws", "path": t.Path}
		if t.Host != "" {
			out["headers"] = M{"Host": t.Host}
		}
		if t.MaxEarlyData > 0 {
			out["max_early_data"] = t.MaxEarlyData
			out["early_data_header_name"] = EffectiveWSEarlyDataHeader(t)
		}
		return out
	case "grpc":
		return M{"type": "grpc", "service_name": t.ServiceName}
	case "httpupgrade":
		out := M{"type": "httpupgrade", "path": t.Path}
		if t.Host != "" {
			out["host"] = t.Host
		}
		return out
	case "http":
		out := M{"type": "http", "path": t.Path}
		if t.Host != "" {
			out["host"] = []string{t.Host}
		}
		return out
	default:
		return nil
	}
}

func transportInbound(n Node) M {
	return transportOptionsToSingBox(n.Transport)
}

func transportOutbound(n Node) M {
	return transportOptionsToSingBox(n.Transport)
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
		if n.Transport.MaxEarlyData > 0 {
			wsOpts["max-early-data"] = n.Transport.MaxEarlyData
			wsOpts["early-data-header-name"] = EffectiveWSEarlyDataHeader(n.Transport)
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
	case "http":
		out["network"] = "h2"
		out["alpn"] = []string{"h2"}
		h2Opts := M{"path": n.Transport.Path}
		if n.Transport.Host != "" {
			h2Opts["host"] = []string{n.Transport.Host}
		}
		out["h2-opts"] = h2Opts
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
		if n.Transport.MaxEarlyData > 0 {
			q.Set("ed", strconv.Itoa(n.Transport.MaxEarlyData))
			if hdr := EffectiveWSEarlyDataHeader(n.Transport); hdr != DefaultWSEarlyDataHeader {
				q.Set("eh", hdr)
			}
		}
	case "grpc":
		q.Set("type", "grpc")
		q.Set("serviceName", n.Transport.ServiceName)
		q.Set("mode", "gun")
		if n.Protocol != "reality" {
			q.Set("alpn", "h2")
		}
	case "httpupgrade":
		q.Set("type", "httpupgrade")
		q.Set("path", n.Transport.Path)
		q.Set("alpn", "http/1.1")
		if n.Transport.Host != "" {
			q.Set("host", n.Transport.Host)
		}
	case "http":
		q.Set("type", "http")
		q.Set("path", n.Transport.Path)
		q.Set("alpn", "h2")
		if n.Transport.Host != "" {
			q.Set("host", n.Transport.Host)
		}
	default:
		q.Set("type", "tcp")
	}
}
