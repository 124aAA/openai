package probe

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Profile is a private client credential, separate from State and from reports.
// Only a single supported outbound is accepted; arbitrary sing-box configs,
// routing, direct fallbacks and server private keys cannot enter the sandbox.
type Profile struct {
	Version          int             `json:"version"`
	NodeID           string          `json:"node_id"`
	CoreVersion      string          `json:"server_core_version"`
	ConfigSHA256     string          `json:"config_sha256"`
	Outbound         json.RawMessage `json:"outbound"`
	ServerPathSHA256 string          `json:"server_path_sha256,omitempty"`
}

type outbound struct {
	profileHY2Options
	profileAnyTLSOptions
	profileTUICOptions
	profileVMessOptions
	Type           string           `json:"type"`
	Tag            string           `json:"tag"`
	Server         string           `json:"server"`
	Port           uint16           `json:"server_port,omitempty"`
	UUID           string           `json:"uuid,omitempty"`
	Flow           string           `json:"flow,omitempty"`
	PacketEncoding string           `json:"packet_encoding,omitempty"`
	Method         string           `json:"method,omitempty"`
	Password       string           `json:"password,omitempty"`
	TLS            *clientTLS       `json:"tls,omitempty"`
	Transport      *clientTransport `json:"transport,omitempty"`
	Multiplex      *clientMultiplex `json:"multiplex,omitempty"`
}

// These are the bounded client fields emitted by the manager, independently
// implemented from the public JSON contract. No upstream implementation is linked.
type profileAnyTLSOptions struct {
	IdleSessionCheckInterval string `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string `json:"idle_session_timeout,omitempty"`
	MinIdleSession           *int   `json:"min_idle_session,omitempty"`
}

func (o profileAnyTLSOptions) validate(kind string) error {
	b, _ := json.Marshal(o)
	if kind != "anytls" {
		if string(b) != "{}" {
			return errors.New("AnyTLS session options cannot be used on another protocol")
		}
		return nil
	}
	for _, raw := range []string{o.IdleSessionCheckInterval, o.IdleSessionTimeout} {
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 5*time.Second || d > 24*time.Hour || d%time.Second != 0 {
			return errors.New("AnyTLS session times must be whole seconds from 6s to 24h")
		}
	}
	if o.MinIdleSession != nil && (*o.MinIdleSession < 0 || *o.MinIdleSession > 1024) {
		return errors.New("AnyTLS retained idle sessions exceed the bounded range")
	}
	return nil
}

type profileTUICOptions struct {
	CongestionControl string `json:"congestion_control,omitempty"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
	ZeroRTTHandshake  *bool  `json:"zero_rtt_handshake,omitempty"`
	Heartbeat         string `json:"heartbeat,omitempty"`
}

func (o profileTUICOptions) validate(kind string) error {
	b, _ := json.Marshal(o)
	if kind != "tuic" {
		if string(b) != "{}" {
			return errors.New("TUIC options cannot be used on another protocol")
		}
		return nil
	}
	if o.CongestionControl != "" && o.CongestionControl != "cubic" && o.CongestionControl != "new_reno" && o.CongestionControl != "bbr" {
		return errors.New("unsupported TUIC congestion control")
	}
	if o.UDPRelayMode != "" && o.UDPRelayMode != "native" && o.UDPRelayMode != "quic" {
		return errors.New("unsupported TUIC UDP relay mode")
	}
	if o.ZeroRTTHandshake != nil && *o.ZeroRTTHandshake {
		return errors.New("TUIC 0-RTT must remain disabled")
	}
	if o.Heartbeat != "" {
		d, err := time.ParseDuration(o.Heartbeat)
		if err != nil || d < time.Second || d > 2*time.Minute || d%time.Millisecond != 0 {
			return errors.New("TUIC heartbeat is outside the bounded millisecond range")
		}
	}
	return nil
}

type profileVMessOptions struct {
	Security            string `json:"security,omitempty"`
	AlterID             *int   `json:"alter_id,omitempty"`
	GlobalPadding       *bool  `json:"global_padding,omitempty"`
	AuthenticatedLength *bool  `json:"authenticated_length,omitempty"`
}

func (o profileVMessOptions) validate(kind string) error {
	b, _ := json.Marshal(o)
	if kind != "vmess" {
		if string(b) != "{}" {
			return errors.New("VMess options cannot be used on another protocol")
		}
		return nil
	}
	if o.Security != "" && o.Security != "auto" && o.Security != "aes-128-gcm" && o.Security != "chacha20-poly1305" {
		return errors.New("unsupported VMess security cipher")
	}
	if o.AlterID != nil && *o.AlterID != 0 {
		return errors.New("VMess alter_id must be 0")
	}
	if o.GlobalPadding != nil && !*o.GlobalPadding {
		return errors.New("VMess global_padding cannot be disabled")
	}
	if o.AuthenticatedLength != nil && !*o.AuthenticatedLength {
		return errors.New("VMess authenticated_length cannot be disabled")
	}
	return nil
}

type transportHost struct {
	Single string
	List   []string
}

func (h *transportHost) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return StrictJSON(trimmed, &h.List)
	}
	return StrictJSON(trimmed, &h.Single)
}

func (h transportHost) MarshalJSON() ([]byte, error) {
	if h.List != nil {
		return json.Marshal(h.List)
	}
	return json.Marshal(h.Single)
}

type clientTransport struct {
	Type                string                  `json:"type"`
	Path                string                  `json:"path,omitempty"`
	Host                *transportHost          `json:"host,omitempty"`
	Headers             *clientTransportHeaders `json:"headers,omitempty"`
	ServiceName         string                  `json:"service_name,omitempty"`
	MaxEarlyData        int                     `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string                  `json:"early_data_header_name,omitempty"`
}

type clientTransportHeaders struct {
	Host string `json:"Host,omitempty"`
}

type clientMultiplex struct {
	Enabled        bool   `json:"enabled"`
	Protocol       string `json:"protocol,omitempty"`
	MaxConnections int    `json:"max_connections,omitempty"`
	MinStreams     int    `json:"min_streams,omitempty"`
	Padding        bool   `json:"padding,omitempty"`
}

var profileGRPCServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var profileHeaderToken = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]{1,64}$`)

func validProfileHeaderToken(h string) bool {
	if !profileHeaderToken.MatchString(h) {
		return false
	}
	switch strings.ToLower(h) {
	case "host", "connection", "upgrade", "content-length", "transfer-encoding":
		return false
	}
	return true
}

func validProfileTransportPath(p string) bool {
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

func (t *clientTransport) validate(kind string, reality bool) error {
	if t == nil {
		return nil
	}
	if reality {
		if kind != "vless" || t.Type != "grpc" {
			return errors.New("REALITY supports only default Vision TCP or gRPC transport")
		}
	} else if kind != "vless" && kind != "vmess" && kind != "trojan" {
		return errors.New("client transport is supported only on VLESS-TLS, VMess-TLS, Trojan and REALITY-gRPC")
	}
	switch t.Type {
	case "ws":
		if !validProfileTransportPath(t.Path) || t.Host != nil || t.ServiceName != "" {
			return errors.New("unsupported WebSocket client transport options")
		}
		if t.Headers != nil && !validGraphHost(t.Headers.Host) {
			return errors.New("invalid WebSocket Host header")
		}
		if t.MaxEarlyData < 0 || t.MaxEarlyData > 65536 || (t.MaxEarlyData == 0 && t.EarlyDataHeaderName != "") {
			return errors.New("invalid WebSocket early data bounds")
		}
		if t.EarlyDataHeaderName != "" && !validProfileHeaderToken(t.EarlyDataHeaderName) {
			return errors.New("invalid WebSocket early_data_header_name")
		}
	case "httpupgrade":
		if !validProfileTransportPath(t.Path) || t.Headers != nil || t.ServiceName != "" || t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return errors.New("unsupported HTTPUpgrade client transport options")
		}
		if t.Host != nil && (t.Host.List != nil || !validGraphHost(t.Host.Single)) {
			return errors.New("invalid HTTPUpgrade host")
		}
	case "http":
		if !validProfileTransportPath(t.Path) || t.Headers != nil || t.ServiceName != "" || t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return errors.New("unsupported HTTP/2 client transport options")
		}
		if t.Host != nil && (t.Host.Single != "" || len(t.Host.List) != 1 || !validGraphHost(t.Host.List[0])) {
			return errors.New("invalid HTTP/2 host list")
		}
	case "grpc":
		if !profileGRPCServiceName.MatchString(t.ServiceName) || t.Path != "" || t.Host != nil || t.Headers != nil || t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return errors.New("unsupported gRPC client transport options")
		}
	default:
		return errors.New("unsupported client transport type")
	}
	return nil
}

func (m *clientMultiplex) validate(kind string, reality bool, flow string) error {
	if m == nil {
		return nil
	}
	if (kind != "shadowsocks" && kind != "trojan" && kind != "vmess" && kind != "vless") || reality || flow != "" {
		return errors.New("multiplex is supported only on compatible non-Vision TCP protocols")
	}
	if !m.Enabled {
		return errors.New("multiplex enabled must be true when present")
	}
	switch m.Protocol {
	case "", "h2mux", "smux", "yamux":
	default:
		return errors.New("unsupported multiplex protocol")
	}
	if m.MaxConnections < 0 || m.MaxConnections > 64 || m.MinStreams < 0 || m.MinStreams > 256 {
		return errors.New("multiplex stream bounds out of range")
	}
	return nil
}

const profileOutboundFields = "type tag server server_port uuid flow packet_encoding method password security alter_id global_padding authenticated_length tls transport multiplex up_mbps down_mbps bbr_profile brutal_debug disable_chrome_parrot stream_receive_window connection_receive_window idle_timeout keep_alive_period max_concurrent_streams initial_packet_size disable_path_mtu_discovery obfs server_ports hop_interval idle_session_check_interval idle_session_timeout min_idle_session congestion_control udp_relay_mode zero_rtt_handshake heartbeat"

// Presence is checked before canonicalization: null, empty and explicit false
// must not disguise an option placed on the wrong protocol.
func profileProtocolFields(raw []byte, kind string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for protocol, names := range map[string]string{
		"hysteria2": "up_mbps down_mbps bbr_profile brutal_debug disable_chrome_parrot stream_receive_window connection_receive_window idle_timeout keep_alive_period max_concurrent_streams initial_packet_size disable_path_mtu_discovery obfs server_ports hop_interval",
		"anytls":    "idle_session_check_interval idle_session_timeout min_idle_session",
		"tuic":      "congestion_control udp_relay_mode zero_rtt_handshake heartbeat",
		"vmess":     "security alter_id global_padding authenticated_length",
	} {
		if kind == protocol {
			continue
		}
		for _, name := range strings.Fields(names) {
			if _, present := fields[name]; present {
				return errors.New("protocol-specific client option is placed on another protocol")
			}
		}
	}
	if rawPort, hasPort := fields["server_port"]; hasPort && (string(rawPort) == "null" || string(rawPort) == "0") {
		return errors.New("invalid selected proxy endpoint")
	}
	if kind == "hysteria2" {
		for _, name := range []string{"obfs", "server_ports", "hop_interval"} {
			if val, present := fields[name]; present && (string(val) == "null" || string(val) == `""` || string(val) == "[]") {
				return errors.New("null or empty HY2 client option is not supported")
			}
		}
		if _, hasPorts := fields["server_ports"]; hasPorts {
			if _, hasPort := fields["server_port"]; hasPort {
				return errors.New("HY2 server_ports cannot be combined with server_port")
			}
		}
		if obfsRaw, present := fields["obfs"]; present {
			if err := graphFields(obfsRaw, "type password"); err != nil {
				return err
			}
		}
	}
	if kind == "vmess" {
		for _, name := range []string{"security", "alter_id", "global_padding", "authenticated_length"} {
			if val, present := fields[name]; present && (string(val) == "null" || string(val) == `""`) {
				return errors.New("null or empty VMess client option is not supported")
			}
		}
	}
	if rawPE, present := fields["packet_encoding"]; present {
		if (kind != "vless" && kind != "vmess") || string(rawPE) == "null" || string(rawPE) == `""` {
			return errors.New("packet_encoding is supported only as a non-empty VLESS-TLS or VMess-TLS option")
		}
	}
	if _, present := fields["transport"]; present && kind != "vless" && kind != "vmess" && kind != "trojan" {
		return errors.New("client transport is placed on an unsupported protocol")
	}
	if _, present := fields["multiplex"]; present && kind != "shadowsocks" && kind != "vless" && kind != "vmess" && kind != "trojan" {
		return errors.New("client multiplex is placed on an unsupported protocol")
	}
	if tls := fields["tls"]; tls != nil && string(tls) != "null" {
		var values map[string]json.RawMessage
		_ = json.Unmarshal(tls, &values)
		if rawALPN, present := values["alpn"]; present {
			if string(rawALPN) == "null" || string(rawALPN) == "[]" {
				return errors.New("empty or null client TLS ALPN is not supported")
			}
			if kind != "tuic" && kind != "vless" && kind != "vmess" && kind != "trojan" {
				return errors.New("ALPN override is not supported on this protocol")
			}
		}
	}
	return nil
}

func validNewProtocolPassword(password string) bool {
	if len(password) < 16 || len(password) > 512 || !utf8.ValidString(password) {
		return false
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type profileHY2Obfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

func validProfileHY2ObfsPassword(pw string) bool {
	if len(pw) < 4 || len(pw) > 256 || strings.TrimSpace(pw) == "" || !utf8.ValidString(pw) {
		return false
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validProfileHY2ServerPortRange(raw string) bool {
	startStr, endStr, ok := strings.Cut(raw, ":")
	if !ok || startStr == "" || endStr == "" || strings.Contains(endStr, ":") {
		return false
	}
	parse := func(s string) (int, bool) {
		if len(s) > 5 || s[0] == '0' {
			return 0, false
		}
		n := 0
		for _, r := range s {
			if r < '0' || r > '9' {
				return 0, false
			}
			n = n*10 + int(r-'0')
		}
		return n, true
	}
	start, ok1 := parse(startStr)
	end, ok2 := parse(endStr)
	return ok1 && ok2 && start >= 1024 && end <= 65535 && start < end && end-start+1 <= 20001
}

// The private portable profile accepts only the fixed 1.14.x HY2 fields
// emitted by the manager. Routing, helper commands and arbitrary JSON remain
// rejected. Pointers retain explicit false versus core-default omission.
type profileHY2Options struct {
	UpMbps                  *int            `json:"up_mbps,omitempty"`
	DownMbps                *int            `json:"down_mbps,omitempty"`
	BBRProfile              string          `json:"bbr_profile,omitempty"`
	BrutalDebug             *bool           `json:"brutal_debug,omitempty"`
	DisableChromeParrot     *bool           `json:"disable_chrome_parrot,omitempty"`
	StreamReceiveWindow     *int64          `json:"stream_receive_window,omitempty"`
	ConnectionReceiveWindow *int64          `json:"connection_receive_window,omitempty"`
	IdleTimeout             string          `json:"idle_timeout,omitempty"`
	KeepAlivePeriod         string          `json:"keep_alive_period,omitempty"`
	MaxConcurrentStreams    *int            `json:"max_concurrent_streams,omitempty"`
	InitialPacketSize       *int            `json:"initial_packet_size,omitempty"`
	DisablePathMTUDiscovery *bool           `json:"disable_path_mtu_discovery,omitempty"`
	Obfs                    *profileHY2Obfs `json:"obfs,omitempty"`
	ServerPorts             []string        `json:"server_ports,omitempty"`
	HopInterval             string          `json:"hop_interval,omitempty"`
}

func (o profileHY2Options) validate(kind string) error {
	b, _ := json.Marshal(o)
	if kind != "hysteria2" {
		if string(b) != "{}" {
			return errors.New("HY2性能字段不能用于其他协议")
		}
		return nil
	}
	if o.Obfs != nil {
		if o.Obfs.Type != "salamander" || !validProfileHY2ObfsPassword(o.Obfs.Password) {
			return errors.New("HY2混淆参数无效")
		}
	}
	if len(o.ServerPorts) > 1 {
		return errors.New("HY2跳跃端口列表超出上限")
	}
	if len(o.ServerPorts) == 1 {
		if !validProfileHY2ServerPortRange(o.ServerPorts[0]) {
			return errors.New("HY2跳跃端口范围无效")
		}
	} else if o.HopInterval != "" {
		return errors.New("未设置HY2跳跃端口时不能设置hop_interval")
	}
	if o.HopInterval != "" {
		d, err := time.ParseDuration(o.HopInterval)
		if err != nil || d < 5*time.Second || d > 10*time.Minute || d%time.Second != 0 {
			return errors.New("HY2跳跃间隔无效")
		}
	}
	if (o.UpMbps == nil) != (o.DownMbps == nil) {
		return errors.New("HY2客户端上传和下载预期须同时提供")
	}
	for _, v := range []*int{o.UpMbps, o.DownMbps} {
		if v != nil && (*v < 1 || *v > 1000000) {
			return errors.New("HY2预期Mbps超出允许范围")
		}
	}
	if o.BBRProfile != "" && o.BBRProfile != "standard" && o.BBRProfile != "conservative" && o.BBRProfile != "aggressive" {
		return errors.New("未支持的HY2 BBR配置")
	}
	for _, v := range []*int64{o.StreamReceiveWindow, o.ConnectionReceiveWindow} {
		if v != nil && (*v < 64<<10 || *v > 256<<20) {
			return errors.New("HY2接收窗口超出允许范围")
		}
	}
	if o.StreamReceiveWindow != nil && o.ConnectionReceiveWindow != nil && *o.StreamReceiveWindow > *o.ConnectionReceiveWindow {
		return errors.New("HY2单流窗口不能大于连接窗口")
	}
	var idle, keep time.Duration
	if o.IdleTimeout != "" {
		var e error
		idle, e = time.ParseDuration(o.IdleTimeout)
		if e != nil || idle < time.Second || idle > 10*time.Minute {
			return errors.New("HY2空闲超时无效")
		}
	}
	if o.KeepAlivePeriod != "" {
		var e error
		keep, e = time.ParseDuration(o.KeepAlivePeriod)
		if e != nil || keep < time.Second || keep > 2*time.Minute {
			return errors.New("HY2保活间隔无效")
		}
	}
	if idle > 0 && keep > idle {
		return errors.New("HY2保活不能长于空闲超时")
	}
	if o.MaxConcurrentStreams != nil && (*o.MaxConcurrentStreams < 1 || *o.MaxConcurrentStreams > 4096) {
		return errors.New("HY2并发流范围无效")
	}
	if o.InitialPacketSize != nil && (*o.InitialPacketSize < 1200 || *o.InitialPacketSize > 1452) {
		return errors.New("HY2初始包大小无效")
	}
	return nil
}

type clientTLS struct {
	Enabled     bool           `json:"enabled"`
	ServerName  string         `json:"server_name"`
	Certificate []string       `json:"certificate,omitempty"`
	UTLS        *clientUTLS    `json:"utls,omitempty"`
	Reality     *clientReality `json:"reality,omitempty"`
	ALPN        []string       `json:"alpn,omitempty"`
}
type clientUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}
type clientReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

var compatibleCore = regexp.MustCompile(`^1\.14\.(0|[1-9][0-9]*)$`)
var profileUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// StrictJSON rejects duplicate keys as well as unknown fields. Reports and
// private profiles are versioned independently of the managed State schema.
func StrictJSON(data []byte, v any) error {
	if len(data) > 1<<20 {
		return errors.New("JSON exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return errors.New("duplicate JSON key")
					}
					seen[s] = true
					if err = walk(); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err = walk(); err != nil {
						return err
					}
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		return errors.New("invalid or duplicate JSON fields")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON content")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("invalid JSON shape or unsupported field")
	}
	return nil
}

func validProfileRealityFingerprint(fp string) bool {
	switch fp {
	case "chrome", "firefox", "safari", "ios", "edge", "random", "randomized", "qq", "android", "360":
		return true
	default:
		return false
	}
}

func validProfileSS2022Password(pw string, size int) bool {
	keys := strings.Split(pw, ":")
	if len(keys) < 1 || len(keys) > 8 {
		return false
	}
	for _, k := range keys {
		b, err := base64.StdEncoding.Strict().DecodeString(k)
		if err != nil || len(b) != size || base64.StdEncoding.EncodeToString(b) != k {
			return false
		}
	}
	return true
}

func NewProfile(nodeID, serverVersion string, raw []byte) (Profile, error) {
	var o outbound
	if err := graphFields(raw, profileOutboundFields); err != nil {
		return Profile{}, err
	}
	if err := graphTLSFields(raw); err != nil {
		return Profile{}, err
	}
	if err := graphTransportFields(raw); err != nil {
		return Profile{}, err
	}
	if err := graphMultiplexFields(raw); err != nil {
		return Profile{}, err
	}
	if err := StrictJSON(raw, &o); err != nil {
		return Profile{}, err
	}
	if err := profileProtocolFields(raw, o.Type); err != nil {
		return Profile{}, err
	}
	canonical, err := json.Marshal(o)
	if err != nil {
		return Profile{}, err
	}
	h := sha256.Sum256(canonical)
	p := Profile{Version: 1, NodeID: nodeID, CoreVersion: serverVersion, ConfigSHA256: hex.EncodeToString(h[:]), Outbound: canonical}
	return p, p.Validate()
}

// WithServerPathDigest records only the manager's declared server path at
// export time. It does not expose remote credentials or prove the remote server
// still uses that path. The explicit version prevents old readers accepting it.
func WithServerPathDigest(p Profile, digest string) (Profile, error) {
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	if !validSHA256(digest) {
		return Profile{}, errors.New("invalid declared server path digest")
	}
	p.Version, p.ServerPathSHA256 = 2, digest
	return p, p.Validate()
}

func validSHA256(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

func (p Profile) Validate() error {
	if (p.Version != 1 && p.Version != 2) || (p.Version == 1 && p.ServerPathSHA256 != "") || (p.Version == 2 && !validSHA256(p.ServerPathSHA256)) {
		return errors.New("unsupported private profile version")
	}
	if p.NodeID == "" || len(p.NodeID) > 256 || strings.ContainsAny(p.NodeID, "\r\n\x00") || !compatibleCore.MatchString(p.CoreVersion) {
		return errors.New("invalid profile identity or unsupported server core version")
	}
	var o outbound
	if err := graphFields(p.Outbound, profileOutboundFields); err != nil {
		return err
	}
	if err := graphTLSFields(p.Outbound); err != nil {
		return err
	}
	if err := graphTransportFields(p.Outbound); err != nil {
		return err
	}
	if err := graphMultiplexFields(p.Outbound); err != nil {
		return err
	}
	if err := StrictJSON(p.Outbound, &o); err != nil {
		return err
	}
	if err := profileProtocolFields(p.Outbound, o.Type); err != nil {
		return err
	}
	b, _ := json.Marshal(o)
	h := sha256.Sum256(b)
	if p.ConfigSHA256 != hex.EncodeToString(h[:]) {
		return errors.New("private profile configuration digest does not match")
	}
	hasHY2PortRange := o.Type == "hysteria2" && len(o.ServerPorts) > 0
	if o.Tag != "proxy" || o.Server == "" || len(o.Server) > 253 || strings.ContainsAny(o.Server, "/\\@\r\n\x00 ") || (o.Port == 0 && !hasHY2PortRange) || (o.Port != 0 && hasHY2PortRange) {
		return errors.New("invalid selected proxy endpoint")
	}
	if len(o.UUID)+len(o.Password) > 1024 {
		return errors.New("client credential exceeds limit")
	}
	if err := o.profileHY2Options.validate(o.Type); err != nil {
		return err
	}
	if err := o.profileAnyTLSOptions.validate(o.Type); err != nil {
		return err
	}
	if err := o.profileTUICOptions.validate(o.Type); err != nil {
		return err
	}
	if err := o.profileVMessOptions.validate(o.Type); err != nil {
		return err
	}
	isReality := o.TLS != nil && o.TLS.Reality != nil
	if err := o.Transport.validate(o.Type, isReality); err != nil {
		return err
	}
	if err := o.Multiplex.validate(o.Type, isReality, o.Flow); err != nil {
		return err
	}
	switch o.Type {
	case "shadowsocks":
		modernAEAD := o.Method == "aes-128-gcm" || o.Method == "aes-256-gcm" || o.Method == "chacha20-ietf-poly1305"
		ss2022Valid := o.Method == "2022-blake3-aes-256-gcm" ||
			(o.Method == "2022-blake3-aes-128-gcm" && validProfileSS2022Password(o.Password, 16)) ||
			(o.Method == "2022-blake3-chacha20-poly1305" && validProfileSS2022Password(o.Password, 32))
		if (!modernAEAD && !ss2022Valid) || o.Password == "" || o.TLS != nil || o.UUID != "" || o.Flow != "" || o.PacketEncoding != "" || modernAEAD && !validNewProtocolPassword(o.Password) {
			return errors.New("unsupported Shadowsocks client profile")
		}
	case "vless":
		if o.Password != "" || o.Method != "" || o.TLS == nil {
			return errors.New("unsupported VLESS client profile")
		}
		if o.TLS.Reality != nil {
			expectedFlow := "xtls-rprx-vision"
			if o.Transport != nil && o.Transport.Type == "grpc" {
				expectedFlow = ""
			}
			if o.UUID == "" || o.Flow != expectedFlow || o.PacketEncoding != "" || !o.TLS.Reality.Enabled || o.TLS.UTLS == nil || !o.TLS.UTLS.Enabled || !validProfileRealityFingerprint(o.TLS.UTLS.Fingerprint) {
				return errors.New("unsupported REALITY client profile")
			}
		} else {
			if !profileUUID.MatchString(o.UUID) || o.UUID == "00000000-0000-0000-0000-000000000000" || o.Flow != "" || (o.PacketEncoding != "" && o.PacketEncoding != "xudp" && o.PacketEncoding != "packetaddr") || o.TLS.UTLS != nil {
				return errors.New("unsupported VLESS-TLS client profile")
			}
		}
	case "vmess":
		if !profileUUID.MatchString(o.UUID) || o.UUID == "00000000-0000-0000-0000-000000000000" || o.Flow != "" || o.Password != "" || o.Method != "" || (o.PacketEncoding != "" && o.PacketEncoding != "xudp" && o.PacketEncoding != "packetaddr") || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
			return errors.New("unsupported VMess-TLS client profile")
		}
	case "hysteria2":
		if o.Password == "" || (o.Obfs != nil && o.Obfs.Password == o.Password) || o.UUID != "" || o.Flow != "" || o.PacketEncoding != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
			return errors.New("unsupported Hysteria2 client profile")
		}
	case "anytls", "trojan":
		if !validNewProtocolPassword(o.Password) || o.UUID != "" || o.Flow != "" || o.PacketEncoding != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
			return errors.New("unsupported native TLS client profile")
		}
	case "tuic":
		if !validNewProtocolPassword(o.Password) || !profileUUID.MatchString(o.UUID) || o.UUID == "00000000-0000-0000-0000-000000000000" || o.Flow != "" || o.PacketEncoding != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
			return errors.New("unsupported TUIC v5 client profile")
		}
	default:
		return errors.New("profile must select a supported proxy protocol; direct and selectors are forbidden")
	}
	if o.TLS != nil {
		if !o.TLS.Enabled || o.TLS.ServerName == "" || len(o.TLS.ServerName) > 253 || len(o.TLS.Certificate) > 16 {
			return errors.New("client TLS must validate its server")
		}
		for _, cert := range o.TLS.Certificate {
			if len(cert) > 256<<10 {
				return errors.New("client CA certificate exceeds limit")
			}
		}
		if len(o.TLS.ALPN) > 0 && !validClientTLSALPN(o.Type, isReality, o.Transport, o.TLS.ALPN) {
			return errors.New("unsupported client TLS ALPN")
		}
	}
	return nil
}

func validClientTLSALPN(kind string, reality bool, tr *clientTransport, alpn []string) bool {
	if len(alpn) != 1 || reality {
		return false
	}
	if kind == "tuic" && tr == nil {
		return alpn[0] == "h3"
	}
	if tr == nil {
		return false
	}
	switch tr.Type {
	case "ws", "httpupgrade":
		return alpn[0] == "http/1.1"
	case "grpc", "http":
		return alpn[0] == "h2"
	default:
		return false
	}
}
func ReadProfile(path string) (Profile, error) {
	var p Profile
	info, err := os.Stat(path)
	if err != nil {
		return p, err
	}
	if !info.Mode().IsRegular() {
		return p, errors.New("private profile must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return p, err
	}
	if err = StrictJSON(b, &p); err != nil {
		return p, err
	}
	if err = validatePathFieldVersion(b, p.Version, false); err != nil {
		return p, err
	}
	return p, p.Validate()
}

// A legacy version may not carry the new field, even as null/empty or under a
// case-disguised spelling that encoding/json would otherwise match.
func validatePathFieldVersion(raw []byte, version int, report bool) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	checkFields := func(object map[string]json.RawMessage) error {
		for key := range object {
			if strings.EqualFold(key, "server_path_sha256") && (version != 2 || key != "server_path_sha256") {
				return errors.New("server path field requires explicit version 2")
			}
		}
		return nil
	}
	if report {
		for key, value := range fields {
			if strings.EqualFold(key, "conditions") {
				var nested map[string]json.RawMessage
				if err := json.Unmarshal(value, &nested); err != nil {
					return err
				}
				if err := checkFields(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return checkFields(fields)
}
func WriteProfile(path string, p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(b, '\n'))
}
