package probe

import (
	"bytes"
	"crypto/sha256"
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
	Type     string     `json:"type"`
	Tag      string     `json:"tag"`
	Server   string     `json:"server"`
	Port     uint16     `json:"server_port"`
	UUID     string     `json:"uuid,omitempty"`
	Flow     string     `json:"flow,omitempty"`
	Method   string     `json:"method,omitempty"`
	Password string     `json:"password,omitempty"`
	TLS      *clientTLS `json:"tls,omitempty"`
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

const profileOutboundFields = "type tag server server_port uuid flow method password tls up_mbps down_mbps bbr_profile brutal_debug disable_chrome_parrot stream_receive_window connection_receive_window idle_timeout keep_alive_period max_concurrent_streams initial_packet_size disable_path_mtu_discovery idle_session_check_interval idle_session_timeout min_idle_session congestion_control udp_relay_mode zero_rtt_handshake heartbeat"

// Presence is checked before canonicalization: null, empty and explicit false
// must not disguise an option placed on the wrong protocol.
func profileProtocolFields(raw []byte, kind string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for protocol, names := range map[string]string{
		"anytls": "idle_session_check_interval idle_session_timeout min_idle_session",
		"tuic":   "congestion_control udp_relay_mode zero_rtt_handshake heartbeat",
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
	if tls := fields["tls"]; tls != nil && string(tls) != "null" {
		var values map[string]json.RawMessage
		_ = json.Unmarshal(tls, &values)
		if _, present := values["alpn"]; present && kind != "tuic" {
			return errors.New("ALPN override is supported only for the bounded TUIC profile")
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

// The private portable profile accepts only the fixed 1.14.x HY2 fields
// emitted by the manager. Routing, helper commands and arbitrary JSON remain
// rejected. Pointers retain explicit false versus core-default omission.
type profileHY2Options struct {
	UpMbps                  *int   `json:"up_mbps,omitempty"`
	DownMbps                *int   `json:"down_mbps,omitempty"`
	BBRProfile              string `json:"bbr_profile,omitempty"`
	BrutalDebug             *bool  `json:"brutal_debug,omitempty"`
	DisableChromeParrot     *bool  `json:"disable_chrome_parrot,omitempty"`
	StreamReceiveWindow     *int64 `json:"stream_receive_window,omitempty"`
	ConnectionReceiveWindow *int64 `json:"connection_receive_window,omitempty"`
	IdleTimeout             string `json:"idle_timeout,omitempty"`
	KeepAlivePeriod         string `json:"keep_alive_period,omitempty"`
	MaxConcurrentStreams    *int   `json:"max_concurrent_streams,omitempty"`
	InitialPacketSize       *int   `json:"initial_packet_size,omitempty"`
	DisablePathMTUDiscovery *bool  `json:"disable_path_mtu_discovery,omitempty"`
}

func (o profileHY2Options) validate(kind string) error {
	b, _ := json.Marshal(o)
	if kind != "hysteria2" {
		if string(b) != "{}" {
			return errors.New("HY2性能字段不能用于其他协议")
		}
		return nil
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

func NewProfile(nodeID, serverVersion string, raw []byte) (Profile, error) {
	var o outbound
	if err := graphFields(raw, profileOutboundFields); err != nil {
		return Profile{}, err
	}
	if err := graphTLSFields(raw); err != nil {
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
	if o.Tag != "proxy" || o.Server == "" || len(o.Server) > 253 || strings.ContainsAny(o.Server, "/\\@\r\n\x00 ") || o.Port == 0 {
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
	switch o.Type {
	case "shadowsocks":
		modernAEAD := o.Method == "aes-128-gcm" || o.Method == "aes-256-gcm" || o.Method == "chacha20-ietf-poly1305"
		if (!modernAEAD && o.Method != "2022-blake3-aes-256-gcm") || o.Password == "" || o.TLS != nil || o.UUID != "" || o.Flow != "" || modernAEAD && !validNewProtocolPassword(o.Password) {
			return errors.New("unsupported Shadowsocks client profile")
		}
	case "vless":
		if o.UUID == "" || o.Flow != "xtls-rprx-vision" || o.Password != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality == nil || !o.TLS.Reality.Enabled || o.TLS.UTLS == nil || !o.TLS.UTLS.Enabled {
			return errors.New("unsupported REALITY client profile")
		}
	case "hysteria2":
		if o.Password == "" || o.UUID != "" || o.Flow != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
			return errors.New("unsupported Hysteria2 client profile")
		}
	case "anytls", "trojan":
		if !validNewProtocolPassword(o.Password) || o.UUID != "" || o.Flow != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
			return errors.New("unsupported native TLS client profile")
		}
	case "tuic":
		if !validNewProtocolPassword(o.Password) || !profileUUID.MatchString(o.UUID) || o.UUID == "00000000-0000-0000-0000-000000000000" || o.Flow != "" || o.Method != "" || o.TLS == nil || o.TLS.Reality != nil || o.TLS.UTLS != nil {
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
			if len(cert) > 64<<10 {
				return errors.New("client CA certificate exceeds limit")
			}
		}
		if len(o.TLS.ALPN) > 0 && (o.Type != "tuic" || len(o.TLS.ALPN) != 1 || o.TLS.ALPN[0] != "h3") {
			return errors.New("unsupported client TLS ALPN")
		}
	}
	return nil
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
