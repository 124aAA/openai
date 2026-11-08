package probe

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// GraphProfile is a private, manager-derived probe path. It is deliberately
// separate from portable Profile v1; the public qingprobe CLI cannot import it.
// A graph contains only one reachable detour chain, without direct, selectors,
// system interfaces, arbitrary routes, listeners or helper processes.
type GraphProfile struct {
	Version      int               `json:"version"`
	NodeID       string            `json:"node_id"`
	CoreVersion  string            `json:"server_core_version"`
	ConfigSHA256 string            `json:"config_sha256"`
	FinalTag     string            `json:"final_tag"`
	Outbounds    []json.RawMessage `json:"outbounds"`
	Endpoints    []json.RawMessage `json:"endpoints,omitempty"`
	Resolver     *GraphResolver    `json:"resolver,omitempty"`
}

// GraphResolver bootstraps remote proxy names and WireGuard destination names.
// UDP resolvers use a literal address so their own lookup cannot recurse.
type GraphResolver struct {
	Type   string `json:"type"`
	Server string `json:"server,omitempty"`
	Port   int    `json:"port,omitempty"`
}

func SetGraphResolver(p GraphProfile, kind, server string, port int) (GraphProfile, error) {
	if err := p.Validate(); err != nil {
		return GraphProfile{}, err
	}
	p.Resolver = &GraphResolver{Type: kind, Server: server, Port: port}
	p.ConfigSHA256 = p.digest()
	return p, p.Validate()
}

type graphOutbound struct {
	outbound
	Detour         string `json:"detour,omitempty"`
	Version        string `json:"version,omitempty"`
	Username       string `json:"username,omitempty"`
	Network        string `json:"network,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
	ConnectTimeout string `json:"connect_timeout,omitempty"`
}

type graphWGPeer struct {
	Address           string   `json:"address,omitempty"`
	Port              uint16   `json:"port,omitempty"`
	PublicKey         string   `json:"public_key"`
	PreSharedKey      string   `json:"pre_shared_key,omitempty"`
	AllowedIPs        []string `json:"allowed_ips"`
	KeepaliveInterval int      `json:"persistent_keepalive_interval,omitempty"`
}

type graphWG struct {
	Type           string        `json:"type"`
	Tag            string        `json:"tag"`
	System         bool          `json:"system"`
	MTU            int           `json:"mtu,omitempty"`
	Address        []string      `json:"address"`
	PrivateKey     string        `json:"private_key"`
	ListenPort     uint16        `json:"listen_port,omitempty"`
	Peers          []graphWGPeer `json:"peers"`
	Detour         string        `json:"detour,omitempty"`
	DomainResolver string        `json:"domain_resolver,omitempty"`
	ConnectTimeout string        `json:"connect_timeout,omitempty"`
}

var graphTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func validGraphHost(value string) bool {
	if a, err := netip.ParseAddr(value); err == nil {
		return a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast()
	}
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\@:#[]\r\n\x00 \t") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Exact field names are checked in addition to StrictJSON so encoding/json's
// case-insensitive struct matching cannot disguise a duplicate or injection.
func graphFields(raw []byte, allowed string) error {
	var fields map[string]json.RawMessage
	if err := StrictJSON(raw, &fields); err != nil || fields == nil {
		return errors.New("invalid private graph object")
	}
	set := map[string]bool{}
	for _, key := range strings.Fields(allowed) {
		set[key] = true
	}
	for key := range fields {
		if !set[key] {
			return errors.New("unsupported private graph field")
		}
	}
	return nil
}

const graphOutboundFields = profileOutboundFields + " detour version username network domain_resolver connect_timeout"

func graphTLSFields(raw []byte) error {
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	if tls := object["tls"]; tls != nil && string(tls) != "null" {
		if err := graphFields(tls, "enabled server_name certificate utls reality alpn"); err != nil {
			return err
		}
		var values map[string]json.RawMessage
		_ = json.Unmarshal(tls, &values)
		for key, allowed := range map[string]string{"utls": "enabled fingerprint", "reality": "enabled public_key short_id"} {
			if field := values[key]; field != nil && string(field) != "null" {
				if err := graphFields(field, allowed); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func canonicalGraphOutbound(raw []byte, version string) (json.RawMessage, graphOutbound, error) {
	var o graphOutbound
	if err := graphFields(raw, graphOutboundFields); err != nil {
		return nil, o, err
	}
	if err := graphTLSFields(raw); err != nil {
		return nil, o, err
	}
	if err := StrictJSON(raw, &o); err != nil {
		return nil, o, err
	}
	if err := profileProtocolFields(raw, o.Type); err != nil {
		return nil, o, err
	}
	if !validGraphHost(o.Server) || o.Port == 0 || !graphTag.MatchString(o.Tag) || o.Tag == "probe" || o.Tag == "bootstrap" {
		return nil, o, errors.New("invalid private graph proxy endpoint")
	}
	if o.DomainResolver != "" && o.DomainResolver != "bootstrap" && o.DomainResolver != "system" {
		return nil, o, errors.New("private graph bootstrap DNS must use the isolated local resolver")
	}
	if o.Detour != "" && (o.DomainResolver != "" || o.ConnectTimeout != "") {
		return nil, o, errors.New("detour cannot be combined with ignored Dial fields")
	}
	if o.ConnectTimeout != "" {
		return nil, o, errors.New("private graph uses its outer bounded deadline, not a Dial override")
	}
	if o.DomainResolver != "" {
		o.DomainResolver = "bootstrap"
	}
	if o.Network != "" && o.Network != "tcp" && o.Network != "udp" {
		return nil, o, errors.New("private graph network must be tcp or udp")
	}
	if o.Type == "socks" {
		if o.Version != "5" || (o.Username == "") != (o.Password == "") || len(o.Username) > 255 || len(o.Password) > 255 || o.UUID != "" || o.Flow != "" || o.Method != "" || o.TLS != nil {
			return nil, o, errors.New("invalid SOCKS5 graph credential or protocol options")
		}
		if err := o.profileHY2Options.validate("socks"); err != nil {
			return nil, o, err
		}
		if err := o.profileAnyTLSOptions.validate("socks"); err != nil {
			return nil, o, err
		}
		if err := o.profileTUICOptions.validate("socks"); err != nil {
			return nil, o, err
		}
	} else {
		if o.Version != "" || o.Username != "" || o.Network != "" && o.Type != "shadowsocks" {
			return nil, o, errors.New("SOCKS options cannot be used on another graph protocol")
		}
		legacy := o.outbound
		legacy.Tag = "proxy"
		b, _ := json.Marshal(legacy)
		if _, err := NewProfile("graph-member", version, b); err != nil {
			return nil, o, err
		}
	}
	b, err := json.Marshal(o)
	return b, o, err
}

func graphWGKey(value string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != value {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}

func canonicalGraphWG(raw []byte) (json.RawMessage, graphWG, error) {
	var w graphWG
	if err := graphFields(raw, "type tag system mtu address private_key listen_port peers detour domain_resolver connect_timeout"); err != nil {
		return nil, w, err
	}
	if err := StrictJSON(raw, &w); err != nil {
		return nil, w, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var peers []json.RawMessage
	_ = json.Unmarshal(fields["peers"], &peers)
	for _, peer := range peers {
		if err := graphFields(peer, "address port public_key pre_shared_key allowed_ips persistent_keepalive_interval"); err != nil {
			return nil, w, err
		}
	}
	if w.Type != "wireguard" || w.System || !graphTag.MatchString(w.Tag) || w.Tag == "probe" || w.Tag == "bootstrap" || !graphWGKey(w.PrivateKey) || len(w.Address) < 1 || len(w.Address) > 16 || len(w.Peers) < 1 || len(w.Peers) > 16 {
		return nil, w, errors.New("private graph requires bounded userspace WireGuard with valid keys and addresses")
	}
	if w.MTU != 0 && (w.MTU < 576 || w.MTU > 9000) {
		return nil, w, errors.New("private graph WireGuard MTU is outside the bounded range")
	}
	if w.Detour != "" && (w.ListenPort != 0 || w.DomainResolver != "" || w.ConnectTimeout != "") {
		return nil, w, errors.New("WireGuard detour conflicts with listen_port or ignored Dial fields")
	}
	if w.ConnectTimeout != "" || w.DomainResolver != "" && w.DomainResolver != "system" && w.DomainResolver != "bootstrap" {
		return nil, w, errors.New("unsupported WireGuard graph Dial or DNS options")
	}
	if w.DomainResolver != "" {
		w.DomainResolver = "bootstrap"
	}
	addresses := map[netip.Addr]bool{}
	for _, address := range w.Address {
		prefix, err := netip.ParsePrefix(address)
		if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().Is4In6() || addresses[prefix.Addr()] {
			return nil, w, errors.New("invalid private graph WireGuard interface prefix")
		}
		addresses[prefix.Addr()] = true
		if prefix.Addr().Is6() && w.MTU != 0 && w.MTU < 1280 {
			return nil, w, errors.New("IPv6 WireGuard requires MTU at least 1280")
		}
	}
	keys := map[string]bool{}
	var assigned []netip.Prefix
	for _, peer := range w.Peers {
		if !validGraphHost(peer.Address) || peer.Port == 0 || !graphWGKey(peer.PublicKey) || keys[peer.PublicKey] || peer.PreSharedKey != "" && !graphWGKey(peer.PreSharedKey) || len(peer.AllowedIPs) < 1 || len(peer.AllowedIPs) > 128 || peer.KeepaliveInterval < 0 || peer.KeepaliveInterval > 3600 {
			return nil, w, errors.New("invalid private graph WireGuard peer")
		}
		keys[peer.PublicKey] = true
		for _, allowed := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(allowed)
			if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				return nil, w, errors.New("invalid private graph WireGuard AllowedIPs")
			}
			for _, before := range assigned {
				if prefix.Overlaps(before) {
					return nil, w, errors.New("overlapping private graph WireGuard AllowedIPs")
				}
			}
			assigned = append(assigned, prefix)
		}
	}
	b, err := json.Marshal(w)
	return b, w, err
}

func NewGraphProfile(nodeID, coreVersion, finalTag string, outbounds, endpoints []json.RawMessage) (GraphProfile, error) {
	if len(outbounds)+len(endpoints) < 1 || len(outbounds)+len(endpoints) > 32 || len(endpoints) > 8 {
		return GraphProfile{}, errors.New("private graph path exceeds bounded member count")
	}
	p := GraphProfile{Version: 1, NodeID: nodeID, CoreVersion: coreVersion, FinalTag: finalTag}
	for _, raw := range outbounds {
		b, _, err := canonicalGraphOutbound(raw, coreVersion)
		if err != nil {
			return GraphProfile{}, err
		}
		p.Outbounds = append(p.Outbounds, b)
	}
	for _, raw := range endpoints {
		b, _, err := canonicalGraphWG(raw)
		if err != nil {
			return GraphProfile{}, err
		}
		p.Endpoints = append(p.Endpoints, b)
	}
	p.ConfigSHA256 = p.digest()
	return p, p.Validate()
}

func (p GraphProfile) digest() string {
	b, _ := json.Marshal(struct {
		FinalTag  string            `json:"final_tag"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Endpoints []json.RawMessage `json:"endpoints,omitempty"`
		Resolver  *GraphResolver    `json:"resolver,omitempty"`
	}{p.FinalTag, p.Outbounds, p.Endpoints, p.Resolver})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (p GraphProfile) Validate() error {
	if p.Version != 1 || p.NodeID == "" || len(p.NodeID) > 256 || strings.ContainsAny(p.NodeID, "\r\n\x00") || !compatibleCore.MatchString(p.CoreVersion) || !graphTag.MatchString(p.FinalTag) || p.ConfigSHA256 != p.digest() {
		return errors.New("invalid private graph identity, version or digest")
	}
	if len(p.Outbounds)+len(p.Endpoints) < 1 || len(p.Outbounds)+len(p.Endpoints) > 32 || len(p.Endpoints) > 8 {
		return errors.New("private graph path exceeds bounded member count")
	}
	if p.Resolver != nil {
		switch p.Resolver.Type {
		case "system":
			if p.Resolver.Server != "" || p.Resolver.Port != 0 {
				return errors.New("system graph resolver has no server or port override")
			}
		case "udp":
			a, err := netip.ParseAddr(p.Resolver.Server)
			if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || p.Resolver.Port < 1 || p.Resolver.Port > 65535 {
				return errors.New("UDP graph resolver needs a literal IP and valid port")
			}
		default:
			return errors.New("unsupported graph resolver")
		}
	}
	detours := map[string]string{}
	for _, raw := range p.Outbounds {
		_, o, err := canonicalGraphOutbound(raw, p.CoreVersion)
		if err != nil {
			return err
		}
		if _, found := detours[o.Tag]; found {
			return errors.New("duplicate private graph tag")
		}
		detours[o.Tag] = o.Detour
	}
	for _, raw := range p.Endpoints {
		_, w, err := canonicalGraphWG(raw)
		if err != nil {
			return err
		}
		if _, found := detours[w.Tag]; found {
			return errors.New("duplicate private graph tag")
		}
		detours[w.Tag] = w.Detour
	}
	seen := map[string]bool{}
	for tag := p.FinalTag; tag != ""; tag = detours[tag] {
		if _, found := detours[tag]; !found {
			return errors.New("missing private graph final or detour member")
		}
		if seen[tag] {
			return errors.New("private graph detour cycle")
		}
		seen[tag] = true
	}
	if len(seen) != len(detours) {
		return errors.New("private graph contains an unused or alternative path")
	}
	return nil
}

// SupportsNetwork checks both application payload and the transport needed to
// reach every next proxy. A TCP-only hop cannot transport QUIC/WireGuard UDP.
func (p GraphProfile) SupportsNetwork(network string) bool {
	if p.Validate() != nil || network != "tcp" && network != "udp" {
		return false
	}
	type member struct{ kind, detour, network string }
	members := map[string]member{}
	for _, raw := range p.Outbounds {
		var o graphOutbound
		_ = json.Unmarshal(raw, &o)
		members[o.Tag] = member{o.Type, o.Detour, o.Network}
	}
	for _, raw := range p.Endpoints {
		var w graphWG
		_ = json.Unmarshal(raw, &w)
		members[w.Tag] = member{"wireguard", w.Detour, ""}
	}
	needTCP, needUDP := network == "tcp", network == "udp"
	for tag := p.FinalTag; tag != ""; {
		m := members[tag]
		if m.network == "tcp" && needUDP || m.network == "udp" && needTCP {
			return false
		}
		switch m.kind {
		case "hysteria2", "tuic", "wireguard":
			needTCP, needUDP = false, true
		case "vless", "anytls", "trojan":
			needTCP, needUDP = true, false
		case "socks":
			needTCP = needTCP || needUDP // UDP ASSOCIATE needs a TCP control channel.
		}
		tag = m.detour
	}
	return true
}

func graphSandboxConfig(p GraphProfile, port int, username, password string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid temporary graph listener port")
	}
	// A probe is never a landing server. Unsolicited traffic entering a WG
	// endpoint must be rejected rather than routed recursively back into it.
	rules := []any{}
	resolver := map[string]any{"type": "local", "tag": "bootstrap"}
	if p.Resolver != nil && p.Resolver.Type == "udp" {
		resolver = map[string]any{"type": "udp", "tag": "bootstrap", "server": p.Resolver.Server, "server_port": p.Resolver.Port}
	}
	for _, raw := range p.Endpoints {
		var w graphWG
		_ = json.Unmarshal(raw, &w)
		rules = append(rules, map[string]any{"inbound": []string{w.Tag}, "action": "reject"})
	}
	return json.MarshalIndent(map[string]any{
		"log":       map[string]any{"disabled": true},
		"dns":       map[string]any{"servers": []any{resolver}},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "probe", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": username, "password": password}}}},
		"outbounds": p.Outbounds, "endpoints": p.Endpoints,
		"route": map[string]any{"final": p.FinalTag, "default_domain_resolver": "bootstrap", "rules": rules},
	}, "", "  ")
}

func StartGraphSandbox(ctx context.Context, p GraphProfile, opts SandboxOptions) (*Sandbox, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	kinds := []string{}
	for _, raw := range p.Outbounds {
		var o graphOutbound
		_ = json.Unmarshal(raw, &o)
		kinds = append(kinds, o.Type)
	}
	if len(p.Endpoints) > 0 {
		kinds = append(kinds, "wireguard")
	}
	version, err := verifyProbeCoreTypes(ctx, kinds, opts)
	if err != nil {
		return nil, err
	}
	return startSandbox(ctx, opts, version, func(port int, username, password string) ([]byte, error) {
		return graphSandboxConfig(p, port, username, password)
	})
}

// String is safe for logs: it never includes upstream credentials or addresses.
func (p GraphProfile) String() string {
	return fmt.Sprintf("private graph %s (%d members)", p.NodeID, len(p.Outbounds)+len(p.Endpoints))
}
