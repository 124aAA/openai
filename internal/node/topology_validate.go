package node

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func topologyError(message string) error { return errors.New(message) }

func safeRemoteText(s string, limit int, required bool) bool {
	if len(s) > limit || !utf8.ValidString(s) || (required && s == "") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validWGKey(s string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	var nonzero byte
	for _, v := range b {
		nonzero |= v
	}
	return nonzero != 0
}
func validRealityPublicKey(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return false
	}
	_, err = ecdh.X25519().NewPublicKey(b)
	return err == nil && s != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
func validateRemoteEgress(e Egress, core string) error {
	count := 0
	for _, present := range []bool{e.Socks != nil, e.Reality != nil, e.Shadowsocks != nil, e.HY2 != nil, e.WireGuard != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return errors.New("远程出口必须且只能包含一种协议设置")
	}
	if e.Protocol != "wireguard" && (!ValidHost(e.Server) || e.Port < 1 || e.Port > 65535) {
		return errors.New("远程出口需要有效连接地址和1–65535端口")
	}
	switch e.Protocol {
	case "socks5":
		p := e.Socks
		if p == nil || !safeRemoteText(p.Username, 255, false) || !safeRemoteText(p.Password, 255, false) || (p.Username == "") != (p.Password == "") {
			return errors.New("SOCKS5用户名与密码须同时提供，长度最多255字节且不能包含控制字符")
		}
	case "reality":
		p := e.Reality
		if p == nil || !uuidRE.MatchString(p.UUID) || !ValidHost(p.ServerName) || net.ParseIP(p.ServerName) != nil || !validRealityPublicKey(p.PublicKey) {
			return errors.New("远程REALITY的UUID、SNI或公钥无效")
		}
		b, err := hex.DecodeString(p.ShortID)
		if err != nil || len(b) < 1 || len(b) > 8 {
			return errors.New("远程REALITY short ID需要1–8字节十六进制")
		}
		switch p.Fingerprint {
		case "", "chrome", "firefox", "safari", "ios", "edge":
		default:
			return errors.New("远程REALITY指纹不受支持")
		}
	case "ss2022":
		p := e.Shadowsocks
		if p == nil || p.Method != SS2022Method {
			return errors.New("远程SS2022仅支持2022-blake3-aes-256-gcm")
		}
		keys := strings.Split(p.Password, ":")
		if len(keys) < 1 || len(keys) > 8 {
			return errors.New("远程SS2022密钥链长度无效")
		}
		for _, key := range keys {
			if !validSSKey(key) {
				return errors.New("远程SS2022密码须由32字节Base64密钥组成")
			}
		}
	case "hysteria2":
		p := e.HY2
		if p == nil || !safeRemoteText(p.Password, 512, true) || !ValidHost(p.ServerName) {
			return errors.New("远程Hysteria2需要有效独立密码和TLS名称")
		}
		if len(p.CertificatePEM) > 256<<10 || (p.CertificatePEM != "" && (!x509.NewCertPool().AppendCertsFromPEM([]byte(p.CertificatePEM)) || strings.Contains(p.CertificatePEM, "PRIVATE KEY"))) {
			return errors.New("远程Hysteria2信任证书PEM无效或混入私钥")
		}
		if p.Performance != nil {
			v := p.Performance
			if v.ServerUpMbps != nil || v.ServerDownMbps != nil || v.IgnoreClientBandwidth != nil || v.Server != nil {
				return errors.New("远程HY2只接受客户端性能选择，不能修改远端服务上限")
			}
			if err := ValidateHY2Capabilities(Node{Protocol: "hysteria2", HY2: v}, core, nil); err != nil {
				return err
			}
		}
	case "wireguard":
		if e.WireGuard == nil || e.Server != "" || e.Port != 0 {
			return errors.New("WireGuard地址和端口须在独立peer中填写")
		}
		if err := validateWireGuard(*e.WireGuard, e.Detour); err != nil {
			return err
		}
	default:
		return errors.New("远程出口仅支持socks5、reality、ss2022、hysteria2或wireguard")
	}
	return nil
}
func validateWireGuard(w WireGuardEndpoint, detour string) error {
	if !validWGKey(w.PrivateKey) || len(w.Address) < 1 || len(w.Address) > 16 || len(w.Peers) < 1 || len(w.Peers) > 16 {
		return errors.New("用户态WireGuard需要有效私钥、1–16个本地前缀和1–16个peer")
	}
	has6 := false
	addresses := map[netip.Addr]bool{}
	for _, value := range w.Address {
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().Is4In6() || addresses[p.Addr()] {
			return errors.New("WireGuard本地地址须为不重复的实际IP/前缀")
		}
		addresses[p.Addr()] = true
		has6 = has6 || p.Addr().Is6()
	}
	if w.ListenPort < 0 || w.ListenPort > 65535 || (w.ListenPort > 0 && (detour != "" || w.ReceiveEgressID == "")) || (w.ListenPort == 0 && w.ReceiveEgressID != "") {
		return errors.New("WireGuard监听端口须为0–65535；固定监听须显式指定接收出口且不能使用detour")
	}
	if w.MTU != 0 && (w.MTU < 576 || w.MTU > 9000 || (has6 && w.MTU < 1280)) {
		return errors.New("WireGuard MTU须为576–9000，含IPv6时至少1280；0保留核心默认")
	}
	keys := map[string]bool{}
	var assigned []netip.Prefix
	for _, p := range w.Peers {
		if !validWGKey(p.PublicKey) || keys[p.PublicKey] || (p.PreSharedKey != "" && !validWGKey(p.PreSharedKey)) {
			return errors.New("WireGuard peer公钥/预共享密钥无效或公钥重复")
		}
		keys[p.PublicKey] = true
		if (p.Address == "") != (p.Port == 0) || (p.Address != "" && (!ValidHost(p.Address) || p.Port < 1 || p.Port > 65535)) || (w.ListenPort == 0 && p.Address == "") {
			return errors.New("WireGuard主动peer需要连接地址和端口；被动peer仅可用于明确监听端")
		}
		if p.Keepalive < 0 || p.Keepalive > 3600 || len(p.AllowedIPs) < 1 || len(p.AllowedIPs) > 128 {
			return errors.New("WireGuard peer需要1–128个AllowedIPs；保活间隔为0–3600秒")
		}
		for _, value := range p.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				return errors.New("WireGuard AllowedIPs须为规范网络前缀")
			}
			for _, before := range assigned {
				if prefix.Overlaps(before) {
					return errors.New("WireGuard peer AllowedIPs不能重复或重叠")
				}
			}
			assigned = append(assigned, prefix)
		}
	}
	return nil
}
func validateHealth(h *EgressHealth) error {
	if h == nil {
		return errors.New("主备策略必须明确应用层健康目标和阈值")
	}
	u, err := url.Parse(h.URL)
	if err != nil || u.Scheme != "https" || !ValidHost(u.Hostname()) || u.User != nil || u.Fragment != "" || len(h.URL) > 2048 {
		return errors.New("健康检查需要无凭据的HTTPS地址")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("健康检查URL端口无效")
		}
	}
	if h.UDPAddress != "" {
		host, port, err := splitLocalAddress(h.UDPAddress)
		if err != nil || !ValidHost(host) || port < 1 || port > 65535 {
			return errors.New("UDP健康目标须为明确的主机:端口")
		}
	}
	if h.FailureThreshold < 1 || h.FailureThreshold > 20 || h.RecoveryThreshold < 1 || h.RecoveryThreshold > 20 || h.CooldownSeconds < 1 || h.CooldownSeconds > 3600 || h.TimeoutSeconds < 1 || h.TimeoutSeconds > 30 {
		return errors.New("主备失败/恢复阈值须为1–20，冷却1–3600秒，单次超时1–30秒")
	}
	return nil
}

func effectiveEgressID(id string) string {
	if id == "" {
		return "direct"
	}
	return id
}

// ResolveEgressID resolves only the explicitly saved policy choice. A failed
// candidate is never silently replaced with direct or another policy member.
func ResolveEgressID(st State, id string) (string, error) {
	id = effectiveEgressID(id)
	if id == "direct" {
		return id, nil
	}
	for _, p := range st.EgressPolicies {
		if p.ID == id {
			switch p.Selected {
			case "", "primary":
				return p.Primary, nil
			case "backup":
				if p.Mode == "failover" {
					return p.Backup, nil
				}
			}
			return "", errors.New("出口策略保存的选择无效")
		}
	}
	for _, e := range st.Egresses {
		if e.ID == id {
			return id, nil
		}
	}
	return "", errors.New("引用的出口或策略不存在")
}

func ValidateTopology(st State) error {
	bindings := StateBindings(st)
	if len(st.Egresses) > 128 || len(st.EgressPolicies) > 64 || len(st.Forwards) > 256 {
		return errors.New("拓扑上限为128个远程出口、64个策略、256条中转")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, n := range st.Nodes {
		ids[n.ID] = true
	}
	claim := func(id, name string) error {
		if !idRE.MatchString(id) || ids[id] || !cleanName(name) || names[name] {
			return errors.New("拓扑ID或名称无效/重复")
		}
		ids[id], names[name] = true, true
		return nil
	}
	egress := map[string]Egress{}
	for _, e := range st.Egresses {
		if err := claim(e.ID, e.Name); err != nil {
			return err
		}
		if err := validateRemoteEgress(e, st.CoreVersion); err != nil {
			return fmt.Errorf("出口 %s：%w", e.Name, err)
		}
		egress[e.ID] = e
	}
	for _, f := range st.Forwards {
		if f.Enabled {
			localDial, _, err := topologyRouteScope(st, f.EgressID)
			if err != nil {
				return err
			}
			for _, network := range ForwardNetworks(f) {
				for _, b := range bindings {
					if b.NodeID != f.ID && !strings.HasPrefix(b.NodeID, "egress-") {
						continue
					}
					if localDial && strings.HasPrefix(b.NodeID, "egress-") && addressHitsBinding(f.TargetHost, f.TargetPort, network, LocalBinding{Network: bindingTransport(b.Network), Address: b.Address, Port: b.Port}) {
						return errors.New("中转目标不能把隧道自身再次送入代理")
					}
				}
				for _, n := range st.Nodes {
					if n.Enabled {
						for _, nn := range Networks(n) {
							if localDial && addressHitsBinding(f.TargetHost, f.TargetPort, network, LocalBinding{Network: nn, Address: n.Listen, Port: n.Port}) {
								return errors.New("中转目标指向本项目代理入口，拒绝重复代理")
							}
						}
						for _, ep := range EffectiveEndpoints(n) {
							if sameTopologyHost(f.TargetHost, ep.Host) && f.TargetPort == ep.Port && topologyHasNetwork(Networks(n), network) && (localDial || !topologyLoopbackHost(f.TargetHost)) {
								return errors.New("中转目标指向本项目已声明入口")
							}
						}
					}
				}
			}
		}
	}
	for _, p := range st.EgressPolicies {
		if err := claim(p.ID, p.Name); err != nil {
			return err
		}
		if _, ok := egress[p.Primary]; !ok {
			return errors.New("策略主出口必须引用现有远程出口，不能自动回落direct")
		}
		switch p.Mode {
		case "fixed":
			if p.Backup != "" || p.Health != nil || (p.Selected != "" && p.Selected != "primary") {
				return errors.New("固定出口不接受备用、健康切换或backup选择")
			}
		case "failover":
			if _, ok := egress[p.Backup]; !ok || p.Backup == p.Primary {
				return errors.New("主备策略需要两个不同的现有远程出口")
			}
			if p.Selected != "" && p.Selected != "primary" && p.Selected != "backup" {
				return errors.New("主备选择只能是primary或backup")
			}
			if err := validateHealth(p.Health); err != nil {
				return err
			}
		default:
			return errors.New("出口策略仅支持fixed或failover")
		}
	}
	// Detours reference real egresses, not mutable policies or direct. Validate
	// both currently selected and dormant backup paths before any write.
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return errors.New("出口detour链存在环")
		}
		if done[id] {
			return nil
		}
		e, ok := egress[id]
		if !ok {
			return errors.New("detour引用的远程出口不存在")
		}
		visiting[id] = true
		if e.Detour != "" {
			up, ok := egress[e.Detour]
			if !ok {
				return errors.New("detour必须引用现有远程出口，不能引用策略或direct")
			}
			if (e.Protocol == "hysteria2" || e.Protocol == "wireguard" || ((e.Protocol == "ss2022" || e.Protocol == "socks5") && e.UDP)) && !up.UDP {
				return errors.New("该协议的上游连接需要UDP，但detour只声明TCP能力")
			}
			if err := visit(e.Detour); err != nil {
				return err
			}
		}
		visiting[id], done[id] = false, true
		return nil
	}
	for id := range egress {
		if err := visit(id); err != nil {
			return err
		}
	}
	checkRef := func(id string, udp bool) error {
		resolved, err := ResolveEgressID(st, id)
		if err != nil {
			return err
		}
		if resolved == "direct" {
			return nil
		}
		if udp && !egress[resolved].UDP {
			return errors.New("此入口承载UDP，选定出口只声明TCP能力")
		}
		for _, p := range st.EgressPolicies {
			if p.ID == id && p.Mode == "failover" && udp && (!egress[p.Primary].UDP || !egress[p.Backup].UDP) {
				return errors.New("UDP入口的主、备出口都必须声明UDP能力")
			}
			if p.ID == id && p.Mode == "failover" && udp && p.Health.UDPAddress == "" {
				return errors.New("UDP入口的主备策略必须显式提供UDP健康目标；HTTPS成功不能证明UDP可用")
			}
		}
		return nil
	}
	for _, n := range st.Nodes {
		capability, _ := ProtocolCapabilities(n.Protocol)
		if err := checkRef(n.EgressID, topologyHasNetwork(capability.BusinessNetworks, "udp")); err != nil {
			return fmt.Errorf("节点 %s：%w", n.Name, err)
		}
	}
	for _, f := range st.Forwards {
		if err := claim(f.ID, f.Name); err != nil {
			return err
		}
		if net.ParseIP(f.Listen) == nil || f.Port < 1 || f.Port > 65535 || len(ForwardNetworks(f)) == 0 || !ValidHost(f.TargetHost) || f.TargetPort < 1 || f.TargetPort > 65535 {
			return errors.New("端口中转需要有效监听IP/端口、tcp/udp/tcp+udp和目标地址/端口")
		}
		if err := checkRef(f.EgressID, f.Network != "tcp"); err != nil {
			return fmt.Errorf("中转 %s：%w", f.Name, err)
		}
	}
	for _, e := range st.Egresses {
		if w := e.WireGuard; w != nil && w.ReceiveEgressID != "" {
			if err := checkRef(w.ReceiveEgressID, true); err != nil {
				return err
			}
			resolved, _ := ResolveEgressID(st, w.ReceiveEgressID)
			candidates := []string{resolved}
			for _, p := range st.EgressPolicies {
				if p.ID == w.ReceiveEgressID {
					candidates = []string{p.Primary}
					if p.Mode == "failover" {
						candidates = append(candidates, p.Backup)
					}
					break
				}
			}
			// Validate every explicitly declared candidate, including a dormant
			// backup. This checks only its known detour closure, not unknown
			// cross-host receive paths or otherwise valid mesh relationships.
			for _, candidate := range candidates {
				for id := candidate; id != "" && id != "direct"; id = egress[id].Detour {
					if id == e.ID {
						return errors.New("WireGuard接收出口的主/备路径不能再次指回自身隧道")
					}
				}
			}
		}
	}
	return validateTopologyDestinations(st)
}

func addressHitsBinding(host string, port int, network string, b LocalBinding) bool {
	if b.Port != port || bindingTransport(b.Network) != network {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	l, err := netip.ParseAddr(b.Address)
	if err != nil {
		return false
	}
	a, l = a.Unmap(), l.Unmap()
	if a == l {
		return true
	}
	return l.IsUnspecified() && (a.IsLoopback() || a.IsUnspecified()) && (a.Is4() == l.Is4() || l.Is6())
}

// topologyRouteScope distinguishes physical host dialing from addresses passed
// to a remote proxy or a userland tunnel. WireGuard's fixed 1.14 implementation
// resolves destination domains through the local DNS router even when the
// resulting IP is reached inside the tunnel. Ordinary proxy outbounds pass the
// destination onward and do not prove that remote host's DNS or bind scope.
func topologyRouteScope(st State, id string) (hostDial, hostDNS bool, err error) {
	id, err = ResolveEgressID(st, id)
	if err != nil {
		return false, false, err
	}
	if id == "direct" {
		return true, true, nil
	}
	for _, e := range st.Egresses {
		if e.ID == id {
			return false, e.Protocol == "wireguard", nil
		}
	}
	return false, false, errors.New("拓扑拨号出口不存在")
}

func sameTopologyHost(a, b string) bool {
	x, ex := netip.ParseAddr(a)
	y, ey := netip.ParseAddr(b)
	if ex == nil && ey == nil {
		return x.Unmap() == y.Unmap()
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func topologyLoopbackHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().IsLoopback()
	}
	return strings.EqualFold(strings.TrimSuffix(host, "."), "localhost")
}

func topologyHasNetwork(networks []string, network string) bool {
	for _, n := range networks {
		if n == network {
			return true
		}
	}
	return false
}

// These are the physical connections to the configured server port. VLESS
// carries its UDP payload over TCP; SOCKS5's separately negotiated UDP relay is
// not necessarily at the TCP server port. SS2022 uses the same fixed server
// port for its separately declared TCP and UDP transport.
func egressServerNetworks(e Egress) []string {
	if e.Protocol == "hysteria2" || e.Protocol == "wireguard" {
		return []string{"udp"}
	}
	if e.Protocol == "ss2022" && e.UDP {
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

func topologyDeclaredEntry(st State, host string, port int, networks []string, localDial bool) bool {
	if !localDial && topologyLoopbackHost(host) {
		return false
	}
	for _, n := range st.Nodes {
		for _, ep := range EffectiveEndpoints(n) {
			if !sameTopologyHost(host, ep.Host) || port != ep.Port {
				continue
			}
			for _, network := range networks {
				if topologyHasNetwork(Networks(n), network) {
					return true
				}
			}
		}
	}
	return false
}

func validateTopologyDestinations(st State) error {
	bindings := StateBindings(st)
	// Project DNS deliberately uses system or a literal-IP UDP resolver outside
	// the graph. Reject a bootstrap resolver that points back at our own socket.
	if d := st.DNS; d != nil && d.Type == "udp" {
		port := 53
		if d.Port != nil {
			port = *d.Port
		}
		for _, b := range bindings {
			if addressHitsBinding(d.Server, port, "udp", b) {
				return errors.New("项目DNS引导目标指向本项目监听，可能产生DNS循环")
			}
		}
	}
	for _, e := range st.Egresses {
		localDial := e.Detour == ""
		for _, b := range bindings {
			for _, transport := range egressServerNetworks(e) {
				if localDial && addressHitsBinding(e.Server, e.Port, transport, b) {
					return errors.New("远程出口连接地址指向本项目入口，拒绝再次代理自身")
				}
			}
		}
		if e.WireGuard != nil {
			for _, p := range e.WireGuard.Peers {
				for _, b := range bindings {
					if localDial && p.Address != "" && addressHitsBinding(p.Address, p.Port, "udp", b) {
						return errors.New("WireGuard peer指向本项目监听端口")
					}
				}
				if p.Address != "" && topologyDeclaredEntry(st, p.Address, p.Port, []string{"udp"}, localDial) {
					return errors.New("WireGuard peer与已声明本项目UDP入口相同")
				}
			}
		}
		if e.Server != "" && topologyDeclaredEntry(st, e.Server, e.Port, egressServerNetworks(e), localDial) {
			return errors.New("远程出口地址与已声明本项目同传输入口相同")
		}
	}
	// A forward may target another distinct forward. Only cycles are rejected;
	// different local IPs sharing a port remain independent.
	edges := map[string][]string{}
	for _, f := range st.Forwards {
		if f.Enabled {
			localDial, _, err := topologyRouteScope(st, f.EgressID)
			if err != nil {
				return err
			}
			if !localDial {
				continue // Its target is reached on the remote side, not at this host's listener.
			}
			for _, n := range ForwardNetworks(f) {
				for _, target := range st.Forwards {
					if target.Enabled {
						for _, tn := range ForwardNetworks(target) {
							if n == tn && addressHitsBinding(f.TargetHost, f.TargetPort, n, LocalBinding{Network: tn, Address: target.Listen, Port: target.Port}) {
								edges[f.ID] = append(edges[f.ID], target.ID)
							}
						}
					}
				}
			}
		}
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return errors.New("端口中转目标形成循环")
		}
		if done[id] {
			return nil
		}
		visiting[id] = true
		for _, next := range edges[id] {
			if err := visit(next); err != nil {
				return err
			}
		}
		visiting[id], done[id] = false, true
		return nil
	}
	for id := range edges {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEgressCapabilities checks the actual binary separately from model
// compatibility. Nil tags means unknown and is rejected for active topology.
func ValidateEgressCapabilities(st State, tags []string) error {
	seen := map[string]bool{}
	for _, t := range tags {
		seen[t] = true
	}
	for _, e := range st.Egresses {
		var needed []string
		switch e.Protocol {
		case "hysteria2":
			needed = []string{"with_quic"}
		case "reality":
			needed = []string{"with_utls"}
		case "wireguard":
			needed = []string{"with_wireguard", "with_gvisor"}
		}
		for _, t := range needed {
			if !seen[t] {
				return fmt.Errorf("出口 %s 所选核心缺少已验证的 %s 构建能力", e.Name, t)
			}
		}
	}
	return nil
}
