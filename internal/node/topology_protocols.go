package node

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type egressAdapter struct {
	MinSchema           int
	IsEndpoint          bool
	SupportsTransport   bool
	SupportsMultiplex   bool
	BuildTags           []string
	ServerNetworks      func(Egress) []string
	RequiresUpstreamUDP func(Egress) bool
	Validate            func(Egress, string) error
	Render              func(Egress, M)
}

func tcpOnlyNetworks(_ Egress) []string { return []string{"tcp"} }
func udpOnlyNetworks(_ Egress) []string { return []string{"udp"} }
func tcpAndOptionalUDPNetworks(e Egress) []string {
	if e.UDP {
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

func alwaysRequiresUpstreamUDP(_ Egress) bool { return true }
func neverRequiresUpstreamUDP(_ Egress) bool  { return false }
func udpFlagRequiresUpstreamUDP(e Egress) bool {
	return e.UDP
}

var egressAdapters = map[string]egressAdapter{
	"socks5": {
		MinSchema:           4,
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: udpFlagRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.Socks
			if p == nil || !safeRemoteText(p.Username, 255, false) || !safeRemoteText(p.Password, 255, false) || (p.Username == "") != (p.Password == "") {
				return errors.New("SOCKS5用户名与密码须同时提供，长度最多255字节且不能包含控制字符")
			}
			return nil
		},
		Render: func(e Egress, m M) {
			m["type"], m["version"] = "socks", "5"
			if !e.UDP {
				m["network"] = "tcp"
			}
			if p := e.Socks; p.Username != "" {
				m["username"], m["password"] = p.Username, p.Password
			}
		},
	},
	"http": {
		MinSchema:           10,
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: neverRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.HTTP
			if p == nil {
				return errors.New("远程HTTP代理需要http配置对象")
			}
			if e.UDP {
				return errors.New("远程HTTP/HTTPS代理仅支持TCP（CONNECT），不能声明UDP能力")
			}
			if !safeRemoteText(p.Username, 255, false) || !safeRemoteText(p.Password, 255, false) || (p.Username == "") != (p.Password == "") {
				return errors.New("HTTP代理用户名与密码须同时提供，长度最多255字节且不能包含控制字符")
			}
			if !p.TLS {
				if p.ServerName != "" || p.CertificatePEM != "" {
					return errors.New("未开启TLS的HTTP代理不能设置SNI或信任证书")
				}
				return nil
			}
			if !ValidHost(p.ServerName) {
				return errors.New("开启TLS的HTTPS代理需要有效TLS服务器名称（SNI）")
			}
			return validateRemoteCertPEM(p.CertificatePEM, "HTTPS代理")
		},
		Render: func(e Egress, m M) {
			p := e.HTTP
			m["type"] = "http"
			if p.Username != "" {
				m["username"], m["password"] = p.Username, p.Password
			}
			if p.TLS {
				m["tls"] = remoteTLSWithTransport(p.ServerName, p.CertificatePEM, nil)
			}
		},
	},
	"reality": {
		MinSchema:           4,
		BuildTags:           []string{"with_utls"},
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: neverRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.Reality
			if p == nil || !validNonZeroUUID(p.UUID) || !ValidHost(p.ServerName) || net.ParseIP(p.ServerName) != nil || !validRealityPublicKey(p.PublicKey) {
				return errors.New("远程REALITY的UUID、SNI或公钥无效")
			}
			if !ValidRealityShortID(p.ShortID) {
				return errors.New("远程REALITY short ID需要1–8字节十六进制")
			}
			if p.Fingerprint != "" && !ValidRealityFingerprint(p.Fingerprint) {
				return errors.New("远程REALITY指纹不受支持")
			}
			return nil
		},
		Render: func(e Egress, m M) {
			p := e.Reality
			fp := p.Fingerprint
			if fp == "" {
				fp = "chrome"
			}
			m["type"], m["uuid"] = "vless", p.UUID
			if tr := transportOptionsToSingBox(e.Transport); tr != nil {
				m["transport"] = tr
			} else {
				m["flow"] = "xtls-rprx-vision"
			}
			m["tls"] = M{"enabled": true, "server_name": p.ServerName, "utls": M{"enabled": true, "fingerprint": fp}, "reality": M{"enabled": true, "public_key": p.PublicKey, "short_id": p.ShortID}}
		},
	},
	"ss2022": {
		MinSchema:           4,
		SupportsMultiplex:   true,
		ServerNetworks:      tcpAndOptionalUDPNetworks,
		RequiresUpstreamUDP: udpFlagRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.Shadowsocks
			size, ok := 0, false
			if p != nil {
				size, ok = SS2022KeyBytes(p.Method)
			}
			if !ok {
				return errors.New("远程SS2022仅支持2022-blake3-aes-256-gcm、2022-blake3-aes-128-gcm或2022-blake3-chacha20-poly1305")
			}
			keys := strings.Split(p.Password, ":")
			if len(keys) < 1 || len(keys) > 8 {
				return errors.New("远程SS2022密钥链长度无效")
			}
			for _, key := range keys {
				if !validSSKeyBytes(key, size) {
					return fmt.Errorf("远程SS2022密码须由%d字节Base64密钥组成", size)
				}
			}
			return nil
		},
		Render: renderShadowsocksEgress,
	},
	"ss-aead": {
		MinSchema:           10,
		SupportsMultiplex:   true,
		ServerNetworks:      tcpAndOptionalUDPNetworks,
		RequiresUpstreamUDP: udpFlagRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.Shadowsocks
			if p == nil || !validSSAEADMethod(p.Method) || safeTLSCredential(User{Password: p.Password}) != nil {
				return errors.New("远程传统Shadowsocks仅支持aes-128-gcm、aes-256-gcm或chacha20-ietf-poly1305，且密码须为16–512字节有效UTF-8（不含控制字符）")
			}
			return nil
		},
		Render: renderShadowsocksEgress,
	},
	"hysteria2": {
		MinSchema:           4,
		BuildTags:           []string{"with_quic"},
		ServerNetworks:      udpOnlyNetworks,
		RequiresUpstreamUDP: alwaysRequiresUpstreamUDP,
		Validate: func(e Egress, core string) error {
			p := e.HY2
			if p == nil || !safeRemoteText(p.Password, 512, true) || !ValidHost(p.ServerName) {
				return errors.New("远程Hysteria2需要有效独立密码和TLS名称")
			}
			if err := validateRemoteCertPEM(p.CertificatePEM, "Hysteria2"); err != nil {
				return err
			}
			if p.Performance != nil {
				v := p.Performance
				if v.ServerUpMbps != nil || v.ServerDownMbps != nil || v.IgnoreClientBandwidth != nil || v.Server != nil || v.HopMode == "nftables" {
					return errors.New("远程HY2只接受客户端性能选择，不能修改远端服务上限或宿主端口跳跃转发")
				}
				if v.Obfs != nil && v.Obfs.Password == p.Password {
					return errors.New("Hysteria2 salamander 混淆密码必须独立于节点认证密码")
				}
				if err := ValidateHY2Capabilities(Node{Protocol: "hysteria2", HY2: v}, core, nil); err != nil {
					return err
				}
			}
			return nil
		},
		Render: func(e Egress, m M) {
			p := e.HY2
			m["type"], m["password"] = "hysteria2", p.Password
			m["tls"] = remoteTLSWithTransport(p.ServerName, p.CertificatePEM, nil)
			applyHY2ClientOutbound(m, p.Performance)
		},
	},
	"trojan": {
		MinSchema:           10,
		SupportsTransport:   true,
		SupportsMultiplex:   true,
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: neverRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.Trojan
			if p == nil || safeTLSCredential(User{Password: p.Password}) != nil || !ValidHost(p.ServerName) {
				return errors.New("远程Trojan需要16–512字节有效UTF-8密码（不含控制字符）和TLS名称")
			}
			return validateRemoteCertPEM(p.CertificatePEM, "Trojan")
		},
		Render: func(e Egress, m M) {
			p := e.Trojan
			m["type"], m["password"] = "trojan", p.Password
			if !e.UDP {
				m["network"] = "tcp"
			}
			m["tls"] = remoteTLSWithTransport(p.ServerName, p.CertificatePEM, e.Transport)
			if tr := transportOptionsToSingBox(e.Transport); tr != nil {
				m["transport"] = tr
			}
			if mux := multiplexOutbound(e.Multiplex); mux != nil {
				m["multiplex"] = mux
			}
		},
	},
	"vless-tls": {
		MinSchema:           10,
		SupportsTransport:   true,
		SupportsMultiplex:   true,
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: neverRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.VLESS
			if p == nil || !validNonZeroUUID(p.UUID) || !ValidHost(p.ServerName) {
				return errors.New("远程VLESS+TLS需要有效UUID和TLS名称")
			}
			switch p.PacketEncoding {
			case "", "xudp", "packetaddr":
			default:
				return errors.New("远程VLESS+TLS packet_encoding仅支持xudp或packetaddr")
			}
			return validateRemoteCertPEM(p.CertificatePEM, "VLESS+TLS")
		},
		Render: func(e Egress, m M) {
			p := e.VLESS
			pe := p.PacketEncoding
			if pe == "" {
				pe = "xudp"
			}
			m["type"], m["uuid"], m["packet_encoding"] = "vless", p.UUID, pe
			if !e.UDP {
				m["network"] = "tcp"
			}
			m["tls"] = remoteTLSWithTransport(p.ServerName, p.CertificatePEM, e.Transport)
			if tr := transportOptionsToSingBox(e.Transport); tr != nil {
				m["transport"] = tr
			}
			if mux := multiplexOutbound(e.Multiplex); mux != nil {
				m["multiplex"] = mux
			}
		},
	},
	"vmess-tls": {
		MinSchema:           10,
		SupportsTransport:   true,
		SupportsMultiplex:   true,
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: neverRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.VMess
			if p == nil || !validNonZeroUUID(p.UUID) || !ValidHost(p.ServerName) {
				return errors.New("远程VMess+TLS需要有效UUID和TLS名称")
			}
			switch p.Security {
			case "", "auto", "aes-128-gcm", "chacha20-poly1305":
			default:
				return errors.New("远程VMess+TLS加密仅支持auto、aes-128-gcm或chacha20-poly1305")
			}
			switch p.PacketEncoding {
			case "", "xudp", "packetaddr":
			default:
				return errors.New("远程VMess+TLS packet_encoding仅支持xudp或packetaddr")
			}
			return validateRemoteCertPEM(p.CertificatePEM, "VMess+TLS")
		},
		Render: func(e Egress, m M) {
			p := e.VMess
			sec := p.Security
			if sec == "" {
				sec = "auto"
			}
			pe := p.PacketEncoding
			if pe == "" {
				pe = "xudp"
			}
			m["type"], m["uuid"], m["security"], m["alter_id"], m["global_padding"], m["authenticated_length"], m["packet_encoding"] = "vmess", p.UUID, sec, 0, true, true, pe
			if !e.UDP {
				m["network"] = "tcp"
			}
			m["tls"] = remoteTLSWithTransport(p.ServerName, p.CertificatePEM, e.Transport)
			if tr := transportOptionsToSingBox(e.Transport); tr != nil {
				m["transport"] = tr
			}
			if mux := multiplexOutbound(e.Multiplex); mux != nil {
				m["multiplex"] = mux
			}
		},
	},
	"anytls": {
		MinSchema:           10,
		ServerNetworks:      tcpOnlyNetworks,
		RequiresUpstreamUDP: neverRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.AnyTLS
			if p == nil || safeTLSCredential(User{Password: p.Password}) != nil || !ValidHost(p.ServerName) {
				return errors.New("远程AnyTLS需要16–512字节有效UTF-8密码（不含控制字符）和TLS名称")
			}
			if !e.UDP {
				return errors.New("远程AnyTLS始终承载TCP与UDP会话复用，必须开启UDP能力")
			}
			if err := validateAnyTLSOptions(&AnyTLSOptions{
				IdleSessionCheckInterval: p.IdleSessionCheckInterval,
				IdleSessionTimeout:       p.IdleSessionTimeout,
				IdleSessionMinKeep:       p.MinIdleSession,
			}); err != nil {
				return err
			}
			return validateRemoteCertPEM(p.CertificatePEM, "AnyTLS")
		},
		Render: func(e Egress, m M) {
			p := e.AnyTLS
			m["type"], m["password"] = "anytls", p.Password
			m["tls"] = remoteTLSWithTransport(p.ServerName, p.CertificatePEM, nil)
			if p.IdleSessionCheckInterval != "" {
				m["idle_session_check_interval"] = p.IdleSessionCheckInterval
			}
			if p.IdleSessionTimeout != "" {
				m["idle_session_timeout"] = p.IdleSessionTimeout
			}
			if p.MinIdleSession != nil {
				m["min_idle_session"] = *p.MinIdleSession
			}
		},
	},
	"tuic": {
		MinSchema:           10,
		BuildTags:           []string{"with_quic"},
		ServerNetworks:      udpOnlyNetworks,
		RequiresUpstreamUDP: alwaysRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			p := e.TUIC
			if p == nil || !validNonZeroUUID(p.UUID) || safeTLSCredential(User{Password: p.Password}) != nil || !ValidHost(p.ServerName) {
				return errors.New("远程TUIC需要有效UUID、16–512字节有效UTF-8密码（不含控制字符）和TLS名称")
			}
			if err := validateTUICOptions(&TUICOptions{
				ClientCongestionControl: p.CongestionControl,
				UDPRelayMode:            p.UDPRelayMode,
				ClientHeartbeat:         p.Heartbeat,
			}); err != nil {
				return err
			}
			return validateRemoteCertPEM(p.CertificatePEM, "TUIC")
		},
		Render: func(e Egress, m M) {
			p := e.TUIC
			tls := remoteTLSWithTransport(p.ServerName, p.CertificatePEM, nil)
			tls["alpn"] = []string{"h3"}
			m["type"], m["uuid"], m["password"], m["tls"], m["zero_rtt_handshake"] = "tuic", p.UUID, p.Password, tls, false
			if !e.UDP {
				m["network"] = "tcp"
			}
			if p.CongestionControl != "" {
				m["congestion_control"] = p.CongestionControl
			}
			if p.UDPRelayMode != "" {
				m["udp_relay_mode"] = p.UDPRelayMode
			}
			if p.Heartbeat != "" {
				m["heartbeat"] = p.Heartbeat
			}
		},
	},
	"wireguard": {
		MinSchema:           4,
		IsEndpoint:          true,
		BuildTags:           []string{"with_wireguard", "with_gvisor"},
		ServerNetworks:      udpOnlyNetworks,
		RequiresUpstreamUDP: alwaysRequiresUpstreamUDP,
		Validate: func(e Egress, _ string) error {
			if e.WireGuard == nil || e.Server != "" || e.Port != 0 {
				return errors.New("WireGuard地址和端口须在独立peer中填写")
			}
			return validateWireGuard(*e.WireGuard, e.Detour)
		},
		Render: func(e Egress, m M) {
			w := e.WireGuard
			m["type"], m["system"], m["address"], m["private_key"] = "wireguard", false, w.Address, w.PrivateKey
			if w.ListenPort != 0 {
				m["listen_port"] = w.ListenPort
			}
			if w.MTU != 0 {
				m["mtu"] = w.MTU
			}
			peers := []M{}
			for _, p := range w.Peers {
				peer := M{"public_key": p.PublicKey, "allowed_ips": p.AllowedIPs}
				if p.Address != "" {
					peer["address"], peer["port"] = p.Address, p.Port
				}
				if p.PreSharedKey != "" {
					peer["pre_shared_key"] = p.PreSharedKey
				}
				if p.Keepalive != 0 {
					peer["persistent_keepalive_interval"] = p.Keepalive
				}
				peers = append(peers, peer)
			}
			m["peers"] = peers
		},
	},
}

func renderShadowsocksEgress(e Egress, m M) {
	p := e.Shadowsocks
	m["type"], m["method"], m["password"] = "shadowsocks", p.Method, p.Password
	if !e.UDP {
		m["network"] = "tcp"
	}
	if mux := multiplexOutbound(e.Multiplex); mux != nil {
		m["multiplex"] = mux
	}
}

func egressProtocol(name string) (egressAdapter, bool) {
	a, ok := egressAdapters[name]
	return a, ok
}
