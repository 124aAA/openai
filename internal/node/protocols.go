package node

import "sort"

// Protocol adapters own authentication, validation, capability metadata and
// wire/client formats. Store, backup, firewall and service code depend only on
// this registry contract rather than scattered protocol-name switches.
type Adapter struct {
	Networks   []string
	Credential func(*User)
	Validate   func(Node) error
	Inbound    func(Node, string) M
	URI        func(Node, User) string
	Outbound   func(Node, User) M
	Mihomo     func(Node, User) M

	ValidateRestore     func(Node) error
	InboundType         string
	MinSchema           int
	RequiresCertificate bool
	SupportsTransport   bool
	SupportsMultiplex   bool
	ServerBuildTags     []string
	ClientBuildTags     []string
	CredentialsDesc     string
	AdvancedOptions     []string
	TLSWarningLabel     string
	DisplaySummary      func(Node) string
	ExportWarnings      func(Node, string) []string
}

func tlsTransportSummary(prefix string) func(Node) string {
	return func(n Node) string {
		tr := EffectiveTransport(n)
		if tr == "tcp" {
			return prefix + " + TLS"
		}
		return prefix + " + " + TransportName(tr) + " + TLS"
	}
}

func fixedSummary(label string) func(Node) string {
	return func(Node) string { return label }
}

var adapters map[string]Adapter

func init() {
	adapters = map[string]Adapter{
		"anytls": {
			Networks:            []string{"tcp"},
			Credential:          anytlsCredential,
			Validate:            validateAnyTLS,
			ValidateRestore:     func(n Node) error { return validateTLSNode(n, false) },
			Inbound:             anytlsInbound,
			URI:                 anytlsURI,
			Outbound:            anytlsOutbound,
			Mihomo:              anytlsMihomo,
			InboundType:         "anytls",
			MinSchema:           8,
			RequiresCertificate: true,
			CredentialsDesc:     "independent UTF-8 user password",
			AdvancedOptions:     []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"},
			DisplaySummary:      fixedSummary("AnyTLS"),
			ExportWarnings: func(n Node, format string) []string {
				if AnyTLSClientSettingsPresent(n.AnyTLS) && (format == "uri" || format == "base64" || format == "qr") {
					return []string{"AnyTLS分享格式不能表达空闲连接池设置；请导出完整sing-box或Mihomo配置"}
				}
				return nil
			},
		},
		"trojan": {
			Networks:            []string{"tcp"},
			Credential:          trojanCredential,
			Validate:            validateTrojan,
			ValidateRestore:     func(n Node) error { return validateTLSNode(n, false) },
			Inbound:             trojanInbound,
			URI:                 trojanURI,
			Outbound:            trojanOutbound,
			Mihomo:              trojanMihomo,
			InboundType:         "trojan",
			MinSchema:           8,
			RequiresCertificate: true,
			SupportsTransport:   true,
			SupportsMultiplex:   true,
			CredentialsDesc:     "independent UTF-8 user password",
			AdvancedOptions:     []string{"transport (tcp/ws/grpc/httpupgrade/http)", "ws early data (0-RTT)", "multiplex (h2mux/smux/yamux)"},
			TLSWarningLabel:     "Trojan",
			DisplaySummary:      tlsTransportSummary("Trojan"),
		},
		"vless-tls": {
			Networks:            []string{"tcp"},
			Credential:          vlessTLSCredential,
			Validate:            validateVLESSTLS,
			ValidateRestore:     func(n Node) error { return validateTLSUUIDNode(n, false) },
			Inbound:             vlessTLSInbound,
			URI:                 vlessTLSURI,
			Outbound:            vlessTLSOutbound,
			Mihomo:              vlessTLSMihomo,
			InboundType:         "vless",
			MinSchema:           8,
			RequiresCertificate: true,
			SupportsTransport:   true,
			SupportsMultiplex:   true,
			CredentialsDesc:     "UUID",
			AdvancedOptions:     []string{"transport (tcp/ws/grpc/httpupgrade/http)", "ws early data (0-RTT)", "multiplex (h2mux/smux/yamux)"},
			TLSWarningLabel:     "VLESS+TLS",
			DisplaySummary:      tlsTransportSummary("VLESS"),
		},
		"vmess-tls": {
			Networks:            []string{"tcp"},
			Credential:          vmessTLSCredential,
			Validate:            validateVMessTLS,
			ValidateRestore:     func(n Node) error { return validateTLSUUIDNode(n, false) },
			Inbound:             vmessTLSInbound,
			URI:                 vmessTLSURI,
			Outbound:            vmessTLSOutbound,
			Mihomo:              vmessTLSMihomo,
			InboundType:         "vmess",
			MinSchema:           8,
			RequiresCertificate: true,
			SupportsTransport:   true,
			SupportsMultiplex:   true,
			CredentialsDesc:     "UUID (AEAD, alterId=0)",
			AdvancedOptions:     []string{"transport (tcp/ws/grpc/httpupgrade/http)", "ws early data (0-RTT)", "multiplex (h2mux/smux/yamux)"},
			TLSWarningLabel:     "VMess+TLS",
			DisplaySummary:      tlsTransportSummary("VMess"),
		},
		"ss-aead": {
			Networks:          []string{"tcp", "udp"},
			Credential:        ssAEADCredential,
			Validate:          validateSSAEAD,
			Inbound:           ssAEADInbound,
			URI:               ssAEADURI,
			Outbound:          ssAEADOutbound,
			Mihomo:            ssAEADMihomo,
			InboundType:       "shadowsocks",
			MinSchema:         8,
			SupportsMultiplex: true,
			CredentialsDesc:   "independent UTF-8 user password; method-specific KDF, no server:user composition",
			AdvancedOptions:   []string{"multiplex (h2mux/smux/yamux)"},
			DisplaySummary:    fixedSummary("Shadowsocks AEAD"),
		},
		"tuic": {
			Networks:            []string{"udp"},
			Credential:          tuicCredential,
			Validate:            validateTUIC,
			ValidateRestore:     func(n Node) error { return validateTUICCertificate(n, false) },
			Inbound:             tuicInbound,
			URI:                 tuicURI,
			Outbound:            tuicOutbound,
			Mihomo:              tuicMihomo,
			InboundType:         "tuic",
			MinSchema:           8,
			RequiresCertificate: true,
			ServerBuildTags:     []string{"with_quic"},
			ClientBuildTags:     []string{"with_quic"},
			CredentialsDesc:     "UUID plus independent user password",
			AdvancedOptions:     []string{"congestion_control", "auth_timeout (server)", "heartbeat", "udp_relay_mode (client)", "zero_rtt_handshake=false"},
			DisplaySummary:      fixedSummary("TUIC v5"),
			ExportWarnings: func(n Node, format string) []string {
				if TUICClientURIUnsupported(n.TUIC) && (format == "uri" || format == "base64" || format == "qr") {
					return []string{"TUIC NEP-408分享链接不能表达客户端心跳（client_heartbeat）；服务端专属项已在服务端生效，如需保留客户端心跳请导出完整sing-box或Mihomo配置"}
				}
				return nil
			},
		},
		"reality": {
			Networks:        []string{"tcp"},
			Credential:      realityCredential,
			Validate:        validateReality,
			Inbound:         realityInbound,
			URI:             realityURI,
			Outbound:        realityOutbound,
			Mihomo:          realityMihomo,
			InboundType:     "vless",
			MinSchema:       1,
			ClientBuildTags: []string{"with_utls"},
			CredentialsDesc: "UUID",
			AdvancedOptions: []string{"short_ids (multi-ShortID)", "transport (tcp vision / grpc)", "extended uTLS fingerprints"},
			DisplaySummary: func(n Node) string {
				if EffectiveTransport(n) == "grpc" {
					return "VLESS + REALITY + gRPC"
				}
				return "VLESS + REALITY + Vision"
			},
		},
		"hysteria2": {
			Networks:            []string{"udp"},
			Credential:          hysteriaCredential,
			Validate:            validateHysteria,
			ValidateRestore:     func(n Node) error { return validateHysteriaCertificate(n, false) },
			Inbound:             hysteriaInbound,
			URI:                 hysteriaURI,
			Outbound:            hysteriaOutbound,
			Mihomo:              hysteriaMihomo,
			InboundType:         "hysteria2",
			MinSchema:           1,
			RequiresCertificate: true,
			ServerBuildTags:     []string{"with_quic"},
			ClientBuildTags:     []string{"with_quic"},
			CredentialsDesc:     "independent user password",
			AdvancedOptions:     []string{"hysteria2 performance settings", "obfs (salamander)", "port hopping (hop_ports/hop_interval/hop_mode)"},
			DisplaySummary:      fixedSummary("Hysteria2"),
		},
		"ss2022": {
			Networks:          []string{"tcp", "udp"},
			Credential:        ssCredential,
			Validate:          validateSS2022,
			Inbound:           ssInbound,
			URI:               ssURI,
			Outbound:          ssOutbound,
			Mihomo:            ssMihomo,
			InboundType:       "shadowsocks",
			MinSchema:         1,
			SupportsMultiplex: true,
			CredentialsDesc:   "16/32-byte base64 server key plus independent 16/32-byte base64 user key",
			AdvancedOptions:   []string{"cipher (2022-blake3-aes-256-gcm / 2022-blake3-aes-128-gcm / 2022-blake3-chacha20-poly1305)", "multiplex (h2mux/smux/yamux)"},
			DisplaySummary:    fixedSummary("Shadowsocks 2022"),
		},
	}
}

func Protocol(name string) (Adapter, bool) { p, ok := adapters[name]; return p, ok }
func Protocols() []string {
	names := make([]string, 0, len(adapters))
	for name := range adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

