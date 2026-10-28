package node

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// ListenerNetworks describe sockets. BusinessNetworks describe traffic carried
// inside the protocol; a TCP listener can carry UDP without a public UDP socket.
type ProtocolCapability struct {
	Protocol            string   `json:"protocol"`
	MinimumManagedCore  string   `json:"minimum_managed_core"`
	TestedCoreVersions  []string `json:"tested_core_versions"`
	ServerBuildTags     []string `json:"server_build_tags"`
	ClientBuildTags     []string `json:"client_build_tags"`
	ListenerNetworks    []string `json:"listener_networks"`
	BusinessNetworks    []string `json:"business_networks"`
	Credentials         string   `json:"credentials"`
	CertificateRequired bool     `json:"certificate_required"`
	Server              bool     `json:"server"`
	// Outbound is the original client-export flag. Keep it for consumers of
	// the version-1 capability response; it does not describe remote Egress.
	Outbound        bool     `json:"outbound"`
	ClientOutbound  bool     `json:"client_outbound"`
	ServerEgress    bool     `json:"server_egress"`
	SingBox         bool     `json:"sing_box"`
	Mihomo          bool     `json:"mihomo"`
	URI             bool     `json:"uri"`
	AdvancedOptions []string `json:"advanced_options"`
}

func ProtocolRequiresCertificate(name string) bool {
	return name == "hysteria2" || name == "anytls" || name == "trojan" || name == "tuic"
}

func ProtocolCapabilities(name string) (ProtocolCapability, bool) {
	p, ok := Protocol(name)
	if !ok {
		return ProtocolCapability{}, false
	}
	// Both fixed official cores passed the Batch09 targeted5 protocol suite.
	// This matrix is project evidence, not verification of the installed binary.
	c := ProtocolCapability{Protocol: name, MinimumManagedCore: "1.14.0", TestedCoreVersions: []string{"1.14.0", "1.14.3"},
		ServerBuildTags: []string{}, ClientBuildTags: []string{}, ListenerNetworks: append([]string{}, p.Networks...), BusinessNetworks: []string{"tcp", "udp"},
		CertificateRequired: ProtocolRequiresCertificate(name), Server: true, Outbound: true, ClientOutbound: true,
		ServerEgress: name == "reality" || name == "ss2022" || name == "hysteria2",
		SingBox:      true, Mihomo: true, URI: true, AdvancedOptions: []string{}}
	// Exact test commands, source commit and transport evidence are in BATCH09.md.
	// An accepted or tested version alone does not verify a custom core build.
	switch name {
	case "reality":
		c.Credentials = "UUID"
		c.ClientBuildTags = []string{"with_utls"}
	case "ss2022":
		c.Credentials = "32-byte base64 server key plus independent 32-byte base64 user key"
	case "ss-aead":
		c.Credentials = "independent UTF-8 user password; method-specific KDF, no server:user composition"
	case "anytls":
		c.Credentials = "independent UTF-8 user password"
		c.AdvancedOptions = []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"}
	case "trojan":
		c.Credentials = "independent UTF-8 user password"
	case "hysteria2":
		c.Credentials = "independent user password"
		c.ServerBuildTags = []string{"with_quic"}
		c.ClientBuildTags = []string{"with_quic"}
		c.AdvancedOptions = []string{"hysteria2 performance settings"}
	case "tuic":
		c.Credentials = "UUID plus independent user password"
		c.ServerBuildTags = []string{"with_quic"}
		c.ClientBuildTags = []string{"with_quic"}
		c.URI = false
		c.AdvancedOptions = []string{"congestion_control", "auth_timeout (server)", "heartbeat", "udp_relay_mode (client)", "zero_rtt_handshake=false"}
	}
	return c, true
}

func ValidateProtocolCapabilities(st State, tags []string) error {
	seen := map[string]bool{}
	for _, tag := range tags {
		seen[tag] = true
	}
	for _, n := range st.Nodes {
		c, ok := ProtocolCapabilities(n.Protocol)
		if !ok {
			return errors.New("不支持节点协议")
		}
		for _, tag := range c.ServerBuildTags {
			if !seen[tag] {
				return fmt.Errorf("节点 %s 所选核心缺少 %s 构建能力", n.ID, tag)
			}
		}
	}
	return nil
}

func ProtocolExportWarnings(n Node, format string) []string {
	if n.Protocol == "trojan" && (format == "uri" || format == "base64" || format == "qr") && n.Certificate != nil && (n.Certificate.Mode == "pem" || n.Certificate.Mode == "file") {
		cert, key, err := certificateMaterial(*n.Certificate)
		if err != nil {
			return []string{"无法核对Trojan分享链接的证书兼容性"}
		}
		leaf, _, err := parseCertificateChain(cert, key)
		if err != nil {
			return []string{"无法核对Trojan分享链接的证书兼容性"}
		}
		if leaf.PublicKeyAlgorithm == x509.Ed25519 {
			return []string{"Mihomo1.19.30导入Trojan URI默认Chrome指纹不支持Ed25519证书；请导出原生TLS完整配置或使用ECDSA/RSA证书"}
		}
	}
	if n.Protocol == "anytls" && AnyTLSClientSettingsPresent(n.AnyTLS) && (format == "uri" || format == "base64" || format == "qr") {
		return []string{"AnyTLS分享格式不能表达空闲连接池设置；请导出完整sing-box或Mihomo配置"}
	}
	if n.Protocol == "tuic" && (format == "uri" || format == "base64" || format == "qr") {
		return []string{"尚未验证通用TUIC分享URI；请导出完整sing-box或Mihomo配置"}
	}
	return nil
}

func ValidateProtocolClient(n Node, format, version string, tags []string) error {
	if n.Protocol != "anytls" && n.Protocol != "trojan" && n.Protocol != "ss-aead" && n.Protocol != "tuic" {
		return nil
	}
	if (format == "sing-box" || format == "sing-box-outbounds") && version != "1.14.0" && version != "1.14.3" {
		return errors.New("新协议sing-box客户端仅核对1.14.0与1.14.3；其他版本须单独适配验证")
	}
	if (format == "mihomo" || format == "provider") && version != "1.19.30" {
		return errors.New("新协议Mihomo导出仅核对1.19.30")
	}
	if (format == "sing-box" || format == "sing-box-outbounds") && tags != nil {
		c, _ := ProtocolCapabilities(n.Protocol)
		seen := map[string]bool{}
		for _, tag := range tags {
			seen[tag] = true
		}
		for _, tag := range c.ClientBuildTags {
			if !seen[tag] {
				return fmt.Errorf("客户端缺少%s构建能力", tag)
			}
		}
	}
	return nil
}
