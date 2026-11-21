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
	p, ok := Protocol(name)
	return ok && p.RequiresCertificate
}

func ProtocolCapabilities(name string) (ProtocolCapability, bool) {
	p, ok := Protocol(name)
	if !ok {
		return ProtocolCapability{}, false
	}
	// Both fixed official cores passed the Batch09 targeted5 protocol suite.
	// This matrix is project evidence, not verification of the installed binary.
	return ProtocolCapability{
		Protocol:            name,
		MinimumManagedCore:  "1.14.0",
		TestedCoreVersions:  []string{"1.14.0", "1.14.3"},
		ServerBuildTags:     append([]string{}, p.ServerBuildTags...),
		ClientBuildTags:     append([]string{}, p.ClientBuildTags...),
		ListenerNetworks:    append([]string{}, p.Networks...),
		BusinessNetworks:    []string{"tcp", "udp"},
		Credentials:         p.CredentialsDesc,
		CertificateRequired: p.RequiresCertificate,
		Server:              true,
		Outbound:            true,
		ClientOutbound:      true,
		ServerEgress:        true,
		SingBox:             true,
		Mihomo:              true,
		URI:                 true,
		AdvancedOptions:     append([]string{}, p.AdvancedOptions...),
	}, true
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
	if n.Multiplex != nil && n.Multiplex.Enabled && (format == "uri" || format == "base64" || format == "qr" || format == "vmess-v2rayn") {
		return []string{"已启用服务端多路复用（multiplex），分享链接无法表达 sing-mux 封装参数；请导出完整 sing-box 或 Mihomo 配置"}
	}
	if n.Transport != nil && n.Transport.Type == "ws" && n.Transport.MaxEarlyData > 0 && EffectiveWSEarlyDataHeader(n.Transport) != DefaultWSEarlyDataHeader && format == "vmess-v2rayn" {
		return []string{"vmess-v2rayn JSON 链接不能表达自定义 WebSocket early_data_header_name；请导出标准 URI、sing-box 或 Mihomo 配置"}
	}
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	if p.TLSWarningLabel != "" && (format == "uri" || format == "base64" || format == "qr" || format == "vmess-v2rayn") && n.Certificate != nil && (n.Certificate.Mode == "pem" || n.Certificate.Mode == "file") {
		cert, key, err := certificateMaterial(*n.Certificate)
		if err != nil {
			return []string{fmt.Sprintf("无法核对%s分享链接的证书兼容性", p.TLSWarningLabel)}
		}
		leaf, _, err := parseCertificateChain(cert, key)
		if err != nil {
			return []string{fmt.Sprintf("无法核对%s分享链接的证书兼容性", p.TLSWarningLabel)}
		}
		if leaf.PublicKeyAlgorithm == x509.Ed25519 {
			return []string{fmt.Sprintf("Mihomo1.19.30导入%s URI默认Chrome指纹不支持Ed25519证书；请导出原生TLS完整配置或使用ECDSA/RSA证书", p.TLSWarningLabel)}
		}
	}
	if p.ExportWarnings != nil {
		return p.ExportWarnings(n, format)
	}
	return nil
}

func ValidateProtocolClient(n Node, format, version string, tags []string) error {
	p, ok := Protocol(n.Protocol)
	if !ok || p.MinSchema < 8 {
		return nil
	}
	if (format == "sing-box" || format == "sing-box-outbounds") && !SupportedVersion(version) {
		return errors.New("新协议sing-box客户端要求1.14.x正式版本；其他主次版本须单独适配验证")
	}
	if (format == "mihomo" || format == "provider") && !SupportedMihomoVersion(version) {
		return errors.New("新协议Mihomo导出要求>=1.19.0正式版本")
	}
	if (format == "sing-box" || format == "sing-box-outbounds") && tags != nil {
		seen := map[string]bool{}
		for _, tag := range tags {
			seen[tag] = true
		}
		for _, tag := range p.ClientBuildTags {
			if !seen[tag] {
				return fmt.Errorf("客户端缺少%s构建能力", tag)
			}
		}
	}
	return nil
}
