package node

import (
	"errors"
	"time"
	"unicode"
	"unicode/utf8"
)

// safeTLSCredential keeps password authentication separate from UUID-based
// protocols. Errors deliberately describe the rule without echoing a secret.
func safeTLSCredential(u User) error {
	if u.UUID != "" || len(u.Password) < 16 || len(u.Password) > 512 || !utf8.ValidString(u.Password) {
		return errors.New("TLS 代理密码须为 16–512 字节的有效 UTF-8，且不能混入 UUID")
	}
	for _, r := range u.Password {
		if unicode.IsControl(r) {
			return errors.New("TLS 代理密码不能含控制字符")
		}
	}
	return nil
}

// validateTLSNode is also used by restore, where externally owned certificate
// files may be checked later on the destination host. All other rules still run.
func validateTLSNode(n Node, checkExternalFiles bool) error {
	if err := ValidateV2RayTransport(n.Protocol, n.Transport); err != nil {
		return err
	}
	if n.Certificate == nil || !ValidHost(n.Certificate.ServerName) {
		return errors.New("TLS 代理需要有效证书名称")
	}
	if n.Reality != nil || n.Shadowsocks != nil || n.HY2 != nil || n.TUIC != nil {
		return errors.New("TLS 代理不能混入 REALITY、Shadowsocks、Hysteria2 或 TUIC 参数")
	}
	if n.Protocol != "anytls" && n.AnyTLS != nil {
		return errors.New("AnyTLS 设置不能用于其他协议")
	}
	if n.Protocol == "anytls" {
		if err := validateAnyTLSOptions(n.AnyTLS); err != nil {
			return err
		}
	}
	for _, u := range n.Users {
		if n.Protocol == "vless" || n.Protocol == "vmess" {
			if !uuidRE.MatchString(u.UUID) || u.Password != "" {
				return errors.New("VLESS/VMess 需要有效 UUID，不能混入密码")
			}
		} else if err := safeTLSCredential(u); err != nil {
			return err
		}
	}
	return validateCertificateResource(CertificateResource{Certificate: *n.Certificate}, time.Time{}, false, checkExternalFiles)
}

func tlsInbound(n Node, root string) M {
	c := n.Certificate
	tls := M{"enabled": true, "server_name": c.ServerName}
	if alpn := transportALPN(n.Transport); len(alpn) != 0 {
		tls["alpn"] = alpn
	}
	switch c.Mode {
	case "pem":
		tls["certificate"], tls["key"] = []string{c.CertPEM}, []string{c.KeyPEM}
	case "file":
		tls["certificate_path"], tls["key_path"] = c.CertificatePath, c.KeyPath
	default:
		tls["certificate_provider"] = certificateACMEProvider(n, root)
	}
	return tls
}

func tlsOutbound(n Node) M {
	tls := M{"enabled": true, "server_name": n.Certificate.ServerName}
	if alpn := transportALPN(n.Transport); len(alpn) != 0 {
		tls["alpn"] = alpn
	}
	return tls
}

func tlsPasswordUsers(n Node) []any {
	users := make([]any, 0, len(n.Users))
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "password": u.Password})
	}
	return users
}
