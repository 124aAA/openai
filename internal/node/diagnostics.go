package node

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var secretPEM = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
var secretURI = regexp.MustCompile(`(?i)(?:vless|hysteria2|hy2|ss|socks5?|tuic|trojan|anytls)://[^\s"'<>]+`)
var secretJSON = regexp.MustCompile(`(?i)("(?:private_key|pre_shared_key|preshared_key|password|username|uuid|key_pem|server_key|token|subscription_token|secret|api_secret|api_key|api_token|zone_token|access_key_id|access_key_secret|security_token|account_key|mac_key|authorization)"\s*:\s*)"(?:\\.|[^"\\])*"`)
var secretUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
var secretIPCKey = regexp.MustCompile(`(?i)((?:private_key|preshared_key|pre_shared_key)\s*=\s*)[0-9a-f]{64}\b`)
var secretSubscriptionPath = regexp.MustCompile(`(?i)(/s/)[a-f0-9]{64}(/|\b)`)
var secretBearer = regexp.MustCompile(`(?im)(authorization[ \t]*:[ \t]*bearer[ \t]+)[^\s]+`)

// Match credential labels at line starts, retaining the label for diagnostics.
// Horizontal whitespace and the value must not consume the next error line;
// the entire value is secret, including both halves of an SS2022 password.
var secretText = regexp.MustCompile(`(?im)^([ \t]*(?:(?:reality[ \t]+)?private[ _-]?key|(?:pre[ _-]?shared|preshared)[ _-]?key|server[ _-]?key|key_pem|password|username|uuid|(?:subscription[ _-]?)?token|api[ _-]?(?:key|token)|订阅令牌|DNS[ \t]*API[ \t]*凭据|服务密钥|密码|私钥)[ \t]*[:：=][ \t]*)[^\r\n]+`)

func Redact(text string, states ...State) string {
	text = secretPEM.ReplaceAllString(text, "[私钥已隐藏]")
	text = secretURI.ReplaceAllString(text, "[节点链接已隐藏]")
	text = secretSubscriptionPath.ReplaceAllString(text, `${1}[订阅令牌已隐藏]${2}`)
	text = secretBearer.ReplaceAllString(text, `${1}[订阅令牌已隐藏]`)
	text = secretJSON.ReplaceAllString(text, `${1}"[凭据已隐藏]"`)
	text = secretIPCKey.ReplaceAllString(text, `${1}[凭据已隐藏]`)
	text = secretUUID.ReplaceAllString(text, "[凭据已隐藏]")
	text = secretText.ReplaceAllString(text, `${1}[凭据已隐藏]`)
	for _, s := range states {
		if s.Observability != nil && s.Observability.Secret != "" {
			text = strings.ReplaceAll(text, s.Observability.Secret, "[API凭据已隐藏]")
		}
		if resolved, err := CanonicalCertificates(s); err == nil {
			s = resolved
		}
		for _, e := range s.Egresses {
			secrets := []string{}
			if e.Socks != nil {
				secrets = append(secrets, e.Socks.Username, e.Socks.Password)
			}
			if e.Reality != nil {
				secrets = append(secrets, e.Reality.UUID)
			}
			if e.Shadowsocks != nil {
				secrets = append(secrets, e.Shadowsocks.Password)
				secrets = append(secrets, strings.Split(e.Shadowsocks.Password, ":")...)
			}
			if e.HY2 != nil {
				secrets = append(secrets, e.HY2.Password)
			}
			if e.WireGuard != nil {
				keys := []string{e.WireGuard.PrivateKey}
				for _, p := range e.WireGuard.Peers {
					keys = append(keys, p.PreSharedKey)
				}
				for _, key := range keys {
					secrets = append(secrets, key)
					// wireguard-go's private IPC format encodes these same keys
					// as hexadecimal. An embedded upstream error must not bypass
					// redaction just because its representation differs from State.
					if decoded, err := base64.StdEncoding.Strict().DecodeString(key); err == nil && len(decoded) == 32 {
						encoded := hex.EncodeToString(decoded)
						secrets = append(secrets, encoded, strings.ToUpper(encoded))
					}
				}
			}
			for _, secret := range secrets {
				if secret != "" {
					text = strings.ReplaceAll(text, secret, "[远程凭据已隐藏]")
				}
			}
		}
		for _, n := range s.Nodes {
			for _, u := range n.Users {
				for _, secret := range []string{u.UUID, u.Password} {
					if secret != "" {
						text = strings.ReplaceAll(text, secret, "[凭据已隐藏]")
					}
				}
			}
			if n.Shadowsocks != nil && n.Shadowsocks.ServerKey != "" {
				text = strings.ReplaceAll(text, n.Shadowsocks.ServerKey, "[服务密钥已隐藏]")
			}
			if n.Reality != nil && n.Reality.PrivateKey != "" {
				text = strings.ReplaceAll(text, n.Reality.PrivateKey, "[私钥已隐藏]")
			}
			for _, secret := range certificateSecrets(n.Certificate) {
				if secret != "" {
					text = strings.ReplaceAll(text, secret, "[证书凭据已隐藏]")
				}
			}
		}
		for _, resource := range s.Certificates {
			for _, secret := range certificateSecrets(&resource.Certificate) {
				if secret != "" {
					text = strings.ReplaceAll(text, secret, "[证书凭据已隐藏]")
				}
			}
		}
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, text)
}
func certificateSecrets(c *Certificate) []string {
	if c == nil {
		return nil
	}
	secrets := []string{c.KeyPEM}
	if c.ACME != nil && c.ACME.DNS01 != nil {
		d := c.ACME.DNS01
		secrets = append(secrets, d.AccessKeyID, d.AccessKeySecret, d.SecurityToken, d.APIToken, d.ZoneToken, d.Username, d.Password, d.Subdomain)
	}
	return secrets
}
func Lookup(host string) ([]string, error) {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(c, host)
}
func PublicIP(family string) (string, error) {
	host := "https://api.ipify.org"
	network := "tcp4"
	if family == "6" {
		host = "https://api6.ipify.org"
		network = "tcp6"
	}
	d := net.Dialer{Timeout: 4 * time.Second}
	tr := &http.Transport{DialContext: func(c context.Context, _, address string) (net.Conn, error) {
		return d.DialContext(c, network, address)
	}, TLSHandshakeTimeout: 4 * time.Second}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("IP 查询不接受跳转") }}
	r, e := client.Get(host)
	if e != nil {
		return "", errors.New("公网 IP 查询失败；可能无对应地址、DNS 异常或 HTTPS 不通")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("公网 IP 查询返回 HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 128))
	if e != nil {
		return "", e
	}
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if ip == nil || (family == "4" && ip.To4() == nil) || (family == "6" && ip.To4() != nil) {
		return "", errors.New("IP 查询返回无效地址")
	}
	return ip.String(), nil
}
func CheckReality(r *Reality) error {
	_, e := ProbeReality(r)
	return e
}
