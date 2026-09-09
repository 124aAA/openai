package node

import (
	"context"
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
var secretURI = regexp.MustCompile(`(?i)(?:vless|hysteria2|hy2|ss|tuic)://[^\s"'<>]+`)
var secretJSON = regexp.MustCompile(`(?i)("(?:private_key|password|uuid|key_pem|server_key)"\s*:\s*)"(?:\\.|[^"\\])*"`)
var secretUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// Match credential labels at line starts, retaining the label for diagnostics.
// Horizontal whitespace and the value must not consume the next error line;
// the entire value is secret, including both halves of an SS2022 password.
var secretText = regexp.MustCompile(`(?im)^([ \t]*(?:(?:reality[ \t]+)?private[ _-]?key|server[ _-]?key|key_pem|password|uuid|服务密钥|密码|私钥)[ \t]*[:：=][ \t]*)[^\r\n]+`)

func Redact(text string, states ...State) string {
	text = secretPEM.ReplaceAllString(text, "[私钥已隐藏]")
	text = secretURI.ReplaceAllString(text, "[节点链接已隐藏]")
	text = secretJSON.ReplaceAllString(text, `${1}"[凭据已隐藏]"`)
	text = secretUUID.ReplaceAllString(text, "[凭据已隐藏]")
	text = secretText.ReplaceAllString(text, `${1}[凭据已隐藏]`)
	for _, s := range states {
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
			if n.Certificate != nil && n.Certificate.KeyPEM != "" {
				text = strings.ReplaceAll(text, n.Certificate.KeyPEM, "[私钥已隐藏]")
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
