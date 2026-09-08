package node

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

func hysteriaCredential(u *User) { u.Password = Token(24) }
func validateHysteria(n Node) error {
	c := n.Certificate
	if c == nil || !ValidHost(c.ServerName) {
		return errors.New("Hysteria2 需要有效证书名称")
	}
	if n.Reality != nil || n.Shadowsocks != nil {
		return errors.New("Hysteria2 不接受其他协议参数")
	}
	for _, u := range n.Users {
		if u.UUID != "" || len(u.Password) < 16 || len(u.Password) > 512 || strings.ContainsAny(u.Password, "\x00\r\n") {
			return errors.New("Hysteria2 密码须为 16–512 字节且不含换行")
		}
	}
	switch c.Mode {
	case "pem":
		pair, e := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if e != nil {
			return errors.New("证书与私钥不匹配或 PEM 无效")
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return e
		}
		if e = leaf.VerifyHostname(c.ServerName); e != nil {
			return fmt.Errorf("证书名称校验失败：%w", e)
		}
	case "acme":
		if net.ParseIP(c.ServerName) != nil || !strings.Contains(c.Email, "@") || strings.ContainsAny(c.Email, "\r\n") {
			return errors.New("ACME 需要域名与有效邮箱")
		}
	default:
		return errors.New("证书模式必须为 pem 或 acme")
	}
	return nil
}
func hysteriaInbound(n Node, root string) M {
	c := n.Certificate
	tls := M{"enabled": true, "server_name": c.ServerName}
	if c.Mode == "pem" {
		tls["certificate"] = []string{c.CertPEM}
		tls["key"] = []string{c.KeyPEM}
	} else {
		tls["certificate_provider"] = M{"type": "acme", "domain": []string{c.ServerName}, "email": c.Email, "data_directory": filepath.Join(root, "acme"), "disable_tls_alpn_challenge": true}
	}
	users := []any{}
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "password": u.Password})
	}
	return M{"type": "hysteria2", "users": users, "tls": tls}
}
func hysteriaURI(n Node, u User) string {
	x := url.URL{Scheme: "hysteria2", User: url.User(u.Password), Host: net.JoinHostPort(n.Host, strconv.Itoa(n.Port)), RawQuery: url.Values{"sni": {n.Certificate.ServerName}}.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func hysteriaOutbound(n Node, u User) M {
	return M{"type": "hysteria2", "password": u.Password, "tls": M{"enabled": true, "server_name": n.Certificate.ServerName}}
}
func hysteriaMihomo(n Node, u User) M {
	return M{"type": "hysteria2", "password": u.Password, "udp": true, "skip-cert-verify": false, "sni": n.Certificate.ServerName}
}
