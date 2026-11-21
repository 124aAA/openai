package node

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func hysteriaCredential(u *User) { u.Password = Token(24) }
func validateHysteria(n Node) error {
	return validateHysteriaCertificate(n, true)
}
func validateHysteriaCertificate(n Node, checkExternalFiles bool) error {
	if err := validateHY2Performance(n.HY2); err != nil {
		return err
	}
	c := n.Certificate
	if c == nil || !ValidHost(c.ServerName) {
		return errors.New("Hysteria2 需要有效证书名称")
	}
	if n.Reality != nil || n.Shadowsocks != nil || n.Transport != nil {
		return errors.New("Hysteria2 不接受其他协议参数")
	}
	if n.HY2 != nil && n.HY2.HopMode == "nftables" {
		if ip := net.ParseIP(n.Listen); ip == nil || ip.IsLoopback() {
			return errors.New("Hysteria2 本机受管 nftables 端口跳跃转发不能绑定仅回环监听地址")
		}
	}
	for _, u := range n.Users {
		if u.UUID != "" || len(u.Password) < 16 || len(u.Password) > 512 || strings.ContainsAny(u.Password, "\x00\r\n") {
			return errors.New("Hysteria2 密码须为 16–512 字节且不含换行")
		}
		if n.HY2 != nil && n.HY2.Obfs != nil && n.HY2.Obfs.Password == u.Password {
			return errors.New("Hysteria2 salamander 混淆密码须独立于用户认证密码")
		}
	}
	return validateCertificateResource(CertificateResource{Certificate: *c}, time.Time{}, false, checkExternalFiles)
}
func hysteriaInbound(n Node, root string) M {
	c := n.Certificate
	tls := M{"enabled": true, "server_name": c.ServerName}
	if c.Mode == "pem" {
		tls["certificate"] = []string{c.CertPEM}
		tls["key"] = []string{c.KeyPEM}
	} else if c.Mode == "file" {
		tls["certificate_path"], tls["key_path"] = c.CertificatePath, c.KeyPath
	} else {
		tls["certificate_provider"] = certificateACMEProvider(n, root)
	}
	users := []any{}
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "password": u.Password})
	}
	out := M{"type": "hysteria2", "users": users, "tls": tls}
	if p := n.HY2; p != nil {
		if p.ServerUpMbps != nil {
			out["up_mbps"] = *p.ServerUpMbps
		}
		if p.ServerDownMbps != nil {
			out["down_mbps"] = *p.ServerDownMbps
		}
		if p.IgnoreClientBandwidth != nil {
			out["ignore_client_bandwidth"] = *p.IgnoreClientBandwidth
		}
		if p.Obfs != nil {
			out["obfs"] = M{"type": p.Obfs.Type, "password": p.Obfs.Password}
		}
		hy2Transport(out, p.Server)
	}
	return out
}
func hysteriaURI(n Node, u User) string {
	q := url.Values{"sni": {n.Certificate.ServerName}}
	if p := n.HY2; p != nil {
		if p.Obfs != nil {
			q.Set("obfs", p.Obfs.Type)
			q.Set("obfs-password", p.Obfs.Password)
		}
		if p.HopPorts != "" {
			q.Set("mport", p.HopPorts)
		}
	}
	x := url.URL{Scheme: "hysteria2", User: url.User(u.Password), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), RawQuery: q.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func hysteriaOutbound(n Node, u User) M {
	out := M{"type": "hysteria2", "password": u.Password, "tls": M{"enabled": true, "server_name": n.Certificate.ServerName}}
	applyHY2ClientOutbound(out, n.HY2)
	return out
}
func hysteriaMihomo(n Node, u User) M {
	out := M{"type": "hysteria2", "password": u.Password, "udp": true, "skip-cert-verify": false, "sni": n.Certificate.ServerName}
	applyHY2Mihomo(out, n.HY2)
	return out
}
