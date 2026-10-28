package node

import (
	"errors"
	"fmt"
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
	if n.Reality != nil || n.Shadowsocks != nil {
		return errors.New("Hysteria2 不接受其他协议参数")
	}
	for _, u := range n.Users {
		if u.UUID != "" || len(u.Password) < 16 || len(u.Password) > 512 || strings.ContainsAny(u.Password, "\x00\r\n") {
			return errors.New("Hysteria2 密码须为 16–512 字节且不含换行")
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
		hy2Transport(out, p.Server)
	}
	return out
}
func hysteriaURI(n Node, u User) string {
	x := url.URL{Scheme: "hysteria2", User: url.User(u.Password), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), RawQuery: url.Values{"sni": {n.Certificate.ServerName}}.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func hysteriaOutbound(n Node, u User) M {
	out := M{"type": "hysteria2", "password": u.Password, "tls": M{"enabled": true, "server_name": n.Certificate.ServerName}}
	if p := n.HY2; p != nil {
		if p.ClientUpMbps != nil {
			out["up_mbps"] = *p.ClientUpMbps
		}
		if p.ClientDownMbps != nil {
			out["down_mbps"] = *p.ClientDownMbps
		}
		hy2Transport(out, p.Client)
	}
	return out
}
func hysteriaMihomo(n Node, u User) M {
	out := M{"type": "hysteria2", "password": u.Password, "udp": true, "skip-cert-verify": false, "sni": n.Certificate.ServerName}
	if p := n.HY2; p != nil {
		if p.ClientUpMbps != nil {
			out["up"] = fmt.Sprintf("%d Mbps", *p.ClientUpMbps)
		}
		if p.ClientDownMbps != nil {
			out["down"] = fmt.Sprintf("%d Mbps", *p.ClientDownMbps)
		}
		if t := p.Client; t != nil {
			if t.BBRProfile != "" {
				out["bbr-profile"] = t.BBRProfile
			}
			if q := t.QUIC; q != nil {
				if q.StreamReceiveWindow != nil {
					out["initial-stream-receive-window"] = *q.StreamReceiveWindow
					out["max-stream-receive-window"] = *q.StreamReceiveWindow
				}
				if q.ConnectionReceiveWindow != nil {
					out["initial-connection-receive-window"] = *q.ConnectionReceiveWindow
					out["max-connection-receive-window"] = *q.ConnectionReceiveWindow
				}
			}
		}
	}
	return out
}
