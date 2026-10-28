package node

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
)

const DefaultSSAEADMethod = "aes-256-gcm"

func validSSAEADMethod(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		return true
	default:
		return false
	}
}

func NewShadowsocksAEAD(method string) (*Shadowsocks, error) {
	if !validSSAEADMethod(method) {
		return nil, errors.New("传统 Shadowsocks 仅支持 aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305")
	}
	return &Shadowsocks{Method: method}, nil
}

func ssAEADCredential(u *User) {
	u.UUID = ""
	u.Password = Token(24)
}

func validateSSAEAD(n Node) error {
	if n.Shadowsocks == nil || !validSSAEADMethod(n.Shadowsocks.Method) || n.Shadowsocks.ServerKey != "" {
		return errors.New("传统 Shadowsocks 需要已支持的 AEAD 方法，不能混入 SS2022 服务密钥")
	}
	if n.Reality != nil || n.Certificate != nil || n.CertificateID != "" || n.HY2 != nil || n.AnyTLS != nil || n.TUIC != nil {
		return errors.New("传统 Shadowsocks 不接受 TLS、REALITY 或其他协议参数")
	}
	passwords := map[string]bool{}
	for _, u := range n.Users {
		if safeTLSCredential(u) != nil || passwords[u.Password] {
			return errors.New("传统 Shadowsocks 每个用户须使用独立的 16–512 字节 UTF-8 密码，不含控制字符或 UUID")
		}
		passwords[u.Password] = true
	}
	return nil
}

func ssAEADInbound(n Node, _ string) M {
	// Traditional AEAD multi-user listeners take independent user passwords.
	// A top-level server password belongs to the separate SS2022 adapter.
	return M{"type": "shadowsocks", "method": n.Shadowsocks.Method, "users": tlsPasswordUsers(n)}
}

func ssAEADURI(n Node, u User) string {
	// SIP002 recommends unpadded Base64URL userinfo for traditional AEAD.
	auth := base64.RawURLEncoding.EncodeToString([]byte(n.Shadowsocks.Method + ":" + u.Password))
	x := url.URL{Scheme: "ss", User: url.User(auth), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), Fragment: n.Name + " / " + u.Name}
	return x.String()
}

func ssAEADOutbound(n Node, u User) M {
	return M{"type": "shadowsocks", "method": n.Shadowsocks.Method, "password": u.Password}
}

func ssAEADMihomo(n Node, u User) M {
	return M{"type": "ss", "cipher": n.Shadowsocks.Method, "password": u.Password, "udp": true}
}
