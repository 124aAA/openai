package node

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
)

const SS2022Method = "2022-blake3-aes-256-gcm"

type Shadowsocks struct {
	Method    string `json:"method"`
	ServerKey string `json:"server_key"`
}

func ssKey() string                { b, _ := hex.DecodeString(Token(32)); return base64.StdEncoding.EncodeToString(b) }
func NewShadowsocks() *Shadowsocks { return &Shadowsocks{Method: SS2022Method, ServerKey: ssKey()} }
func ssCredential(u *User)         { u.Password = ssKey() }
func validSSKey(s string) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s
}
func validateSS2022(n Node) error {
	s := n.Shadowsocks
	if s == nil || s.Method != SS2022Method || !validSSKey(s.ServerKey) {
		return errors.New("SS2022 需要 AES-256-GCM 方法和 32 字节 Base64 服务密钥")
	}
	if n.Reality != nil || n.Certificate != nil {
		return errors.New("SS2022 不使用 REALITY 或 TLS 证书参数")
	}
	for _, u := range n.Users {
		if u.UUID != "" || !validSSKey(u.Password) || u.Password == s.ServerKey {
			return errors.New("SS2022 用户密钥必须为独立的 32 字节 Base64 密钥")
		}
	}
	return nil
}
func SSPassword(n Node, u User) string { return n.Shadowsocks.ServerKey + ":" + u.Password }
func ssInbound(n Node, _ string) M {
	users := []any{}
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "password": u.Password})
	}
	return M{"type": "shadowsocks", "method": n.Shadowsocks.Method, "password": n.Shadowsocks.ServerKey, "users": users}
}

// SIP002 requires percent-encoded userinfo (not Base64URL userinfo) for AEAD-2022.
func ssURI(n Node, u User) string {
	x := url.URL{Scheme: "ss", User: url.UserPassword(n.Shadowsocks.Method, SSPassword(n, u)), Host: net.JoinHostPort(n.Host, strconv.Itoa(n.Port)), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func ssOutbound(n Node, u User) M {
	return M{"type": "shadowsocks", "method": n.Shadowsocks.Method, "password": SSPassword(n, u)}
}
func ssMihomo(n Node, u User) M {
	return M{"type": "ss", "cipher": n.Shadowsocks.Method, "password": SSPassword(n, u), "udp": true}
}
