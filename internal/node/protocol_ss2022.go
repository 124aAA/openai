package node

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
)

const (
	SS2022Method         = "2022-blake3-aes-256-gcm"
	SS2022AES128Method   = "2022-blake3-aes-128-gcm"
	SS2022ChaCha20Method = "2022-blake3-chacha20-poly1305"
)

type Shadowsocks struct {
	Method    string `json:"method"`
	ServerKey string `json:"server_key"`
}

func SS2022KeyBytes(method string) (int, bool) {
	switch method {
	case SS2022Method, SS2022ChaCha20Method:
		return 32, true
	case SS2022AES128Method:
		return 16, true
	default:
		return 0, false
	}
}

func ssKeyBytes(size int) string {
	b, _ := hex.DecodeString(Token(size))
	return base64.StdEncoding.EncodeToString(b)
}

func ssKey() string                { return ssKeyBytes(32) }
func NewShadowsocks() *Shadowsocks { return &Shadowsocks{Method: SS2022Method, ServerKey: ssKey()} }

func NewShadowsocks2022(method string) (*Shadowsocks, error) {
	if method == "" {
		method = SS2022Method
	}
	size, ok := SS2022KeyBytes(method)
	if !ok {
		return nil, errors.New("SS2022 仅支持 2022-blake3-aes-256-gcm、2022-blake3-aes-128-gcm 或 2022-blake3-chacha20-poly1305")
	}
	return &Shadowsocks{Method: method, ServerKey: ssKeyBytes(size)}, nil
}

func NewUserForNode(name string, n Node) User {
	if n.Protocol == "ss2022" && n.Shadowsocks != nil {
		if size, ok := SS2022KeyBytes(n.Shadowsocks.Method); ok {
			return User{ID: Token(8), Name: name, Password: ssKeyBytes(size)}
		}
	}
	return NewUser(name, n.Protocol)
}

func ssCredential(u *User) { u.Password = ssKey() }

func validSSKeyBytes(s string, size int) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == size && base64.StdEncoding.EncodeToString(b) == s
}

func validSSKey(s string) bool { return validSSKeyBytes(s, 32) }

func validateSS2022(n Node) error {
	s := n.Shadowsocks
	if s == nil {
		return errors.New("SS2022 需要有效加密方法和服务密钥")
	}
	size, ok := SS2022KeyBytes(s.Method)
	if !ok || !validSSKeyBytes(s.ServerKey, size) {
		return errors.New("SS2022 方法仅支持 2022-blake3-aes-256-gcm（32B）、2022-blake3-aes-128-gcm（16B）或 2022-blake3-chacha20-poly1305（32B），且服务密钥须为对应长度的严格 Base64")
	}
	if n.Reality != nil || n.Certificate != nil || n.CertificateID != "" || n.HY2 != nil || n.AnyTLS != nil || n.TUIC != nil || n.Transport != nil {
		return errors.New("SS2022 不使用 REALITY 或 TLS 证书参数")
	}
	if err := validateNodeMultiplex(n); err != nil {
		return err
	}
	for _, u := range n.Users {
		if u.UUID != "" || !validSSKeyBytes(u.Password, size) || u.Password == s.ServerKey {
			return errors.New("SS2022 用户密钥必须为独立的对应长度（16 或 32 字节）Base64 密钥")
		}
	}
	return nil
}
func SSPassword(n Node, u User) string {
	if n.Protocol == "ss-aead" {
		return u.Password
	}
	return n.Shadowsocks.ServerKey + ":" + u.Password
}
func ssInbound(n Node, _ string) M {
	users := []any{}
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "password": u.Password})
	}
	out := M{"type": "shadowsocks", "method": n.Shadowsocks.Method, "password": n.Shadowsocks.ServerKey, "users": users}
	if mux := multiplexInbound(n.Multiplex); mux != nil {
		out["multiplex"] = mux
	}
	return out
}

// SIP002 requires percent-encoded userinfo (not Base64URL userinfo) for AEAD-2022.
func ssURI(n Node, u User) string {
	x := url.URL{Scheme: "ss", User: url.UserPassword(n.Shadowsocks.Method, SSPassword(n, u)), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func ssOutbound(n Node, u User) M {
	out := M{"type": "shadowsocks", "method": n.Shadowsocks.Method, "password": SSPassword(n, u)}
	if mux := multiplexOutbound(n.Multiplex); mux != nil {
		out["multiplex"] = mux
	}
	return out
}
func ssMihomo(n Node, u User) M {
	out := M{"type": "ss", "cipher": n.Shadowsocks.Method, "password": SSPassword(n, u), "udp": true}
	applyMultiplexMihomo(out, n.Multiplex)
	return out
}
