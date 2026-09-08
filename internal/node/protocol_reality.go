package node

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
)

func realityCredential(u *User) {
	b, _ := hex.DecodeString(Token(16))
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	u.UUID = h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func validateReality(n Node) error {
	r := n.Reality
	if r == nil || !ValidHost(r.ServerName) || net.ParseIP(r.ServerName) != nil {
		return errors.New("REALITY 需要有效 SNI 域名")
	}
	if n.Certificate != nil || n.Shadowsocks != nil {
		return errors.New("REALITY 不接受其他协议的私密参数")
	}
	switch Fingerprint(r) {
	case "chrome", "firefox", "safari", "ios", "edge":
	default:
		return errors.New("不支持该 fingerprint")
	}
	h, p, e := net.SplitHostPort(r.Target)
	port, _ := strconv.Atoi(p)
	if e != nil || !ValidHost(h) || port < 1 || port > 65535 {
		return errors.New("REALITY 目标必须为 主机:端口")
	}
	b, e := base64.RawURLEncoding.DecodeString(r.PrivateKey)
	if e != nil {
		return errors.New("REALITY 私钥无效")
	}
	key, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil || base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) != r.PublicKey {
		return errors.New("REALITY 公私钥不匹配")
	}
	b, e = hex.DecodeString(r.ShortID)
	if e != nil || len(b) < 1 || len(b) > 8 {
		return errors.New("REALITY short ID 无效")
	}
	for _, u := range n.Users {
		if !uuidRE.MatchString(u.UUID) || u.Password != "" {
			return errors.New("REALITY UUID 无效或混入密码")
		}
	}
	return nil
}
func realityInbound(n Node, _ string) M {
	r := n.Reality
	host, p, _ := net.SplitHostPort(r.Target)
	port, _ := strconv.Atoi(p)
	users := []any{}
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "uuid": u.UUID, "flow": "xtls-rprx-vision"})
	}
	return M{"type": "vless", "users": users, "tls": M{"enabled": true, "server_name": r.ServerName, "reality": M{"enabled": true, "handshake": M{"server": host, "server_port": port}, "private_key": r.PrivateKey, "short_id": []string{r.ShortID}}}}
}
func realityURI(n Node, u User) string {
	r := n.Reality
	q := url.Values{"encryption": {"none"}, "security": {"reality"}, "type": {"tcp"}, "flow": {"xtls-rprx-vision"}, "sni": {r.ServerName}, "fp": {Fingerprint(r)}, "pbk": {r.PublicKey}, "sid": {r.ShortID}}
	x := url.URL{Scheme: "vless", User: url.User(u.UUID), Host: net.JoinHostPort(n.Host, strconv.Itoa(n.Port)), RawQuery: q.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func realityOutbound(n Node, u User) M {
	r := n.Reality
	return M{"type": "vless", "uuid": u.UUID, "flow": "xtls-rprx-vision", "tls": M{"enabled": true, "server_name": r.ServerName, "utls": M{"enabled": true, "fingerprint": Fingerprint(r)}, "reality": M{"enabled": true, "public_key": r.PublicKey, "short_id": r.ShortID}}}
}
func realityMihomo(n Node, u User) M {
	r := n.Reality
	return M{"type": "vless", "uuid": u.UUID, "udp": true, "tls": true, "skip-cert-verify": false, "network": "tcp", "flow": "xtls-rprx-vision", "servername": r.ServerName, "client-fingerprint": Fingerprint(r), "reality-opts": M{"public-key": r.PublicKey, "short-id": r.ShortID}}
}
