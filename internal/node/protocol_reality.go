package node

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func ValidRealityFingerprint(fp string) bool {
	switch fp {
	case "chrome", "firefox", "safari", "ios", "edge", "random", "randomized", "qq", "android", "360":
		return true
	default:
		return false
	}
}

func ValidRealityShortID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) >= 1 && len(b) <= 8
}

func EffectiveRealityShortIDs(r *Reality) []string {
	if r == nil {
		return nil
	}
	if len(r.ShortIDs) == 0 {
		return []string{r.ShortID}
	}
	return append([]string(nil), r.ShortIDs...)
}

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
	if n.Certificate != nil || n.CertificateID != "" || n.Shadowsocks != nil || n.HY2 != nil || n.AnyTLS != nil || n.TUIC != nil || n.Multiplex != nil {
		return errors.New("REALITY 不接受其他协议的私密参数或多路复用")
	}
	if err := validateTransport(n); err != nil {
		return err
	}
	if !ValidRealityFingerprint(Fingerprint(r)) {
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
	if !ValidRealityShortID(r.ShortID) {
		return errors.New("REALITY short ID 无效")
	}
	if len(r.ShortIDs) > 16 {
		return errors.New("REALITY short_ids 数量最多 16 个")
	}
	if len(r.ShortIDs) > 0 {
		seen := map[string]bool{}
		hasPrimary := false
		primary := strings.ToLower(r.ShortID)
		for _, sid := range r.ShortIDs {
			if !ValidRealityShortID(sid) || strings.ToLower(sid) != sid {
				return errors.New("REALITY short_ids 须为 1–8 字节小写十六进制")
			}
			if seen[sid] {
				return errors.New("REALITY short_ids 不能包含重复项")
			}
			seen[sid] = true
			if sid == primary {
				hasPrimary = true
			}
		}
		if !hasPrimary {
			return errors.New("REALITY short_ids 必须包含客户端默认主 short_id")
		}
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
	isGRPC := EffectiveTransport(n) == "grpc"
	users := []any{}
	for _, u := range n.Users {
		entry := M{"name": u.ID, "uuid": u.UUID}
		if !isGRPC {
			entry["flow"] = "xtls-rprx-vision"
		}
		users = append(users, entry)
	}
	out := M{
		"type":  "vless",
		"users": users,
		"tls": M{
			"enabled":     true,
			"server_name": r.ServerName,
			"reality": M{
				"enabled":     true,
				"handshake":   M{"server": host, "server_port": port},
				"private_key": r.PrivateKey,
				"short_id":    EffectiveRealityShortIDs(r),
			},
		},
	}
	if isGRPC {
		out["transport"] = transportInbound(n)
	}
	return out
}
func realityURI(n Node, u User) string {
	r := n.Reality
	q := url.Values{"encryption": {"none"}, "security": {"reality"}, "sni": {r.ServerName}, "fp": {Fingerprint(r)}, "pbk": {r.PublicKey}, "sid": {r.ShortID}}
	if EffectiveTransport(n) == "grpc" {
		q.Set("type", "grpc")
		q.Set("serviceName", n.Transport.ServiceName)
		q.Set("mode", "gun")
	} else {
		q.Set("type", "tcp")
		q.Set("flow", "xtls-rprx-vision")
	}
	x := url.URL{Scheme: "vless", User: url.User(u.UUID), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), RawQuery: q.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}
func realityOutbound(n Node, u User) M {
	r := n.Reality
	out := M{
		"type": "vless",
		"uuid": u.UUID,
		"tls": M{
			"enabled":     true,
			"server_name": r.ServerName,
			"utls":        M{"enabled": true, "fingerprint": Fingerprint(r)},
			"reality":     M{"enabled": true, "public_key": r.PublicKey, "short_id": r.ShortID},
		},
	}
	if EffectiveTransport(n) == "grpc" {
		out["transport"] = transportOutbound(n)
	} else {
		out["flow"] = "xtls-rprx-vision"
	}
	return out
}
func realityMihomo(n Node, u User) M {
	r := n.Reality
	out := M{
		"type":               "vless",
		"uuid":               u.UUID,
		"udp":                true,
		"tls":                true,
		"skip-cert-verify":   false,
		"network":            "tcp",
		"servername":         r.ServerName,
		"client-fingerprint": Fingerprint(r),
		"reality-opts":       M{"public-key": r.PublicKey, "short-id": r.ShortID},
	}
	if EffectiveTransport(n) == "grpc" {
		out["network"] = "grpc"
		out["grpc-opts"] = M{"grpc-service-name": n.Transport.ServiceName}
	} else {
		out["flow"] = "xtls-rprx-vision"
	}
	return out
}
