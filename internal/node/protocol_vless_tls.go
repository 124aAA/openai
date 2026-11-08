package node

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func vlessTLSCredential(u *User) {
	realityCredential(u)
	u.Password = ""
}

func validateVLESSTLS(n Node) error { return validateTLSUUIDNode(n, true) }

func validateTLSUUIDNode(n Node, checkExternalFiles bool) error {
	label := "VLESS+TLS"
	if n.Protocol == "vmess-tls" {
		label = "VMess+TLS"
	}
	if n.Certificate == nil || !ValidHost(n.Certificate.ServerName) {
		return fmt.Errorf("%s 需要有效证书名称", label)
	}
	if n.Reality != nil || n.Shadowsocks != nil || n.HY2 != nil || n.AnyTLS != nil || n.TUIC != nil {
		return fmt.Errorf("%s 不使用 REALITY、Shadowsocks、Hysteria2、AnyTLS 或 TUIC 参数", label)
	}
	if err := validateTransport(n); err != nil {
		return err
	}
	uuids := map[string]bool{}
	for _, u := range n.Users {
		identity := strings.ToLower(u.UUID)
		if !uuidRE.MatchString(u.UUID) || u.Password != "" || uuids[identity] {
			return fmt.Errorf("%s 每个用户须使用不同的有效 UUID 且不能混入密码", label)
		}
		uuids[identity] = true
	}
	return validateCertificateResource(CertificateResource{Certificate: *n.Certificate}, time.Time{}, false, checkExternalFiles)
}

func vlessTLSInbound(n Node, root string) M {
	u := make([]any, 0, len(n.Users))
	for _, x := range n.Users {
		u = append(u, M{"name": x.ID, "uuid": x.UUID})
	}
	out := M{"type": "vless", "users": u, "tls": tlsInboundWithTransport(n, root)}
	if tr := transportInbound(n); tr != nil {
		out["transport"] = tr
	}
	return out
}

func vlessTLSURI(n Node, u User) string {
	q := url.Values{
		"encryption":    {"none"},
		"security":      {"tls"},
		"sni":           {n.Certificate.ServerName},
		"allowInsecure": {"0"},
	}
	applyTransportURIQuery(q, n)
	x := url.URL{
		Scheme:   "vless",
		User:     url.User(u.UUID),
		Host:     net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))),
		RawQuery: q.Encode(),
		Fragment: n.Name + " / " + u.Name,
	}
	return x.String()
}

func vlessTLSOutbound(n Node, u User) M {
	out := M{
		"type":            "vless",
		"uuid":            u.UUID,
		"packet_encoding": "xudp",
		"tls":             tlsOutboundWithTransport(n),
	}
	if tr := transportOutbound(n); tr != nil {
		out["transport"] = tr
	}
	return out
}

func vlessTLSMihomo(n Node, u User) M {
	out := M{
		"type":             "vless",
		"uuid":             u.UUID,
		"tls":              true,
		"udp":              true,
		"packet-encoding":  "xudp",
		"servername":       n.Certificate.ServerName,
		"skip-cert-verify": false,
		"network":          "tcp",
	}
	applyTransportMihomo(out, n)
	return out
}
