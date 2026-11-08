package node

import (
	"net"
	"net/url"
	"strconv"
)

func trojanCredential(u *User) {
	u.UUID = ""
	u.Password = Token(24)
}

func validateTrojan(n Node) error { return validateTLSNode(n, true) }

func trojanInbound(n Node, root string) M {
	out := M{"type": "trojan", "users": tlsPasswordUsers(n), "tls": tlsInboundWithTransport(n, root)}
	if tr := transportInbound(n); tr != nil {
		out["transport"] = tr
	}
	return out
}

func trojanURI(n Node, u User) string {
	q := url.Values{"sni": {n.Certificate.ServerName}, "allowInsecure": {"false"}}
	applyTransportURIQuery(q, n)
	x := url.URL{Scheme: "trojan", User: url.User(u.Password), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), RawQuery: q.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}

func trojanOutbound(n Node, u User) M {
	out := M{"type": "trojan", "password": u.Password, "tls": tlsOutboundWithTransport(n)}
	if tr := transportOutbound(n); tr != nil {
		out["transport"] = tr
	}
	return out
}

func trojanMihomo(n Node, u User) M {
	out := M{"type": "trojan", "password": u.Password, "udp": true, "skip-cert-verify": false, "sni": n.Certificate.ServerName, "network": "tcp"}
	applyTransportMihomo(out, n)
	return out
}
