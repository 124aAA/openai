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
	return withV2RayTransport(M{"type": "trojan", "users": tlsPasswordUsers(n), "tls": tlsInbound(n, root)}, n.Transport)
}

func trojanURI(n Node, u User) string {
	q := url.Values{"sni": {n.Certificate.ServerName}, "allowInsecure": {"false"}, "type": {"tcp"}}
	addTransportQuery(q, n.Transport)
	x := url.URL{Scheme: "trojan", User: url.User(u.Password), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), RawQuery: q.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}

func trojanOutbound(n Node, u User) M {
	return withV2RayTransport(M{"type": "trojan", "password": u.Password, "tls": tlsOutbound(n)}, n.Transport)
}

func trojanMihomo(n Node, u User) M {
	return withMihomoTransport(M{"type": "trojan", "password": u.Password, "udp": true, "skip-cert-verify": false, "sni": n.Certificate.ServerName, "network": "tcp"}, n.Transport)
}
