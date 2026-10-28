package node

import (
	"net/url"
	"reflect"
	"testing"
)

func TestTrojanClientFormatsPreserveCredentialsAndTLS(t *testing.T) {
	n := tlsProtocolFixture(t, "trojan")
	u := n.Users[0]
	if err := validateTrojan(n); err != nil {
		t.Fatal(err)
	}
	want := M{"type": "trojan", "password": u.Password, "tls": M{"enabled": true, "server_name": "localhost"}}
	if !reflect.DeepEqual(trojanOutbound(n, u), want) {
		t.Fatal("native outbound changed the password or certificate verification")
	}
	want = M{"type": "trojan", "password": u.Password, "sni": "localhost", "udp": true, "skip-cert-verify": false, "network": "tcp"}
	if !reflect.DeepEqual(trojanMihomo(n, u), want) {
		t.Fatal("Mihomo outbound lost TCP listener/UDP payload distinction or secure TLS")
	}
	second := trojanOutbound(n, n.Users[1])
	if second["password"] == u.Password || second["password"] != n.Users[1].Password {
		t.Fatal("client exports collapsed independent credentials")
	}
}

func TestTrojanURIUsesParsedPasswordAndConnectEndpoint(t *testing.T) {
	n := tlsProtocolFixture(t, "trojan")
	port := 3443
	n.ConnectPort = &port
	u := n.Users[0]
	raw := trojanURI(n, u)
	got, err := url.Parse(raw)
	if err != nil || got.Scheme != "trojan" || got.Hostname() != "2001:db8::1" || got.Port() != "3443" || got.User.Username() != u.Password || got.Fragment != n.Name+" / "+u.Name {
		t.Fatal("Trojan URL lost the encoded password, IPv6 endpoint, or name", err)
	}
	if _, hasPassword := got.User.Password(); hasPassword || !reflect.DeepEqual(got.Query(), url.Values{"sni": {"localhost"}, "allowInsecure": {"false"}, "type": {"tcp"}}) {
		t.Fatal("Trojan URL mixed auth pairs or weakened verification")
	}
}
