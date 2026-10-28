package node

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func ssAEADFixture(t *testing.T, method string) Node {
	t.Helper()
	n := tlsProtocolFixture(t, "ss-aead")
	n.Certificate = nil
	var err error
	n.Shadowsocks, err = NewShadowsocksAEAD(method)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestShadowsocksAEADMethodsAndIndependentMultiUserCredentials(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			n := ssAEADFixture(t, method)
			if err := validateSSAEAD(n); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(n)
			in := ssAEADInbound(n, "/unused")
			wantUsers := []any{M{"name": n.Users[0].ID, "password": n.Users[0].Password}, M{"name": n.Users[1].ID, "password": n.Users[1].Password}}
			if len(in) != 3 || in["type"] != "shadowsocks" || in["method"] != method || !reflect.DeepEqual(in["users"], wantUsers) {
				t.Fatal("traditional AEAD lost independent same-listener users or added a server password")
			}
			for _, u := range n.Users {
				if !reflect.DeepEqual(ssAEADOutbound(n, u), M{"type": "shadowsocks", "method": method, "password": u.Password}) || !reflect.DeepEqual(ssAEADMihomo(n, u), M{"type": "ss", "cipher": method, "password": u.Password, "udp": true}) {
					t.Fatal("client password was combined with a service key or another user's password")
				}
			}
			after, _ := json.Marshal(n)
			if string(before) != string(after) {
				t.Fatal("rendering rotated or mutated credentials")
			}
		})
	}
	u := User{UUID: "old-uuid", Password: "old-password"}
	ssAEADCredential(&u)
	if u.UUID != "" || len(u.Password) != 48 || safeTLSCredential(u) != nil {
		t.Fatal("classic SS generation did not create an opaque independent password")
	}
}

func TestShadowsocksAEADRejectsWrongMethodsMixedSecretsAndUnsafePasswords(t *testing.T) {
	for _, method := range []string{"", SS2022Method, "none", "aes-192-gcm", "rc4-md5", "AES-256-GCM"} {
		if _, err := NewShadowsocksAEAD(method); err == nil {
			t.Fatal("unsupported method accepted", method)
		}
	}
	for _, change := range []func(*Node){
		func(n *Node) { n.Shadowsocks = nil },
		func(n *Node) { n.Shadowsocks.Method = SS2022Method },
		func(n *Node) { n.Shadowsocks.ServerKey = ssKey() },
		func(n *Node) { n.Reality = &Reality{} },
		func(n *Node) { n.Certificate = &Certificate{} },
		func(n *Node) { n.CertificateID = "4444444444444444" },
		func(n *Node) { n.AnyTLS = &AnyTLSOptions{} },
		func(n *Node) { n.TUIC = &TUICOptions{} },
		func(n *Node) { n.HY2 = &HY2Performance{} },
		func(n *Node) { n.Users[0].UUID = "mixed-uuid" },
		func(n *Node) { n.Users[0].Password = strings.Repeat("a", 15) },
		func(n *Node) { n.Users[0].Password = strings.Repeat("a", 513) },
		func(n *Node) { n.Users[0].Password = "password-with-\n-control" },
		func(n *Node) { n.Users[1].Password = n.Users[0].Password },
	} {
		n := ssAEADFixture(t, DefaultSSAEADMethod)
		change(&n)
		if validateSSAEAD(n) == nil {
			t.Fatal("mixed or unsafe traditional AEAD candidate accepted")
		}
	}
}

func TestShadowsocksAEADSIP002KeepsOpaquePasswordAndConnectPort(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		n := ssAEADFixture(t, method)
		port := 2443
		n.ConnectPort = &port
		u := n.Users[0]
		got, err := url.Parse(ssAEADURI(n, u))
		if err != nil || got.Scheme != "ss" || got.Hostname() != "2001:db8::1" || got.Port() != "2443" || got.Fragment != n.Name+" / "+u.Name {
			t.Fatal("SIP002 URI lost the IPv6 connection endpoint or label", err)
		}
		auth, err := base64.RawURLEncoding.Strict().DecodeString(got.User.Username())
		if err != nil || string(auth) != method+":"+u.Password || got.RawQuery != "" {
			t.Fatal("SIP002 did not preserve the exact method and opaque password", err)
		}
		if _, exists := got.User.Password(); exists {
			t.Fatal("traditional URI mixed SS2022 percent-encoded auth with Base64URL auth")
		}
	}
}
