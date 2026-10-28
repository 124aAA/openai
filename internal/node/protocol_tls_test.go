package node

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func tlsProtocolFixture(t *testing.T, protocol string) Node {
	t.Helper()
	cert, key := makeCert(t)
	return Node{ID: "1111111111111111", Name: "TLS # 节点", Protocol: protocol, Host: "2001:db8::1", Listen: "127.0.0.1", Port: 1443, Enabled: true,
		Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key},
		Users:       []User{{ID: "2222222222222222", Name: "用户 / 一", Password: "opaque:@/?#%密码-123456"}, {ID: "3333333333333333", Name: "用户二", Password: "independent-password-234567"}}}
}

func TestPasswordTLSCredentialRulesAndGeneration(t *testing.T) {
	for _, credential := range []func(*User){anytlsCredential, trojanCredential} {
		u := User{UUID: "old-uuid", Password: "old-password"}
		credential(&u)
		if len(u.Password) != 48 || u.UUID != "" || safeTLSCredential(u) != nil {
			t.Fatal("generated credentials are not independent password credentials")
		}
	}
	for _, password := range []string{strings.Repeat("a", 16), strings.Repeat("a", 512), "任意UTF8-:@/?#%密码"} {
		if err := safeTLSCredential(User{Password: password}); err != nil {
			t.Fatal("safe opaque password rejected", err)
		}
	}
	for _, u := range []User{{Password: strings.Repeat("a", 15)}, {Password: strings.Repeat("a", 513)}, {Password: "password-with-\x00-control"}, {Password: "password-with-\n-control"}, {Password: "password-with-\t-control"}, {Password: "password-with-\u0085-control"}, {Password: "invalid-utf8-" + string([]byte{0xff, 0xfe})}, {Password: strings.Repeat("a", 16), UUID: "mixed-uuid"}} {
		if err := safeTLSCredential(u); err == nil {
			t.Fatal("unsafe credential accepted")
		} else if strings.Contains(err.Error(), u.Password) {
			t.Fatal("credential appeared in validation error")
		}
	}
}

func TestPasswordTLSValidationCertificateAndRestore(t *testing.T) {
	for _, protocol := range []string{"anytls", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			n := tlsProtocolFixture(t, protocol)
			if err := validateTLSNode(n, true); err != nil {
				t.Fatal(err)
			}
			for _, change := range []func(*Node){
				func(n *Node) { n.Certificate = nil },
				func(n *Node) { n.Certificate.ServerName = "wrong.example.test" },
				func(n *Node) { _, n.Certificate.KeyPEM = makeCert(t) },
				func(n *Node) { n.Reality = &Reality{} },
				func(n *Node) { n.Shadowsocks = &Shadowsocks{} },
				func(n *Node) { n.HY2 = &HY2Performance{} },
				func(n *Node) { n.TUIC = &TUICOptions{} },
				func(n *Node) { n.Users[0].UUID = "mixed" },
			} {
				bad := n
				bad.Certificate = cloneCertificate(*n.Certificate)
				bad.Users = append([]User(nil), n.Users...)
				change(&bad)
				if validateTLSNode(bad, false) == nil {
					t.Fatal("restore skipped a non-file validation rule")
				}
			}
			n.Certificate = &Certificate{Mode: "file", ServerName: "localhost", CertificatePath: filepath.Join(t.TempDir(), "missing-cert.pem"), KeyPath: filepath.Join(t.TempDir(), "missing-key.pem")}
			if err := validateTLSNode(n, false); err != nil {
				t.Fatal("restore did not defer destination certificate access", err)
			}
			if validateTLSNode(n, true) == nil {
				t.Fatal("runnable validation accepted absent certificate files")
			}
			n.Certificate = &Certificate{Mode: "acme", ServerName: "tls.example.test", Email: "owner@example.test"}
			if err := validateTLSNode(n, true); err != nil {
				t.Fatal("managed ACME certificate rejected", err)
			}
			cert, key := certificateTestPair(t, time.Now(), false, true)
			n.Certificate = &Certificate{Mode: "pem", ServerName: "hy2.example.test", CertPEM: cert, KeyPEM: key}
			if err := validateTLSNode(n, true); err != nil {
				t.Fatal("native TCP TLS inherited a QUIC/Chrome certificate restriction", err)
			}
		})
	}
	bad := tlsProtocolFixture(t, "trojan")
	bad.AnyTLS = &AnyTLSOptions{}
	if validateTrojan(bad) == nil {
		t.Fatal("Trojan accepted AnyTLS client options")
	}
	bad.Protocol = "anytls"
	bad.AnyTLS.IdleSessionTimeout = "1s"
	if validateTLSNode(bad, false) == nil {
		t.Fatal("restore skipped AnyTLS option validation")
	}
}

func TestPasswordTLSInboundKeepsStableIdentitiesAndCertificateModes(t *testing.T) {
	for _, protocol := range []string{"anytls", "trojan"} {
		n := tlsProtocolFixture(t, protocol)
		var inbound func(Node, string) M = anytlsInbound
		if protocol == "trojan" {
			inbound = trojanInbound
		}
		got := inbound(n, "/owned/root")
		wantUsers := []any{M{"name": n.Users[0].ID, "password": n.Users[0].Password}, M{"name": n.Users[1].ID, "password": n.Users[1].Password}}
		if got["type"] != protocol || !reflect.DeepEqual(got["users"], wantUsers) {
			t.Fatal("server lost stable user attribution or independent credentials")
		}
		pemTLS := got["tls"].(M)
		if !reflect.DeepEqual(pemTLS["certificate"], []string{n.Certificate.CertPEM}) || !reflect.DeepEqual(pemTLS["key"], []string{n.Certificate.KeyPEM}) || pemTLS["enabled"] != true {
			t.Fatal("PEM material did not reach the TLS listener")
		}
		n.Certificate = &Certificate{Mode: "file", ServerName: "localhost", CertificatePath: "/owned/cert.pem", KeyPath: "/owned/key.pem"}
		fileTLS := inbound(n, "/owned/root")["tls"].(M)
		if fileTLS["certificate_path"] != "/owned/cert.pem" || fileTLS["key_path"] != "/owned/key.pem" || fileTLS["certificate"] != nil || fileTLS["key"] != nil {
			t.Fatal("external certificate reference was replaced with inline material")
		}
		n.CertificateID = "4444444444444444"
		n.Certificate = &Certificate{Mode: "acme", ServerName: "tls.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01", KeyType: "p256"}}
		provider := inbound(n, "/owned/root")["tls"].(M)["certificate_provider"].(M)
		if provider["type"] != "acme" || provider["data_directory"] != filepath.Join("/owned/root", "acme", "resources", n.CertificateID) || provider["key_type"] != "p256" {
			t.Fatal("managed certificate provider lost its resource identity")
		}
		clientTLS := tlsOutbound(n)
		if !reflect.DeepEqual(clientTLS, M{"enabled": true, "server_name": "tls.example.test"}) {
			t.Fatal("client received server private certificate material or unsafe TLS options")
		}
	}
}
