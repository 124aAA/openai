package node

import (
	"bytes"
	"encoding/json"
	"net/url"
	"testing"
)

func ssFixture() Node {
	return Node{ID: Token(8), Name: "SS # 中文 / +", Protocol: "ss2022", Host: "2001:db8::9", Listen: "::", Port: 24567, Enabled: true, Users: []User{NewUser("phone", "ss2022"), NewUser("laptop", "ss2022")}, Shadowsocks: NewShadowsocks()}
}
func TestSS2022MultiuserURIAndClientFormats(t *testing.T) {
	n := ssFixture()
	s := NewState()
	s.Nodes = []Node{n}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, u := range n.Users {
		parsed, e := url.Parse(URI(n, u))
		if e != nil {
			t.Fatal(e)
		}
		password, ok := parsed.User.Password()
		if parsed.Scheme != "ss" || parsed.User.Username() != SS2022Method || !ok || password != SSPassword(n, u) || parsed.Hostname() != n.Host || parsed.Fragment != n.Name+" / "+u.Name {
			t.Fatal("SIP002 AEAD-2022 roundtrip failed")
		}
		for _, format := range []string{"uri", "qr", "mihomo", "provider", "sing-box"} {
			b, e := Export(n, u, format)
			if e != nil || len(b) == 0 {
				t.Fatal(format, e)
			}
		}
		out := Outbound(n, u)
		if out["password"] != SSPassword(n, u) || out["tls"] != nil {
			t.Fatal("SS client auth incorrect")
		}
	}
	server, e := Server(s, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	var doc M
	if e = json.Unmarshal(server, &doc); e != nil {
		t.Fatal(e)
	}
	in := doc["inbounds"].([]any)[0].(map[string]any)
	if in["password"] != n.Shadowsocks.ServerKey || len(in["users"].([]any)) != 2 || in["tls"] != nil {
		t.Fatal("SS server auth incorrect")
	}
	if bytes.Contains([]byte(Redact(string(server), s)), []byte(n.Shadowsocks.ServerKey)) {
		t.Fatal("SS server key leaked to log")
	}
}
func TestSS2022ReservesBothTCPAndUDP(t *testing.T) {
	s := fixture(t)
	ss := ssFixture()
	ss.Port = s.Nodes[0].Port
	s.Nodes = append(s.Nodes, ss)
	if s.Validate() == nil {
		t.Fatal("SS/REALITY TCP conflict ignored")
	}
	cert, key := makeCert(t)
	s = NewState()
	s.Nodes = []Node{ss, {ID: Token(8), Name: "HY2", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "0.0.0.0", Port: ss.Port, Enabled: true, Users: []User{NewUser("test", "hysteria2")}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
	if s.Validate() == nil {
		t.Fatal("SS/HY2 UDP conflict ignored")
	}
	s.Nodes[1].Enabled = false
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	s.Nodes[0].Users[0].Password = "incorrect"
	if s.Validate() == nil {
		t.Fatal("weak key accepted")
	}
}
