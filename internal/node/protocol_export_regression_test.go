package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestVMessSubscriptionUsesEmbeddedNameAndSelectedEndpoint(t *testing.T) {
	n := tlsProtocolFixture(t, "vmess")
	n.Users = []User{NewUser("手机 # 一", "vmess"), NewUser("其他设备", "vmess")}
	n.Transport = &V2RayTransport{Type: "ws", Path: "/node+:@&=", Host: "front.example.test"}
	n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "nat", Host: "2001:db8::99", Port: 30443}}
	s := NewState()
	s.Nodes = []Node{n}
	p := DeviceProfile{ID: Token(8), Name: "手机", Bindings: []DeviceBinding{{NodeID: n.ID, UserID: n.Users[0].ID, EndpointID: "nat"}}}
	s.Devices = []DeviceProfile{p}
	var err error
	s, err = CanonicalCertificates(s)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(s)
	for _, format := range []string{"uri", "base64"} {
		r, err := ExportDeviceProfile(s, p, format, "", false)
		if err != nil {
			t.Fatal(format, err)
		}
		content := strings.TrimSpace(string(r.Content))
		if format == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(content)
			if err != nil {
				t.Fatal(err)
			}
			content = strings.TrimSpace(string(decoded))
		}
		if !strings.HasPrefix(content, "vmess://") || strings.Contains(content, "#") {
			t.Fatal("VMess subscription must contain a complete Base64 JSON URI")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(content, "vmess://"))
		if err != nil {
			t.Fatal(err)
		}
		var share map[string]any
		if err = json.Unmarshal(decoded, &share); err != nil {
			t.Fatal(err)
		}
		if share["ps"] != deviceExportName(n, n.Users[0], p.Bindings[0]) || share["id"] != n.Users[0].UUID || share["add"] != "2001:db8::99" || share["port"] != "30443" || share["path"] != "/node+:@&=" || share["host"] != "front.example.test" {
			t.Fatal("subscription lost its selected name, identity, NAT endpoint or transport")
		}
		if bytes.Contains(decoded, []byte(n.Users[1].UUID)) {
			t.Fatal("unselected credentials were exported")
		}
	}
	after, _ := json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("export mutated saved state")
	}
}

func TestLegacyExportsRejectInvalidProtocolParameters(t *testing.T) {
	n := fixture(t).Nodes[0]
	n.Reality.PublicKey = "invalid-public-key"
	ss := Node{Protocol: "ss2022", Name: "ss", Host: "example.com", Port: 443, Enabled: true, Shadowsocks: NewShadowsocks(), Users: []User{NewUser("one", "ss2022")}}
	ss.Users[0].Password = "invalid-key"
	hy := tlsProtocolFixture(t, "hysteria2")
	hy.Certificate = nil
	for _, broken := range []Node{n, ss, hy} {
		if _, err := Export(broken, broken.Users[0], "sing-box"); err == nil {
			t.Fatal("invalid protocol was serialized as a usable client", broken.Protocol)
		}
	}
	valid := fixture(t).Nodes[0]
	valid.ConnectPort = endpointPort(0)
	if _, err := Export(valid, valid.Users[0], "uri"); err == nil {
		t.Fatal("invalid external port was exported")
	}
}

func TestUUIDCaseDoesNotCreateAnotherIdentity(t *testing.T) {
	for _, protocol := range []string{"reality", "vless", "vmess"} {
		n := fixture(t).Nodes[0]
		if protocol != "reality" {
			n = tlsProtocolFixture(t, protocol)
			n.Users = []User{NewUser("first", protocol)}
		}
		n.Users[0].UUID = "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f"
		duplicate := n.Users[0]
		duplicate.ID, duplicate.Name, duplicate.UUID = Token(8), "another name", strings.ToUpper(duplicate.UUID)
		n.Users = append(n.Users, duplicate)
		s := NewState()
		s.Nodes = []Node{n}
		if err := s.Validate(); err == nil {
			t.Fatal("same UUID under different letter case was accepted", protocol)
		}
	}
}
