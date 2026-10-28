package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func protocolExpansionDeviceFixture(t *testing.T) (State, DeviceProfile) {
	t.Helper()
	cert, key := makeCert(t)
	s := NewState()
	s.Certificates = []CertificateResource{{ID: Token(8), Name: "shared four-protocol certificate", Certificate: Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
	p := DeviceProfile{ID: Token(8), Name: "手机 / # 中文", SubscriptionFormats: []string{"sing-box", "mihomo", "provider"}}
	for i, protocol := range []string{"anytls", "trojan", "ss-aead", "tuic", "ss2022"} {
		n := Node{ID: Token(8), Name: fmt.Sprintf("同名前缀 # 中文 / %d", i), Protocol: protocol, Enabled: true,
			Host: "entrance.example.test", Listen: "127.0.0.1", Port: 42000 + i, ConnectPort: endpointPort(30000 + i),
			AdditionalEndpoints: []ConnectionEndpoint{{ID: "v6", Host: "2001:0db8:0000::9", Port: 31000 + i}},
			Users:               []User{NewUser("手机 / # : Unicode", protocol), NewUser("其他设备", protocol)}}
		if ProtocolRequiresCertificate(protocol) {
			n.CertificateID = s.Certificates[0].ID
		}
		if protocol == "ss-aead" {
			n.Shadowsocks, _ = NewShadowsocksAEAD(DefaultSSAEADMethod)
		}
		if protocol == "ss2022" {
			n.Shadowsocks = NewShadowsocks()
		}
		p.Bindings = append(p.Bindings, DeviceBinding{NodeID: n.ID, UserID: n.Users[0].ID, EndpointID: "v6"})
		s.Nodes = append(s.Nodes, n)
	}
	var err error
	s, err = CanonicalCertificates(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Devices = []DeviceProfile{p}
	if err = s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestProtocolExpansionDeviceFullExportsExplicitSecretsIPv6AndNAT(t *testing.T) {
	s, p := protocolExpansionDeviceFixture(t)
	before := s.Clone()
	legacyURI := URI(s.Nodes[4], s.Nodes[4].Users[0])
	for _, format := range []string{"sing-box", "sing-box-outbounds", "mihomo", "provider"} {
		version := "1.14.3"
		if format == "mihomo" || format == "provider" {
			version = "1.19.30"
		}
		r, err := ExportDeviceProfile(s, p, format, version, false)
		if err != nil || len(r.NodeIDs) != len(s.Nodes) {
			t.Fatal("full new-protocol collection failed", format, err)
		}
		for _, n := range s.Nodes {
			if bytes.Contains(r.Content, []byte(n.Users[1].Password)) || n.Users[1].UUID != "" && bytes.Contains(r.Content, []byte(n.Users[1].UUID)) {
				t.Fatal("an unselected device credential escaped")
			}
		}
		if bytes.Contains(r.Content, []byte(s.Certificates[0].Certificate.KeyPEM)) {
			t.Fatal("shared server certificate private key escaped")
		}
		var entries []map[string]any
		if format == "mihomo" || format == "provider" {
			var doc struct{ Proxies []map[string]any }
			if err = yaml.Unmarshal(r.Content, &doc); err != nil {
				t.Fatal(err)
			}
			entries = doc.Proxies
		} else {
			var doc struct{ Outbounds []map[string]any }
			if err = json.Unmarshal(r.Content, &doc); err != nil {
				t.Fatal(err)
			}
			for _, out := range doc.Outbounds {
				if out["server"] != nil {
					entries = append(entries, out)
				} else if out["type"] != "selector" {
					t.Fatal("unexpected or direct fallback outbound")
				}
			}
		}
		if len(entries) != len(s.Nodes) {
			t.Fatal("a protocol disappeared from complete export")
		}
		seen := map[string]bool{}
		for _, out := range entries {
			name, portKey := "tag", "server_port"
			if format == "mihomo" || format == "provider" {
				name, portKey = "name", "port"
			}
			label := fmt.Sprint(out[name])
			if seen[label] || out["server"] != "2001:0db8:0000::9" || !strings.HasPrefix(fmt.Sprint(out[portKey]), "3100") {
				t.Fatal("stable names, original IPv6 spelling or external NAT port was lost")
			}
			seen[label] = true
		}
		reversed := s.Clone()
		for i := range reversed.Nodes {
			reversed.Nodes[i].Users[0], reversed.Nodes[i].Users[1] = reversed.Nodes[i].Users[1], reversed.Nodes[i].Users[0]
		}
		for i, j := 0, len(reversed.Nodes)-1; i < j; i, j = i+1, j-1 {
			reversed.Nodes[i], reversed.Nodes[j] = reversed.Nodes[j], reversed.Nodes[i]
		}
		q := p
		q.Bindings = append([]DeviceBinding(nil), p.Bindings...)
		for i, j := 0, len(q.Bindings)-1; i < j; i, j = i+1, j-1 {
			q.Bindings[i], q.Bindings[j] = q.Bindings[j], q.Bindings[i]
		}
		again, err := ExportDeviceProfile(reversed, q, format, version, false)
		if err != nil || !bytes.Equal(r.Content, again.Content) {
			t.Fatal("explicit ID selection was replaced by collection order", err)
		}
	}
	if !reflect.DeepEqual(s, before) || URI(s.Nodes[4], s.Nodes[4].Users[0]) != legacyURI {
		t.Fatal("read-only collection changed State or SS2022 byte semantics")
	}
	for _, format := range []string{"uri", "base64"} {
		if _, err := ExportDeviceProfile(s, p, format, "", true); err == nil {
			t.Fatal("TUIC silently disappeared or received an invented URI")
		}
	}
	// The remaining four protocols have verified basic URI formats. Credentials
	// and labels use the same selected IDs, including SS2022's composite key.
	p.Bindings = nil
	for _, b := range before.Devices[0].Bindings {
		if b.NodeID != s.Nodes[3].ID {
			p.Bindings = append(p.Bindings, b)
		}
	}
	r, err := ExportDeviceProfile(s, p, "uri", "", false)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(r.Content)), "\n")
	if len(lines) != 4 {
		t.Fatal("URI collection dropped a selected credential")
	}
	for _, line := range lines {
		u, err := url.Parse(line)
		if err != nil || u.Hostname() != "2001:0db8:0000::9" || !strings.HasPrefix(u.Port(), "3100") || !strings.Contains(u.Fragment, "中文") {
			t.Fatal("URI endpoint or Unicode label failed", err)
		}
		if u.Scheme == "ss" && u.User.Username() != SS2022Method {
			auth, err := base64.RawURLEncoding.DecodeString(u.User.Username())
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(string(auth), DefaultSSAEADMethod+":") && strings.Count(string(auth), ":") != 1 {
				t.Fatal("classic SS inherited SS2022 composite credentials")
			}
		}
	}
}

func TestProtocolExpansionCapabilityTransportTagsAndClientVersionGates(t *testing.T) {
	s, _ := protocolExpansionDeviceFixture(t)
	for _, n := range s.Nodes {
		cap, ok := ProtocolCapabilities(n.Protocol)
		if !ok || !reflect.DeepEqual(cap.BusinessNetworks, []string{"tcp", "udp"}) {
			t.Fatal("missing business network contract")
		}
		want := []string{"tcp"}
		if n.Protocol == "tuic" {
			want = []string{"udp"}
		} else if n.Protocol == "ss-aead" || n.Protocol == "ss2022" {
			want = []string{"tcp", "udp"}
		}
		if !reflect.DeepEqual(cap.ListenerNetworks, want) {
			t.Fatal("public sockets confused with relayed UDP")
		}
		if n.Protocol != "ss2022" && ValidateProtocolClient(n, "sing-box", "1.15.0", nil) == nil {
			t.Fatal("future client fields were guessed")
		}
		if n.Protocol == "tuic" {
			if ValidateProtocolClient(n, "sing-box", "1.14.3", []string{}) == nil || ValidateProtocolCapabilities(State{Nodes: []Node{n}}, []string{}) == nil {
				t.Fatal("version string substituted for actual QUIC build capability")
			}
		}
	}
	if err := ValidateProtocolCapabilities(s, []string{"with_quic"}); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolCapabilitySeparatesServerEgressFromClientOutbound(t *testing.T) {
	remote := map[string]bool{"reality": true, "ss2022": true, "hysteria2": true}
	for _, name := range Protocols() {
		capability, ok := ProtocolCapabilities(name)
		if !ok || !capability.Server || !capability.ClientOutbound || !capability.Outbound || capability.ServerEgress != remote[name] {
			t.Fatalf("incorrect inbound, client export or remote Egress capability for %s: %+v", name, capability)
		}
		data, err := json.Marshal(capability)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err = json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if fields["server_egress"] != remote[name] || fields["client_outbound"] != true || fields["outbound"] != true {
			t.Fatalf("ambiguous serialized capability for %s: %s", name, data)
		}
	}
}

func TestProtocolExpansionDerivedImpactKeepsClientOnlyEditsOffServer(t *testing.T) {
	s, _ := protocolExpansionDeviceFixture(t)
	for i := 0; i < 4; i++ {
		next := s.Clone()
		next.Nodes[i].Host = "changed-entrance.example.test"
		next.Nodes[i].ConnectPort = endpointPort(33000 + i)
		impact, err := compareImpact(s, next, "/isolated-owned-root")
		if err != nil || !impact.ClientExport || impact.ServerRuntime || impact.HostEffects || impact.NeedsRestart {
			t.Fatal("public endpoint unnecessarily changed the running server", err, impact)
		}
	}
	next := s.Clone()
	next.Nodes[0].AnyTLS = &AnyTLSOptions{IdleSessionTimeout: "6s"}
	impact, err := compareImpact(s, next, "/isolated-owned-root")
	if err != nil || !impact.ClientExport || impact.ServerRuntime || impact.NeedsRestart {
		t.Fatal("AnyTLS client pool option restarted the server", err, impact)
	}
	next = s.Clone()
	next.Nodes[3].TUIC = &TUICOptions{ClientCongestionControl: "bbr", ClientHeartbeat: "1500ms"}
	impact, err = compareImpact(s, next, "/isolated-owned-root")
	if err != nil || !impact.ClientExport || impact.ServerRuntime || impact.NeedsRestart {
		t.Fatal("TUIC client settings restarted the server", err, impact)
	}
	next.Nodes[3].TUIC.ServerHeartbeat = "2s"
	impact, err = compareImpact(s, next, "/isolated-owned-root")
	if err != nil || !impact.ServerRuntime || !impact.NeedsRestart {
		t.Fatal("TUIC server change was hidden as client metadata", err, impact)
	}
}
