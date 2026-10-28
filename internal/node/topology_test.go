package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func topologySOCKS(id, name string) Egress {
	return Egress{ID: id, Name: name, Protocol: "socks5", Server: "192.0.2.10", Port: 1080, UDP: true, Socks: &RemoteSOCKS{Username: "remote-account", Password: "remote-password"}}
}

func topologyFixture(t *testing.T) State {
	t.Helper()
	s := fixture(t)
	s.Egresses = []Egress{topologySOCKS("3333333333333333", "primary"), topologySOCKS("4444444444444444", "backup")}
	s.Nodes[0].EgressID = s.Egresses[0].ID
	return s
}

func topologyWG(t *testing.T) Egress {
	t.Helper()
	private, public := strings.Repeat("\x01", 32), strings.Repeat("\x02", 32)
	return Egress{ID: "7777777777777777", Name: "landing", Protocol: "wireguard", UDP: true, WireGuard: &WireGuardEndpoint{PrivateKey: base64.StdEncoding.EncodeToString([]byte(private)), Address: []string{"10.77.0.2/32"}, ListenPort: 51820, ReceiveEgressID: "direct", Peers: []WireGuardPeer{{PublicKey: base64.StdEncoding.EncodeToString([]byte(public)), AllowedIPs: []string{"10.77.0.1/32"}}}}}
}

func TestTopologyValidationRejectsInvalidGraphBeforeRendering(t *testing.T) {
	base := topologyFixture(t)
	for _, tc := range []struct {
		name string
		edit func(*State)
	}{
		{"deleted referenced egress", func(s *State) { s.Egresses = s.Egresses[1:] }},
		{"unknown node reference", func(s *State) { s.Nodes[0].EgressID = "9999999999999999" }},
		{"duplicate egress ID", func(s *State) { s.Egresses[1].ID = s.Egresses[0].ID }},
		{"node collision", func(s *State) { s.Egresses[1].ID = s.Nodes[0].ID }},
		{"arbitrary protocol settings", func(s *State) { s.Egresses[0].HY2 = &RemoteHY2{Password: "unrelated", ServerName: "example.com"} }},
		{"detour self loop", func(s *State) { s.Egresses[0].Detour = s.Egresses[0].ID }},
		{"detour cycle", func(s *State) { s.Egresses[0].Detour = s.Egresses[1].ID; s.Egresses[1].Detour = s.Egresses[0].ID }},
		{"detour direct fallback", func(s *State) { s.Egresses[0].Detour = "direct" }},
		{"TCP-only carrying node UDP", func(s *State) { s.Egresses[0].UDP = false }},
		{"SOCKS UDP TCP-only detour", func(s *State) { s.Egresses[0].Detour = s.Egresses[1].ID; s.Egresses[1].UDP = false }},
		{"remote points at local inbound", func(s *State) { s.Egresses[0].Server = "::1"; s.Egresses[0].Port = s.Nodes[0].Port }},
		{"remote points at declared NAT endpoint", func(s *State) {
			s.Egresses[0].Server = s.Nodes[0].Host
			s.Egresses[0].Port = EffectiveConnectPort(s.Nodes[0])
		}},
		{"forward same TCP socket", func(s *State) {
			s.Forwards = []PortForward{{ID: "5555555555555555", Name: "collision", Listen: s.Nodes[0].Listen, Port: s.Nodes[0].Port, Network: "tcp", TargetHost: "192.0.2.20", TargetPort: 8443, Enabled: true}}
		}},
		{"invalid forward target", func(s *State) {
			s.Forwards = []PortForward{{ID: "5555555555555555", Name: "invalid", Listen: "127.0.0.1", Port: 12345, Network: "tcp", TargetHost: "https://bad.example", TargetPort: 443, Enabled: true}}
		}},
		{"DNS bootstrap cycle", func(s *State) {
			p := 53
			s.DNS = &DNSSettings{Type: "udp", Server: "127.0.0.1", Port: &p}
			s.Forwards = []PortForward{{ID: "5555555555555555", Name: "DNS-loop", Listen: "0.0.0.0", Port: 53, Network: "udp", TargetHost: "192.0.2.20", TargetPort: 5353, Enabled: true}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base.Clone()
			tc.edit(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("invalid topology accepted")
			}
			if _, err := Server(s, t.TempDir()); err == nil {
				t.Fatal("invalid topology rendered")
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatal("valid fixture rejected", err)
	}
}

func TestTopologyPolicyRequiresSeparateUDPHealthAndNoFallback(t *testing.T) {
	s := topologyFixture(t)
	p := EgressPolicy{ID: "5555555555555555", Name: "main-backup", Mode: "failover", Primary: s.Egresses[0].ID, Backup: s.Egresses[1].ID, Health: &EgressHealth{URL: "https://health.example/status", FailureThreshold: 2, RecoveryThreshold: 3, CooldownSeconds: 60, TimeoutSeconds: 5}}
	s.EgressPolicies, s.Nodes[0].EgressID = []EgressPolicy{p}, p.ID
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "UDP健康目标") {
		t.Fatal("HTTPS-only health concealed missing UDP validation", err)
	}
	s.EgressPolicies[0].Health.UDPAddress = "health.example:7000"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{"", "primary", "backup"} {
		s.EgressPolicies[0].Selected = selected
		out, _, tag, err := BuildEgressGraph(s, p.ID)
		want := EgressTag(p.Primary)
		if selected == "backup" {
			want = EgressTag(p.Backup)
		}
		if err != nil || len(out) != 1 || tag != want {
			t.Fatalf("selection changed/fell back: %s %#v %v", tag, out, err)
		}
	}
	for _, tc := range []struct {
		name string
		edit func(*State)
	}{
		{"HTTP health", func(st *State) { st.EgressPolicies[0].Health.URL = "http://health.example" }},
		{"bad backup", func(st *State) { st.EgressPolicies[0].Backup = "direct" }},
		{"UDP backup disabled", func(st *State) { st.Egresses[1].UDP = false }},
		{"policy as detour", func(st *State) { st.Egresses[0].Detour = p.ID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := s.Clone()
			tc.edit(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	// A TCP-only forward may use a TCP-only policy and HTTPS health alone.
	s.Nodes = nil
	s.Egresses[0].UDP, s.Egresses[1].UDP = false, false
	s.EgressPolicies[0].Health.UDPAddress = ""
	s.Forwards = []PortForward{{ID: "6666666666666666", Name: "tcp-only", Listen: "127.0.0.1", Port: 12345, Network: "tcp", TargetHost: "192.0.2.30", TargetPort: 443, EgressID: p.ID, Enabled: true}}
	if err := s.Validate(); err != nil {
		t.Fatal("TCP-only path incorrectly requires UDP", err)
	}
}

func TestTopologyServerPrunesUnusedEgressesAndNeverLeaksRemoteExports(t *testing.T) {
	s := topologyFixture(t)
	s.Egresses[0].Detour = s.Egresses[1].ID
	s.Egresses = append(s.Egresses, topologySOCKS("5555555555555555", "unused"))
	s.Egresses[2].Socks.Password = "UNUSED-DO-NOT-RENDER"
	data, err := Server(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("UNUSED-DO-NOT-RENDER")) || bytes.Contains(data, []byte(EgressTag(s.Egresses[2].ID))) {
		t.Fatal("unused outbound rendered")
	}
	var config struct {
		Outbounds []M `json:"outbounds"`
		Route     struct {
			Final string `json:"final"`
			Rules []struct {
				Inbound  []string `json:"inbound"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Outbounds) != 3 || len(config.Route.Rules) != 1 || config.Route.Rules[0].Outbound != EgressTag(s.Egresses[0].ID) || len(config.Route.Rules[0].Inbound) != 1 || config.Route.Rules[0].Inbound[0] != s.Nodes[0].ID {
		t.Fatalf("entry has no explicit route: %s", data)
	}
	for _, format := range []string{"uri", "sing-box", "mihomo", "provider", "qr", "base64"} {
		out, err := Export(s.Nodes[0], s.Nodes[0].Users[0], format)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range s.Egresses {
			if bytes.Contains(out, []byte(e.Socks.Password)) || bytes.Contains(out, []byte(e.Socks.Username)) {
				t.Fatal("remote credential leaked in entry export", format)
			}
		}
	}
	redacted := Redact(string(data)+" "+s.Egresses[2].Socks.Password, s)
	if strings.Contains(redacted, "remote-password") || strings.Contains(redacted, "remote-account") || strings.Contains(redacted, "UNUSED-DO-NOT-RENDER") {
		t.Fatal("remote secret not redacted")
	}
}

func TestTopologyWireGuardLandingStartsWithoutProxyInboundsAndIsStrict(t *testing.T) {
	s := NewState()
	s.Egresses = []Egress{topologyWG(t)}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := Server(s, t.TempDir())
	if err != nil || !HasEnabled(s) {
		t.Fatal("passive landing was not enabled", err)
	}
	var config struct {
		Inbounds  []M `json:"inbounds"`
		Endpoints []M `json:"endpoints"`
		Route     struct {
			Rules []M `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 0 || len(config.Endpoints) != 1 || len(config.Route.Rules) != 1 || config.Endpoints[0]["system"] != false {
		t.Fatalf("landing config wrong: %s", data)
	}
	if config.Route.Rules[0]["action"] != "route" || config.Route.Rules[0]["outbound"] != "direct" {
		t.Fatal("explicit landing receive policy was blocked or lost")
	}
	bindings := StateBindings(s)
	if len(bindings) != 2 || bindings[0].Network != "udp4" || bindings[1].Network != "udp6" {
		t.Fatalf("wireguard-go sockets wrong: %+v", bindings)
	}
	s.Firewall = "ufw"
	if rules := RequiredRules(s); len(rules) != 1 || rules[0].Network != "udp" || rules[0].Port != 51820 {
		t.Fatalf("WG UDP rule dedup wrong: %+v", rules)
	}
	for _, tc := range []struct {
		name string
		edit func(*State)
	}{
		{"bad key", func(s *State) { s.Egresses[0].WireGuard.PrivateKey = "wrong" }},
		{"overlapping allowed", func(s *State) {
			s.Egresses[0].WireGuard.Peers[0].AllowedIPs = append(s.Egresses[0].WireGuard.Peers[0].AllowedIPs, "10.77.0.0/24")
		}},
		{"small v6 MTU", func(s *State) {
			s.Egresses[0].WireGuard.Address = append(s.Egresses[0].WireGuard.Address, "fd77::2/128")
			s.Egresses[0].WireGuard.MTU = 1200
		}},
		{"receive itself", func(s *State) { s.Egresses[0].WireGuard.ReceiveEgressID = s.Egresses[0].ID }},
		{"unowned receive", func(s *State) { s.Egresses[0].WireGuard.ReceiveEgressID = "9999999999999999" }},
		{"passive without listener", func(s *State) { s.Egresses[0].WireGuard.ListenPort = 0; s.Egresses[0].WireGuard.ReceiveEgressID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := s.Clone()
			tc.edit(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid WG accepted")
			}
		})
	}
	if err := ValidateEgressCapabilities(s, []string{"with_wireguard"}); err == nil {
		t.Fatal("userland gvisor requirement missing")
	}
	if err := ValidateEgressCapabilities(s, []string{"with_wireguard", "with_gvisor"}); err != nil {
		t.Fatal(err)
	}
}

func TestTopologyActiveWireGuardRejectsUnrequestedPeerFlows(t *testing.T) {
	base := topologyFixture(t)
	active := topologyWG(t)
	active.Name = "active"
	active.WireGuard.ListenPort, active.WireGuard.ReceiveEgressID = 0, ""
	active.WireGuard.Peers[0].Address, active.WireGuard.Peers[0].Port = "192.0.2.40", 51820
	unused := topologyWG(t)
	unused.ID, unused.Name = "8888888888888888", "unused-active"
	unused.WireGuard.ListenPort, unused.WireGuard.ReceiveEgressID = 0, ""
	unused.WireGuard.Peers[0].Address, unused.WireGuard.Peers[0].Port = "192.0.2.50", 51820
	base.Egresses = append(base.Egresses, active, unused)
	for _, use := range []string{"node", "forward", "detour", "landing-receive", "unused"} {
		t.Run(use, func(t *testing.T) {
			st := base.Clone()
			st.Nodes[0].EgressID = "direct"
			switch use {
			case "node":
				st.Nodes[0].EgressID = active.ID
			case "forward":
				st.Forwards = []PortForward{{ID: "9999999999999999", Name: "through-active", Listen: "127.0.0.1", Port: 12345, Network: "tcp+udp", TargetHost: "192.0.2.100", TargetPort: 443, EgressID: active.ID, Enabled: true}}
			case "detour":
				st.Nodes[0].EgressID = st.Egresses[0].ID
				st.Egresses[0].Detour = active.ID
			case "landing-receive":
				landing := topologyWG(t)
				landing.ID, landing.Name = "9999999999999999", "receive-via-active"
				landing.WireGuard.ReceiveEgressID = active.ID
				st.Egresses = append(st.Egresses, landing)
			}
			raw, err := Server(st, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Endpoints []M `json:"endpoints"`
				Route     struct {
					Rules []struct {
						Inbound  []string `json:"inbound"`
						Action   string   `json:"action"`
						Outbound string   `json:"outbound"`
					} `json:"rules"`
				} `json:"route"`
			}
			if err = json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			activeRules := 0
			for _, rule := range config.Route.Rules {
				for _, tag := range rule.Inbound {
					if tag == EgressTag(unused.ID) {
						t.Fatal("unused active endpoint changed runtime rules")
					}
					if tag == EgressTag(active.ID) {
						activeRules++
						if rule.Action != "reject" || rule.Outbound != "" {
							t.Fatal("active peer-initiated flow could reach a routed/default outbound")
						}
					}
				}
			}
			want := 1
			if use == "unused" {
				want = 0
			}
			if activeRules != want {
				t.Fatalf("active inbound guards=%d, want %d", activeRules, want)
			}
			for _, ep := range config.Endpoints {
				if ep["tag"] == EgressTag(unused.ID) || (use == "unused" && ep["tag"] == EgressTag(active.ID)) {
					t.Fatal("unused active endpoint was rendered")
				}
			}
		})
	}
}

func TestTopologyDNSResolutionRejectsAliasesAndPreservesUnusedDefinitions(t *testing.T) {
	s := topologyFixture(t)
	local := map[netip.Addr]bool{netip.MustParseAddr("10.1.2.3"): true}
	lookup := func(host string) ([]netip.Addr, error) {
		if host == "unused.invalid" {
			return nil, errors.New("must not query unused")
		}
		if host == "self.example" {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		}
		a, e := netip.ParseAddr(host)
		return []netip.Addr{a}, e
	}
	s.Egresses[1].Server = "unused.invalid"
	if err := validateTopologyResolved(s, local, lookup); err != nil {
		t.Fatal("unused remote required DNS", err)
	}
	s.Egresses[0].Server, s.Egresses[0].Port = "self.example", s.Nodes[0].Port
	if err := validateTopologyResolved(s, local, lookup); err == nil {
		t.Fatal("DNS alias to wildcard local entry accepted")
	}
	s = NewState()
	s.Forwards = []PortForward{{ID: "5555555555555555", Name: "first", Listen: "0.0.0.0", Port: 12345, Network: "udp", TargetHost: "self.example", TargetPort: 12346, Enabled: true}, {ID: "6666666666666666", Name: "second", Listen: "0.0.0.0", Port: 12346, Network: "udp", TargetHost: "192.0.2.30", TargetPort: 5000, Enabled: true}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateTopologyResolved(s, local, lookup); err != nil {
		t.Fatal("acyclic DNS forward chain rejected", err)
	}
	s.Forwards[1].TargetHost, s.Forwards[1].TargetPort = "self.example", 12345
	if err := validateTopologyResolved(s, local, lookup); err == nil {
		t.Fatal("DNS forward chain cycle accepted")
	}
	s.Forwards[1].TargetHost = "empty.example"
	if err := validateTopologyResolved(s, local, func(string) ([]netip.Addr, error) { return nil, nil }); err == nil {
		t.Fatal("empty DNS result accepted")
	}
}

func TestTopologySchemaMigrationPreservesOriginalAndRejectsHiddenExtensions(t *testing.T) {
	for _, schema := range []string{"1", "2", "3"} {
		var filename string
		switch schema {
		case "1":
			filename = "state-v1.json"
		case "2":
			filename = "state-v2-hy2-performance.json"
		case "3":
			filename = "state-v3-endpoints.json"
		}
		raw, err := os.ReadFile(filepath.Join("testdata", filename))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "state.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := ReadState(path)
		if err != nil || got.Schema != Schema {
			t.Fatal("migration failed", schema, err)
		}
		if err = got.Validate(); err != nil {
			t.Fatal(schema, err)
		}
		var old State
		if err = json.Unmarshal(raw, &old); err != nil {
			t.Fatal(err)
		}
		if got.Nodes[0].ID != old.Nodes[0].ID || !equalJSON(got.Nodes[0].Users, old.Nodes[0].Users) || got.Nodes[0].EgressID != "" || URI(got.Nodes[0], got.Nodes[0].Users[0]) != URI(old.Nodes[0], old.Nodes[0].Users[0]) {
			t.Fatal("migration changed identity/share or default direct", schema)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(raw, after) {
			t.Fatal("read migrated on disk", schema)
		}
		for _, key := range []string{"egresses", "Egress_Policies", "forwards"} {
			var obj map[string]json.RawMessage
			_ = json.Unmarshal(raw, &obj)
			obj[key] = json.RawMessage("null")
			bad, _ := json.Marshal(obj)
			if _, err = DecodeState(bad); err == nil {
				t.Fatal("legacy hidden extension accepted", schema, key)
			}
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(raw, &obj)
		var nodes []map[string]json.RawMessage
		_ = json.Unmarshal(obj["nodes"], &nodes)
		nodes[0]["EGRESS_ID"] = json.RawMessage("null")
		obj["nodes"], _ = json.Marshal(nodes)
		bad, _ := json.Marshal(obj)
		if _, err = DecodeState(bad); err == nil {
			t.Fatal("legacy hidden node reference accepted", schema)
		}
	}
	for _, bad := range []string{`{"schema":4,"Schema":3}`, `{"schema":4,"nodes":[],"Nodes":[]}`, `{"schema":` + strconv.Itoa(Schema+1) + `}`} {
		if _, err := DecodeState([]byte(bad)); err == nil {
			t.Fatal("ambiguous/future schema accepted")
		}
	}
}

func TestTopologyStateUnicodeFoldDuplicatesAreRejectedWithoutNormalization(t *testing.T) {
	for _, file := range []string{"state-v4-duplicate-schema-unicode.json", "state-v4-duplicate-auth-unicode.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		// Demonstrate the decoder equivalence which the duplicate check must
		// match, rather than claiming all Unicode spelling is normalization.
		if _, err = DecodeState(raw); err == nil || !strings.Contains(err.Error(), "重复字段") {
			t.Fatal("Unicode-fold duplicate was accepted or misclassified", file, err)
		}
	}
	for _, pair := range [][2]string{{"schema", "ſchema"}, {"password", "paſſword"}, {"private_key", "private_Key"}, {"DNS", "dns"}} {
		if !strings.EqualFold(pair[0], pair[1]) || stateFieldKey(pair[0]) != stateFieldKey(pair[1]) {
			t.Fatal("canonical key differs from Unicode SimpleFold", pair)
		}
	}
	if stateFieldKey("schema") == stateFieldKey("ｓchema") {
		t.Fatal("compatibility normalization broadened JSON field matching")
	}
}

func TestTopologyImpactFollowsOnlyReferencedDependencies(t *testing.T) {
	s := topologyFixture(t)
	second := s.Nodes[0]
	second.ID, second.Name, second.Port, second.EgressID = Token(8), "unrelated", 8443, ""
	s.Nodes = append(s.Nodes, second)
	s.Egresses = append(s.Egresses, topologySOCKS("5555555555555555", "unused"))
	for _, tc := range []struct {
		name    string
		edit    func(*State)
		runtime bool
		nodes   int
	}{
		{"unused credentials", func(st *State) { st.Egresses[2].Socks.Password = "changed-unused" }, false, 0},
		{"used credentials", func(st *State) { st.Egresses[0].Socks.Password = "changed-used" }, true, 1},
		{"used display name", func(st *State) { st.Egresses[0].Name = "renamed" }, false, 0},
		{"used dependency", func(st *State) { st.Egresses[0].Detour = st.Egresses[1].ID }, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := s.Clone()
			tc.edit(&next)
			impact, err := compareImpact(s, next, t.TempDir())
			if err != nil || impact.ServerRuntime != tc.runtime || impact.NeedsRestart != tc.runtime || impact.ClientExport || len(impact.Nodes) != tc.nodes {
				t.Fatalf("wrong derived impact: %+v %v", impact, err)
			}
			if tc.nodes == 1 && impact.Nodes[0].ID != s.Nodes[0].ID {
				t.Fatal("unrelated node marked affected")
			}
			if tc.name == "used display name" && !impact.Display {
				t.Fatal("display change not reported")
			}
		})
	}
}

func TestTopologyForwardPreflightClosesOwnedListenersAndChecksTransports(t *testing.T) {
	s := NewState()
	port := bindingTestPort(t)
	s.Forwards = []PortForward{{ID: "5555555555555555", Name: "both", Listen: "127.0.0.1", Port: port, Network: "tcp+udp", TargetHost: "192.0.2.20", TargetPort: 443, Enabled: true}}
	if _, err := ProbeLocalBindings(context.Background(), StateBindings(s), BindingProbeOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "udp"} {
		l, _, err := openLocalBinding(context.Background(), LocalBinding{Network: network, Address: "127.0.0.1", Port: port}, net.ListenConfig{})
		if err != nil {
			t.Fatal("preflight leaked listener", err)
		}
		defer l.Close()
	}
	if _, err := ProbeLocalBindings(context.Background(), StateBindings(s), BindingProbeOptions{}); err == nil {
		t.Fatal("foreign listener accepted")
	}
}

func TestTopologyWireGuardReadinessRequiresEveryAvailableOwnedFamily(t *testing.T) {
	s := NewState()
	s.Egresses = []Egress{topologyWG(t)}
	v4 := Socket{Network: "udp", Address: "0.0.0.0", Port: 51820, Owned: true, Inode: "101", State: "07"}
	v6 := Socket{Network: "udp", Address: "::", Port: 51820, Owned: true, Inode: "102", State: "07"}
	if !SocketsReady(s, []Socket{v4, v6}) {
		t.Fatal("actual separate WG sockets rejected")
	}
	if SocketsReady(s, []Socket{v4}) || SocketsReady(s, []Socket{v6}) {
		t.Fatal("missing WG family reported ready without evidence")
	}
	v6.Owned = false
	if SocketsReady(s, []Socket{v4, v6}) {
		t.Fatal("foreign IPv6 socket masked missing owned listener")
	}
	if !socketsReadyWithUnavailableFamilies(s, []Socket{v4}, map[string]bool{"udp6": true}) {
		t.Fatal("explicitly unsupported IPv6 required")
	}
	if socketsReadyWithUnavailableFamilies(s, nil, map[string]bool{"udp4": true, "udp6": true}) {
		t.Fatal("no WG socket reported ready")
	}
	for _, tc := range []struct {
		name        string
		fault       error
		wantSuccess bool
	}{
		{"IPv6 unsupported", syscall.EAFNOSUPPORT, true},
		{"IPv6 permission denied", syscall.EPERM, false},
		{"IPv6 address unavailable", syscall.EADDRNOTAVAIL, false},
		{"IPv6 port conflict", syscall.EADDRINUSE, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
				if network == "udp6" {
					return tc.fault
				}
				return nil
			}}
			missing, err := wireGuardUnavailableFamilies(context.Background(), s, lc)
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("wrong family evidence: %+v %v", missing, err)
			}
			if tc.wantSuccess && !missing["udp6"] {
				t.Fatal("unsupported family evidence missing")
			}
		})
	}
}

func TestNodeRouteDigestTracksOnlyActualSelectedClosure(t *testing.T) {
	s := topologyFixture(t)
	want, err := NodeRouteDigest(s, s.Nodes[0].ID)
	if err != nil || len(want) != 64 {
		t.Fatal(want, err)
	}
	for _, tc := range []struct {
		name    string
		edit    func(*State)
		changed bool
	}{
		{"remote display", func(st *State) { st.Egresses[0].Name = "renamed" }, false},
		{"unused credential", func(st *State) { st.Egresses[1].Socks.Password = "unused-change" }, false},
		{"selected credential", func(st *State) { st.Egresses[0].Socks.Password = "used-change" }, true},
		{"selected chain", func(st *State) { st.Egresses[0].Detour = st.Egresses[1].ID }, true},
		{"core", func(st *State) { st.CoreVersion = "1.14.3" }, true},
		{"resolver", func(st *State) { st.DNS = &DNSSettings{Type: "udp", Server: "192.0.2.53"} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := s.Clone()
			tc.edit(&next)
			got, err := NodeRouteDigest(next, s.Nodes[0].ID)
			if err != nil || (got != want) != tc.changed {
				t.Fatal("wrong route binding", got, err)
			}
		})
	}
	s.Nodes[0].EgressID = ""
	if digest, err := NodeRouteDigest(s, s.Nodes[0].ID); err != nil || digest != "" {
		t.Fatal("legacy direct binding changed", digest, err)
	}
	if _, err := NodeRouteDigest(s, s.Nodes[0].Name); err == nil {
		t.Fatal("display name accepted instead of stable ID")
	}
}

func TestTopologyRemoteProxyHopDoesNotUseHostLoopbackOrHostDNS(t *testing.T) {
	st := topologyFixture(t)
	st.Nodes[0].Listen, st.Nodes[0].Host = "127.0.0.1", "127.0.0.1"
	st.Egresses[0].Server, st.Egresses[0].Port, st.Egresses[0].Detour = "127.0.0.1", st.Nodes[0].Port, st.Egresses[1].ID
	if err := st.Validate(); err != nil {
		t.Fatal("remote proxy's loopback was mistaken for the local listener", err)
	}
	queries := map[string]int{}
	lookup := func(host string) ([]netip.Addr, error) {
		queries[host]++
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, errors.New("controlled local NXDOMAIN; remote resolver is independent")
		}
		return []netip.Addr{ip}, nil
	}
	if err := validateTopologyResolved(st, nil, lookup); err != nil {
		t.Fatal("remote proxy's loopback failed local preflight", err)
	}
	st.Egresses[0].Server = "only.remote.internal"
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateTopologyResolved(st, nil, lookup); err != nil || queries["only.remote.internal"] != 0 {
		t.Fatal("a detoured domain required an unrelated local DNS answer", err, queries)
	}
	st.Egresses[0].Detour = ""
	if err := validateTopologyResolved(st, nil, lookup); err == nil || queries["only.remote.internal"] != 1 {
		t.Fatal("the physical first hop stopped requiring local bootstrap resolution", err, queries)
	}
	// The correction must not allow an explicitly declared public entry to be
	// selected as a remote exit and sent back through the same entry again.
	st.Nodes[0].Host = "203.0.113.30"
	st.Egresses[0].Server, st.Egresses[0].Detour = st.Nodes[0].Host, st.Egresses[1].ID
	if err := st.Validate(); err == nil {
		t.Fatal("detour concealed a declared public entry loop")
	}
}

func TestTopologyRemoteForwardTargetDoesNotCreateLocalCycleOrRequireLocalDNS(t *testing.T) {
	st := topologyFixture(t)
	st.Nodes[0].Listen, st.Nodes[0].Host = "127.0.0.1", "127.0.0.1"
	st.Forwards = []PortForward{{ID: "5555555555555555", Name: "remote-target", Listen: "127.0.0.1", Port: 23456, Network: "tcp+udp", TargetHost: "127.0.0.1", TargetPort: st.Nodes[0].Port, EgressID: st.Egresses[0].ID, Enabled: true}}
	if err := st.Validate(); err != nil {
		t.Fatal("remote forward loopback was mistaken for local entry", err)
	}
	queries := map[string]int{}
	lookup := func(host string) ([]netip.Addr, error) {
		queries[host]++
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, errors.New("controlled local DNS failure")
		}
		return []netip.Addr{ip}, nil
	}
	st.Forwards[0].TargetHost = "only.remote.internal"
	if err := validateTopologyResolved(st, nil, lookup); err != nil || queries["only.remote.internal"] != 0 {
		t.Fatal("proxy forward target was locally resolved", err, queries)
	}
	st.Forwards[0].TargetHost, st.Forwards[0].TargetPort = "127.0.0.1", 23457
	st.Forwards = append(st.Forwards, PortForward{ID: "6666666666666666", Name: "direct-into-remote", Listen: "127.0.0.1", Port: 23457, Network: "tcp+udp", TargetHost: "127.0.0.1", TargetPort: 23456, Enabled: true})
	if err := st.Validate(); err != nil {
		t.Fatal("different host scopes incorrectly formed a static forward cycle", err)
	}
	if err := validateTopologyResolved(st, nil, lookup); err != nil {
		t.Fatal("different host scopes incorrectly formed a resolved forward cycle", err)
	}
	st.Forwards[0].EgressID = ""
	if err := st.Validate(); err == nil {
		t.Fatal("physical direct forward cycle was no longer rejected")
	}
	st.Forwards = st.Forwards[:1]
	st.Forwards[0].EgressID = st.Egresses[0].ID
	st.Nodes[0].Host = "entry.example.test"
	st.Forwards[0].TargetHost, st.Forwards[0].TargetPort = st.Nodes[0].Host, EffectiveConnectPort(st.Nodes[0])
	if err := st.Validate(); err == nil {
		t.Fatal("non-direct forward accepted a declared public entry loop")
	}
}

func TestTopologyWireGuardRetainsItsLocalResolverOnDetour(t *testing.T) {
	st := topologyFixture(t)
	wg := topologyWG(t)
	wg.WireGuard.ListenPort, wg.WireGuard.ReceiveEgressID = 0, ""
	wg.WireGuard.Peers[0].Address, wg.WireGuard.Peers[0].Port = "peer.remote.internal", 51820
	wg.Detour = st.Egresses[1].ID
	st.Egresses = append(st.Egresses, wg)
	st.Nodes[0].EgressID = wg.ID
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
	queries := map[string]int{}
	lookup := func(host string) ([]netip.Addr, error) {
		queries[host]++
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, errors.New("controlled missing local bootstrap")
		}
		return []netip.Addr{ip}, nil
	}
	if err := validateTopologyResolved(st, nil, lookup); err == nil || queries["peer.remote.internal"] != 1 {
		t.Fatal("WireGuard ResolverOnDetour peer lookup was skipped", err, queries)
	}
	st.Egresses[2].WireGuard.Peers[0].Address = "192.0.2.40"
	st.Egresses[2].Detour = ""
	st.Forwards = []PortForward{{ID: "5555555555555555", Name: "tunnel-domain-target", Listen: "127.0.0.1", Port: 23456, Network: "tcp", TargetHost: "target.remote.internal", TargetPort: 443, EgressID: wg.ID, Enabled: true}}
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateTopologyResolved(st, nil, lookup); err == nil || queries["target.remote.internal"] != 1 {
		t.Fatal("WireGuard DialContext destination domain lookup was skipped", err, queries)
	}
	st.Forwards = nil
	st.Nodes[0].EgressID = st.Egresses[0].ID
	st.Egresses[0].Server, st.Egresses[0].Detour = "proxy.remote.internal", wg.ID
	if err := validateTopologyResolved(st, nil, lookup); err == nil || queries["proxy.remote.internal"] != 1 {
		t.Fatal("proxy dial through WireGuard skipped WireGuard's local resolver", err, queries)
	}
}

func TestTopologyDeclaredPublicEntriesComparePhysicalTransport(t *testing.T) {
	const public = "203.0.113.30"
	st := topologyFixture(t)
	st.Nodes[0].Host, st.Nodes[0].Listen = public, "127.0.0.1"
	st.Egresses[0] = Egress{ID: st.Egresses[0].ID, Name: "remote-HY2", Protocol: "hysteria2", Server: public, Port: st.Nodes[0].Port, UDP: true, HY2: &RemoteHY2{Password: "remote-secret", ServerName: "upstream.example"}}
	if err := st.Validate(); err != nil {
		t.Fatal("public HY2 UDP port collided with a distinct REALITY TCP port", err)
	}
	st.Forwards = []PortForward{{ID: "5555555555555555", Name: "separate-public-UDP", Listen: "127.0.0.1", Port: 23456, Network: "udp", TargetHost: public, TargetPort: st.Nodes[0].Port, Enabled: true}}
	if err := st.Validate(); err != nil {
		t.Fatal("UDP forward target was mistaken for public TCP entry", err)
	}
	st.Forwards[0].Network = "tcp"
	if err := st.Validate(); err == nil {
		t.Fatal("same-protocol public TCP forward loop was accepted")
	}
	st.Forwards = nil
	st.Egresses[0] = topologySOCKS(st.Egresses[0].ID, "same-public-TCP")
	st.Egresses[0].Server, st.Egresses[0].Port = public, st.Nodes[0].Port
	if err := st.Validate(); err == nil {
		t.Fatal("same-protocol public TCP outbound loop was accepted")
	}
	// WireGuard peers have their own address field, not Egress.Server.
	wg := topologyWG(t)
	wg.WireGuard.ListenPort, wg.WireGuard.ReceiveEgressID = 0, ""
	wg.WireGuard.Peers[0].Address, wg.WireGuard.Peers[0].Port = public, st.Nodes[0].Port
	st.Egresses, st.Nodes[0].EgressID = []Egress{wg}, wg.ID
	if err := st.Validate(); err != nil {
		t.Fatal("WireGuard UDP peer was mistaken for a distinct TCP entry", err)
	}
	hy := hyFixture(t).Nodes[0]
	hy.Host, hy.Listen, hy.Port, hy.EgressID = public, "127.0.0.1", st.Nodes[0].Port, wg.ID
	st.Nodes = []Node{hy}
	if err := st.Validate(); err == nil {
		t.Fatal("WireGuard peer pointed at a declared public UDP entry")
	}
	// SS2022's physical UDP port must be checked as well as its TCP port.
	ss := ssFixture()
	st.Egresses = []Egress{{ID: "3333333333333333", Name: "same-public-SS", Protocol: "ss2022", Server: public, Port: hy.Port, UDP: true, Shadowsocks: &RemoteSS{Method: SS2022Method, Password: SSPassword(ss, ss.Users[0])}}}
	st.Nodes[0].EgressID = st.Egresses[0].ID
	if err := st.Validate(); err == nil {
		t.Fatal("SS2022 UDP self-reference was missed because TCP was different")
	}
	st.Nodes[0].EgressID = ""
	st.Egresses[0].UDP = false
	if err := st.Validate(); err != nil {
		t.Fatal("TCP-only SS2022 server port was mistaken for public UDP entry", err)
	}
}
