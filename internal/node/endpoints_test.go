package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func endpointPort(port int) *int { return &port }

func TestConnectionEndpointPortAndTLSIdentityAreIndependent(t *testing.T) {
	states := []State{fixture(t), hyFixture(t)}
	ss := NewState()
	ss.Nodes = []Node{ssFixture()}
	states = append(states, ss)
	for _, st := range states {
		t.Run(st.Nodes[0].Protocol, func(t *testing.T) {
			n := &st.Nodes[0]
			u := n.Users[0]
			oldURI := URI(*n, u)
			oldOutbound := Outbound(*n, u)
			oldServer, err := Server(st, "/test/root")
			if err != nil {
				t.Fatal(err)
			}
			n.ConnectPort = endpointPort(30000)
			defaultHost := n.Host
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "v6", Host: "2001:0db8:0:0::9", Port: 31000}, {ID: "relay", Host: "relay.example.test", Port: 32000}}
			if err = st.Validate(); err != nil {
				t.Fatal(err)
			}
			newServer, err := Server(st, "/test/root")
			if err != nil || !bytes.Equal(oldServer, newServer) {
				t.Fatal("client declarations changed the listener or server identity", err)
			}
			if EffectiveConnectPort(*n) != 30000 || n.Port == 30000 {
				t.Fatal("connection and listener port were conflated")
			}
			for _, endpoint := range EffectiveEndpoints(*n) {
				selected, err := WithEndpoint(*n, endpoint.ID)
				if err != nil {
					t.Fatal(err)
				}
				uri := URI(selected, u)
				parsed, err := url.Parse(uri)
				if err != nil || parsed.Hostname() != endpoint.Host || parsed.Port() != fmt.Sprint(endpoint.Port) {
					t.Fatal("URI did not select endpoint", endpoint.ID, err)
				}
				out, mihomo := Outbound(selected, u), MihomoProxy(selected, u)
				if out["server"] != endpoint.Host || out["server_port"] != endpoint.Port || mihomo["server"] != endpoint.Host || mihomo["port"] != endpoint.Port {
					t.Fatal("client formats disagree", endpoint.ID)
				}
				delete(out, "server")
				delete(out, "server_port")
				old := M{}
				for key, value := range oldOutbound {
					if key != "server" && key != "server_port" {
						old[key] = value
					}
				}
				if !equalJSON(old, out) || selected.Port != n.Port || selected.Listen != n.Listen || !reflect.DeepEqual(selected.Users, n.Users) {
					t.Fatal("endpoint selection changed authentication, TLS or local listener")
				}
				for _, format := range []string{"uri", "base64", "qr", "sing-box", "mihomo", "provider"} {
					data, err := Export(selected, u, format)
					if err != nil || len(data) == 0 {
						t.Fatal(format, err)
					}
					if format == "base64" {
						decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
						if err != nil || string(decoded) != uri+"\n" {
							t.Fatal("base64 did not encode selected URI", err)
						}
					}
				}
			}
			if URI(*n, u) == oldURI {
				t.Fatal("explicit public port was omitted")
			}
			if n.Host != defaultHost || *n.ConnectPort != 30000 {
				t.Fatal("selection mutated saved default")
			}
			if _, err = WithEndpoint(*n, "missing"); err == nil {
				t.Fatal("missing endpoint silently selected default")
			}
		})
	}
}

func TestConnectionEndpointValidationAndInputNormalization(t *testing.T) {
	for input, want := range map[string]string{"[2001:0db8::8]": "2001:0db8::8", "2001:db8::8": "2001:db8::8", "192.0.2.8": "192.0.2.8", "Example.TEST.": "Example.TEST."} {
		got, err := NormalizeEndpointHost(input)
		if err != nil || got != want {
			t.Fatal(input, got, err)
		}
	}
	for _, input := range []string{"", " 192.0.2.8", "https://example.test", "example.test:443", "[::1]:443", "[example.test]", "[192.0.2.8]", "fe80::1%eth0", "bad\n.test", "::not-ip"} {
		if _, err := NormalizeEndpointHost(input); err == nil {
			t.Fatal("invalid host normalized", input)
		}
	}
	st := fixture(t)
	st.Nodes[0].Host = "Example.TEST."
	for _, invalid := range []func(*Node){
		func(n *Node) { n.ConnectPort = endpointPort(0) },
		func(n *Node) { n.ConnectPort = endpointPort(65536) },
		func(n *Node) {
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "default", Host: "other.test", Port: 1}}
		},
		func(n *Node) {
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "invalid id", Host: "other.test", Port: 1}}
		},
		func(n *Node) {
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: strings.Repeat("x", 33), Host: "other.test", Port: 1}}
		},
		func(n *Node) { n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "x", Host: "[::1]", Port: 1}} },
		func(n *Node) { n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "x", Host: "other.test", Port: -1}} },
		func(n *Node) {
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "x", Host: "example.test", Port: n.Port}}
		},
		func(n *Node) {
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "x", Host: "one.test", Port: 1}, {ID: "x", Host: "two.test", Port: 2}}
		},
		func(n *Node) {
			n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "x", Host: "2001:db8::1", Port: 1}, {ID: "y", Host: "2001:0db8:0:0:0:0:0:1", Port: 1}}
		},
		func(n *Node) {
			for i := 0; i <= MaxAdditionalEndpoints; i++ {
				n.AdditionalEndpoints = append(n.AdditionalEndpoints, ConnectionEndpoint{ID: fmt.Sprint("ep", i), Host: "other.test", Port: i + 1})
			}
		},
	} {
		next := st.Clone()
		invalid(&next.Nodes[0])
		if err := next.Validate(); err == nil {
			t.Fatal("invalid endpoint accepted", next.Nodes[0].AdditionalEndpoints)
		}
	}
	n := st.Nodes[0]
	if EffectiveConnectPort(n) != n.Port {
		t.Fatal("omitted field lost compatibility")
	}
	n.Port++
	if EffectiveConnectPort(n) != n.Port {
		t.Fatal("omitted field stopped following local port")
	}
	n.ConnectPort = endpointPort(30000)
	n.Port++
	if EffectiveConnectPort(n) != 30000 {
		t.Fatal("explicit public port followed local edit")
	}
	endpoints := EffectiveEndpoints(n)
	endpoints[0].Host = "different.test"
	if n.Host != "Example.TEST." {
		t.Fatal("effective endpoint slice aliases saved node")
	}
}

func TestLegacyEndpointMigrationPreservesEverySavedFieldAndExport(t *testing.T) {
	for _, name := range []string{"state-v1.json", "state-v2-hy2-performance.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			var legacy State
			if err = json.Unmarshal(raw, &legacy); err != nil {
				t.Fatal(err)
			}
			before := legacy.Clone()
			st, err := DecodeState(raw)
			if err != nil {
				t.Fatal(err)
			}
			if st.Schema != Schema || st.Validate() != nil {
				t.Fatal("legacy state not migrated")
			}
			want := before.Clone()
			want.Schema = Schema
			for i := range want.Nodes {
				want.Nodes[i].ConnectPort = endpointPort(want.Nodes[i].Port)
			}
			want, err = CanonicalCertificates(want)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(st, want) || !reflect.DeepEqual(legacy, before) {
				t.Fatal("migration changed unrelated source fields or identity")
			}
			for i, old := range legacy.Nodes {
				if st.Nodes[i].ConnectPort == nil || *st.Nodes[i].ConnectPort != old.Port {
					t.Fatal("old connection port not locked explicitly")
				}
				for j, u := range old.Users {
					if URI(st.Nodes[i], st.Nodes[i].Users[j]) != URI(old, u) || !equalJSON(Outbound(st.Nodes[i], st.Nodes[i].Users[j]), Outbound(old, u)) {
						t.Fatal("legacy client definition changed")
					}
				}
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = ReadState(path); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(raw, after) {
				t.Fatal("read persisted migration")
			}
			for _, magic := range [][]byte{backupMagic, []byte("QNBK2\x00")} {
				plain := raw
				if string(magic) != string(backupMagic) {
					plain = append([]byte(`{"format":2,"state":`), append(raw, []byte(`}`)...)...)
				}
				sealed, err := sealBackup(plain, "batch04 fixture passphrase", magic)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := RestoreSnapshot(sealed, "batch04 fixture passphrase")
				if err != nil || !reflect.DeepEqual(snapshot.State, want) {
					t.Fatal("legacy backup migrated differently", err)
				}
			}
		})
	}
}

func TestLegacySchemaRejectsEndpointFieldsIncludingNullAndCase(t *testing.T) {
	for _, schema := range []int{1, 2} {
		for _, key := range []string{"connect_port", "CONNECT_PORT", "additional_endpoints", "ADDITIONAL_ENDPOINTS"} {
			for _, nodes := range []string{"nodes", "Nodes"} {
				raw := []byte(fmt.Sprintf(`{"schema":%d,"core_version":"1.14.0",%q:[{%q:null}]}`, schema, nodes, key))
				if _, err := DecodeState(raw); err == nil {
					t.Fatal("old schema accepted new field", string(raw))
				}
			}
		}
		legacy := NewState()
		legacy.Schema = schema
		legacy.Nodes = []Node{{Port: 443, ConnectPort: endpointPort(443)}}
		if _, err := MigrateState(legacy); err == nil {
			t.Fatal("typed legacy extension accepted")
		}
		legacy.Nodes[0].ConnectPort = nil
		legacy.Nodes[0].AdditionalEndpoints = []ConnectionEndpoint{}
		if _, err := MigrateState(legacy); err == nil {
			t.Fatal("typed empty legacy extension accepted")
		}
	}
}

func TestConnectionEndpointVersionThreeFixtureAndSnapshotRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/state-v3-endpoints.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := DecodeState(raw)
	if err != nil || st.Validate() != nil {
		t.Fatal("current endpoint fixture is invalid", err)
	}
	n := st.Nodes[0]
	if n.Port != 443 || EffectiveConnectPort(n) != 30000 || len(EffectiveEndpoints(n)) != 3 {
		t.Fatal("fixture lost distinct local/public addresses")
	}
	for _, endpoint := range EffectiveEndpoints(n) {
		selected, err := WithEndpoint(n, endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.Parse(URI(selected, selected.Users[0]))
		if err != nil || uri.Hostname() != endpoint.Host || uri.Port() != fmt.Sprint(endpoint.Port) {
			t.Fatal("fixture export chose wrong endpoint", err)
		}
	}
	plain, err := json.Marshal(Snapshot{Format: 2, State: st})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := RestorePlainSnapshot(plain)
	if err != nil || !reflect.DeepEqual(st, snapshot.State) {
		t.Fatal("current snapshot changed endpoint declarations", err)
	}
	unknown := bytes.Replace(raw, []byte(`"port": 31000`), []byte(`"port": 31000, "route_override": "direct"`), 1)
	if _, err := DecodeState(unknown); err == nil {
		t.Fatal("unknown endpoint extension silently discarded")
	}
}

func TestAdditionalConnectionEndpointChangesClassifyAndApplyWithoutRestart(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(fmt.Sprint("stopped=", stopped), func(t *testing.T) {
			store, backend, st := impactStore(t)
			if stopped {
				if err := backend.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			activation, stops := backend.activations, backend.stops
			original := st.Clone()
			oldGeneration, _ := store.current()
			server, _ := Server(st, store.Root)
			st.Nodes[0].ConnectPort = endpointPort(30000)
			st.Nodes[0].AdditionalEndpoints = []ConnectionEndpoint{{ID: "relay", Host: "relay.example.test", Port: 30001}}
			for _, edit := range []func(*State){func(*State) {}, func(s *State) { s.Nodes[0].AdditionalEndpoints[0].Port++ }} {
				edit(&st)
				impact, err := store.Preview(st)
				if err != nil || !impact.ClientExport || impact.ServerRuntime || impact.HostEffects || impact.NeedsRestart {
					t.Fatalf("wrong endpoint impact %+v: %v", impact, err)
				}
				if err = store.WithLock(func() error { return store.Apply(st) }); err != nil {
					t.Fatal(err)
				}
				current, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				st = current
			}
			currentGeneration, _ := store.current()
			if currentGeneration == oldGeneration {
				t.Fatal("endpoint history not saved")
			}
			if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
				t.Fatal(err)
			}
			repeated, _ := store.current()
			if repeated != currentGeneration {
				t.Fatal("identical endpoint apply created new history")
			}
			if err := os.WriteFile(filepath.Join(store.Root, currentGeneration, "server.json"), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			impact, err := store.Preview(st)
			if err != nil || !impact.RepairDerived || impact.NeedsRestart {
				t.Fatal("metadata endpoint no-op skipped derived check", err, impact)
			}
			if err = store.WithLock(func() error { return store.Apply(st) }); err != nil {
				t.Fatal(err)
			}
			if err = store.WithLock(func() error { return store.Apply(original) }); err != nil {
				t.Fatal(err)
			}
			got, _ := store.Load()
			repaired, _ := Server(got, store.Root)
			if !bytes.Equal(server, repaired) || got.Nodes[0].Reality.PrivateKey != original.Nodes[0].Reality.PrivateKey || backend.activations != activation || backend.stops != stops || backend.active == stopped {
				t.Fatal("endpoint edit/revert/repair changed service state or identity")
			}
		})
	}
}
