package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func TestAutoEndpointIPFallbackAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name, ipv4, ipv6, want string
		families               []string
	}{
		{"ipv4", "203.0.113.8", "2001:db8::8", "203.0.113.8", []string{"4"}},
		{"ipv6", "", "2001:db8::8", "2001:db8::8", []string{"4", "6"}},
		{"failure", "", "", "", []string{"4", "6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			p := autoProbes{publicIP: func(family string) (string, error) {
				calls = append(calls, family)
				ip := tc.ipv4
				if family == "6" {
					ip = tc.ipv6
				}
				if ip == "" {
					return "", errors.New("unreachable")
				}
				return ip, nil
			}}
			host, _, _, e := autoEndpoint("ss2022", "", "", "", p)
			if host != tc.want || (e != nil) != (tc.want == "") || !reflect.DeepEqual(calls, tc.families) {
				t.Fatalf("host=%q error=%v families=%v", host, e, calls)
			}
			if e != nil && !strings.Contains(e.Error(), "--server") {
				t.Fatal(e)
			}
		})
	}
}

func TestAutoRealitySelectionAndExplicitTarget(t *testing.T) {
	for _, tc := range []struct {
		name, sni, target, succeeds, want string
		wantCalls                         int
		fails                             bool
	}{
		{"explicit", "custom.example.com", "192.0.2.8:8443", "custom.example.com", "custom.example.com", 1, false},
		{"explicit fail", "custom.example.com", "", "www.microsoft.com", "", 1, true},
		{"target without sni", "", "192.0.2.8:8443", "", "", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []*node.Reality
			p := autoProbes{checkReality: func(r *node.Reality) error {
				calls = append(calls, r)
				if r.ServerName != tc.succeeds {
					return errors.New("TLS rejected")
				}
				return nil
			}}
			host, sni, target, e := autoEndpoint("reality", "203.0.113.8", tc.sni, tc.target, p)
			if (e != nil) != tc.fails || sni != tc.want || len(calls) != tc.wantCalls {
				t.Fatalf("sni=%q error=%v calls=%v", sni, e, calls)
			}
			if e == nil {
				if host != "203.0.113.8" {
					t.Fatal("explicit host changed")
				}
				wantTarget := tc.target
				if wantTarget == "" {
					wantTarget = tc.want + ":443"
				}
				if target != wantTarget || calls[len(calls)-1].Target != wantTarget {
					t.Fatal("target changed")
				}
			} else if !strings.Contains(e.Error(), "--sni") {
				t.Fatal(e)
			}
		})
	}
}

func TestAutoPortRespectsExplicitChoiceAndSSH(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		explicit, random, busy, ssh, saved, fails bool
		want, randomCalls                         int
	}{
		{"default free", false, false, false, false, false, false, 443, 0},
		{"default busy", false, false, true, false, false, false, 32123, 1},
		{"default SSH", false, false, false, true, false, false, 32123, 1},
		{"saved node", false, false, false, false, true, false, 32123, 1},
		{"explicit free", true, false, false, false, false, false, 443, 0},
		{"explicit busy", true, false, true, false, false, true, 0, 0},
		{"explicit SSH", true, false, false, true, false, true, 0, 0},
		{"random", false, true, false, false, false, false, 32123, 1},
		{"conflicting flags", true, true, false, false, false, true, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssh := []int{22}
			if tc.ssh {
				ssh = append(ssh, 443)
			}
			calls := 0
			p := autoProbes{
				sshPorts: func() []int { return ssh },
				availablePort: func(node.Node) error {
					if tc.busy {
						return errors.New("address in use")
					}
					return nil
				},
				randomPort: func(_ node.State, _ node.Node, got []int) (int, error) {
					calls++
					if !reflect.DeepEqual(ssh, got) {
						t.Fatal("SSH ports were not reserved")
					}
					return 32123, nil
				},
			}
			n := node.Node{Protocol: "reality", Listen: "0.0.0.0", Port: 443, Enabled: true}
			s := node.NewState()
			if tc.saved {
				s.Nodes = append(s.Nodes, n)
			}
			port, e := autoPort(s, n, tc.explicit, tc.random, p)
			if port != tc.want || calls != tc.randomCalls || (e != nil) != tc.fails {
				t.Fatalf("port=%d error=%v random calls=%d", port, e, calls)
			}
		})
	}
}

type autoBackend struct{ activations int }

func (*autoBackend) Check(node.State, string) error { return nil }
func (b *autoBackend) Active() bool                 { return b.activations > 0 }
func (b *autoBackend) Activate(node.State) error    { b.activations++; return nil }
func (*autoBackend) Stop() error                    { return nil }

func TestAutoInitAppliesOnceAndRepeatsWithoutProbes(t *testing.T) {
	backend := &autoBackend{}
	root := t.TempDir()
	a := app{store: &node.Store{Root: root, GID: -1, Backend: backend}}
	p := autoProbes{
		publicIP: func(family string) (string, error) {
			if family == "4" {
				return "", errors.New("no IPv4")
			}
			return "2001:db8::8", nil
		},
		probeReality: func(r *node.Reality) (time.Duration, error) {
			if r.ServerName == "www.apple.com" {
				return time.Millisecond, nil
			}
			return 0, errors.New("unreachable")
		},
		sshPorts:      func() []int { return []int{22} },
		availablePort: func(node.Node) error { return errors.New("busy") },
		randomPort:    func(node.State, node.Node, []int) (int, error) { return 32123, nil },
	}
	if e := a.addWithProbes("init", []string{"--auto", "--quiet"}, p); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "current", "state.json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	s, e := node.ReadState(path)
	if e != nil {
		t.Fatal(e)
	}
	n := s.Nodes[0]
	if n.Host != "2001:db8::8" || n.Listen != "::" || n.Port != 32123 || n.Reality.ServerName != "www.apple.com" || n.Users[0].UUID == "" {
		t.Fatal("auto settings not persisted")
	}
	// Nil probes and reader make accidental network probes or prompts fail immediately.
	if e = a.addWithProbes("init", []string{"--auto", "--quiet"}, autoProbes{}); e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) || backend.activations != 1 {
		t.Fatal("repeat changed identity or restarted service", e)
	}
}

func TestAutoRejectsOfflineAndIncompleteHysteriaWithoutProbes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offline bool
		args    []string
		want    string
	}{
		{"offline", true, []string{"--auto"}, "离线"},
		{"hysteria missing sni", false, []string{"--auto", "--protocol", "hysteria2"}, "--sni"},
		{"hysteria missing cert", false, []string{"--auto", "--protocol", "hysteria2", "--sni", "example.com"}, "--cert"},
		{"unknown protocol", false, []string{"--auto", "--protocol", "unknown"}, "不支持"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			a := app{store: &node.Store{Root: root, GID: -1, Backend: &autoBackend{}}, offline: tc.offline}
			e := a.addWithProbes("init", tc.args, autoProbes{})
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatal("unexpected error", e)
			}
			if _, e = os.Lstat(filepath.Join(root, "current")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("failed auto init committed state")
			}
		})
	}
}

func TestAutoSS2022UsesExplicitEndpointWithoutTLS(t *testing.T) {
	root := t.TempDir()
	a := app{store: &node.Store{Root: root, GID: -1, Backend: &autoBackend{}}}
	p := autoProbes{sshPorts: func() []int { return []int{22} }, availablePort: func(node.Node) error { return nil }}
	if e := a.addWithProbes("add", []string{"--auto", "--protocol", "ss2022", "--server", "203.0.113.8", "--port", "24567", "--quiet"}, p); e != nil {
		t.Fatal(e)
	}
	s, e := node.ReadState(filepath.Join(root, "current", "state.json"))
	if e != nil || len(s.Nodes) != 1 || s.Nodes[0].Port != 24567 || s.Nodes[0].Users[0].Password == "" {
		t.Fatal("SS2022 auto failed", e)
	}
}
