package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestBindingOverlapUsesAddressesTransportsAndUncertainDualStack(t *testing.T) {
	for _, tc := range []struct {
		name, first, second, firstNet, secondNet string
		overlap, certain                         bool
	}{
		{"same IPv4", "127.0.0.1", "127.0.0.1", "tcp", "tcp", true, true},
		{"different IPv4", "127.0.0.1", "127.0.0.2", "tcp", "tcp", false, true},
		{"IPv4 wildcard", "0.0.0.0", "127.0.0.2", "udp", "udp", true, true},
		{"TCP versus UDP", "0.0.0.0", "0.0.0.0", "tcp", "udp", false, true},
		{"canonical IPv6", "0:0:0:0:0:0:0:1", "::1", "tcp", "tcp", true, true},
		{"different IPv6", "2001:db8::1", "2001:db8::2", "tcp", "tcp", false, true},
		{"IPv6 wildcard", "::", "::1", "tcp", "tcp", true, true},
		{"uncertain dual wildcard", "::", "0.0.0.0", "tcp", "tcp", false, false},
		{"uncertain dual concrete", "127.0.0.1", "::", "udp", "udp", false, false},
		{"explicit v6 only", "::", "0.0.0.0", "tcp6", "tcp4", false, true},
		{"separate concrete families", "::1", "127.0.0.1", "udp", "udp", false, true},
		{"mapped IPv4", "::ffff:127.0.0.1", "127.0.0.1", "tcp", "tcp", true, true},
		{"mapped unspecified may dual", "::ffff:0.0.0.0", "::1", "tcp", "tcp", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := LocalBinding{Network: tc.firstNet, Address: tc.first, Port: 23456}
			b := LocalBinding{Network: tc.secondNet, Address: tc.second, Port: 23456}
			if o, c := BindingOverlap(a, b); o != tc.overlap || c != tc.certain {
				t.Fatalf("overlap=%t certain=%t", o, c)
			}
			if o, c := BindingOverlap(b, a); o != tc.overlap || c != tc.certain {
				t.Fatal("overlap relation is asymmetric")
			}
			b.Port++
			if o, c := BindingOverlap(a, b); o || !c {
				t.Fatal("different port conflicts")
			}
		})
	}
	for _, tc := range []struct{ address, network, want string }{
		{"0.0.0.0", "tcp", "tcp4"}, {"0.0.0.0", "udp", "udp4"}, {"::", "tcp", "tcp"},
		{"::ffff:0.0.0.0", "udp", "udp"}, {"::", "tcp6", "tcp6"}, {"127.0.0.1", "tcp", "tcp"},
	} {
		if got := localBindingNetwork(LocalBinding{Address: tc.address, Network: tc.network}); got != tc.want {
			t.Fatalf("network for %s/%s = %s", tc.address, tc.network, got)
		}
	}
}

func TestStateLocalConflictsPermitDistinctAddressesAndIndependentTransports(t *testing.T) {
	s := fixture(t)
	first := s.Nodes[0]
	first.Listen = "127.0.0.1"
	second := first
	second.ID, second.Name, second.Listen = Token(8), "second local address", "127.0.0.2"
	s.Nodes = []Node{first, second}
	if e := s.Validate(); e != nil {
		t.Fatal("different local IPv4 addresses incorrectly conflict", e)
	}
	s.Nodes[1].Listen = "0.0.0.0"
	if e := s.Validate(); e == nil {
		t.Fatal("wildcard/concrete conflict accepted")
	}
	s.Nodes[1].Enabled = false
	if e := s.Validate(); e != nil {
		t.Fatal("disabled listener reserved a port", e)
	}
	if e := ValidateNodeListeners([]Node{{Protocol: "reality", Listen: "0.0.0.0", Port: 443, Enabled: true}, {Protocol: "hysteria2", Listen: "0.0.0.0", Port: 443, Enabled: true}}); e != nil {
		t.Fatal("independent TCP/UDP listeners conflict", e)
	}
}

func bindingTestPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestProbeLocalBindingsReallySupportsDifferentIPv4AndTCPUDP(t *testing.T) {
	port := bindingTestPort(t)
	bindings := []LocalBinding{{Network: "tcp", Address: "127.0.0.1", Port: port}, {Network: "tcp", Address: "127.0.0.2", Port: port}, {Network: "udp", Address: "127.0.0.1", Port: port}}
	controls, firstWasHeld := 0, false
	lc := &net.ListenConfig{Control: func(_ string, _ string, _ syscall.RawConn) error {
		controls++
		if controls == 2 {
			l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			firstWasHeld = errors.Is(e, syscall.EADDRINUSE)
			if l != nil {
				l.Close()
			}
		}
		return nil
	}}
	r, e := ProbeLocalBindings(context.Background(), bindings, BindingProbeOptions{ListenConfig: lc})
	if e != nil || len(r.Results) != 3 || !firstWasHeld {
		t.Fatalf("listeners were not held and verified together: %+v %v held=%t", r, e, firstWasHeld)
	}
	for _, b := range bindings {
		closer, _, e := openLocalBinding(context.Background(), b, net.ListenConfig{})
		if e != nil {
			t.Fatal("successful probe leaked listener", e)
		}
		closer.Close()
	}
}

func TestProbeLocalBindingsFailureAndCancellationReleaseAllOwnedSockets(t *testing.T) {
	for _, cancelSecond := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelSecond), func(t *testing.T) {
			port := bindingTestPort(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var lc net.ListenConfig
			if cancelSecond {
				calls := 0
				lc.Control = func(_ string, _ string, _ syscall.RawConn) error {
					calls++
					if calls == 2 {
						cancel()
						return ctx.Err()
					}
					return nil
				}
			} else {
				external, e := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if e != nil {
					t.Fatal(e)
				}
				defer external.Close()
			}
			_, e := ProbeLocalBindings(ctx, []LocalBinding{{Network: "tcp", Address: "127.0.0.1", Port: port}, {Network: "udp", Address: "127.0.0.1", Port: port}}, BindingProbeOptions{ListenConfig: &lc})
			if e == nil {
				t.Fatal("failed second listener was accepted")
			}
			if cancelSecond && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation identity lost", e)
			}
			l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if e != nil {
				t.Fatal("failed probe leaked first listener", e)
			}
			l.Close()
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ProbeLocalBindings(ctx, []LocalBinding{{Network: "udp", Address: "127.0.0.1", Port: bindingTestPort(t)}}, BindingProbeOptions{}); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled operation passed", e)
	}
}

func TestSocketSnapshotCannotHideUnreadableTablesOrConnectedUDP(t *testing.T) {
	proc := t.TempDir()
	for _, dir := range []string{"42/fd", "42/net", "42/ns", "self/ns"} {
		if e := os.MkdirAll(filepath.Join(proc, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, path := range []string{"42/ns/net", "self/ns/net"} {
		if e := os.Symlink("net:[123]", filepath.Join(proc, path)); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink("socket:[777]", filepath.Join(proc, "42/fd/3")); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if e := os.WriteFile(filepath.Join(proc, "42/net", table), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	row := []byte("0: 0100007F:5BA0 00000000:0000 07 0 0 0 0 0 777\n")
	if e := os.WriteFile(filepath.Join(proc, "42/net/udp"), row, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := ReadSocketSnapshot(proc, 42)
	if e != nil || !s.Complete || !s.NamespaceVerified || len(s.Sockets) != 1 || !s.Sockets[0].Owned || s.Sockets[0].Inode != "777" {
		t.Fatalf("ownership snapshot incomplete: %+v %v", s, e)
	}
	state := NewState()
	state.Nodes = []Node{{Protocol: "hysteria2", Enabled: true, Listen: "127.0.0.1", Port: 23456}}
	if !SocketsReady(state, s.Sockets) {
		t.Fatal("owned unconnected UDP listener rejected")
	}
	s.Sockets[0].State = "01"
	if SocketsReady(state, s.Sockets) {
		t.Fatal("connected outbound UDP counted as listener readiness")
	}
	if e := os.WriteFile(filepath.Join(proc, "42/net/tcp"), []byte("broken socket table\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e = ReadSocketSnapshot(proc, 42); e == nil || s.Complete {
		t.Fatal("malformed socket table treated as absence of foreign listeners")
	}
}

func TestProbeLocalBindingsDefersOnlyVerifiedPreviousInodes(t *testing.T) {
	old, e := net.Listen("tcp4", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	port := old.Addr().(*net.TCPAddr).Port
	s, e := ReadSocketSnapshot("/proc", os.Getpid())
	if e != nil || !s.Complete {
		t.Fatalf("cannot read actual process ownership: %v", e)
	}
	candidate := []LocalBinding{{Network: "tcp", Address: "127.0.0.1", Port: port}}
	opts := BindingProbeOptions{Previous: []LocalBinding{{Network: "tcp", Address: "0.0.0.0", Port: port}}, Sockets: s.Sockets, SnapshotComplete: s.Complete}
	r, e := ProbeLocalBindings(context.Background(), candidate, opts)
	if e != nil || len(r.Results) != 1 || r.Results[0].Status != "owned_deferred" {
		t.Fatalf("owned wildcard range change blocked: %+v %v", r, e)
	}
	two := append(append([]LocalBinding{}, candidate...), LocalBinding{Network: "tcp", Address: "127.0.0.2", Port: port})
	if r, e = ProbeLocalBindings(context.Background(), two, opts); e != nil || len(r.Results) != 2 || r.Results[1].Status != "owned_deferred" {
		t.Fatalf("old owned wildcard prevented a valid split into distinct local IPv4 listeners: %+v %v", r, e)
	}
	for _, kind := range []string{"incomplete", "not-in-old-state", "foreign"} {
		t.Run(kind, func(t *testing.T) {
			bad := opts
			switch kind {
			case "incomplete":
				bad.SnapshotComplete = false
			case "not-in-old-state":
				bad.Previous = nil
			case "foreign":
				bad.Sockets = append([]Socket{}, s.Sockets...)
				for i := range bad.Sockets {
					bad.Sockets[i].Owned = false
				}
			}
			if _, e := ProbeLocalBindings(context.Background(), candidate, bad); !errors.Is(e, syscall.EADDRINUSE) {
				t.Fatal("unverified listener was exempted", e)
			}
		})
	}
}

func TestProbeLocalBindingsUnrelatedRangeCannotHideBehindOwnedListener(t *testing.T) {
	old, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	port := old.Addr().(*net.TCPAddr).Port
	other, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	snapshot, e := ReadSocketSnapshot("/proc", os.Getpid())
	if e != nil || !snapshot.Complete {
		t.Fatal("cannot read actual distinct-IP holders", e)
	}
	options := BindingProbeOptions{Previous: []LocalBinding{{Network: "tcp", Address: "127.0.0.1", Port: port}}, Sockets: snapshot.Sockets, SnapshotComplete: true}
	if _, e = ProbeLocalBindings(context.Background(), []LocalBinding{{Network: "tcp", Address: "0.0.0.0", Port: port}}, options); !errors.Is(e, syscall.EADDRINUSE) {
		t.Fatal("unrelated holder was ignored because another overlapping holder belonged to the old node", e)
	}
}

func TestProbeLocalBindingsIPv6AndChangedOwnedWildcardCandidateConflict(t *testing.T) {
	old, e := net.Listen("tcp", "[::]:0")
	if e != nil {
		t.Skipf("IPv6实际绑定不可用；IPv6子项未验证：%v", e)
	}
	defer old.Close()
	port := old.Addr().(*net.TCPAddr).Port
	conn, e := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		t.Skipf("当前内核的实际IPv6监听不承载IPv4；跨族双栈子项未验证：%v", e)
	}
	conn.Close()
	s, e := ReadSocketSnapshot("/proc", os.Getpid())
	if e != nil || !s.Complete {
		t.Fatal("cannot verify actual dual-stack owner", e)
	}
	opts := BindingProbeOptions{Previous: []LocalBinding{{Network: "tcp", Address: "::", Port: port}}, Sockets: s.Sockets, SnapshotComplete: s.Complete}
	// Both candidates could otherwise be exempted against the same owned old
	// dual-stack listener. The shared temporary port must catch their conflict.
	_, e = ProbeLocalBindings(context.Background(), []LocalBinding{{Network: "tcp", Address: "::", Port: port}, {Network: "tcp", Address: "127.0.0.1", Port: port}}, opts)
	if !errors.Is(e, syscall.EADDRINUSE) {
		t.Fatal("changed-owned wildcard and new IPv4 candidates both deferred despite internal conflict", e)
	}
	if _, e = ProbeLocalBindings(context.Background(), []LocalBinding{{Network: "tcp", Address: "::", Port: port}}, BindingProbeOptions{}); !errors.Is(e, syscall.EADDRINUSE) {
		t.Fatal("foreign actual IPv6 wildcard passed", e)
	}
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	r, e := ProbeLocalBindings(context.Background(), []LocalBinding{{Network: "tcp6", Address: "::1", Port: port}, {Network: "tcp4", Address: "127.0.0.1", Port: port}}, BindingProbeOptions{})
	if e != nil || len(r.Results) != 2 {
		t.Fatalf("explicit IPv6/IPv4 separate loopback bind failed: %+v %v", r, e)
	}
}
