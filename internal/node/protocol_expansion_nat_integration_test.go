//go:build linux

package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"qingnode/internal/probe"
)

type protocolExpansionNATForward struct {
	port int
	tcp  *natTCPForward
	udp  *natUDPForward
}

func (f *protocolExpansionNATForward) close() {
	if f.tcp != nil {
		f.tcp.Close()
	}
	if f.udp != nil {
		f.udp.Close()
	}
}

// The reused relays translate only this fixture's owned loopback sockets.
// They do not alter the host's NAT, firewall, routes, interfaces or services.
func protocolExpansionNATStartForward(t *testing.T, protocol, host string, local int, ipv6 bool) *protocolExpansionNATForward {
	t.Helper()
	family := "4"
	if ipv6 {
		family = "6"
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(local))
	for attempt := 0; attempt < 8; attempt++ {
		f := &protocolExpansionNATForward{}
		var err error
		if protocol != "tuic" {
			f.tcp, err = startNATTCPForward("tcp"+family, net.JoinHostPort(host, "0"), target)
			if err != nil {
				t.Fatal("controlled TCP mapping cannot bind", err)
			}
			f.port = f.tcp.listener.Addr().(*net.TCPAddr).Port
		}
		if protocol == "tuic" || protocol == "ss-aead" {
			f.udp, err = startNATUDPForward("udp"+family, net.JoinHostPort(host, strconv.Itoa(f.port)), target)
			if err != nil {
				f.close()
				if errors.Is(err, syscall.EADDRINUSE) {
					continue
				} // Reserve a shared TCP/UDP port before any traffic.
				t.Fatal("controlled UDP mapping cannot bind", err)
			}
			if f.port == 0 {
				f.port = f.udp.listener.LocalAddr().(*net.UDPAddr).Port
			}
		}
		if f.port == local {
			f.close()
			continue
		}
		t.Cleanup(f.close)
		return f
	}
	t.Fatal("could not reserve an external mapping distinct from the local listener")
	return nil
}

func protocolExpansionNATClient(t *testing.T, core, version string, n Node) (int, *http.Client, func()) {
	t.Helper()
	for _, out := range []M{Outbound(n, n.Users[0]), MihomoProxy(n, n.Users[0])} {
		if out["server"] != n.Host {
			t.Fatal("client export lost the external mapping host")
		}
		key := "server_port"
		if out["port"] != nil {
			key = "port"
		}
		if out[key] != EffectiveConnectPort(n) {
			t.Fatal("client export lost the external mapping port")
		}
	}
	if n.Protocol == "anytls" || n.Protocol == "trojan" {
		return protocolExpansionClient(t, core, "", version, "sing-box", n, n.Users[0], n.Certificate.CertPEM, "")
	}
	return protocolExpansionPhase2Client(t, core, "", version, "sing-box", n, n.Users[0], "")
}

func protocolExpansionNATUDP(t *testing.T, ctx context.Context, port int, target protocolExpansionTargets, success bool) {
	t.Helper()
	before := target.UDPHits.Load()
	udpCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := probe.RunUDP(udpCtx, probe.UDPOptions{Target: target.UDPAddress, Family: "ipv4", ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Samples: 2, PayloadBytes: 64, MaxBytes: 257, Timeout: 700 * time.Millisecond, Interval: 10 * time.Millisecond})
	if success {
		if err != nil || r.Status != "passed" || r.Sent != 2 || r.Received != 2 || r.Lost != 0 || r.Unfinished != 0 || r.SentBytes != 128 || r.ReceivedBytes != 128 || len(r.Samples) != 2 || target.UDPHits.Load() != before+2 {
			t.Fatalf("actual mapped sequence UDP failed: %+v error=%v", r, err)
		}
		for i, sample := range r.Samples {
			if sample.Sequence != i || sample.Error != "" || sample.RTTMS == nil || sample.Discarded != 0 {
				t.Fatal("mapped UDP did not validate both exact sequence/token replies")
			}
		}
	} else if err == nil || r.Status == "passed" || r.Received != 0 || r.ReceivedBytes != 0 || r.Sent < 1 || target.UDPHits.Load() != before {
		t.Fatalf("closed mapping reached UDP target, fell back direct, or did not attempt the local proxy: %+v error=%v", r, err)
	}
}

func protocolExpansionNATHTTP(t *testing.T, ctx context.Context, client *http.Client, target protocolExpansionTargets, success bool) {
	t.Helper()
	before := target.HTTPHits.Load()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.HTTPURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	matched := false
	status := 0
	if resp != nil {
		status = resp.StatusCode
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		matched = err == nil && readErr == nil && status == http.StatusOK && string(body) == "protocol-expansion-owned-payload"
	}
	if success {
		if !matched || target.HTTPHits.Load() != before+1 {
			t.Fatalf("actual mapped TCP payload failed: status=%d error=%v", status, err)
		}
	} else if err == nil && status < 400 || target.HTTPHits.Load() != before {
		t.Fatal("new TCP request succeeded or reached target after its external mapping was closed")
	}
}

func protocolExpansionNATRun(t *testing.T, core, version string, ipv6 bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	cases := []protocolExpansionPhase2Case{{Protocol: "anytls"}, {Protocol: "trojan"}}
	cases = append(cases, protocolExpansionPhase2Cases()...)
	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			t.Fatal("controlled protocol NAT gate exceeded its 110s budget", err)
		}
		t.Run(c.name(), func(t *testing.T) {
			caseCtx, caseCancel := context.WithTimeout(ctx, 25*time.Second)
			defer caseCancel()
			var s State
			if c.Protocol == "anytls" || c.Protocol == "trojan" {
				s = protocolExpansionTLSState(t, version)
				index := 0
				if c.Protocol == "trojan" {
					index = 1
				}
				s.Nodes = []Node{s.Nodes[index]}
			} else {
				s = protocolExpansionPhase2State(t, version, c)
			}
			root := t.TempDir()
			before, err := Server(s, root)
			if err != nil {
				t.Fatal(err)
			}
			local := s.Nodes[0].Port
			host := "127.0.0.2"
			if ipv6 {
				host = "::1"
			}
			forward := protocolExpansionNATStartForward(t, c.Protocol, host, local, ipv6)
			mapped := s.Clone()
			mapped.Nodes[0].Host, mapped.Nodes[0].ConnectPort = host, endpointPort(forward.port)
			after, err := Server(mapped, root)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("Host/ConnectPort changed server listener, protocol settings or certificate", err)
			}
			backend := &protocolExpansionBackend{processBackend: processBackend{root: root, bin: core}}
			store := &Store{Root: root, Backend: backend, GID: -1}
			t.Cleanup(func() {
				if err := backend.Stop(); err != nil {
					t.Error(err)
				}
			})
			if err = store.WithLock(func() error { return store.Apply(mapped) }); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			n := loaded.Nodes[0]
			pid := backend.cmd.Process.Pid
			assertLocal := func() {
				t.Helper()
				if !backend.Active() || backend.cmd.Process.Pid != pid || n.Port != local || n.Listen != "127.0.0.1" || EffectiveConnectPort(n) == local {
					t.Fatal("mapping altered/stopped the local core or collapsed external/local identity")
				}
				owned, e := coreOwnedListeners("/proc", pid)
				if e != nil {
					t.Fatal("owned local listener observation unavailable", e)
				}
				networks := []string{"tcp"}
				if c.Protocol == "ss-aead" {
					networks = []string{"tcp", "udp"}
				} else if c.Protocol == "tuic" {
					networks = []string{"udp"}
				}
				for _, network := range networks {
					if !owned[coreListener{network, local}] {
						t.Fatal("actual owned local server listener changed", network, local)
					}
				}
				actual, e := os.ReadFile(filepath.Join(root, "current", "server.json"))
				if e != nil || !bytes.Equal(actual, after) {
					t.Fatal("managed server config changed while forwarding was toggled", e)
				}
			}
			assertLocal()
			target := protocolExpansionTarget(t)
			port, client, stop := protocolExpansionNATClient(t, core, version, n)
			defer stop()
			protocolExpansionNATHTTP(t, caseCtx, client, target, true)
			protocolExpansionNATUDP(t, caseCtx, port, target, true)
			if forward.tcp != nil && forward.tcp.accepted.Load() == 0 || forward.udp != nil && (forward.udp.requests.Load() == 0 || forward.udp.responses.Load() == 0) {
				t.Fatal("successful traffic did not traverse every required external transport")
			}
			forward.close()
			assertLocal() // The server remains live while only this owned mapping stops.
			_, blockedHTTP, stopHTTP := protocolExpansionNATClient(t, core, version, n)
			protocolExpansionNATHTTP(t, caseCtx, blockedHTTP, target, false)
			stopHTTP()
			// A separate new core avoids reusing a pooled TLS/QUIC session or a
			// canceled HTTP handshake for the independent UDP failure witness.
			blockedUDP, _, stopUDP := protocolExpansionNATClient(t, core, version, n)
			protocolExpansionNATUDP(t, caseCtx, blockedUDP, target, false)
			stopUDP()
			assertLocal()
			if target.HTTPHits.Load() != 1 || target.UDPHits.Load() != 2 {
				t.Fatal("closed mapping sent additional traffic to the controlled targets")
			}
			if forward.tcp != nil && forward.tcp.bytesIn.Load() == 0 {
				t.Fatal("closed owned TCP relay recorded no forwarded protocol bytes")
			}
			transport := "TCP"
			if c.Protocol == "ss-aead" {
				transport = "TCP+UDP same external port"
			} else if c.Protocol == "tuic" {
				transport = "UDP"
			}
			t.Logf("official %s %s external=%s local=127.0.0.1:%d carrier=%s: exact exported endpoint and unchanged owned server; real TCP and sequence UDP0/1 passed; closed relay denied separate fresh TCP/UDP clients with unchanged target counts; IPv6 endpoint=%t (IPv4 local listener/controlled payload targets)", version, c.name(), net.JoinHostPort(host, strconv.Itoa(forward.port)), local, transport, ipv6)
		})
	}
}

func TestOfficialCoreProtocolExpansionControlledNAT(t *testing.T) {
	if os.Getenv("QINGNODE_PROTOCOL_NAT_TEST") != "1" {
		t.Skip("QINGNODE_PROTOCOL_NAT_TEST=1 and verified SING_BOX_BIN required; new protocol IPv4 NAT not measured")
	}
	core, version, _ := protocolExpansionInputs(t, false)
	protocolExpansionNATRun(t, core, version, false)
}

func TestOfficialCoreProtocolExpansionControlledNATIPv6(t *testing.T) {
	if os.Getenv("QINGNODE_PROTOCOL_NAT_IPV6_TEST") != "1" {
		t.Skip("QINGNODE_PROTOCOL_NAT_IPV6_TEST=1 and verified SING_BOX_BIN required; independent IPv6 endpoint gate not measured")
	}
	tcp, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 TCP loopback is actually unavailable; independent IPv6 endpoint gate skipped: %v", err)
	}
	tcp.Close()
	udp, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 UDP loopback is actually unavailable; independent IPv6 endpoint gate skipped: %v", err)
	}
	udp.Close()
	core, version, _ := protocolExpansionInputs(t, false)
	protocolExpansionNATRun(t, core, version, true)
}
