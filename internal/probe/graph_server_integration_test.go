//go:build linux

package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/node"
)

// A selected WireGuard egress remains an endpoint: its authenticated peer can
// initiate new flows after learning the active endpoint's ephemeral UDP port.
// Exercise the actual manager renderer, rather than a hand-written reject rule.
func TestOfficialCoreGraphServerActiveWireGuardRejectsPeerInitiatedFlows(t *testing.T) {
	bin, _, version := portableOfficialCore(t)
	privateA, publicA := graphWGKeys(t)
	privateB, publicB := graphWGKeys(t)
	wgPort := graphFreePort(t, "udp4")
	normalTCP, normalUDP := graphFreePort(t, "tcp4"), graphFreePort(t, "udp4")
	reverseTCP, reverseUDP := graphFreePort(t, "tcp4"), graphFreePort(t, "udp4")
	var normalRequests, guardRequests, guardConnections atomic.Int64
	normalTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normalRequests.Add(1)
		_, _ = w.Write([]byte("selected-wg-response"))
	}))
	defer normalTarget.Close()
	guardTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardRequests.Add(1)
		_, _ = w.Write([]byte("owned-guard-response"))
	}))
	guardTarget.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			guardConnections.Add(1)
		}
	}
	guardTarget.StartTLS()
	defer guardTarget.Close()
	normalUDPAddress, normalUDPRequests, _ := graphUDPTarget(t)
	guardUDPAddress, guardUDPRequests, _ := graphUDPTarget(t)
	port := func(address string) int {
		_, value, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	pool := x509.NewCertPool()
	pool.AddCert(normalTarget.Certificate())
	pool.AddCert(guardTarget.Certificate())
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, Timeout: 2 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	// Direct controls prove both protected targets are live before the attack;
	// a blocked reverse flow must not be explained by an unavailable target.
	graphRequireHTTPS(t, client, guardTarget.URL, "owned-guard-response")
	control, err := RunUDP(context.Background(), UDPOptions{Target: guardUDPAddress, Samples: 1, PayloadBytes: 64, Timeout: time.Second})
	if err != nil || control.Received != 1 || guardUDPRequests.Load() != 1 {
		t.Fatal("owned reverse UDP target control failed", err)
	}
	guardRequests.Store(0)
	guardConnections.Store(0)
	guardUDPRequests.Store(0)
	a := node.NewState()
	a.CoreVersion = version
	a.Egresses = []node.Egress{{ID: "a111111111111111", Name: "active-egress", Protocol: "wireguard", UDP: true, WireGuard: &node.WireGuardEndpoint{Address: []string{"10.79.0.1/32"}, PrivateKey: privateA, MTU: 1408, Peers: []node.WireGuardPeer{{Address: "127.0.0.1", Port: wgPort, PublicKey: publicB, AllowedIPs: []string{"10.79.0.2/32"}}}}}}
	a.Forwards = []node.PortForward{
		{ID: "a222222222222222", Name: "normal-tcp", Listen: "127.0.0.1", Port: normalTCP, Network: "tcp", TargetHost: "10.79.0.2", TargetPort: port(normalTarget.Listener.Addr().String()), EgressID: a.Egresses[0].ID, Enabled: true},
		{ID: "a333333333333333", Name: "normal-udp", Listen: "127.0.0.1", Port: normalUDP, Network: "udp", TargetHost: "10.79.0.2", TargetPort: port(normalUDPAddress), EgressID: a.Egresses[0].ID, Enabled: true},
	}
	b := node.NewState()
	b.CoreVersion = version
	b.Egresses = []node.Egress{{ID: "b111111111111111", Name: "explicit-landing", Protocol: "wireguard", UDP: true, WireGuard: &node.WireGuardEndpoint{Address: []string{"10.79.0.2/32"}, PrivateKey: privateB, ListenPort: wgPort, MTU: 1408, ReceiveEgressID: "direct", Peers: []node.WireGuardPeer{{PublicKey: publicA, AllowedIPs: []string{"10.79.0.1/32"}}}}}}
	// These private fixture listeners model a peer initiating new connections.
	// They are all loopback-only; production interfaces and routes are unchanged.
	b.Forwards = []node.PortForward{
		{ID: "b222222222222222", Name: "peer-new-tcp", Listen: "127.0.0.1", Port: reverseTCP, Network: "tcp", TargetHost: "10.79.0.1", TargetPort: port(guardTarget.Listener.Addr().String()), EgressID: b.Egresses[0].ID, Enabled: true},
		{ID: "b333333333333333", Name: "peer-new-udp", Listen: "127.0.0.1", Port: reverseUDP, Network: "udp", TargetHost: "10.79.0.1", TargetPort: port(guardUDPAddress), EgressID: b.Egresses[0].ID, Enabled: true},
	}
	start := func(st node.State, ready int) {
		raw, err := node.Server(st, t.TempDir())
		if err != nil {
			t.Fatal("manager rejected owned WG reverse fixture", err)
		}
		var config map[string]any
		if err = json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		graphFixtureCore(t, bin, config, ready)
	}
	start(b, reverseTCP)
	start(a, normalTCP)
	normalURL := "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(normalTCP))
	graphRequireHTTPS(t, client, normalURL, "selected-wg-response")
	u, err := RunUDP(context.Background(), UDPOptions{Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(normalUDP)), Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
	if err != nil || u.Received != 2 || normalRequests.Load() != 1 || normalUDPRequests.Load() != 2 {
		t.Fatalf("normal HTTPS/UDP replies through active WG failed: %+v %v", u, err)
	}
	response, reverseErr := client.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(reverseTCP)))
	if response != nil {
		response.Body.Close()
	}
	if reverseErr == nil || guardRequests.Load() != 0 || guardConnections.Load() != 0 {
		t.Errorf("peer-initiated TCP reached active egress host: requestSucceeded=%t targetTCP=%d targetHTTP=%d", reverseErr == nil, guardConnections.Load(), guardRequests.Load())
	}
	reverse, reverseUDPErr := RunUDP(context.Background(), UDPOptions{Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(reverseUDP)), Samples: 2, PayloadBytes: 64, Timeout: 700 * time.Millisecond, Interval: 10 * time.Millisecond})
	if reverseUDPErr == nil || reverse.Received != 0 || guardUDPRequests.Load() != 0 {
		t.Errorf("peer-initiated UDP reached active egress host: received=%d targetUDP=%d errorPresent=%t", reverse.Received, guardUDPRequests.Load(), reverseUDPErr != nil)
	}
	graphRequireHTTPS(t, client, normalURL, "selected-wg-response")
	u, err = RunUDP(context.Background(), UDPOptions{Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(normalUDP)), Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
	if err != nil || u.Received != 2 || normalRequests.Load() != 2 || normalUDPRequests.Load() != 4 {
		t.Fatalf("rejecting peer-initiated flows broke established-direction HTTPS/UDP: %+v %v", u, err)
	}
	t.Logf("official %s actual manager Server: normal HTTPS=%d sequence UDP=%d; peer-new target counters TCP=%d HTTP=%d UDP=%d", version, normalRequests.Load(), normalUDPRequests.Load(), guardConnections.Load(), guardRequests.Load(), guardUDPRequests.Load())
}
