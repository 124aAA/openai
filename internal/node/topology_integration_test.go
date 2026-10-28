//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"qingnode/internal/probe"
)

func topologyOfficialCore(t *testing.T) (string, string, string) {
	t.Helper()
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("SING_BOX_BIN unset; real topology data paths not run")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("topology fixture core must be an absolute verified input")
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(b)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimPrefix(strings.Split(string(output), "\n")[0], "sing-box version ")
	version = strings.TrimSpace(version)
	if !SupportedVersion(version) {
		t.Fatal("unsupported real fixture core")
	}
	return bin, hex.EncodeToString(digest[:]), version
}

// This test fixture starts exactly the official core with a generated private
// config. Namespace launch is only used after creating our own namespace. Core
// errors stay private: upstream WireGuard errors may contain IPC key material.
func topologyStartCore(t *testing.T, bin string, raw []byte, namespace string, bindings []LocalBinding) func() {
	t.Helper()
	path := filepath.Join(t.TempDir(), "topology-core.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	check := exec.CommandContext(ctx, bin, "check", "-c", path)
	check.Stdout, check.Stderr = io.Discard, io.Discard
	err := check.Run()
	cancel()
	if err != nil {
		t.Fatalf("official core rejected generated topology (private details suppressed): %v", err)
	}
	args := []string{bin, "run", "-c", path}
	if namespace != "" {
		args = append([]string{"ip", "netns", "exec", namespace}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("owned topology core group did not exit")
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-done:
			t.Fatal("official topology core exited before owned listeners")
		default:
		}
		sockets := ReadSockets("/proc", cmd.Process.Pid)
		all := len(bindings) > 0
		for _, binding := range bindings {
			found := false
			for _, socket := range sockets {
				if socket.Owned && socket.Network == bindingTransport(binding.Network) && socket.Port == binding.Port && (binding.Address == socket.Address) && (socket.State == "07" || socket.State == "0A") {
					found = true
					break
				}
			}
			// wireguard-go explicitly tolerates an absent address family. An
			// enabled family is still required to have its owned exact socket.
			if !found && binding.Network == "udp6" {
				if _, err := os.Stat("/proc/net/if_inet6"); os.IsNotExist(err) {
					found = true
				}
			}
			all = all && found
		}
		if all {
			return stop
		}
		if time.Now().After(deadline) {
			t.Fatal("generated topology did not acquire all its exact address/transport sockets")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func topologyEncode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func topologyUDPExchange(t *testing.T, address string, payload []byte) {
	t.Helper()
	c, err := net.DialTimeout("udp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload)+1)
	n, err := c.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("actual UDP forwarding payload differs: %v", err)
	}
}

func topologyHTTPClient(t *testing.T, port int, cert *x509.Certificate) *http.Client {
	t.Helper()
	proxy, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	if cert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	transport.DisableKeepAlives = true
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestOfficialCoreTopologyPureTCPUDPForwards(t *testing.T) {
	bin, _, version := topologyOfficialCore(t)
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("forwarded-by-official-direct-inbound"))
	}))
	defer target.Close()
	udpTarget, udpRequests := probeTestUDP(t, true)
	_, targetPortText, _ := net.SplitHostPort(target.Listener.Addr().String())
	targetPort, _ := strconv.Atoi(targetPortText)
	udpHost, udpPortText, _ := net.SplitHostPort(udpTarget)
	udpPort, _ := strconv.Atoi(udpPortText)
	localPort := freePort(t)
	st := NewState()
	st.CoreVersion = version
	st.Forwards = []PortForward{
		{ID: Token(8), Name: "TCP direct forward", Listen: "127.0.0.1", Port: localPort, Network: "tcp", TargetHost: "127.0.0.1", TargetPort: targetPort, Enabled: true},
		{ID: Token(8), Name: "UDP direct forward", Listen: "127.0.0.1", Port: localPort, Network: "udp", TargetHost: udpHost, TargetPort: udpPort, Enabled: true},
	}
	raw, err := Server(st, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	topologyStartCore(t, bin, raw, "", StateBindings(st))
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(localPort))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	response.Body.Close()
	if err != nil || string(body) != "forwarded-by-official-direct-inbound" || requests.Load() != 1 {
		t.Fatal("real TCP direct forwarding failed", err)
	}
	for sequence := 0; sequence < 3; sequence++ {
		topologyUDPExchange(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), []byte(fmt.Sprintf("qingnode-sequence-%d", sequence)))
	}
	if udpRequests.Load() != 3 {
		t.Fatal("UDP forward bypassed controlled target")
	}
	t.Logf("official %s generated Server direct inbounds: same local port%d distinct TCP/UDP => HTTP payload +3 exact sequence echoes; separate local target ports, owned socket readiness", version, localPort)
}

func topologyRemoteFixture(t *testing.T, version, protocol string) (State, Egress) {
	t.Helper()
	remote := NewState()
	remote.CoreVersion = version
	n := ssFixture()
	n.Host, n.Listen, n.Port = "127.0.0.1", "127.0.0.1", freePort(t)
	n.Users = n.Users[:1]
	e := Egress{ID: Token(8), Name: "Remote " + protocol, Protocol: protocol, Server: n.Host, Port: n.Port, UDP: true}
	switch protocol {
	case "ss2022":
		e.Shadowsocks = &RemoteSS{Method: SS2022Method, Password: SSPassword(n, n.Users[0])}
	case "hysteria2":
		n = hyFixture(t).Nodes[0]
		n.Host, n.Listen, n.Port = "127.0.0.1", "127.0.0.1", freePort(t)
		e.Server, e.Port = n.Host, n.Port
		e.HY2 = &RemoteHY2{Password: n.Users[0].Password, ServerName: n.Certificate.ServerName, CertificatePEM: n.Certificate.CertPEM}
	case "reality":
		cert, key := makeCert(t)
		pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("controlled handshake")) }))
		handshake.EnableHTTP2 = true
		handshake.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
		handshake.StartTLS()
		t.Cleanup(handshake.Close)
		r, err := NewReality("localhost", handshake.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		n.Protocol, n.Reality, n.Shadowsocks, n.Users = "reality", r, nil, []User{NewUser("remote", "reality")}
		e.Reality = &RemoteReality{UUID: n.Users[0].UUID, ServerName: r.ServerName, PublicKey: r.PublicKey, ShortID: r.ShortID, Fingerprint: "chrome"}
	default:
		t.Fatal("unsupported fixture protocol")
	}
	remote.Nodes = []Node{n}
	return remote, e
}

func TestOfficialCoreTopologyEntryToRemoteProtocols(t *testing.T) {
	bin, _, version := topologyOfficialCore(t)
	for _, protocol := range []string{"ss2022", "reality", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			remote, e := topologyRemoteFixture(t, version, protocol)
			raw, err := Server(remote, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			stopRemote := topologyStartCore(t, bin, raw, "", StateBindings(remote))
			entry := ssFixture()
			entry.Name = "local entry"
			entry.Host, entry.Listen, entry.Port = "127.0.0.1", "127.0.0.1", freePort(t)
			entry.Users = entry.Users[:1]
			entry.EgressID = e.ID
			st := NewState()
			st.CoreVersion = version
			st.Nodes = []Node{entry}
			st.Egresses = []Egress{e}
			raw, err = Server(st, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			topologyStartCore(t, bin, raw, "", StateBindings(st))
			clientPort := freePort(t)
			clientRaw := topologyEncode(t, Client(entry, entry.Users[0], clientPort))
			startCore(t, bin, clientRaw)
			var requests atomic.Int64
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Write([]byte("entry-and-remote-payload"))
			}))
			defer target.Close()
			client := topologyHTTPClient(t, clientPort, target.Certificate())
			r, err := client.Get(target.URL)
			if err != nil {
				t.Fatal("entry+remote actual HTTPS failed", err)
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			r.Body.Close()
			if err != nil || string(body) != "entry-and-remote-payload" || requests.Load() != 1 {
				t.Fatal("entry+remote target payload differs", err)
			}
			udpTarget, count := probeTestUDP(t, true)
			u, err := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udpTarget, ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
			if err != nil || u.Sent != 2 || u.Received != 2 || count.Load() != 2 {
				t.Fatalf("entry+remote actual UDP failed: %+v %v target=%d", u, err, count.Load())
			}
			for _, format := range []string{"uri", "sing-box", "mihomo"} {
				out, err := Export(entry, entry.Users[0], format)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{remote.Nodes[0].Users[0].Password, remote.Nodes[0].Users[0].UUID} {
					if secret != "" && bytes.Contains(out, []byte(secret)) {
						t.Fatal("entry export exposed internal remote credential", format)
					}
				}
			}
			stopRemote()
			before := requests.Load()
			response, err := client.Get(target.URL)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || requests.Load() != before {
				t.Fatal("remote exit stopped but entry silently used direct")
			}
			beforeUDP := count.Load()
			u, udpErr := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udpTarget, ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), Samples: 1, PayloadBytes: 64, Timeout: 700 * time.Millisecond})
			if udpErr == nil || u.Received != 0 || count.Load() != beforeUDP {
				t.Fatalf("remote exit stopped but UDP escaped: %+v %v", u, udpErr)
			}
			control, err := target.Client().Get(target.URL)
			if err != nil {
				t.Fatal("controlled origin became unavailable", err)
			}
			control.Body.Close()
			t.Logf("official %s actual Server SS2022 entry -> remote %s: HTTPS payload and2 sequence UDP replies; stopping remote blocks new TCP/UDP while origin stays reachable; client exports contain entry credentials only", version, protocol)
		})
	}
}

func topologyWGKeyPair(t *testing.T) (string, string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// This opt-in uses only an owned veth + netns, without a system WG interface,
// host default route, firewall rule or sysctl change. Only the owned namespace
// gets a default interface; target-side source IP proves the landing path.
func TestOfficialCoreTopologyWireGuardNamespaceExit(t *testing.T) {
	if os.Getenv("QINGNODE_TOPOLOGY_DISPOSABLE") != "1" {
		t.Skip("QINGNODE_TOPOLOGY_DISPOSABLE=1 required for owned Linux netns/veth acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("explicit topology namespace acceptance needs disposable root capability")
	}
	bin, digest, version := topologyOfficialCore(t)
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatal("opt-in namespace acceptance needs iproute2")
	}
	run := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("owned fixture %s: %w: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	id := Token(4)
	ns, hostIf, peerIf := "qn-wg-"+id, "qnwh"+id, "qnwp"+id
	suffix, _ := strconv.ParseUint(id[:2], 16, 8)
	base := fmt.Sprintf("198.18.%d", suffix)
	targetIP, landingIP := base+".1", base+".2"
	if out, err := exec.Command("ip", "route", "show", "match", base+".0/30").Output(); err != nil {
		t.Fatal("cannot prove selected fixture subnet ownership")
	} else {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "default ") {
				t.Skip("chosen fixture subnet already routed; refusing to shadow another route")
			}
		}
	}
	if err := run("ip", "netns", "add", ns); err != nil {
		t.Fatal("opt-in namespace capability unavailable", err)
	}
	t.Cleanup(func() {
		if err := run("ip", "netns", "del", ns); err != nil {
			t.Error(err)
		}
	})
	if err := run("ip", "link", "add", hostIf, "type", "veth", "peer", "name", peerIf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := run("ip", "link", "del", hostIf); err != nil {
			t.Error(err)
		}
	})
	// 1.14.3 pauses endpoint networking when there is no default interface.
	// This route stays in the fresh test namespace and uses its reachable peer.
	for _, args := range [][]string{{"ip", "link", "set", peerIf, "netns", ns}, {"ip", "addr", "add", targetIP + "/30", "dev", hostIf}, {"ip", "link", "set", hostIf, "up"}, {"ip", "netns", "exec", ns, "ip", "addr", "add", landingIP + "/30", "dev", peerIf}, {"ip", "netns", "exec", ns, "ip", "link", "set", peerIf, "up"}, {"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"}, {"ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", targetIP, "dev", peerIf}} {
		if err := run(args...); err != nil {
			t.Fatal(err)
		}
	}
	privateA, publicA := topologyWGKeyPair(t)
	privateB, publicB := topologyWGKeyPair(t)
	port := 25120
	landing := NewState()
	landing.CoreVersion = version
	landing.Egresses = []Egress{{ID: Token(8), Name: "WG landing", Protocol: "wireguard", UDP: true, WireGuard: &WireGuardEndpoint{Address: []string{"10.79.0.2/32"}, PrivateKey: privateB, ListenPort: port, MTU: 1408, ReceiveEgressID: "direct", Peers: []WireGuardPeer{{PublicKey: publicA, AllowedIPs: []string{"10.79.0.1/32"}}}}}}
	raw, err := Server(landing, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stopLanding := topologyStartCore(t, bin, raw, ns, StateBindings(landing))
	wg := Egress{ID: Token(8), Name: "WG egress", Protocol: "wireguard", UDP: true, WireGuard: &WireGuardEndpoint{Address: []string{"10.79.0.1/32"}, PrivateKey: privateA, MTU: 1408, Peers: []WireGuardPeer{{Address: landingIP, Port: port, PublicKey: publicB, AllowedIPs: []string{base + ".0/30"}}}}}
	entry := ssFixture()
	entry.Host, entry.Listen, entry.Port = "127.0.0.1", "127.0.0.1", freePort(t)
	entry.Users = entry.Users[:1]
	entry.EgressID = wg.ID
	st := NewState()
	st.CoreVersion = version
	st.Nodes = []Node{entry}
	st.Egresses = []Egress{wg}
	raw, err = Server(st, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	topologyStartCore(t, bin, raw, "", StateBindings(st))
	var requests atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Write([]byte(source))
	}))
	target.Listener.Close()
	listener, err := net.Listen("tcp4", net.JoinHostPort(targetIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	target.Listener = listener
	target.Start()
	defer target.Close()
	udp, err := net.ListenPacket("udp4", net.JoinHostPort(targetIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var udpRequests atomic.Int64
	var udpSource atomic.Value
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 1201)
		for {
			n, from, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpRequests.Add(1)
			source, _, _ := net.SplitHostPort(from.String())
			udpSource.Store(source)
			_, _ = udp.WriteTo(buffer[:n], from)
		}
	}()
	t.Cleanup(func() { udp.Close(); <-udpDone })
	clientPort := freePort(t)
	startCore(t, bin, topologyEncode(t, Client(entry, entry.Users[0], clientPort)))
	client := topologyHTTPClient(t, clientPort, nil)
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal("generated WG topology failed non-loopback HTTP payload", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	response.Body.Close()
	if err != nil || string(body) != landingIP || requests.Load() != 1 {
		t.Fatalf("WG observed exit source %q, expected landing %s: %v", body, landingIP, err)
	}
	u, err := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udp.LocalAddr().String(), ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), Samples: 3, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
	if err != nil || u.Received != 3 || udpRequests.Load() != 3 || udpSource.Load() != landingIP {
		t.Fatalf("WG non-loopback UDP exit mismatch: %+v %v source=%v", u, err, udpSource.Load())
	}
	// Independently test the manager's exact derived egress closure using the
	// same authenticated graph sandbox used by health diagnostics.
	outs, eps, finalTag, err := BuildEgressGraph(st, wg.ID)
	if err != nil {
		t.Fatal(err)
	}
	outRaw, epRaw := []json.RawMessage{}, []json.RawMessage{}
	for _, out := range outs {
		outRaw = append(outRaw, topologyEncode(t, out))
	}
	for _, ep := range eps {
		epRaw = append(epRaw, topologyEncode(t, ep))
	}
	profile, err := probe.NewGraphProfile(wg.ID, version, finalTag, outRaw, epRaw)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := probe.StartGraphSandbox(context.Background(), profile, probe.SandboxOptions{CoreBinary: bin, SHA256: digest, TempParent: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer sandbox.Close()
	graphTransport := sandbox.Transport()
	graphTransport.DisableKeepAlives = true
	defer graphTransport.CloseIdleConnections()
	graphClient := &http.Client{Transport: graphTransport, Timeout: 2 * time.Second}
	response, err = graphClient.Get(target.URL)
	if err != nil {
		t.Fatal("derived graph disagreed with real server route", err)
	}
	body, _ = io.ReadAll(io.LimitReader(response.Body, 128))
	response.Body.Close()
	if string(body) != landingIP {
		t.Fatal("derived graph used wrong exit", string(body))
	}
	stopLanding()
	before, beforeUDP := requests.Load(), udpRequests.Load()
	response, err = client.Get(target.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || requests.Load() != before {
		t.Fatal("stopped WG landing silently used direct")
	}
	u, udpErr := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udp.LocalAddr().String(), ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), Samples: 1, PayloadBytes: 64, Timeout: 700 * time.Millisecond})
	if udpErr == nil || u.Received != 0 || udpRequests.Load() != beforeUDP {
		t.Fatalf("stopped WG landing leaked UDP: %+v %v", u, udpErr)
	}
	control := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
	response, err = control.Get(target.URL)
	if err != nil {
		t.Fatal("controlled target no longer reachable independently", err)
	}
	response.Body.Close()
	for _, args := range [][]string{{"ip", "route", "get", targetIP}, {"ip", "netns", "exec", ns, "ip", "route", "get", targetIP}, {"ip", "netns", "exec", ns, "ip", "address", "show", "dev", peerIf}} {
		out, err := exec.Command(args[0], args[1:]...).Output()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("route/source evidence: %s", strings.TrimSpace(string(out)))
	}
	t.Logf("official %s generated SS2022 entry -> userspace WG endpoint -> separate landing namespace: non-loopback target %s observed actual exit%s for HTTP payload+3 sequence UDP; derived graph agrees; stop landing blocks new TCP/UDP while target direct control remains available; owned namespace/veth only", version, targetIP, landingIP)
}
