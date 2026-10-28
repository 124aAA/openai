package node

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/probe"
)

func probeTestCore(t *testing.T, bin string, config []byte) func() {
	t.Helper()
	p := filepath.Join(t.TempDir(), "probe.json")
	if e := os.WriteFile(p, config, 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command(bin, "check", "-c", p).CombinedOutput(); e != nil {
		t.Fatalf("probe config rejected: %v\n%s", e, out)
	}
	log, e := os.CreateTemp(t.TempDir(), "core-log-")
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(bin, "run", "-c", p)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("probe core did not exit")
			}
			log.Close()
			if t.Failed() {
				b, _ := os.ReadFile(log.Name())
				t.Logf("probe core log: %s", b)
			}
		})
	}
	t.Cleanup(stop)
	if e = waitCoreListeners(cmd.Process.Pid, config, done, 5*time.Second); e != nil {
		select {
		case <-done:
			t.Fatalf("probe core exited before its own listeners became ready: %v (%v)", e, exitErr)
		default:
			t.Fatalf("probe core listener readiness: %v", e)
		}
	}
	return stop
}

func probeTestUDP(t *testing.T, echo bool) (string, *atomic.Int32) {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1201)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			count.Add(1)
			if echo {
				_, _ = c.WriteTo(b[:n], a)
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("controlled UDP target leaked")
		}
	})
	return c.LocalAddr().String(), count
}

func probeTestNXDOMAIN(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1500)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			if n < 12 {
				continue
			}
			count.Add(1)
			response := append([]byte(nil), b[:n]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8183)
			for i := 6; i < 12; i++ {
				response[i] = 0
			}
			_, _ = c.WriteTo(response, a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).Port, count
}

func probeTransport(t *testing.T, port int, cert, username, password string) *http.Transport {
	t.Helper()
	u, e := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if e != nil {
		t.Fatal(e)
	}
	if username != "" {
		u.User = url.UserPassword(username, password)
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM([]byte(cert)) {
		t.Fatal("fixture CA parse")
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: ca, MinVersion: tls.VersionTLS12}}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

// The endpoint counters and failure with the selected server disabled prove
// these measurements cannot silently use a direct outbound. They are loopback
// protocol evidence, not evidence about a user's ISP or a public VPS.
func TestOfficialCoreBoundedProbeThreeProtocolsAndFaults(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires a verified official sing-box binary")
	}
	cert, key := makeCert(t)
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("reality target")) }))
	handshake.EnableHTTP2 = true
	handshake.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	handshake.StartTLS()
	defer handshake.Close()
	originRequests := &atomic.Int32{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originRequests.Add(1)
		if r.URL.Path == "/download" {
			w.Header().Set("Content-Length", "8192")
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			for i := 0; i < 8; i++ {
				time.Sleep(10 * time.Millisecond)
				if _, e := w.Write(make([]byte, 1024)); e != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			return
		}
		w.Write([]byte("selected-proxy-controlled-origin"))
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	defer origin.Close()
	udp, udpRequests := probeTestUDP(t, true)
	blackhole, blackholeRequests := probeTestUDP(t, false)
	dnsPort, dnsRequests := probeTestNXDOMAIN(t)
	reality, e := NewReality("localhost", handshake.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	ss := ssFixture()
	ss.Host, ss.Listen, ss.Port = "127.0.0.1", "127.0.0.1", freePort(t)
	s := NewState()
	s.Nodes = []Node{{ID: Token(8), Name: "probe reality", Protocol: "reality", Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true, Users: []User{NewUser("fixture", "reality")}, Reality: reality}, ss, {ID: Token(8), Name: "probe hy2", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true, Users: []User{NewUser("fixture", "hysteria2")}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
	server, e := Server(s, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	var controlled M
	if e = json.Unmarshal(server, &controlled); e != nil {
		t.Fatal(e)
	}
	controlled["dns"] = M{"servers": []any{M{"type": "udp", "tag": "controlled-dns", "server": "127.0.0.1", "server_port": dnsPort}}}
	controlled["route"].(map[string]any)["default_domain_resolver"] = "controlled-dns"
	server, e = json.Marshal(controlled)
	if e != nil {
		t.Fatal(e)
	}
	stopServer := probeTestCore(t, bin, server)
	coreBytes, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	coreHash := sha256.Sum256(coreBytes)
	sandboxes := map[int]*probe.Sandbox{}
	newClient := func(t *testing.T, n Node, u User) (int, func()) {
		t.Helper()
		outbound := Outbound(n, u)
		if n.Protocol == "hysteria2" {
			outbound["tls"].(M)["certificate"] = []string{cert}
		}
		encoded, e := json.Marshal(outbound)
		if e != nil {
			t.Fatal(e)
		}
		p, e := probe.NewProfile(n.ID, s.CoreVersion, encoded)
		if e != nil {
			t.Fatal(e)
		}
		sandbox, e := probe.StartSandbox(context.Background(), p, probe.SandboxOptions{CoreBinary: bin, SHA256: hex.EncodeToString(coreHash[:]), TempParent: t.TempDir()})
		if e != nil {
			t.Fatal(e)
		}
		_, portString, _ := net.SplitHostPort(sandbox.Address)
		port, _ := strconv.Atoi(portString)
		sandboxes[port] = sandbox
		stop := func() {
			if e := sandbox.Close(); e != nil {
				t.Error(e)
			}
			if _, e := os.Stat(sandbox.Directory); !os.IsNotExist(e) {
				t.Error("private sandbox directory remains", e)
			}
		}
		t.Cleanup(stop)
		return port, stop
	}
	run := func(t *testing.T, n Node, port int, target, udpTarget string) probe.Report {
		t.Helper()
		sandbox := sandboxes[port]
		r, e := probe.Run(context.Background(), probe.Options{Path: "client-proxy", Mode: "light", TargetURL: target, Family: "auto", Timeout: 5 * time.Second, MaxBytes: 4096, Samples: 2, Concurrency: 1, Initiator: "controlled loopback fixture", NodeID: n.ID, UDPAddress: udpTarget, UDPProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), UDPProxyUsername: sandbox.Username, UDPProxyPassword: sandbox.Password, UDPTimeout: 300 * time.Millisecond}, probe.Dependencies{Transport: probeTransport(t, port, cert, sandbox.Username, sandbox.Password)})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	for _, n := range s.Nodes {
		t.Run(n.Protocol, func(t *testing.T) {
			port, stop := newClient(t, n, n.Users[0])
			defer stop()
			beforeOrigin, beforeUDP := originRequests.Load(), udpRequests.Load()
			r := run(t, n, port, origin.URL, udp)
			if r.Status != "completed" || r.UDP == nil || r.UDP.Status != "passed" || r.UDP.Received != 2 || originRequests.Load() <= beforeOrigin || udpRequests.Load() != beforeUDP+2 {
				if r.UDP != nil {
					t.Logf("UDP samples and counters: %+v", *r.UDP)
				}
				t.Logf("controlled target counters: HTTPS %d -> %d; UDP %d -> %d", beforeOrigin, originRequests.Load(), beforeUDP, udpRequests.Load())
				t.Fatalf("official protocol probe failed: %#v", r)
			}
			sandbox := sandboxes[port]
			download, e := probe.Run(context.Background(), probe.Options{Path: "client-proxy", Mode: "download", TargetURL: origin.URL + "/download", Timeout: 3 * time.Second, MaxBytes: 2048, Samples: 2, Concurrency: 1, Initiator: "controlled loopback fixture", NodeID: n.ID}, probe.Dependencies{Transport: probeTransport(t, port, cert, sandbox.Username, sandbox.Password)})
			if e != nil || download.Status != "completed" || download.Traffic.PayloadBytesReceived != 2048 || download.Statistics["download_throughput"].Median == nil {
				t.Fatalf("real single-connection bounded download failed: %#v %v", download, e)
			}
			for _, sample := range download.Samples {
				if sample.Kind == "download" && !sample.BudgetLimited {
					t.Fatal("oversized controlled response was not capped")
				}
			}
			badUser := NewUser("bad-auth", n.Protocol)
			badPort, badStop := newClient(t, n, badUser)
			defer badStop()
			beforeOrigin, beforeUDP = originRequests.Load(), udpRequests.Load()
			r = run(t, n, badPort, origin.URL, udp)
			if r.Status == "completed" || r.UDP == nil || r.UDP.Status == "passed" || originRequests.Load() != beforeOrigin || udpRequests.Load() != beforeUDP {
				t.Fatalf("wrong credentials escaped proxy: %#v", r)
			}
			beforeOrigin = originRequests.Load()
			r = run(t, n, port, origin.URL, blackhole)
			if r.Status == "completed" || r.UDP == nil || r.UDP.Error != "udp_no_response" || r.UDP.Lost != 2 || originRequests.Load() <= beforeOrigin || blackholeRequests.Load() == 0 {
				t.Fatalf("TCP success masked UDP blackhole: %#v", r)
			}
		})
	}
	// Keep a good SS client alive for deterministic target/DNS/IPv6 failures.
	port, stopClient := newClient(t, ss, ss.Users[0])
	defer stopClient()
	t.Run("target-unreachable", func(t *testing.T) {
		r := run(t, ss, port, fmt.Sprintf("https://127.0.0.1:%d", freePort(t)), "")
		if r.Status == "completed" || len(r.Errors) == 0 {
			t.Fatalf("unreachable target passed: %#v", r)
		}
	})
	t.Run("controlled-dns-nxdomain", func(t *testing.T) {
		before := dnsRequests.Load()
		r := run(t, ss, port, "https://qingnode-controlled.invalid/", "")
		if r.Status == "completed" || dnsRequests.Load() == before || r.DNS.Status != "unknown" {
			t.Fatalf("controlled DNS failure missing/independent time invented: %#v", r)
		}
	})
	t.Run("ipv6-unreachable", func(t *testing.T) {
		r := run(t, ss, port, "https://[2001:db8::1]/", "")
		if r.Status == "completed" || len(r.Errors) == 0 {
			t.Fatalf("IPv6 no-route target passed: %#v", r)
		}
	})
	t.Run("disabled-proxy-server", func(t *testing.T) {
		stopServer()
		beforeOrigin, beforeUDP := originRequests.Load(), udpRequests.Load()
		r := run(t, ss, port, origin.URL, udp)
		if r.Status == "completed" || originRequests.Load() != beforeOrigin || udpRequests.Load() != beforeUDP {
			t.Fatalf("disabled server fell back direct: %#v", r)
		}
		resp, e := origin.Client().Get(origin.URL)
		if e != nil {
			t.Fatal("control target was not independently available", e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	})
}

func TestOfficialCoreProbeSandboxCancellationCrashAndConcurrentCleanup(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires a verified official sing-box binary")
	}
	data, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(data)
	n := ssFixture()
	n.Host = "127.0.0.1"
	n.Port = 9
	b, e := json.Marshal(Outbound(n, n.Users[0]))
	if e != nil {
		t.Fatal(e)
	}
	p, e := probe.NewProfile(n.ID, DefaultCore, b)
	if e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	sentinel := filepath.Join(parent, "production-state.json")
	original := []byte("unchanged-production-state-and-credentials")
	if e = os.WriteFile(sentinel, original, 0600); e != nil {
		t.Fatal(e)
	}
	start := func(t *testing.T, ctx context.Context) *probe.Sandbox {
		t.Helper()
		s, e := probe.StartSandbox(ctx, p, probe.SandboxOptions{CoreBinary: bin, SHA256: hex.EncodeToString(sum[:]), TempParent: parent})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s := start(t, ctx)
		cancel()
		select {
		case <-s.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("cancel did not reap actual core")
		}
		if e := s.Close(); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(s.Directory); !os.IsNotExist(e) {
			t.Fatal("cancel leaked private directory", e)
		}
	})
	t.Run("core-crash", func(t *testing.T) {
		s := start(t, context.Background())
		process, e := os.FindProcess(s.PID)
		if e != nil {
			t.Fatal(e)
		}
		if e = process.Kill(); e != nil {
			t.Fatal(e)
		}
		select {
		case <-s.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("crashed core was not reaped")
		}
		r, e := probe.Run(context.Background(), probe.Options{Path: "client-proxy", TargetURL: "https://127.0.0.1:9", Timeout: time.Second, Samples: 1, Initiator: "crash fixture"}, probe.Dependencies{Transport: s.Transport()})
		if e != nil || r.Status == "completed" {
			t.Fatalf("crashed core fabricated a pass: %#v %v", r, e)
		}
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(s.Directory); !os.IsNotExist(e) {
			t.Fatal("core crash leaked private directory", e)
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		var wg sync.WaitGroup
		addresses := make(chan string, 4)
		sandboxes := make(chan *probe.Sandbox, 4)
		failures := make(chan error, 4)
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, e := probe.StartSandbox(context.Background(), p, probe.SandboxOptions{CoreBinary: bin, SHA256: hex.EncodeToString(sum[:]), TempParent: parent})
				if e != nil {
					failures <- e
					return
				}
				sandboxes <- s
				addresses <- s.Address
			}()
		}
		wg.Wait()
		close(failures)
		close(sandboxes)
		close(addresses)
		for e := range failures {
			t.Error(e)
		}
		seen := map[string]bool{}
		for a := range addresses {
			if seen[a] {
				t.Error("concurrent probes share a listener")
			}
			seen[a] = true
		}
		for s := range sandboxes {
			if e := s.Close(); e != nil {
				t.Error(e)
			}
			if _, e := os.Stat(s.Directory); !os.IsNotExist(e) {
				t.Error("concurrent core directory leaked")
			}
		}
	})
	got, e := os.ReadFile(sentinel)
	if e != nil || string(got) != string(original) {
		t.Fatal("probe changed production sentinel", e)
	}
	entries, e := os.ReadDir(parent)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 1 {
		t.Fatalf("probe left private resources: %v", entries)
	}
}
