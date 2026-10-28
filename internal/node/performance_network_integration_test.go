//go:build linux

package node

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
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

// This opt-in test alters only its own netns/veth/cgroup. It never changes a
// default route, a production listener, the manager State, or a host sysctl.
// Retain raw reports with QINGNODE_NETEM_RESULTS=/absolute/new-directory.
func TestOfficialCoreHY2ControlledNetwork(t *testing.T) {
	if os.Getenv("QINGNODE_NETEM_TEST") != "1" {
		t.Skip("QINGNODE_NETEM_TEST=1 required: disposable root Linux netns/netem acceptance not run")
	}
	if os.Geteuid() != 0 {
		t.Skip("controlled network requires root or an equivalent disposable privileged environment")
	}
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" || !filepath.IsAbs(bin) {
		t.Fatal("opt-in requires an absolute checksum-verified SING_BOX_BIN")
	}
	for _, name := range []string{"ip", "tc"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s unavailable; no controlled network evidence", name)
		}
	}
	core, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(core)
	version, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual official core: %s; binary SHA256=%s", strings.TrimSpace(string(version)), hex.EncodeToString(hash[:]))
	resultDir := t.TempDir()
	if requested := os.Getenv("QINGNODE_NETEM_RESULTS"); requested != "" {
		if !filepath.IsAbs(requested) {
			t.Fatal("QINGNODE_NETEM_RESULTS must be absolute")
		}
		if err = os.Mkdir(requested, 0700); err != nil {
			t.Fatal("results directory must be new", err)
		}
		resultDir = requested
	}
	run := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	id := Token(4)
	ns, hostIf, peerIf := "qn-n-"+id, "qnh"+id, "qnp"+id
	if err = run("ip", "netns", "add", ns); err != nil {
		t.Skipf("netns unavailable; no network shaping executed: %v", err)
	}
	t.Cleanup(func() {
		if e := run("ip", "netns", "del", ns); e != nil {
			t.Error("owned namespace cleanup", e)
		}
	})
	if err = run("ip", "link", "add", hostIf, "type", "veth", "peer", "name", peerIf); err != nil {
		t.Skipf("veth unavailable: %v", err)
	}
	t.Cleanup(func() {
		// Namespace deletion also removes its peer, but this owned host link is
		// deleted first on normal and failure paths.
		if e := run("ip", "link", "del", hostIf); e != nil {
			t.Error("owned veth cleanup", e)
		}
	})
	// 198.18/15 is reserved for benchmarking. Reject a preexisting route to
	// the chosen /30 instead of replacing anyone else's route or address.
	suffix, _ := strconv.ParseUint(id[:2], 16, 8)
	base := fmt.Sprintf("198.19.%d", suffix)
	if out, e := exec.Command("ip", "route", "show", "match", base+".0/30").Output(); e != nil {
		t.Skip("cannot inspect existing benchmarking routes; refusing ownership ambiguity")
	} else {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "default ") {
				t.Skip("chosen benchmarking subnet has a preexisting non-default route; refusing to shadow it")
			}
		}
	}
	commands := [][]string{
		{"ip", "link", "set", peerIf, "netns", ns},
		{"ip", "addr", "add", base + ".1/30", "dev", hostIf},
		{"ip", "link", "set", hostIf, "up"},
		{"ip", "netns", "exec", ns, "ip", "addr", "add", base + ".2/30", "dev", peerIf},
		{"ip", "netns", "exec", ns, "ip", "link", "set", peerIf, "up"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"},
	}
	for _, cmd := range commands {
		if err = run(cmd...); err != nil {
			t.Fatal(err)
		}
	}
	// Verify both qdiscs before testing. Failure is an explicit environment gap,
	// not a simulated application delay standing in for network delay.
	for _, cmd := range [][]string{
		{"tc", "qdisc", "replace", "dev", hostIf, "root", "netem", "delay", "1ms"},
		{"ip", "netns", "exec", ns, "tc", "qdisc", "replace", "dev", peerIf, "root", "netem", "delay", "1ms"},
	} {
		if err = run(cmd...); err != nil {
			t.Skipf("kernel netem unavailable: %v", err)
		}
	}
	clearShape := func() {
		for _, cmd := range [][]string{{"tc", "qdisc", "del", "dev", hostIf, "root"}, {"ip", "netns", "exec", ns, "tc", "qdisc", "del", "dev", peerIf, "root"}} {
			if err := run(cmd...); err != nil {
				t.Fatal(err)
			}
		}
	}
	clearShape()
	s := hyFixture(t)
	s.CoreVersion = strings.TrimSpace(strings.TrimPrefix(strings.Split(string(version), "\n")[0], "sing-box version "))
	if !SupportedVersion(s.CoreVersion) {
		t.Fatal("actual core is outside the fixed 1.14.x compatibility line")
	}
	s.Nodes[0].Host, s.Nodes[0].Listen, s.Nodes[0].Port = base+".2", "0.0.0.0", 14443
	root := t.TempDir()
	serverConfig, err := Server(s, root)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "server.json")
	if err = os.WriteFile(configPath, serverConfig, 0600); err != nil {
		t.Fatal(err)
	}
	newFixture := func(t *testing.T, cgroup string) (networkFixtureReady, func()) {
		t.Helper()
		private := t.TempDir()
		spec := networkFixtureSpec{Core: bin, Config: configPath, Cert: s.Nodes[0].Certificate.CertPEM, Key: s.Nodes[0].Certificate.KeyPEM, Ready: filepath.Join(private, "ready.json"), Counts: filepath.Join(private, "counts.json"), Gate: filepath.Join(private, "start")}
		path := filepath.Join(private, "fixture.json")
		writeNetworkJSON(t, path, spec)
		log, e := os.Create(filepath.Join(private, "helper.log"))
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestHY2NetworkFixtureProcess$", "-test.v")
		cmd.Env = append(os.Environ(), "QINGNODE_NETWORK_FIXTURE="+path)
		cmd.Stdout, cmd.Stderr = log, log
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		var processErr error
		go func() { processErr = cmd.Wait(); close(done) }()
		var once sync.Once
		stop := func() {
			once.Do(func() {
				// Ask the helper to stop its own core first. Signalling the whole
				// group here races the helper's signal handler against core exit.
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-done
					t.Error("fixture needed forced cleanup")
				}
				if processErr != nil {
					t.Errorf("owned fixture exited unsuccessfully: %v", processErr)
				}
				log.Close()
				if t.Failed() {
					b, _ := os.ReadFile(log.Name())
					t.Logf("fixture log: %s", b)
				}
			})
		}
		t.Cleanup(stop)
		if cgroup != "" {
			if e = os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); e != nil {
				stop()
				t.Skipf("cgroup process placement denied: %v", e)
			}
		}
		if e = os.WriteFile(spec.Gate, []byte("start"), 0600); e != nil {
			t.Fatal(e)
		}
		var ready networkFixtureReady
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if b, e := os.ReadFile(spec.Ready); e == nil && json.Unmarshal(b, &ready) == nil {
				ready.Counts = spec.Counts
				return ready, stop
			}
			select {
			case <-done:
				t.Fatalf("network fixture exited before readiness: %v", processErr)
			case <-time.After(25 * time.Millisecond):
			}
		}
		t.Fatal("network fixture did not become ready")
		return ready, stop
	}
	ready, stop := newFixture(t, "")
	defer stop()
	measure := func(t *testing.T, name string, endpoint networkFixtureReady, download bool) probe.Report {
		t.Helper()
		n := s.Nodes[0]
		outbound := Outbound(n, n.Users[0])
		outbound["tls"].(M)["certificate"] = []string{n.Certificate.CertPEM}
		raw, _ := json.Marshal(outbound)
		profile, e := probe.NewProfile(n.ID, s.CoreVersion, raw)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
		defer cancel()
		sandbox, e := probe.StartSandbox(ctx, profile, probe.SandboxOptions{CoreBinary: bin, SHA256: hex.EncodeToString(hash[:]), TempParent: t.TempDir()})
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := sandbox.Close(); e != nil {
				t.Error(e)
			}
		}()
		transport := sandbox.Transport()
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(n.Certificate.CertPEM))
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		defer transport.CloseIdleConnections()
		o := probe.Options{Path: "client-proxy", Mode: "light", TargetURL: endpoint.URL, Family: "ipv4", Timeout: 50 * time.Second, MaxBytes: 65536, Samples: 8, Concurrency: 1, Initiator: "disposable-linux-netns", NodeID: n.ID, ConfigSHA256: profile.ConfigSHA256, CoreVersion: s.CoreVersion, ClientVersion: sandbox.Version, UDPAddress: endpoint.UDP, UDPProxyAddress: sandbox.Address, UDPProxyUsername: sandbox.Username, UDPProxyPassword: sandbox.Password, UDPTimeout: time.Second}
		if download {
			o.Mode, o.MaxBytes = "download", 2<<20
		}
		serverBefore := probe.ReadMetrics(endpoint.CorePID)
		if b, e := exec.Command("ip", "netns", "exec", ns, "cat", "/proc/net/snmp").Output(); e == nil {
			if e = os.WriteFile(filepath.Join(resultDir, name+"-server-net-snmp-before.txt"), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		report, e := probe.Run(ctx, o, probe.Dependencies{Transport: transport, MetricsPID: sandbox.PID})
		if e != nil {
			t.Fatal(e)
		}
		if e = probe.WriteReport(filepath.Join(resultDir, name+".json"), report); e != nil {
			t.Fatal(e)
		}
		writeNetworkJSON(t, filepath.Join(resultDir, name+"-server-metrics.json"), map[string]any{"before": serverBefore, "after": probe.ReadMetrics(endpoint.CorePID), "udp_scope": "ReadMetrics UDP fields are the test-parent namespace, not server PID; separate server-net-snmp files record the actual owned server namespace"})
		if b, e := exec.Command("ip", "netns", "exec", ns, "cat", "/proc/net/snmp").Output(); e == nil {
			if e = os.WriteFile(filepath.Join(resultDir, name+"-server-net-snmp-after.txt"), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		t.Logf("%s: %s", name, probe.FormatText(report))
		if report.Traffic.PayloadBytesReceived+report.Traffic.UDPPayloadBytesReceived+report.Traffic.UDPPayloadBytesSent > o.MaxBytes {
			t.Fatal("bounded test exceeded payload budget")
		}
		return report
	}
	baseline := measure(t, "baseline", ready, true)
	if baseline.Status != "completed" || baseline.UDP == nil || baseline.UDP.Received != 8 {
		t.Fatal("baseline real HY2 TCP/UDP incomplete")
	}
	for _, cmd := range [][]string{
		{"tc", "qdisc", "replace", "dev", hostIf, "root", "netem", "delay", "80ms", "loss", "2%", "rate", "2mbit"},
		{"ip", "netns", "exec", ns, "tc", "qdisc", "replace", "dev", peerIf, "root", "netem", "delay", "80ms", "loss", "2%", "rate", "2mbit"},
	} {
		if e := run(cmd...); e != nil {
			t.Fatal(e)
		}
	}
	for name, cmd := range map[string][]string{"host": {"tc", "-s", "qdisc", "show", "dev", hostIf}, "namespace": {"ip", "netns", "exec", ns, "tc", "-s", "qdisc", "show", "dev", peerIf}} {
		b, e := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(resultDir, "shaped-"+name+"-qdisc.txt"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	shaped := measure(t, "delay-loss-rate", ready, true)
	for name, cmd := range map[string][]string{"host": {"tc", "-s", "qdisc", "show", "dev", hostIf}, "namespace": {"ip", "netns", "exec", ns, "tc", "-s", "qdisc", "show", "dev", peerIf}} {
		b, e := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(resultDir, "shaped-"+name+"-qdisc-after.txt"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if shaped.Statistics["idle_request"].Successes != 8 || shaped.Statistics["download_throughput"].Successes != 1 || shaped.Traffic.PayloadBytesReceived < 1<<20 {
		t.Fatal("shaped real HY2 HTTPS did not complete its bounded download")
	}
	if shaped.UDP == nil || shaped.UDP.Received == 0 || shaped.UDP.MedianRTTMS == nil || baseline.UDP.MedianRTTMS == nil {
		t.Fatal("shaped UDP has no valid round trip measurement")
	}
	if *shaped.UDP.MedianRTTMS < *baseline.UDP.MedianRTTMS+80 {
		t.Fatal("actual two-direction network delay was not reflected in UDP RTT")
	}
	stat := shaped.Statistics["download_throughput"]
	if stat.Median == nil || *stat.Median > 3 {
		t.Fatal("2 Mbit/s qdisc rate was not reflected by bounded download")
	}
	// Loss is probabilistic and QUIC retransmits stream data. Record raw loss
	// and qdisc counters rather than claiming a precise 2% application loss.
	clearShape()
	t.Run("udp-filtered-https-still-works", func(t *testing.T) {
		_, port, _ := net.SplitHostPort(ready.UDP)
		if e := run("ip", "netns", "exec", ns, "tc", "qdisc", "add", "dev", "lo", "clsact"); e != nil {
			t.Skipf("loopback clsact unavailable: %v", e)
		}
		defer func() {
			if e := run("ip", "netns", "exec", ns, "tc", "qdisc", "del", "dev", "lo", "clsact"); e != nil {
				t.Error("owned UDP filter cleanup", e)
			}
		}()
		if e := run("ip", "netns", "exec", ns, "tc", "filter", "add", "dev", "lo", "egress", "protocol", "ip", "pref", "1", "u32", "match", "ip", "protocol", "17", "0xff", "match", "ip", "dport", port, "0xffff", "action", "drop"); e != nil {
			t.Skipf("kernel UDP-only filter unavailable: %v", e)
		}
		r := measure(t, "udp-filtered", ready, false)
		if r.UDP == nil || r.UDP.Received != 0 || r.UDP.Lost != 8 || r.Statistics["idle_request"].Successes != 8 || r.Status == "completed" {
			t.Fatal("UDP failure was hidden by successful HTTPS", r.Status, r.UDP)
		}
	})
	t.Run("cgroup-memory-128MiB", func(t *testing.T) {
		stop()
		b, e := os.ReadFile("/proc/self/cgroup")
		if e != nil {
			t.Skip("cgroup membership unavailable")
		}
		current := ""
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "0::/") {
				current = strings.TrimPrefix(line, "0::")
			}
		}
		if current == "" {
			t.Skip("no unified cgroup v2; no real low-memory evidence")
		}
		group := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(current, "/"), "qingnode-test-"+id)
		if e = os.Mkdir(group, 0700); e != nil {
			t.Skipf("owned cgroup unavailable: %v", e)
		}
		defer func() {
			if e := os.Remove(group); e != nil {
				t.Error("owned cgroup cleanup", e)
			}
		}()
		if _, e = os.Stat(filepath.Join(group, "memory.max")); e != nil {
			t.Skip("memory controller not delegated; no low-memory test executed")
		}
		if e = os.WriteFile(filepath.Join(group, "memory.max"), []byte("134217728"), 0600); e != nil {
			t.Skipf("memory bound cannot be set: %v", e)
		}
		limited, limitedStop := newFixture(t, group)
		defer limitedStop()
		r := measure(t, "memory-128MiB", limited, true)
		for _, file := range []string{"memory.max", "memory.current", "memory.peak", "memory.events"} {
			if b, e := os.ReadFile(filepath.Join(group, file)); e == nil {
				if e = os.WriteFile(filepath.Join(resultDir, "cgroup-"+file+".txt"), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
		}
		if r.Status != "completed" || r.UDP == nil || r.UDP.Received != 8 {
			t.Fatal("real memory-bound HY2 TCP/UDP incomplete")
		}
	})
	// The helper flushes its atomic counters on exit. Endpoint handlers never
	// synchronously write evidence files during measured requests.
	stop()
	counts, err := os.ReadFile(ready.Counts)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(resultDir, "controlled-target-counts.json"), counts, 0600); err != nil {
		t.Fatal(err)
	}
	var c networkFixtureCounts
	if json.Unmarshal(counts, &c) != nil || c.HTTP == 0 || c.UDP == 0 {
		t.Fatal("selected HY2 did not reach namespace-only controlled targets")
	}
	t.Logf("raw reports and resource/qdisc evidence: %s; no public network, GUI, ISP or native ARM performance claim", resultDir)
}

type networkFixtureSpec struct {
	Core, Config, Cert, Key, Ready, Counts, Gate string
}
type networkFixtureReady struct {
	URL, UDP, Counts string
	CorePID          int
}
type networkFixtureCounts struct {
	HTTP int64 `json:"http_requests"`
	UDP  int64 `json:"udp_requests"`
}

func writeNetworkJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}

// Runs only inside the owned namespace. Its HTTPS and UDP targets bind lo,
// which the parent cannot reach directly over the veth. sing-box is the sole
// proxy transport across that veth; the test never mocks network delay.
func TestHY2NetworkFixtureProcess(t *testing.T) {
	path := os.Getenv("QINGNODE_NETWORK_FIXTURE")
	if path == "" {
		t.Skip("private netns helper process")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var s networkFixtureSpec
	if e = json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	for {
		if _, e := os.Stat(s.Gate); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	var httpCount, udpCount atomic.Int64
	count := func() {
		writeNetworkJSON(t, s.Counts, networkFixtureCounts{httpCount.Load(), udpCount.Load()})
	}
	count()
	defer count()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair([]byte(s.Cert), []byte(s.Key))
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCount.Add(1)
		w.Header().Set("Content-Length", strconv.Itoa(2<<20))
		if r.Method == http.MethodHead {
			return
		}
		block := make([]byte, 16<<10)
		for i := 0; i < 128; i++ {
			if _, e := w.Write(block); e != nil {
				return
			}
		}
	})}
	go server.ServeTLS(listener, "", "")
	defer server.Close()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 1201)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udpCount.Add(1)
			_, _ = udp.WriteTo(b[:n], a)
		}
	}()
	core := exec.Command(s.Core, "run", "-c", s.Config)
	core.Stdout, core.Stderr = os.Stdout, os.Stderr
	if e = core.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	var coreErr error
	go func() { coreErr = core.Wait(); close(done) }()
	defer func() {
		_ = core.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned namespace core failed to exit")
		}
	}()
	config, e := os.ReadFile(s.Config)
	if e != nil {
		t.Fatal(e)
	}
	if e = waitCoreListeners(core.Process.Pid, config, done, 5*time.Second); e != nil {
		t.Fatalf("namespace core listeners not owned and ready: %v", e)
	}
	writeNetworkJSON(t, s.Ready, networkFixtureReady{URL: "https://" + listener.Addr().String() + "/download", UDP: udp.LocalAddr().String(), CorePID: core.Process.Pid})
	select {
	case <-ctx.Done():
	case <-done:
		if ctx.Err() == nil {
			t.Error("namespace core exited during measurement", coreErr)
		}
	}
}
