//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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
	"testing"
	"time"

	"qingnode/internal/probe"
)

// This backend keeps the real Store transaction and original process backend
// state/stop behavior, but startup waits only for owned socket readiness. It
// never warms up, retries, or hides a failing application request.
type failoverProcessBackend struct{ processBackend }

func (b *failoverProcessBackend) Activate(st State) error {
	if err := b.Stop(); err != nil {
		return err
	}
	b.starts++
	if b.failNext {
		b.failNext = false
		return errors.New("injected startup failure after stopping old core")
	}
	path := filepath.Join(b.root, "current", "server.json")
	config, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b.cmd = exec.Command(b.bin, "run", "-c", path)
	b.cmd.Stdout, b.cmd.Stderr = io.Discard, io.Discard
	if err = b.cmd.Start(); err != nil {
		b.cmd = nil
		return err
	}
	b.done = make(chan error, 1)
	exited := make(chan struct{})
	cmd, done := b.cmd, b.done
	go func() { done <- cmd.Wait(); close(exited) }()
	return waitCoreListeners(cmd.Process.Pid, config, exited, 5*time.Second)
}

func failoverFixtureCore(t *testing.T, bin string, config M) func() {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-core.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command(bin, "check", "-c", path)
	check.Stdout, check.Stderr = io.Discard, io.Discard
	if err = check.Run(); err != nil {
		t.Fatal("official failover fixture config rejected", err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("owned failover fixture process leaked")
			}
		})
	}
	t.Cleanup(stop)
	if err = waitCoreListeners(cmd.Process.Pid, data, done, 5*time.Second); err != nil {
		t.Fatal("owned fixture socket readiness", err)
	}
	return stop
}

func failoverRemote(port int, source string) M {
	return M{"log": M{"disabled": true}, "inbounds": []any{M{"type": "socks", "tag": "remote", "listen": "127.0.0.1", "listen_port": port, "users": []any{M{"username": "remote-user", "password": "remote-pass"}}}}, "outbounds": []any{M{"type": "direct", "tag": "landing", "inet4_bind_address": source}}, "route": M{"final": "landing"}}
}

func failoverMixedGraph(t *testing.T, st State, id string, port int) M {
	t.Helper()
	out, eps, final, err := BuildEgressGraph(st, id)
	if err != nil {
		t.Fatal(err)
	}
	config := M{"log": M{"disabled": true}, "inbounds": []any{M{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": out, "route": M{"final": final}}
	if len(eps) > 0 {
		config["endpoints"] = eps
	}
	return config
}

func failoverHTTPClient(t *testing.T, port int, target *httptest.Server) *http.Client {
	t.Helper()
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func failoverObservedHTTP(client *http.Client, target string) (string, error) {
	r, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil {
		return "", err
	}
	if r.StatusCode != http.StatusOK {
		return "", errors.New("controlled HTTPS target returned unexpected status")
	}
	return string(b), nil
}

func TestOfficialCoreFailoverThresholdsSourcesSessionsAndRecovery(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires a verified official 1.14.x core; real systemd lifecycle is a separate host gate")
	}
	version, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(strings.SplitN(string(version), "\n", 2)[0])
	if len(fields) != 3 || !SupportedVersion(fields[2]) {
		t.Fatal("official core compatibility line required")
	}
	var requests atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = io.WriteString(w, host)
	}))
	defer target.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var udpSource atomic.Value
	var udpRequests atomic.Int64
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		b := make([]byte, 1201)
		for {
			n, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udpRequests.Add(1)
			host, _, _ := net.SplitHostPort(addr.String())
			udpSource.Store(host)
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()
	t.Cleanup(func() {
		udp.Close()
		select {
		case <-udpDone:
		case <-time.After(time.Second):
			t.Error("controlled UDP target leaked")
		}
	})
	firstPort := freePort(t)
	stopFirst := failoverFixtureCore(t, bin, failoverRemote(firstPort, "127.0.0.2"))
	secondPort := freePort(t)
	stopSecond := failoverFixtureCore(t, bin, failoverRemote(secondPort, "127.0.0.3"))
	state := NewState()
	state.CoreVersion = fields[2]
	n := ssFixture()
	n.Host, n.Listen, n.Port = "127.0.0.1", "127.0.0.1", freePort(t)
	primary := topologySOCKS("3333333333333333", "primary")
	primary.Server, primary.Port = "127.0.0.1", firstPort
	primary.Socks = &RemoteSOCKS{Username: "remote-user", Password: "remote-pass"}
	backup := primary
	backup.ID, backup.Name, backup.Port = "4444444444444444", "backup", secondPort
	policy := EgressPolicy{ID: "5555555555555555", Name: "explicit-main-backup", Mode: "failover", Primary: primary.ID, Backup: backup.ID, Health: &EgressHealth{URL: target.URL, UDPAddress: udp.LocalAddr().String(), FailureThreshold: 2, RecoveryThreshold: 2, CooldownSeconds: 30, TimeoutSeconds: 2}}
	n.EgressID = policy.ID
	state.Nodes, state.Egresses, state.EgressPolicies = []Node{n}, []Egress{primary, backup}, []EgressPolicy{policy}
	backend := &failoverProcessBackend{processBackend: processBackend{root: t.TempDir(), bin: bin}}
	store := &Store{Root: backend.root, Backend: backend, GID: -1}
	t.Cleanup(func() {
		if e := backend.Stop(); e != nil {
			t.Error("owned entry cleanup", e)
		}
	})
	apply := func(st State) {
		t.Helper()
		if e := store.WithLock(func() error { return store.Apply(st) }); e != nil {
			t.Fatal(e)
		}
		var e error
		state, e = store.Load()
		if e != nil {
			t.Fatal(e)
		}
	}
	apply(state)
	entryPort := freePort(t)
	entryConfig := Client(state.Nodes[0], state.Nodes[0].Users[0], entryPort)
	failoverFixtureCore(t, bin, entryConfig)
	entryClient := failoverHTTPClient(t, entryPort, target)
	primaryProbePort := freePort(t)
	failoverFixtureCore(t, bin, failoverMixedGraph(t, state, primary.ID, primaryProbePort))
	backupProbePort := freePort(t)
	failoverFixtureCore(t, bin, failoverMixedGraph(t, state, backup.ID, backupProbePort))
	primaryClient, backupClient := failoverHTTPClient(t, primaryProbePort, target), failoverHTTPClient(t, backupProbePort, target)
	assertPath := func(client *http.Client, proxyPort int, source string) {
		t.Helper()
		before := requests.Load()
		got, e := failoverObservedHTTP(client, target.URL)
		if e != nil || got != source || requests.Load() != before+1 {
			t.Fatalf("single HTTPS request source=%q want=%s error=%v delta=%d", got, source, e, requests.Load()-before)
		}
		beforeUDP := udpRequests.Load()
		result, e := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udp.LocalAddr().String(), Family: "ipv4", ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), Samples: 2, PayloadBytes: 64, MaxBytes: 257, Timeout: 2 * time.Second})
		if e != nil || result.Sent != 2 || result.Received != 2 || result.Lost != 0 || udpRequests.Load() != beforeUDP+2 || udpSource.Load() != source {
			t.Fatalf("actual sequenced UDP path mismatch: %+v err=%v source=%v delta=%d", result, e, udpSource.Load(), udpRequests.Load()-beforeUDP)
		}
	}
	assertPath(entryClient, entryPort, "127.0.0.2")
	assertPath(primaryClient, primaryProbePort, "127.0.0.2")
	assertPath(backupClient, backupProbePort, "127.0.0.3")
	binding, e := PolicyHealthDigest(state, state.EgressPolicies[0])
	if e != nil {
		t.Fatal(e)
	}
	var observation FailoverObservation
	clock := time.Unix(2000000000, 0).UTC()
	decision := func(offset int, first, second, want string) {
		t.Helper()
		p := state.EgressPolicies[0]
		d, e := EvaluateFailover(p, observation, binding, first, second, clock.Add(time.Duration(offset)*time.Second))
		if e != nil || d.To != want {
			t.Fatalf("threshold/cooldown decision: %+v %v", d, e)
		}
		observation = d.Observation
		if d.Changed {
			next := state.Clone()
			next.EgressPolicies[0].Selected = d.To
			apply(next)
		}
	}
	failedPath := func(client *http.Client, proxyPort int) {
		t.Helper()
		before, beforeUDP := requests.Load(), udpRequests.Load()
		if got, e := failoverObservedHTTP(client, target.URL); e == nil {
			t.Fatalf("stopped egress fell back to a working route, source %s", got)
		}
		result, e := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udp.LocalAddr().String(), Family: "ipv4", ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), Samples: 1, PayloadBytes: 64, MaxBytes: 129, Timeout: 250 * time.Millisecond})
		if result.Received != 0 {
			t.Fatal("UDP egress failure concealed by fallback", result, e)
		}
		if requests.Load() != before || udpRequests.Load() != beforeUDP {
			t.Fatal("disabled egress still reached application target")
		}
	}
	stopFirst()
	failedPath(entryClient, entryPort)
	failedPath(primaryClient, primaryProbePort)
	assertPath(backupClient, backupProbePort, "127.0.0.3")
	oldPID, oldStarts := backend.cmd.Process.Pid, backend.starts
	decision(0, "unhealthy", "healthy", "primary")
	if backend.cmd.Process.Pid != oldPID || backend.starts != oldStarts {
		t.Fatal("one failed observation restarted before threshold")
	}
	failedPath(primaryClient, primaryProbePort)
	assertPath(backupClient, backupProbePort, "127.0.0.3")
	decision(1, "unhealthy", "healthy", "backup")
	if backend.cmd.Process.Pid == oldPID || backend.starts != oldStarts+1 {
		t.Fatal("real selected-route switch did not restart exactly once")
	}
	assertPath(entryClient, entryPort, "127.0.0.3")
	// Keep one established application TCP session across the later recovery.
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan struct{})
	echoSource := make(chan string, 1)
	go func() {
		defer close(echoDone)
		c, e := echo.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		echoSource <- host
		_, _ = io.Copy(c, c)
	}()
	t.Cleanup(func() {
		echo.Close()
		select {
		case <-echoDone:
		case <-time.After(time.Second):
			t.Error("old TCP target leaked")
		}
	})
	stream := sustainedSOCKS(t, entryPort, echo.Addr().(*net.TCPAddr).Port)
	defer stream.Close()
	payload := []byte("existing-session-must-not-be-migrated")
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = stream.Write(payload); e != nil {
		t.Fatal(e)
	}
	gotFrame := make([]byte, len(payload))
	if _, e = io.ReadFull(stream, gotFrame); e != nil || !bytes.Equal(gotFrame, payload) {
		t.Fatal("existing TCP baseline", e)
	}
	if source := <-echoSource; source != "127.0.0.3" {
		t.Fatal("old TCP did not use saved backup", source)
	}
	stopFirst = failoverFixtureCore(t, bin, failoverRemote(firstPort, "127.0.0.2"))
	assertPath(primaryClient, primaryProbePort, "127.0.0.2")
	decision(2, "healthy", "healthy", "backup")
	assertPath(primaryClient, primaryProbePort, "127.0.0.2")
	decision(3, "healthy", "healthy", "backup")
	assertPath(entryClient, entryPort, "127.0.0.3")
	assertPath(primaryClient, primaryProbePort, "127.0.0.2")
	decision(31, "healthy", "healthy", "primary")
	assertPath(entryClient, entryPort, "127.0.0.2")
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, e = stream.Read(make([]byte, 1))
	if e == nil {
		t.Fatal("old TCP unexpectedly produced data after entry restart")
	}
	var timeout net.Error
	if errors.As(e, &timeout) && timeout.Timeout() {
		t.Fatal("old TCP closure was not observed; cannot claim migration or interruption", e)
	}
	t.Log("old established TCP stream closed on real config restart; it was not migrated. Cooldown uses an explicit deterministic decision clock; application traffic and source observations are real.")
	beforeState := state.Clone()
	beforeGeneration, e := store.current()
	if e != nil {
		t.Fatal(e)
	}
	beforeConfig, e := os.ReadFile(filepath.Join(store.Root, beforeGeneration, "server.json"))
	if e != nil {
		t.Fatal(e)
	}
	next := state.Clone()
	next.EgressPolicies[0].Selected = "backup"
	backend.failNext = true
	if e = store.WithLock(func() error { return store.Apply(next) }); e == nil {
		t.Fatal("injected apply failure reported success")
	}
	restored, e := store.Load()
	if e != nil {
		t.Fatal(e)
	}
	afterGeneration, _ := store.current()
	afterConfig, _ := os.ReadFile(filepath.Join(store.Root, afterGeneration, "server.json"))
	if afterGeneration != beforeGeneration || !equalJSON(restored, beforeState) || !bytes.Equal(beforeConfig, afterConfig) || !backend.Active() {
		t.Fatal("failed switch did not fully restore old selection/config/state")
	}
	assertPath(entryClient, entryPort, "127.0.0.2")
	stopFirst()
	stopSecond()
	failedPath(entryClient, entryPort)
	failedPath(primaryClient, primaryProbePort)
	failedPath(backupClient, backupProbePort)
	decision(32, "unhealthy", "unhealthy", "primary")
	decision(62, "unhealthy", "unhealthy", "primary")
	failedPath(entryClient, entryPort)
	// A separate direct control proves that target availability cannot explain
	// the entry failure. This control never enters generated proxy config.
	if source, e := failoverObservedHTTP(target.Client(), target.URL); e != nil || source != "127.0.0.1" {
		t.Fatal("direct control target unavailable", source, e)
	}
	if state.EgressPolicies[0].Selected != "primary" {
		t.Fatal("both failed paths silently selected another route")
	}
	t.Logf("official core %s: primary source 127.0.0.2, backup source 127.0.0.3, TCP/UDP paths and no-direct-fallback observed; restored original generation after injected startup failure", state.CoreVersion)
}
