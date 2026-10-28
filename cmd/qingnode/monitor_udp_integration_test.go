package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"qingnode/internal/monitor"
	"qingnode/internal/node"
)

// This opt-in gate uses the actual official binary for both the remote SOCKS
// listener and the adapter's isolated graph client. No service manager or VM is
// touched. A fresh test subprocess loads a private loopback CA before the first
// TLS request, avoiding changes to the parent process's cached system roots.
func TestOfficialMonitorUDPPreflightThroughRealCore(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires separately verified official SING_BOX_BIN; real monitor UDP-preflight path was not run")
	}
	if os.Getenv("QINGNODE_MONITOR_UDP_CHILD") == "1" {
		monitorRealUDPPreflightChild(t, bin)
		return
	}
	var requests atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	caPath := filepath.Join(t.TempDir(), "loopback-ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw})
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestOfficialMonitorUDPPreflightThroughRealCore$", "-test.v")
	child.Env = append(os.Environ(), "QINGNODE_MONITOR_UDP_CHILD=1", "QINGNODE_MONITOR_UDP_TARGET="+target.URL, "SSL_CERT_FILE="+caPath, "SSL_CERT_DIR="+t.TempDir())
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("real official adapter preflight child failed: %v\n%s", err, output)
	}
	if requests.Load() < 4 {
		t.Fatalf("expected independent proxy and server-outbound HTTPS witnesses for both budgets, got %d", requests.Load())
	}
	t.Logf("real loopback TLS requests=%d; isolated official-core adapter result:\n%s", requests.Load(), output)
}

func monitorRealUDPPreflightChild(t *testing.T, bin string) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	versionOutput, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if line != "sing-box version 1.14.0" && line != "sing-box version 1.14.3" {
		t.Fatal("requires separately verified official 1.14.0/1.14.3")
	}
	version := strings.TrimPrefix(line, "sing-box version ")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	remoteConfig := map[string]any{
		"log":       map[string]any{"level": "info"},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "owned-remote", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]string{"username": "owned-test-user", "password": "owned-test-password"}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	encoded, err := json.Marshal(remoteConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "remote.json")
	if err = os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(ctx, bin, "check", "-c", configPath).CombinedOutput(); err != nil {
		t.Fatalf("official remote config check: %v %s", err, output)
	}
	logfile, err := os.CreateTemp(t.TempDir(), "remote-startup")
	if err != nil {
		t.Fatal(err)
	}
	defer logfile.Close()
	remote := exec.CommandContext(ctx, bin, "run", "-c", configPath)
	remote.Stdout, remote.Stderr = logfile, logfile
	if err = remote.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = remote.Wait(); close(done) }()
	defer func() {
		_ = remote.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned official remote core did not exit")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		startup, err := os.ReadFile(logfile.Name())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(startup, []byte("sing-box started (")) {
			break
		}
		select {
		case <-done:
			t.Fatalf("official remote exited before startup: %s", startup)
		default:
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			t.Fatalf("official remote startup not observed: %s", startup)
		}
		time.Sleep(20 * time.Millisecond)
	}
	a := wizardApp(t, "")
	st := node.NewState()
	st.CoreVersion = version
	egress := node.Egress{ID: "aaaaaaaaaaaaaaaa", Name: "owned-tcp-only", Protocol: "socks5", Server: "127.0.0.1", Port: port, UDP: false, Socks: &node.RemoteSOCKS{Username: "owned-test-user", Password: "owned-test-password"}}
	st.Egresses = []node.Egress{egress}
	if err = a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	st, err = a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := makeEgressGraph(st, egress.ID)
	if err != nil || !graph.SupportsNetwork("tcp") || graph.SupportsNetwork("udp") {
		t.Fatalf("actual production graph must be TCP-only: %v", err)
	}
	// Copy only the caller-selected verified executable into this temporary
	// managed fixture; production probeDefaultCore still verifies its hash.
	corePath := node.CorePath(a.store.Root, version)
	if err = os.MkdirAll(filepath.Dir(corePath), 0700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	installed, err := os.OpenFile(corePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	copied, copyErr := io.Copy(io.MultiWriter(installed, hash), io.LimitReader(source, (256<<20)+1))
	closeErr := installed.Close()
	if copyErr != nil || closeErr != nil || copied > 256<<20 {
		t.Fatalf("temporary verified-core copy failed: %v %v bytes=%d", copyErr, closeErr, copied)
	}
	if err = os.WriteFile(corePath+".sha256", []byte(hex.EncodeToString(hash.Sum(nil))), 0600); err != nil {
		t.Fatal(err)
	}
	targetURL := os.Getenv("QINGNODE_MONITOR_UDP_TARGET")
	if !strings.HasPrefix(targetURL, "https://127.0.0.1:") {
		t.Fatal("controlled loopback HTTPS target missing")
	}
	adapter := monitorAdapter{app: a, state: st}
	job := monitor.Job{ID: "bbbbbbbbbbbbbbbb", EgressID: egress.ID, Enabled: true, Family: "ipv4", TargetURL: targetURL, UDPAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Signals: []monitor.SignalKind{monitor.Authentication, monitor.TCP, monitor.UDP, monitor.Target}}
	generation, before := savedBatchState(t, a)
	for _, test := range []struct {
		bytes  int64
		status monitor.Status
		cause  string
	}{
		{1024, monitor.Failed, "egress_does_not_support_udp"},
		{128, monitor.Unknown, "udp_payload_budget_too_small"},
	} {
		var observation monitor.Observation
		signals := map[monitor.SignalKind]monitor.Signal{}
		adapter.measure(ctx, job, monitor.Budget{Timeout: 5 * time.Second, MaxBytes: test.bytes, Concurrency: 1}, &observation, func(kind monitor.SignalKind, status monitor.Status, location, cause string) {
			signals[kind] = monitor.Signal{Kind: kind, Status: status, Location: location, Cause: cause}
		})
		for _, kind := range []monitor.SignalKind{monitor.Authentication, monitor.TCP, monitor.Target} {
			if signals[kind].Status != monitor.Healthy {
				t.Fatalf("real official-core HTTPS path did not succeed: signal=%s value=%+v budget=%d", kind, signals[kind], test.bytes)
			}
		}
		if udp := signals[monitor.UDP]; udp.Status != test.status || udp.Cause != test.cause {
			t.Fatalf("real measure overwrote UDP preflight: got=%+v want=%s/%s", udp, test.status, test.cause)
		}
		if observation.UDP != nil || observation.Traffic.UDPPayloadBytesSent != 0 || observation.Traffic.UDPPayloadBytesReceived != 0 {
			t.Fatal("suppressed UDP still emitted a controlled measurement")
		}
		t.Logf("official %s real graph HTTPS succeeded; budget=%d UDP=%s/%s; no UDP payload emitted", version, test.bytes, signals[monitor.UDP].Status, signals[monitor.UDP].Cause)
	}
	// Change only the in-memory remote credential. The independent direct
	// witness must not turn a failed authenticated proxy path into success.
	originalPID := remote.Process.Pid
	wrongState := st.Clone()
	wrongState.Egresses[0].Socks.Password = "wrong-owned-test-password"
	wrongAdapter := monitorAdapter{app: a, state: wrongState}
	var wrongObservation monitor.Observation
	wrongSignals := map[monitor.SignalKind]monitor.Signal{}
	wrongAdapter.measure(ctx, job, monitor.Budget{Timeout: 5 * time.Second, MaxBytes: 1024, Concurrency: 1}, &wrongObservation, func(kind monitor.SignalKind, status monitor.Status, location, cause string) {
		wrongSignals[kind] = monitor.Signal{Kind: kind, Status: status, Location: location, Cause: cause}
	})
	if signal := wrongSignals[monitor.Target]; signal.Status != monitor.Healthy || signal.Location != "server-outbound" {
		t.Fatalf("controlled target direct witness must stay healthy with wrong proxy credentials: %+v", signal)
	}
	if signal := wrongSignals[monitor.TCP]; signal.Status != monitor.Failed || signal.Location != "client-proxy" {
		t.Fatalf("direct target availability fabricated proxy TCP success: %+v", signal)
	}
	if signal := wrongSignals[monitor.Authentication]; signal.Status != monitor.Unknown || signal.Cause != "auth_route_target_cannot_be_separated" {
		t.Fatalf("wrong-credential path fabricated a conclusive authentication result: %+v", signal)
	}
	if signal := wrongSignals[monitor.UDP]; signal.Status != monitor.Failed || signal.Cause != "egress_does_not_support_udp" {
		t.Fatalf("wrong-credential probe overwrote explicit UDP restriction: %+v", signal)
	}
	select {
	case <-done:
		t.Fatal("original official remote core exited during wrong-credential observation")
	default:
	}
	if remote.Process.Pid != originalPID || remote.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("original official remote PID is no longer active")
	}
	currentState, err := a.store.Load()
	if err != nil || len(currentState.Egresses) != 1 || currentState.Egresses[0].Socks == nil || currentState.Egresses[0].Socks.Password != "owned-test-password" || st.Egresses[0].Socks.Password != "owned-test-password" {
		t.Fatalf("wrong-credential observation changed original remote credentials: %v", err)
	}
	t.Logf("official %s wrong in-memory remote credential: direct target healthy; proxy TCP failed; authentication unknown/ambiguous; UDP unsupported retained; original remote PID=%d and saved password unchanged", version, originalPID)
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) {
		t.Fatal("read-only graph measurement changed managed State")
	}
}
