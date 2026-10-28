package probe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This integration test imports no Linux manager package. It runs unchanged
// against official Windows or Linux cores and proves the portable client path.
func portableOfficialCore(t *testing.T) (string, string, string) {
	t.Helper()
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("SING_BOX_BIN is unset; official portable core integration was not run")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("official core input is unavailable: %v", err)
	}
	digest := sha256.Sum256(b)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, err := exec.CommandContext(ctx, abs, "version").Output()
	if err != nil {
		t.Fatalf("official core version command failed: %v", err)
	}
	version := ""
	for _, line := range strings.Split(string(v), "\n") {
		if strings.HasPrefix(line, "sing-box version ") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "sing-box version "))
		}
	}
	if !compatibleCore.MatchString(version) {
		t.Fatalf("unsupported official test version %q", version)
	}
	return abs, hex.EncodeToString(digest[:]), version
}

func portableSSFixture(t *testing.T, bin, version string) (Profile, func()) {
	t.Helper()
	key := func() string {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	serverKey, userKey := key(), key()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "shadowsocks", "tag": "portable-test", "listen": "127.0.0.1", "listen_port": port,
			"method": "2022-blake3-aes-256-gcm", "password": serverKey,
			"users": []any{map[string]any{"name": "portable-user", "password": userKey}},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "fixture-target"}},
		"route":     map[string]any{"final": "fixture-target"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = protectPrivate(dir, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture-server.json")
	if err = writePrivate(path, config); err != nil {
		t.Fatal(err)
	}
	checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	check := exec.CommandContext(checkCtx, bin, "check", "-c", path)
	check.Stdout, check.Stderr = io.Discard, io.Discard
	err = check.Run()
	cancel()
	if err != nil {
		t.Fatalf("official SS2022 fixture configuration was rejected: %v (private output suppressed)", err)
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
				t.Error("owned fixture core did not exit")
			}
		})
	}
	t.Cleanup(stop)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-done:
			t.Fatal("official fixture core exited before listening")
		default:
		}
		conn, e := net.DialTimeout("tcp4", address, 50*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("official fixture core did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, err := json.Marshal(map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": port,
		"method": "2022-blake3-aes-256-gcm", "password": serverKey + ":" + userKey})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProfile("portable-ss", version, raw)
	if err != nil {
		t.Fatal(err)
	}
	return p, stop
}

func portableSandbox(t *testing.T, ctx context.Context, p Profile, bin, digest string) *Sandbox {
	t.Helper()
	s, err := StartSandbox(ctx, p, SandboxOptions{CoreBinary: bin, SHA256: digest, TempParent: t.TempDir()})
	if err != nil {
		t.Fatalf("official portable sandbox failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func portableAssertClean(t *testing.T, s *Sandbox) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	default:
		t.Error("owned sandbox process remains after Close")
	}
	if _, err := os.Lstat(s.Directory); !os.IsNotExist(err) {
		t.Errorf("owned sandbox directory remains after Close: %v", err)
	}
	if conn, err := net.DialTimeout("tcp4", s.Address, 50*time.Millisecond); err == nil {
		conn.Close()
		t.Error("owned sandbox listener remains after Close")
	}
}

func TestOfficialCorePortableSandboxNoFallbackAndCleanup(t *testing.T) {
	bin, digest, version := portableOfficialCore(t)
	p, stopServer := portableSSFixture(t, bin, version)
	var requests atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s := portableSandbox(t, ctx, p, bin, digest)
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	transport := s.Transport()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	o := Options{Path: "client-proxy", TargetURL: target.URL, Samples: 2, Timeout: 5 * time.Second,
		Initiator: "native-portable-fixture", NodeID: p.NodeID, ConfigSHA256: p.ConfigSHA256,
		CoreVersion: p.CoreVersion, ClientVersion: s.Version}
	r, err := Run(ctx, o, Dependencies{Transport: transport, MetricsPID: s.PID})
	if err != nil || r.Status != "completed" || requests.Load() != 2 {
		t.Fatalf("selected real SS2022 path failed: err=%v status=%s requests=%d", err, r.Status, requests.Load())
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var client outbound
	if err = json.Unmarshal(p.Outbound, &client); err != nil {
		t.Fatal(err)
	}
	for _, secret := range strings.Split(client.Password, ":") {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("automatic report exposed a client credential")
		}
	}
	if err = WriteReport(filepath.Join(t.TempDir(), "portable-report.json"), r); err != nil {
		t.Fatalf("native private report write failed: %v", err)
	}
	stopServer()
	// Keep the HTTPS origin demonstrably reachable by direct control. Only the
	// selected proxy is removed; automatic requests must not take that path.
	resp, err := target.Client().Head(target.URL)
	if err != nil {
		t.Fatalf("controlled target became unavailable independently of proxy: %v", err)
	}
	resp.Body.Close()
	before := requests.Load()
	transport.CloseIdleConnections()
	r, err = Run(ctx, o, Dependencies{Transport: transport, MetricsPID: s.PID})
	if err != nil || r.Status == "completed" || requests.Load() != before {
		t.Fatalf("disabled proxy bypassed failure: err=%v status=%s extra target requests=%d", err, r.Status, requests.Load()-before)
	}
	portableAssertClean(t, s)
}

func TestOfficialCorePortableSandboxCancellationAndCrash(t *testing.T) {
	bin, digest, version := portableOfficialCore(t)
	p, _ := portableSSFixture(t, bin, version)
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := portableSandbox(t, ctx, p, bin, digest)
		cancel()
		select {
		case <-s.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation left the owned portable core running")
		}
		portableAssertClean(t, s)
	})
	t.Run("crash", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s := portableSandbox(t, ctx, p, bin, digest)
		if err := s.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("crashed owned portable core was not waited for")
		}
		portableAssertClean(t, s)
	})
}
