//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"testing"
	"time"

	"qingnode/internal/probe"
)

// This test uses the fixed official Pebble test CA, never a public CA. The CA's
// private trust is confined to these owned processes; no host trust is changed.
// Startup renewal is deliberately distinguished from the ten-minute background
// renewal ticker in the fixed certmagic dependency.
func TestOfficialCoreACMEPebbleHTTP01StartupRenewalAndFailure(t *testing.T) {
	acmeFixtureLifecycle(t, false)
}

func TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess(t *testing.T) {
	if os.Getenv("QINGNODE_ACME_BACKGROUND_TEST") != "1" {
		t.Skip("set QINGNODE_ACME_BACKGROUND_TEST=1 for the separate real ten-minute core maintenance observation (bounded fourteen minutes fifteen seconds including the fixed CA's native retry path)")
	}
	acmeFixtureLifecycle(t, true)
}

func acmeFixtureLifecycle(t *testing.T, background bool) {
	pebble, core := os.Getenv("PEBBLE_BIN"), os.Getenv("SING_BOX_BIN")
	if pebble == "" || core == "" {
		t.Skip("requires verified official PEBBLE_BIN and SING_BOX_BIN; isolated test CA only")
	}
	if out, err := exec.Command(pebble, "-version").CombinedOutput(); err != nil || !strings.Contains(string(out), "2.10.1") {
		t.Fatalf("requires fixed Pebble 2.10.1: %v %s", err, out)
	}
	coreVersion := acmeFixtureCoreVersion(t, core)
	validity := 20
	if background {
		validity = 900
	}
	dir := t.TempDir()
	cert, key := makeCert(t)
	write := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certFile, keyFile := write("test-ca-https.pem", []byte(cert)), write("test-ca-https.key", []byte(key))
	caPort, mgmtPort, httpChallenge, hy2Port := freePort(t), freePort(t), freePort(t), freePort(t)
	caURL := "https://127.0.0.1:" + strconv.Itoa(caPort)
	mgmtURL := "https://127.0.0.1:" + strconv.Itoa(mgmtPort)
	pebbleConfig := map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:" + strconv.Itoa(caPort), "managementListenAddress": "127.0.0.1:" + strconv.Itoa(mgmtPort),
		"certificate": certFile, "privateKey": keyFile, "httpPort": httpChallenge, "tlsPort": freePort(t),
		"keyAlgorithm": "ecdsa", "domainBlocklist": []string{"blocked-domain.example"},
		"retryAfter": map[string]any{"authz": 1, "order": 1},
		"profiles":   map[string]any{"default": map[string]any{"description": "owned short test lifetime", "validityPeriod": validity}},
	}}
	b, _ := json.Marshal(pebbleConfig)
	pebblePath := write("pebble.json", b)
	dnsAddress, dnsQueries := acmeFixtureDNS(t, "qingnode-acme.example.test")
	caProcess := acmeFixtureProcess(t, pebble, []string{"-config", pebblePath, "-dnsserver", dnsAddress}, append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0"))
	defer caProcess.stop()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cert)) {
		t.Fatal("test HTTPS root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	var rootPEM []byte
	acmeFixtureWait(t, 5*time.Second, "test CA verified HTTPS readiness", func() bool {
		resp, err := httpClient.Get(mgmtURL + "/roots/0")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		rootPEM, err = io.ReadAll(io.LimitReader(resp.Body, 16384))
		return err == nil && resp.StatusCode == 200 && bytes.Contains(rootPEM, []byte("BEGIN CERTIFICATE"))
	})
	state := NewState()
	state.CoreVersion = coreVersion
	resource := CertificateResource{ID: Token(8), Name: "owned-test-certificate", Certificate: Certificate{Mode: "acme", ServerName: "qingnode-acme.example.test", Email: "fixture@example.test", ACME: &ACMESettings{Challenge: "http-01", Provider: caURL + "/dir", KeyType: "p256", AlternativeHTTPPort: httpChallenge}}}
	state.Certificates = []CertificateResource{resource}
	state.Nodes = []Node{{ID: Token(8), Name: "owned-test-node", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: hy2Port, Enabled: true, CertificateID: resource.ID, Users: []User{{ID: Token(8), Name: "owned-user", Password: "fixture-auth-preserved"}}}}
	assetRoot := filepath.Join(dir, "owned-assets")
	// Prepare the private managed State before the real core creates its storage.
	// This is the supported offline preparation path, not directory adoption.
	preparedStore := &Store{Root: assetRoot, Backend: OfflineBackend{}, GID: -1}
	if err := preparedStore.WithLock(func() error { return preparedStore.Apply(state) }); err != nil {
		t.Fatal("prepare managed ACME source", err)
	}
	prepared, err := preparedStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	state = prepared
	dataDir := CertificateACMEDirectory(assetRoot, resource)
	startServer := func(name string) *acmeFixtureChild {
		t.Helper()
		if err := ResolveCertificates(&state); err != nil {
			t.Fatal("resolve explicit resource update in fixture", err)
		}
		generated, err := Server(state, assetRoot)
		if err != nil {
			t.Fatal("production resource/server renderer", err)
		}
		var server M
		if err := json.Unmarshal(generated, &server); err != nil {
			t.Fatal(err)
		}
		// Add only the owned CA transport root and observable fixture logging.
		// All challenge, resource, authentication and protocol fields above came
		// from the production renderer. Never disable TLS verification.
		server["log"] = M{"level": "debug", "timestamp": false}
		inbound := server["inbounds"].([]any)[0].(map[string]any)
		tlsOptions := inbound["tls"].(map[string]any)
		providerTag, ok := tlsOptions["certificate_provider"].(string)
		if !ok || providerTag != "certificate-"+resource.ID {
			t.Fatal("production renderer did not use the stable shared certificate provider")
		}
		providers, ok := server["certificate_providers"].([]any)
		if !ok || len(providers) != 1 {
			t.Fatal("production renderer did not emit exactly the referenced shared provider")
		}
		provider := providers[0].(map[string]any)
		if provider["tag"] != providerTag {
			t.Fatal("provider reference does not match emitted resource")
		}
		provider["http_client"] = M{"tls": M{"enabled": true, "certificate": []string{cert}}}
		b, _ := json.Marshal(server)
		path := write(name+".json", b)
		if out, err := exec.Command(core, "check", "-c", path).CombinedOutput(); err != nil {
			t.Fatalf("production ACME config parser: %v %s", err, out)
		}
		return acmeFixtureProcess(t, core, []string{"run", "-c", path}, os.Environ())
	}
	serverProcess := startServer("server-first")
	first, firstKey := acmeFixtureIssued(t, dataDir, nil, 12*time.Second)
	if _, ok := first.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected P-256 certificate; got %T", first.PublicKey)
	}
	if err := first.VerifyHostname("qingnode-acme.example.test"); err != nil {
		t.Fatal(err)
	}
	t.Logf("test CA issued valid P-256 DNS SAN; remaining=%s; core PID=%d", time.Until(first.NotAfter), serverProcess.cmd.Process.Pid)
	acmeFixtureHY2(t, core, hy2Port, "qingnode-acme.example.test", rootPEM)
	if background {
		pid := serverProcess.cmd.Process.Pid
		accountsBefore := acmeFixtureAccountHashes(t, dataDir)
		observationStarted := time.Now()
		second, _ := acmeFixtureRenewed(t, dataDir, first, serverProcess, 11*time.Minute)
		// An immediate renewal is not evidence of the unchanged ten-minute
		// maintenance ticker, even if it happens in the same process.
		if time.Since(observationStarted) < 9*time.Minute {
			t.Fatal("renewal occurred before the real background maintenance observation window")
		}
		select {
		case <-serverProcess.done:
			t.Fatal("owned core exited before background renewal")
		default:
		}
		if serverProcess.cmd.Process.Pid != pid || !second.NotAfter.After(first.NotAfter) || !equalACMEFixtureHashes(accountsBefore, acmeFixtureAccountHashes(t, dataDir)) {
			t.Fatal("background renewal changed process/account identity or did not extend validity")
		}
		acmeFixtureHY2(t, core, hy2Port, "qingnode-acme.example.test", rootPEM)
		t.Logf("real background renewal kept core PID=%d; serial changed %s -> %s; expiry extended %s -> %s; original account key and proxy authentication worked for HTTPS/UDP before and after; no ticker override, signal, forced issuance or process restart", pid, first.SerialNumber, second.SerialNumber, first.NotAfter, second.NotAfter)
		return
	}
	acmeFixtureWait(t, 2*time.Second, "complete initial issuance storage commit", func() bool {
		return bytes.Contains(serverProcess.logBytes(), []byte("certificate obtained successfully"))
	})
	serverProcess.stop()
	select {
	case <-serverProcess.done:
	default:
		t.Fatal("source ACME writer cmd.Wait completion not confirmed")
	}
	state, assetRoot = acmeFixtureMigrationRoundTrip(t, state, assetRoot)
	dataDir = CertificateACMEDirectory(assetRoot, state.Certificates[0])
	serverProcess = startServer("server-migrated")
	first, firstKey = acmeFixtureIssued(t, dataDir, nil, 12*time.Second)
	acmeFixtureHY2(t, core, hy2Port, "qingnode-acme.example.test", rootPEM)
	serverProcess.stop()
	// Managing a restored short-lived leaf can start an asynchronous renewal.
	// Once its writer has stopped, use the last committed certificate/key for
	// the expiry wait and subsequent comparison, not the leaf read at startup.
	// A successful renewal during the preceding transport check must not make
	// the next step wait for or compare against an obsolete serial number.
	committed, committedKey := acmeFixtureReadCertificate(dataDir, nil, false)
	if committed == nil {
		t.Fatal("migrated ACME writer stopped without a committed matching certificate/key")
	}
	if committed.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Logf("migrated core renewed during the transport check; using committed serial %s instead of startup serial %s", committed.SerialNumber, first.SerialNumber)
	}
	first, firstKey = committed, committedKey
	accountsBefore := acmeFixtureAccountHashes(t, dataDir)
	if len(accountsBefore) == 0 {
		t.Fatal("issued certificate did not persist account assets")
	}
	// Wait for the real test CA's short validity; do not forge cache metadata or
	// call an external issuance loop. The core decides renewal on the next start.
	if delay := time.Until(first.NotAfter.Add(150 * time.Millisecond)); delay > 0 {
		if delay > 25*time.Second {
			t.Fatal("unexpected unbounded CA fixture lifetime")
		}
		time.Sleep(delay)
	}
	serverProcess = startServer("server-renew")
	second, secondKey := acmeFixtureRenewed(t, dataDir, first, serverProcess, 12*time.Second)
	if !second.NotAfter.After(first.NotAfter) {
		t.Fatal("startup renewal did not extend validity")
	}
	t.Logf("core renewal leaf key retained=%t (observed official core behavior, not forced by this fixture)", bytes.Equal(firstKey, secondKey))
	if !equalACMEFixtureHashes(accountsBefore, acmeFixtureAccountHashes(t, dataDir)) {
		t.Fatal("startup renewal unexpectedly replaced account identity")
	}
	acmeFixtureHY2(t, core, hy2Port, "qingnode-acme.example.test", rootPEM)
	t.Log("real startup-triggered core renewal changed serial/expiry, retained account private key and proxy authentication, and carried HY2 HTTPS/sequence UDP; background timer was not accelerated or asserted")
	serverProcess.stop()

	// A real CA policy rejection is a failure even though sing-box check accepts
	// this provider configuration. No certificate may appear in the failed store.
	state.Certificates[0].Certificate.ServerName = "blocked-domain.example"
	assetRoot = filepath.Join(dir, "failed-policy-assets")
	failedDataDir := CertificateACMEDirectory(assetRoot, state.Certificates[0])
	failed := startServer("server-policy-rejected")
	acmeFixtureWait(t, 8*time.Second, "CA policy failure", func() bool {
		log := failed.logBytes()
		return bytes.Contains(log, []byte("rejectedIdentifier")) || bytes.Contains(log, []byte("blocked"))
	})
	failed.stop()
	if acmeFixtureHasCertificate(failedDataDir) {
		t.Fatal("CA-rejected issuance produced a certificate")
	}
	// Distinguish unreachable HTTP-01 from CA policy: same allowed IP, but
	// Pebble contacts the original port and the core listens on another one.
	state.Certificates[0].Certificate.ServerName = "qingnode-acme.example.test"
	assetRoot = filepath.Join(dir, "failed-http-assets")
	state.Certificates[0].Certificate.ACME.AlternativeHTTPPort = freePort(t)
	failedDataDir = CertificateACMEDirectory(assetRoot, state.Certificates[0])
	failed = startServer("server-http-unreachable")
	acmeFixtureWait(t, 12*time.Second, "HTTP-01 reachability failure", func() bool {
		log := failed.logBytes()
		return bytes.Contains(log, []byte("urn:ietf:params:acme:error:connection")) || bytes.Contains(log, []byte("connection refused"))
	})
	failed.stop()
	if acmeFixtureHasCertificate(failedDataDir) {
		t.Fatal("unreachable challenge produced a certificate")
	}
	if dnsQueries.Load() == 0 {
		t.Fatal("test CA never queried the owned DNS resolver")
	}
	t.Log("check success distinguished from real CA policy rejection and unreachable HTTP-01; private test CA and all child processes are cleaned")
}

type acmeFixtureChild struct {
	t       *testing.T
	cmd     *exec.Cmd
	log     *os.File
	done    chan struct{}
	stopped bool
}

func acmeFixtureProcess(t *testing.T, bin string, args, env []string) *acmeFixtureChild {
	t.Helper()
	log, err := os.CreateTemp(t.TempDir(), "owned-child-log-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env, cmd.Stdout, cmd.Stderr = env, log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	p := &acmeFixtureChild{t: t, cmd: cmd, log: log, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			t.Logf("owned child log: %s", p.logBytes())
		}
		_ = log.Close()
	})
	return p
}
func (p *acmeFixtureChild) stop() {
	if p.stopped {
		return
	}
	p.stopped = true
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.t.Error("owned ACME fixture child did not stop after kill")
	}
}
func (p *acmeFixtureChild) logBytes() []byte { b, _ := os.ReadFile(p.log.Name()); return b }
func acmeFixtureWait(t *testing.T, budget time.Duration, label string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s not observed within %s", label, budget)
}
func acmeFixtureHasCertificate(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && strings.Contains(filepath.ToSlash(path), "/certificates/") && strings.HasSuffix(path, ".crt") {
			found = true
		}
		return nil
	})
	return found
}
func acmeFixtureIssued(t *testing.T, dir string, previous any, budget time.Duration) (*x509.Certificate, []byte) {
	t.Helper()
	var leaf *x509.Certificate
	var key []byte
	acmeFixtureWait(t, budget, "real ACME issuance in owned storage", func() bool {
		leaf, key = acmeFixtureReadCertificate(dir, previous, true)
		return leaf != nil
	})
	return leaf, key
}

func acmeFixtureReadCertificate(dir string, previous any, requireValid bool) (*x509.Certificate, []byte) {
	var leaf *x509.Certificate
	var key []byte
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.Contains(filepath.ToSlash(path), "/certificates/") || !strings.HasSuffix(path, ".crt") {
			return nil
		}
		b, _ := os.ReadFile(path)
		block, _ := pem.Decode(b)
		if block == nil {
			return nil
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || (previous != nil && cert.SerialNumber.String() == fmt.Sprint(previous)) || (requireValid && (time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter))) {
			return nil
		}
		kb, err := os.ReadFile(strings.TrimSuffix(path, ".crt") + ".key")
		if err != nil {
			return nil
		}
		if _, err = tls.X509KeyPair(b, kb); err == nil {
			leaf, key = cert, kb
		}
		return nil
	})
	return leaf, key
}

// These are test-only limits for the unchanged official core's native retry,
// not a QingNode renewal loop or a changed core timer. Keep ordinary errors on
// the original fast budget. Only the verified Pebble 2.10.1 sign-padding error
// allows the two upstream backoffs (one minute, then two minutes) plus 15s for
// local challenge/finalization. No CA response or stored asset is rewritten.
func acmeFixtureRenewed(t *testing.T, dir string, previous *x509.Certificate, process *acmeFixtureChild, budget time.Duration) (*x509.Certificate, []byte) {
	t.Helper()
	started := time.Now()
	deadline := started.Add(budget)
	allowedRetry := false
	for time.Now().Before(deadline) {
		if cert, key := acmeFixtureReadCertificate(dir, previous.SerialNumber.String(), true); cert != nil {
			return cert, key
		}
		select {
		case <-process.done:
			t.Fatal("owned core exited before a new valid ACME certificate/key was committed")
		default:
		}
		if !allowedRetry && acmeFixturePebbleARISignPaddingFailure(previous, process.logBytes()) {
			allowedRetry = true
			retryDeadline := time.Now().Add(3*time.Minute + 15*time.Second)
			if retryDeadline.After(deadline) {
				deadline = retryDeadline
			}
			t.Log("observed fixed Pebble 2.10.1 ARI DER sign-padding HTTP 500; waiting for the official core's unchanged 60s + 120s retry path (third attempt omits Replaces), still requiring a new valid serial/key, extended expiry, original account and real HY2 HTTPS/UDP")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if allowedRetry {
		t.Fatalf("real ACME renewal not observed after %s, including the fixed Pebble ARI failure and official core's bounded native retry; the CA HTTP 500 is not a successful renewal", time.Since(started))
	}
	t.Fatalf("real ACME renewal in owned storage not observed within %s", budget)
	return nil, nil
}

func acmeFixturePebbleARISignPaddingFailure(leaf *x509.Certificate, log []byte) bool {
	if leaf == nil || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return false
	}
	der, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil || len(der) < 4 || der[2] != 0 || der[3]&0x80 == 0 {
		return false
	}
	// Fixed upstream evidence (test compatibility, no source copied): Pebble
	// b1e1ca4f3c30abb64111adaca4544bc5374cc306 ca/ca.go stores unsigned serial
	// bytes; core/types.go NewCertID hex-encodes the DER integer bytes including
	// a sign byte; db/memorystore.go GetOrderByIssuedSerial does an exact lookup.
	// acmez 7dcf056529711646f5b419cac305fa170b108bb7 correctly sends the DER
	// integer. CertMagic 60d9d8b415d6e3f2fa7aec9b440c7dc2473126d4 async.go and
	// acmeissuer.go retain their native retry/backoff and Replaces fallback.
	return bytes.Contains(log, []byte("HTTP 500 urn:ietf:params:acme:error:serverInternal - could not find an order for the given certificate: could not find order resulting in the given certificate serial number"))
}
func acmeFixtureAccountHashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	values := map[string]string{}
	_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() && strings.Contains(filepath.ToSlash(path), "/users/") && strings.HasSuffix(path, ".key") {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(dir, path)
			digest := sha256.Sum256(b)
			values[rel] = hex.EncodeToString(digest[:])
		}
		return nil
	})
	return values
}
func equalACMEFixtureHashes(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func acmeFixtureHY2(t *testing.T, core string, serverPort int, serverName string, root []byte) {
	t.Helper()
	proxyPort := freePort(t)
	user := User{ID: Token(8), Name: "owned-test-user", Password: "fixture-auth-preserved"}
	node := Node{ID: Token(8), Name: "owned-issued-entry", Protocol: "hysteria2", Host: "127.0.0.1", Port: serverPort, Certificate: &Certificate{Mode: "pem", ServerName: serverName}, Users: []User{user}}
	config := Client(node, user, proxyPort)
	config["log"] = M{"level": "info", "timestamp": false}
	config["outbounds"].([]any)[0].(M)["tls"].(M)["certificate"] = []string{string(root)}
	b, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "hy2-client.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	p := acmeFixtureProcess(t, core, []string{"run", "-c", path}, os.Environ())
	defer p.stop()
	startup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitCoreStartup(startup, p.cmd.Process.Pid, b, p.done, p.log.Name()); err != nil {
		t.Fatal("issued-certificate client owned listener/startup readiness", err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "owned-acme-hy2-https") }))
	defer origin.Close()
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	// The HTTPS origin is another private test CA. Pin exactly that root.
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	// A restored certificate already exists on disk, so acmeFixtureIssued can
	// return before this new server's provider has loaded its cache. The real
	// failure showed "no matching certificates" and a QUIC TLS internal error.
	// Wait for an authenticated, verified application request in this same
	// client/server pair; neither a bound UDP port nor disk PEM proves readiness.
	readiness, cancelReadiness := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelReadiness()
	resp, attempts, err := acmeFixtureHTTPSReadiness(readiness, client, origin.URL, p.done)
	if err != nil {
		t.Fatal("HTTPS through issued-certificate HY2 did not become ready within its independent budget", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != 200 || string(body) != "owned-acme-hy2-https" {
		t.Fatal("HY2 HTTPS payload", resp.StatusCode, err)
	}
	if attempts > 1 {
		t.Logf("verified authenticated HY2 HTTPS became ready after %d bounded requests without restarting either core; checking sequence UDP next", attempts)
	}
	target, count := probeTestUDP(t, true)
	udp, err := probe.RunUDP(context.Background(), probe.UDPOptions{Target: target, ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
	if err != nil || udp.Sent != 2 || udp.Received != 2 || count.Load() != 2 {
		t.Fatalf("issued-certificate HY2 sequence UDP failed: %+v %v target=%d", udp, err, count.Load())
	}
}

// A network/TLS setup error can be transient while a new core loads its
// certificate provider. Application responses are returned immediately so the
// original exact status/body assertion still rejects a wrong or failed target.
// There is one caller deadline, no process restart or unverified TLS fallback.
func acmeFixtureHTTPSReadiness(ctx context.Context, client *http.Client, target string, exited <-chan struct{}) (*http.Response, int, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, 0, fmt.Errorf("fixture application readiness requires an explicit deadline")
	}
	attempts := 0
	var lastErr error
	for {
		select {
		case <-exited:
			return nil, attempts, fmt.Errorf("owned client exited before application readiness")
		case <-ctx.Done():
			return nil, attempts, fmt.Errorf("application readiness deadline: %w; last request: %v", ctx.Err(), lastErr)
		default:
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, attempts, err
		}
		attempts++
		response, err := client.Do(request)
		if err == nil {
			return response, attempts, nil
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		lastErr = err
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, attempts, fmt.Errorf("application readiness deadline: %w; last request: %v", ctx.Err(), lastErr)
		case <-exited:
			timer.Stop()
			return nil, attempts, fmt.Errorf("owned client exited before application readiness; last request: %v", lastErr)
		case <-timer.C:
		}
	}
}

func TestACMEHTTPSReadinessKeepsTLSAndApplicationFailuresBounded(t *testing.T) {
	t.Run("transient-connection-reset", func(t *testing.T) {
		var requests atomic.Int32
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 1 {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
			_, _ = io.WriteString(w, "verified-ready")
		}))
		defer origin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		response, attempts, err := acmeFixtureHTTPSReadiness(ctx, origin.Client(), origin.URL, make(chan struct{}))
		if err != nil {
			t.Fatal("real verified HTTPS should recover from one owned connection reset", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 100))
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "verified-ready" || attempts != 2 || requests.Load() != 2 {
			t.Fatal("readiness did not preserve the exact real HTTPS response and attempts", attempts, requests.Load(), err)
		}
	})
	t.Run("wrong-trust-remains-failure", func(t *testing.T) {
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted HTTPS must never reach application") }))
		defer origin.Close()
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
		defer cancel()
		response, attempts, err := acmeFixtureHTTPSReadiness(ctx, client, origin.URL, make(chan struct{}))
		if err == nil || response != nil || attempts < 1 || ctx.Err() == nil {
			t.Fatal("wrong trust must exhaust one deadline and remain failure", attempts, err)
		}
	})
	t.Run("application-failure-is-not-retried", func(t *testing.T) {
		var requests atomic.Int32
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer origin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		response, attempts, err := acmeFixtureHTTPSReadiness(ctx, origin.Client(), origin.URL, make(chan struct{}))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusServiceUnavailable || attempts != 1 || requests.Load() != 1 {
			t.Fatal("a failed application response must remain visible to the exact caller assertion")
		}
	})
	t.Run("dead-client-and-unbounded-context-rejected", func(t *testing.T) {
		exited := make(chan struct{})
		close(exited)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if response, attempts, err := acmeFixtureHTTPSReadiness(ctx, http.DefaultClient, "https://127.0.0.1:1", exited); err == nil || response != nil || attempts != 0 {
			t.Fatal("already exited client must be rejected before any request")
		}
		if response, attempts, err := acmeFixtureHTTPSReadiness(context.Background(), http.DefaultClient, "https://127.0.0.1:1", nil); err == nil || response != nil || attempts != 0 {
			t.Fatal("readiness cannot run without an independent deadline")
		}
	})
}

// Pebble v2.10.1 resolves challenges over TCP. This owned authoritative fixture
// handles both transports, returning one A record only for the explicit name.
// No global resolver or host file is changed, and no external DNS is contacted.
func acmeFixtureDNS(t *testing.T, name string) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	queries := &atomic.Int32{}
	var workers sync.WaitGroup
	answer := func(query []byte) []byte {
		if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
			return nil
		}
		end := 12
		var labels []string
		for end < len(query) && query[end] != 0 {
			n := int(query[end])
			if n > 63 || end+1+n >= len(query) {
				return nil
			}
			labels = append(labels, string(query[end+1:end+1+n]))
			end += 1 + n
		}
		end += 5
		if end > len(query) {
			return nil
		}
		qtype := binary.BigEndian.Uint16(query[end-4 : end-2])
		result := append([]byte(nil), query[:end]...)
		binary.BigEndian.PutUint16(result[2:4], 0x8400|(binary.BigEndian.Uint16(query[2:4])&0x0100))
		for i := 6; i < 12; i++ {
			result[i] = 0
		}
		if qtype == 1 && strings.EqualFold(strings.Join(labels, "."), name) {
			binary.BigEndian.PutUint16(result[6:8], 1)
			result = append(result, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1)
		}
		queries.Add(1)
		return result
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		b := make([]byte, 4096)
		for {
			n, addr, err := packet.ReadFrom(b)
			if err != nil {
				return
			}
			if response := answer(b[:n]); response != nil {
				_, _ = packet.WriteTo(response, addr)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(connection, length[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(length[:]))
				if n < 17 || n > 4096 {
					return
				}
				b := make([]byte, n)
				if _, err := io.ReadFull(connection, b); err != nil {
					return
				}
				response := answer(b)
				if response == nil {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(response)))
				_, _ = connection.Write(append(length[:], response...))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		_ = packet.Close()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("owned ACME DNS fixture did not stop")
		}
	})
	return listener.Addr().String(), queries
}

func acmeFixtureCoreVersion(t *testing.T, core string) string {
	t.Helper()
	out, err := exec.Command(core, "version").CombinedOutput()
	fields := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	if err != nil || len(fields) != 3 || fields[0] != "sing-box" || fields[1] != "version" || fields[2] != "1.14.0" && fields[2] != "1.14.3" || !strings.Contains(string(out), "with_acme") {
		t.Fatalf("requires fixed official 1.14.0/1.14.3 with_acme: %v %s", err, out)
	}
	return fields[2]
}

// Asset restoration deliberately
// uses the public offline preparation backend; the caller then performs the
// separate real-core startup and HY2 data assertions from that restored State.
func acmeFixtureMigrationRoundTrip(t *testing.T, state State, assetRoot string) (State, string) {
	t.Helper()
	var err error
	state, err = CanonicalCertificates(state)
	if err != nil {
		t.Fatal(err)
	}
	sourceStore := &Store{Root: assetRoot, Backend: OfflineBackend{}, GID: -1}
	var encrypted []byte
	if err = sourceStore.WithLock(func() error {
		snapshot, err := Capture(assetRoot, state, "owned-real-acme-migration-fixture", "[Service]\nExecStart=/source/evidence-only\n")
		if err != nil {
			return err
		}
		migration, err := CaptureMigration(snapshot, []MigrationRoot{{ID: "acme", Kind: "acme-storage", Source: filepath.Join(assetRoot, "acme"), OwnerID: os.Geteuid(), GroupID: -1}}, nil, true)
		if err != nil {
			return err
		}
		if migration.Mode != "complete" || migration.Consistency != "stopped-owned-core" {
			return fmt.Errorf("real ACME assets were not accepted as a complete stopped-core package")
		}
		encrypted, err = BackupMigration(migration, "owned-acme-migration-password")
		return err
	}); err != nil {
		t.Fatal("capture/encrypt real stopped ACME storage", err)
	}
	if !IsMigrationBackup(encrypted) {
		t.Fatal("real ACME asset package is not QNBK3")
	}
	migration, err := RestoreMigration(encrypted, "owned-acme-migration-password")
	if err != nil {
		t.Fatal("decrypt real ACME package", err)
	}
	targetRoot := t.TempDir()
	targetStore := &Store{Root: targetRoot, Backend: OfflineBackend{}, GID: -1}
	if err = targetStore.WithLock(func() error {
		return targetStore.RestoreMigrationAssets(migration, MigrationTargets{"acme": {Path: filepath.Join(targetRoot, "acme"), OwnerID: os.Geteuid(), GroupID: -1}}, false)
	}); err != nil {
		t.Fatal("restore real ACME assets to clean offline target", err)
	}
	loaded, err := targetStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !migrationSameState(loaded, state) {
		t.Fatal("ACME migration changed resource, entry or proxy credential identity")
	}
	for _, entry := range migration.Files {
		if entry.Directory {
			continue
		}
		data, err := os.ReadFile(filepath.Join(targetRoot, "acme", filepath.FromSlash(entry.Path)))
		if err != nil || !bytes.Equal(data, entry.Data) {
			t.Fatal("real ACME account/certificate/private key storage changed on restore", entry.Path, err)
		}
	}
	t.Log("complete encrypted QNBK3 round trip preserved every real ACME account, certificate, private-key and metadata byte in a clean offline target; subsequent caller checks use the actual official core and authenticated HY2 transport")
	return loaded, targetRoot
}
