//go:build linux

package node

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/probe"

	"gopkg.in/yaml.v3"
)

// These fixtures run owned loopback child processes only. They do not install
// services, change a trust store, use public targets, or claim systemd evidence.
func protocolExpansionInputs(t *testing.T, needMihomo bool) (core, version, mihomo string) {
	t.Helper()
	core, mihomo = os.Getenv("SING_BOX_BIN"), os.Getenv("MIHOMO_BIN")
	if core == "" || needMihomo && mihomo == "" {
		t.Skip("requires separately verified official SING_BOX_BIN and, for Mihomo, MIHOMO_BIN; real protocol expansion evidence was not collected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, core, "version").Output()
	if err != nil {
		t.Fatal("official core version unavailable", err)
	}
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	if line != "sing-box version 1.14.0" && line != "sing-box version 1.14.3" {
		t.Fatal("protocol expansion fixture requires official sing-box 1.14.0 or 1.14.3")
	}
	version = strings.TrimPrefix(line, "sing-box version ")
	for _, protocol := range []string{"anytls", "trojan"} {
		if _, ok := Protocol(protocol); !ok {
			t.Fatal("requested protocol expansion adapter is not registered", protocol)
		}
	}
	if needMihomo {
		output, err = exec.CommandContext(ctx, mihomo, "-v").Output()
		if err != nil || !strings.Contains(string(output), "v1.19.30") {
			t.Fatal("protocol expansion fixture requires official Mihomo v1.19.30")
		}
		t.Logf("actual %s; %s", line, strings.TrimSpace(string(output)))
	} else {
		t.Logf("actual %s", line)
	}
	return
}

func protocolExpansionTLSState(t *testing.T, version string) State {
	t.Helper()
	cert, key := makeCert(t)
	s := NewState()
	s.CoreVersion = version
	s.Certificates = []CertificateResource{{ID: Token(8), Name: "shared expansion private CA", Certificate: Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
	for _, protocol := range []string{"anytls", "trojan"} {
		s.Nodes = append(s.Nodes, Node{ID: Token(8), Name: "expansion-" + protocol, Protocol: protocol,
			Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
			CertificateID: s.Certificates[0].ID, Users: []User{NewUser("first", protocol), NewUser("survivor", protocol)}})
	}
	var err error
	s, err = CanonicalCertificates(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Validate(); err != nil {
		t.Fatal("new TLS protocol fixture validation", err)
	}
	if s.Nodes[0].CertificateID != s.Nodes[1].CertificateID {
		t.Fatal("two TLS protocols did not share the explicit certificate resource")
	}
	return s
}

// The startup marker is observed after listener ownership. Only logging is
// adjusted in this child-only configuration, as in the existing core fixtures.
func protocolExpansionStartCore(t *testing.T, bin string, config []byte) func() {
	t.Helper()
	config, err := testCoreStartupLogConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "protocol-client.json")
	if err = os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("official parser rejected protocol client: %v %s", err, output)
	}
	log, err := os.CreateTemp(root, "startup-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
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
				t.Error("owned protocol expansion client did not stop")
			}
			log.Close()
		})
	}
	t.Cleanup(stop)
	if err = waitCoreStartup(ctx, cmd.Process.Pid, config, done, log.Name()); err != nil {
		t.Fatal("owned protocol client startup did not complete", err)
	}
	return stop
}

// Apply still checks the exact generated server.json. Its isolated test backend
// runs a child-only logging projection to observe complete startup, rather than
// assuming that an open TCP port means the protocol is ready.
type protocolExpansionBackend struct {
	processBackend
}

func (b *protocolExpansionBackend) Activate(s State) error {
	if err := b.Stop(); err != nil {
		return err
	}
	b.starts++
	config, err := os.ReadFile(filepath.Join(b.root, "current", "server.json"))
	if err != nil {
		return err
	}
	config, err = testCoreStartupLogConfig(config)
	if err != nil {
		return err
	}
	path := filepath.Join(b.root, "expansion-owned-running.json")
	if err = os.WriteFile(path, config, 0600); err != nil {
		return err
	}
	log, err := os.CreateTemp(b.root, "expansion-startup-")
	if err != nil {
		return err
	}
	defer log.Close()
	b.cmd = exec.Command(b.bin, "run", "-c", path)
	b.cmd.Stdout, b.cmd.Stderr = log, log
	if err = b.cmd.Start(); err != nil {
		b.cmd = nil
		return err
	}
	b.done = make(chan error, 1)
	exited := make(chan struct{})
	cmd, done := b.cmd, b.done
	go func() { done <- cmd.Wait(); close(exited) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return waitCoreStartup(ctx, cmd.Process.Pid, config, exited, log.Name())
}

type protocolExpansionTargets struct {
	HTTPURL    string
	UDPAddress string
	HTTPHits   *atomic.Int32
	UDPHits    *atomic.Int32
}

func protocolExpansionTarget(t *testing.T) protocolExpansionTargets {
	t.Helper()
	hits := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "protocol-expansion-owned-payload")
	}))
	t.Cleanup(origin.Close)
	udp, count := probeTestUDP(t, true)
	return protocolExpansionTargets{origin.URL, udp, hits, count}
}

func protocolExpansionClient(t *testing.T, core, mihomo, version, format string, n Node, u User, cert, wrongName string) (int, *http.Client, func()) {
	t.Helper()
	port := freePort(t)
	client := deviceHTTPClient(port)
	client.Timeout = 3 * time.Second
	t.Cleanup(client.CloseIdleConnections)
	if format == "sing-box" {
		cfg := Client(n, u, port)
		out := cfg["outbounds"].([]any)[0].(M)
		tlsConfig, ok := out["tls"].(M)
		if !ok || tlsConfig["enabled"] != true || tlsConfig["insecure"] == true {
			t.Fatal("TLS protocol client does not preserve certificate verification")
		}
		tlsConfig["certificate"] = []string{cert}
		if wrongName != "" {
			tlsConfig["server_name"] = wrongName
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return port, client, protocolExpansionStartCore(t, core, data)
	}
	exported, err := ExportWithCapabilities(n, u, "mihomo", "1.19.30", nil, false)
	if err != nil || len(exported.Warnings) != 0 {
		t.Fatal("new TLS protocol Mihomo export is unsupported or lossy", err)
	}
	var cfg M
	if err = yaml.Unmarshal(exported.Data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["mixed-port"], cfg["allow-lan"], cfg["bind-address"] = port, false, "127.0.0.1"
	cfg["external-controller"] = ""
	proxy := cfg["proxies"].([]any)[0].(map[string]any)
	if proxy["skip-cert-verify"] == true {
		t.Fatal("Mihomo protocol export disabled certificate verification")
	}
	if wrongName != "" {
		proxy["sni"] = wrongName
	}
	return port, client, deviceStartMihomo(t, mihomo, cfg, cert)
}

func protocolExpansionExchange(t *testing.T, port int, client *http.Client, target protocolExpansionTargets, wantSuccess bool) {
	t.Helper()
	httpBefore, udpBefore := target.HTTPHits.Load(), target.UDPHits.Load()
	response, err := client.Get(target.HTTPURL)
	matched := false
	if response != nil {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 256))
		response.Body.Close()
		matched = err == nil && readErr == nil && response.StatusCode == http.StatusOK && string(body) == "protocol-expansion-owned-payload"
	}
	if matched != wantSuccess {
		t.Fatalf("TCP authentication/payload success=%v expected=%v error=%v", matched, wantSuccess, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, udpErr := probe.RunUDP(ctx, probe.UDPOptions{Target: target.UDPAddress, Family: "ipv4", ProxyAddress: "127.0.0.1:" + strconv.Itoa(port), Samples: 2, PayloadBytes: 64, MaxBytes: 257, Timeout: 700 * time.Millisecond, Interval: 10 * time.Millisecond})
	if wantSuccess {
		if udpErr != nil || result.Status != "passed" || result.Sent != 2 || result.Received != 2 || result.Lost != 0 || result.Unfinished != 0 || result.LossPercent == nil || *result.LossPercent != 0 {
			t.Fatalf("independent authenticated UDP payload failed: %+v error=%v", result, udpErr)
		}
		if target.HTTPHits.Load() != httpBefore+1 || target.UDPHits.Load() != udpBefore+2 {
			t.Fatal("controlled target counters did not match actual TCP/UDP requests")
		}
	} else {
		if result.Status == "passed" || result.Received != 0 || target.HTTPHits.Load() != httpBefore || target.UDPHits.Load() != udpBefore {
			t.Fatalf("rejected protocol client reached the controlled target or bypassed the proxy: TCP=%d->%d UDP=%d->%d result=%+v", httpBefore, target.HTTPHits.Load(), udpBefore, target.UDPHits.Load(), result)
		}
	}
}

func TestOfficialCoreTLSProtocolExpansionTCPUDPRevokeBackupAndCertificateMismatch(t *testing.T) {
	core, version, _ := protocolExpansionInputs(t, false)
	for _, protocol := range []string{"anytls", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			s := protocolExpansionTLSState(t, version)
			backend := &protocolExpansionBackend{processBackend: processBackend{root: t.TempDir(), bin: core}}
			store := &Store{Root: backend.root, Backend: backend, GID: -1}
			t.Cleanup(func() {
				if err := backend.Stop(); err != nil {
					t.Error(err)
				}
			})
			apply := func(candidate State) State {
				t.Helper()
				if err := store.WithLock(func() error { return store.Apply(candidate) }); err != nil {
					t.Fatal(err)
				}
				loaded, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				return loaded
			}
			s = apply(s)
			original := s.Clone()
			index := 0
			if protocol == "trojan" {
				index = 1
			}
			n := s.Nodes[index]
			target := protocolExpansionTarget(t)
			ports := make([]int, 2)
			clients := make([]*http.Client, 2)
			for i, u := range n.Users {
				port, client, stop := protocolExpansionClient(t, core, "", version, "sing-box", n, u, n.Certificate.CertPEM, "")
				defer stop()
				ports[i], clients[i] = port, client
				protocolExpansionExchange(t, port, client, target, true)
			}
			for _, negative := range []string{"wrong-password", "wrong-certificate-name"} {
				u := n.Users[0]
				wrongName := ""
				if negative == "wrong-password" {
					u = NewUser("not-on-server", protocol)
				} else {
					wrongName = "wrong-name.invalid"
				}
				port, client, stop := protocolExpansionClient(t, core, "", version, "sing-box", n, u, n.Certificate.CertPEM, wrongName)
				protocolExpansionExchange(t, port, client, target, false)
				stop()
			}
			// Snapshot the two live identities before revoking the first one.
			snapshot, err := Capture(store.Root, s, "protocol-expansion-fixture", ServiceUnit)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := BackupSnapshot(snapshot, "owned protocol expansion backup password")
			if err != nil {
				t.Fatal(err)
			}
			pid, starts := backend.cmd.Process.Pid, backend.starts
			revoked := s.Clone()
			revoked.Nodes[index].Users = append([]User(nil), revoked.Nodes[index].Users[1:]...)
			s = apply(revoked)
			if backend.cmd.Process.Pid == pid || backend.starts != starts+1 {
				t.Fatal("credential removal did not replace the isolated core exactly once")
			}
			protocolExpansionExchange(t, ports[0], clients[0], target, false)
			protocolExpansionExchange(t, ports[1], clients[1], target, true)
			restored, err := RestoreSnapshot(sealed, "owned protocol expansion backup password")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored.State, original) {
				t.Fatal("encrypted restore changed protocol, node/user IDs, credentials, or shared certificate identity")
			}
			s = apply(restored.State)
			if s.Nodes[index].ID != n.ID || s.Nodes[index].CertificateID != n.CertificateID || !reflect.DeepEqual(s.Nodes[index].Users, n.Users) || s.Nodes[index].Certificate.CertPEM != n.Certificate.CertPEM || s.Nodes[index].Certificate.KeyPEM != n.Certificate.KeyPEM {
				t.Fatal("applied restore did not preserve original TLS/user identity")
			}
			// Fresh clients avoid treating a pre-revocation pooled session as a
			// successful restored authentication.
			for _, u := range s.Nodes[index].Users {
				port, client, stop := protocolExpansionClient(t, core, "", version, "sing-box", s.Nodes[index], u, n.Certificate.CertPEM, "")
				protocolExpansionExchange(t, port, client, target, true)
				stop()
			}
			if err = backend.Stop(); err != nil {
				t.Fatal(err)
			}
			protocolExpansionExchange(t, ports[1], clients[1], target, false)
			t.Logf("official %s %s: shared verified TLS certificate; two distinct users passed TCP and two UDP payloads; wrong password/name rejected without target hits; revoked user denied and survivor passed after one core replacement; encrypted pre-revocation backup restored exact identities and fresh authentication; stopped server had no direct fallback", version, protocol)
		})
	}
}

func TestMihomoTLSProtocolExpansionTCPUDPAndCertificateMismatch(t *testing.T) {
	core, version, mihomo := protocolExpansionInputs(t, true)
	for _, protocol := range []string{"anytls", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			s := protocolExpansionTLSState(t, version)
			server, err := Server(s, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			stopServer := protocolExpansionStartCore(t, core, server)
			defer stopServer()
			index := 0
			if protocol == "trojan" {
				index = 1
			}
			n := s.Nodes[index]
			target := protocolExpansionTarget(t)
			for _, u := range n.Users {
				port, client, stop := protocolExpansionClient(t, core, mihomo, version, "mihomo", n, u, n.Certificate.CertPEM, "")
				protocolExpansionExchange(t, port, client, target, true)
				stop()
			}
			for _, negative := range []string{"wrong-password", "wrong-certificate-name"} {
				u := n.Users[0]
				wrongName := ""
				if negative == "wrong-password" {
					u = NewUser("not-on-server", protocol)
				} else {
					wrongName = "wrong-name.invalid"
				}
				port, client, stop := protocolExpansionClient(t, core, mihomo, version, "mihomo", n, u, n.Certificate.CertPEM, wrongName)
				protocolExpansionExchange(t, port, client, target, false)
				stop()
			}
			stopServer()
			port, client, stop := protocolExpansionClient(t, core, mihomo, version, "mihomo", n, n.Users[1], n.Certificate.CertPEM, "")
			defer stop()
			protocolExpansionExchange(t, port, client, target, false)
			t.Logf("official %s server + Mihomo 1.19.30 %s: parser accepted unweakened TLS export; two users passed actual TCP and UDP; wrong password and certificate name denied without target hits; stopped server did not fall back direct; private CA scoped only to child process", version, protocol)
		})
	}
}
