//go:build linux

package node

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Read only a log path created by this fixture, with bounded output and State
// redaction. Never dump client/server configuration or raw secret-bearing errors.
func protocolExpansionPhase2LogOwned(t *testing.T, label, path string, states ...State) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Logf("phase2 owned log unavailable: %s", label)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		t.Logf("phase2 owned log unreadable: %s", label)
		return
	}
	defer f.Close()
	if info.Size() > 16<<10 {
		_, _ = f.Seek(-(16 << 10), io.SeekEnd)
	}
	data, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err != nil {
		t.Logf("phase2 owned log read failed: %s", label)
		return
	}
	t.Logf("phase2 owned log %s (last <=16KiB):\n%s", label, Redact(string(data), states...))
}

// Use the same owned listener/startup marker as the first-stage fixture, while
// retaining a bounded, redacted child log if a later payload assertion fails.
func protocolExpansionPhase2StartCore(t *testing.T, bin string, config []byte, state State) func() {
	t.Helper()
	config, err := testCoreStartupLogConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "phase2-client.json")
	if err = os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("official parser rejected phase2 client: %s", Redact(string(output), state))
	}
	log, err := os.CreateTemp(root, "phase2-owned-client-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal("phase2 owned client could not start")
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
				t.Error("owned phase2 client did not stop")
			}
			log.Close()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			protocolExpansionPhase2LogOwned(t, "client", log.Name(), state)
		}
	})
	if err = waitCoreStartup(ctx, cmd.Process.Pid, config, done, log.Name()); err != nil {
		t.Fatal("owned phase2 client startup did not complete")
	}
	return stop
}

type protocolExpansionPhase2Case struct {
	Protocol string
	Method   string
	Relay    string
}

func (c protocolExpansionPhase2Case) name() string {
	if c.Method != "" {
		return c.Protocol + "/" + c.Method
	}
	return c.Protocol + "/" + c.Relay
}

func protocolExpansionPhase2Cases() []protocolExpansionPhase2Case {
	return []protocolExpansionPhase2Case{
		{Protocol: "ss-aead", Method: "aes-128-gcm"},
		{Protocol: "ss-aead", Method: "aes-256-gcm"},
		{Protocol: "ss-aead", Method: "chacha20-ietf-poly1305"},
		{Protocol: "tuic", Relay: "native"},
		{Protocol: "tuic", Relay: "quic"},
	}
}

func protocolExpansionPhase2State(t *testing.T, version string, c protocolExpansionPhase2Case) State {
	t.Helper()
	if _, ok := Protocol(c.Protocol); !ok {
		t.Fatal("requested phase-two protocol adapter is not registered", c.Protocol)
	}
	s := NewState()
	s.CoreVersion = version
	n := Node{ID: Token(8), Name: "phase-two-" + c.Protocol, Protocol: c.Protocol, Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		Users: []User{NewUser("first", c.Protocol), NewUser("survivor", c.Protocol)}}
	if c.Protocol == "ss-aead" {
		n.Shadowsocks = &Shadowsocks{Method: c.Method}
		if n.Users[0].Password == n.Users[1].Password || n.Users[0].Password == "" || n.Users[0].UUID != "" || n.Users[1].UUID != "" {
			t.Fatal("classic AEAD requires two independent password-only identities")
		}
	} else {
		cert, key := makeCert(t)
		s.Certificates = []CertificateResource{{ID: Token(8), Name: "phase-two-TUIC-private-CA", Certificate: Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
		n.CertificateID = s.Certificates[0].ID
		n.TUIC = &TUICOptions{UDPRelayMode: c.Relay}
		if n.Users[0].UUID == "" || n.Users[1].UUID == "" || n.Users[0].UUID == n.Users[1].UUID || n.Users[0].Password == "" || n.Users[0].Password == n.Users[1].Password {
			t.Fatal("TUIC needs two distinct UUID/password pairs")
		}
	}
	s.Nodes = []Node{n}
	var err error
	s, err = CanonicalCertificates(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Validate(); err != nil {
		t.Fatal("phase-two real transport fixture validation", err)
	}
	return s
}

// Classic AEAD has no TLS and no SS2022 server:user composite. TUIC uses only
// the private fixture CA in its child client; production verification stays on.
func protocolExpansionPhase2Client(t *testing.T, core, mihomo, version, format string, n Node, u User, wrongName string) (int, *http.Client, func()) {
	t.Helper()
	port := freePort(t)
	client := deviceHTTPClient(port)
	client.Timeout = 3 * time.Second
	t.Cleanup(client.CloseIdleConnections)
	if format == "sing-box" {
		cfg := Client(n, u, port)
		out := cfg["outbounds"].([]any)[0].(M)
		if n.Protocol == "ss-aead" {
			if _, exists := out["tls"]; exists {
				t.Fatal("classic AEAD client invented TLS")
			}
			if n.Shadowsocks.ServerKey != "" || out["password"] != u.Password || out["method"] != n.Shadowsocks.Method {
				t.Fatal("classic AEAD client changed independent password/method into SS2022 material")
			}
		} else {
			tls, ok := out["tls"].(M)
			if !ok || tls["enabled"] != true || tls["insecure"] == true {
				t.Fatal("TUIC client disabled certificate verification")
			}
			tls["certificate"] = []string{n.Certificate.CertPEM}
			if wrongName != "" {
				tls["server_name"] = wrongName
			}
			if out["uuid"] != u.UUID || out["password"] != u.Password || out["udp_relay_mode"] != n.TUIC.UDPRelayMode {
				t.Fatal("TUIC client lost the selected UUID/password or UDP relay mode")
			}
		}
		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		clientNode := n
		clientNode.Users = []User{u}
		return port, client, protocolExpansionPhase2StartCore(t, core, encoded, State{Nodes: []Node{clientNode}})
	}
	result, err := ExportWithCapabilities(n, u, "mihomo", "1.19.30", nil, false)
	if err != nil || len(result.Warnings) != 0 {
		t.Fatal("phase-two Mihomo export was unsupported/lossy", err)
	}
	var cfg M
	if err = yaml.Unmarshal(result.Data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["mixed-port"], cfg["allow-lan"], cfg["bind-address"], cfg["external-controller"] = port, false, "127.0.0.1", ""
	proxy := cfg["proxies"].([]any)[0].(map[string]any)
	cert := ""
	if n.Protocol == "ss-aead" {
		if n.Shadowsocks.ServerKey != "" || proxy["password"] != u.Password || proxy["cipher"] != n.Shadowsocks.Method {
			t.Fatal("Mihomo classic AEAD export changed independent password/method")
		}
	} else {
		if proxy["skip-cert-verify"] == true || proxy["uuid"] != u.UUID || proxy["password"] != u.Password || proxy["udp-relay-mode"] != n.TUIC.UDPRelayMode {
			t.Fatal("Mihomo TUIC export lost native verification, UUID/password or UDP relay mode")
		}
		cert = n.Certificate.CertPEM
		if wrongName != "" {
			proxy["sni"] = wrongName
		}
	}
	return port, client, deviceStartMihomo(t, mihomo, cfg, cert)
}

func protocolExpansionPhase2Lifecycle(t *testing.T, core, version, mihomo, format string, c protocolExpansionPhase2Case) {
	t.Helper()
	s := protocolExpansionPhase2State(t, version, c)
	backend := &protocolExpansionBackend{processBackend: processBackend{root: t.TempDir(), bin: core}}
	store := &Store{Root: backend.root, Backend: backend, GID: -1}
	t.Cleanup(func() {
		if err := backend.Stop(); err != nil {
			t.Error(err)
		}
		if t.Failed() {
			entries, err := os.ReadDir(backend.root)
			if err == nil {
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "expansion-startup-") && entry.Type().IsRegular() {
						protocolExpansionPhase2LogOwned(t, "server/"+entry.Name(), filepath.Join(backend.root, entry.Name()), s)
					}
				}
			}
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
	t.Logf("phase=initial_apply protocol=%s format=%s", c.name(), format)
	s = apply(s)
	original := s.Clone()
	n := s.Nodes[0]
	target := protocolExpansionTarget(t)
	ports := make([]int, 2)
	clients := make([]*http.Client, 2)
	for i, u := range n.Users {
		t.Logf("phase=initial_user_start index=%d user_id=%s", i, u.ID)
		port, client, stop := protocolExpansionPhase2Client(t, core, mihomo, version, format, n, u, "")
		defer stop()
		ports[i], clients[i] = port, client
		protocolExpansionExchange(t, port, client, target, true)
		t.Logf("phase=initial_user_pass index=%d user_id=%s", i, u.ID)
	}
	negatives := []string{"wrong-password"}
	if c.Protocol == "tuic" {
		negatives = append(negatives, "wrong-uuid", "wrong-certificate-name")
	}
	for _, negative := range negatives {
		t.Logf("phase=negative_start case=%s", negative)
		u := n.Users[0]
		wrongName := ""
		switch negative {
		case "wrong-password":
			u.Password = NewUser("not-on-server", c.Protocol).Password
		case "wrong-uuid":
			u.UUID = NewUser("not-on-server", c.Protocol).UUID
		case "wrong-certificate-name":
			wrongName = "wrong-name.invalid"
		}
		port, client, stop := protocolExpansionPhase2Client(t, core, mihomo, version, format, n, u, wrongName)
		protocolExpansionExchange(t, port, client, target, false)
		t.Logf("phase=negative_pass case=%s", negative)
		stop()
	}
	t.Log("phase=backup_capture_start")
	snapshot, err := Capture(store.Root, s, "phase-two-real-protocol-fixture", ServiceUnit)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := BackupSnapshot(snapshot, "phase-two owned encrypted backup password")
	if err != nil {
		t.Fatal(err)
	}
	pid, starts := backend.cmd.Process.Pid, backend.starts
	t.Logf("phase=revoke_apply_start old_server_pid=%d", pid)
	revoked := s.Clone()
	revoked.Nodes[0].Users = append([]User(nil), revoked.Nodes[0].Users[1:]...)
	s = apply(revoked)
	if backend.cmd.Process.Pid == pid || backend.starts != starts+1 {
		t.Fatal("phase-two user removal did not replace the isolated core exactly once")
	}
	t.Logf("phase=revoked_existing_client_denied_start new_server_pid=%d", backend.cmd.Process.Pid)
	protocolExpansionExchange(t, ports[0], clients[0], target, false)
	t.Log("phase=revoked_existing_client_denied_pass")
	// Replacing a running QUIC server can strand the previous client's
	// connection pool until its own heartbeat or idle timer detects closure.
	// Verify the surviving identity through a fresh connection. The old
	// connection's continuity is not a service guarantee after revocation.
	t.Log("phase=survivor_fresh_client_authentication_start")
	survivorPort, survivorClient, survivorStop := protocolExpansionPhase2Client(t, core, mihomo, version, format, s.Nodes[0], s.Nodes[0].Users[0], "")
	protocolExpansionExchange(t, survivorPort, survivorClient, target, true)
	survivorStop()
	t.Log("phase=survivor_fresh_client_authentication_pass")
	t.Log("phase=backup_restore_start")
	restored, err := RestoreSnapshot(sealed, "phase-two owned encrypted backup password")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.State, original) {
		t.Fatal("encrypted backup lost original method, relay, stable identities, passwords or certificate")
	}
	s = apply(restored.State)
	if !reflect.DeepEqual(s.Nodes[0].Users, n.Users) || s.Nodes[0].ID != n.ID || s.Nodes[0].Protocol != n.Protocol || !reflect.DeepEqual(s.Nodes[0].Shadowsocks, n.Shadowsocks) || !reflect.DeepEqual(s.Nodes[0].TUIC, n.TUIC) || s.Nodes[0].CertificateID != n.CertificateID {
		t.Fatal("phase-two restored runtime identities/settings changed")
	}
	for _, u := range s.Nodes[0].Users {
		t.Logf("phase=restored_fresh_client_start user_id=%s", u.ID)
		port, client, stop := protocolExpansionPhase2Client(t, core, mihomo, version, format, s.Nodes[0], u, "")
		protocolExpansionExchange(t, port, client, target, true)
		t.Logf("phase=restored_fresh_client_pass user_id=%s", u.ID)
		stop()
	}
	if err = backend.Stop(); err != nil {
		t.Fatal(err)
	}
	t.Log("phase=stopped_server_existing_client_denied_start")
	protocolExpansionExchange(t, ports[1], clients[1], target, false)
	t.Log("phase=stopped_server_existing_client_denied_pass")
	t.Logf("official %s %s %s: same-port two independent users passed TCP and two UDP samples each; wrong credentials denied without direct target hits; revoke denied only first user and surviving user passed; encrypted backup restored exact IDs/settings and both fresh authentications; stopped server had no fallback", version, format, c.name())
}

func TestOfficialCoreSSAEADTUICProtocolExpansionTCPUDPRevokeAndRestore(t *testing.T) {
	core, version, _ := protocolExpansionInputs(t, false)
	for _, c := range protocolExpansionPhase2Cases() {
		t.Run(c.name(), func(t *testing.T) { protocolExpansionPhase2Lifecycle(t, core, version, "", "sing-box", c) })
	}
}

func TestMihomoSSAEADTUICProtocolExpansionTCPUDPRevokeAndRestore(t *testing.T) {
	core, version, mihomo := protocolExpansionInputs(t, true)
	for _, c := range protocolExpansionPhase2Cases() {
		t.Run(c.name(), func(t *testing.T) { protocolExpansionPhase2Lifecycle(t, core, version, mihomo, "mihomo", c) })
	}
}

func protocolExpansionObservationCaseName(n Node) string {
	if n.Shadowsocks != nil && n.Protocol == "ss-aead" {
		return n.Protocol + "/" + n.Shadowsocks.Method
	}
	if n.TUIC != nil {
		return n.Protocol + "/" + n.TUIC.UDPRelayMode
	}
	return strings.TrimSpace(n.Protocol)
}
