package node

import (
	"encoding/json"
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

	"gopkg.in/yaml.v3"
)

// Parser acceptance and actual Mihomo HY2 TCP/UDP transport are separate
// evidence. Both programs are external checksum-verified official binaries.
func TestOfficialCoreMihomoHY2PerformanceInterop(t *testing.T) {
	core, mihomo := os.Getenv("SING_BOX_BIN"), os.Getenv("MIHOMO_BIN")
	if core == "" || mihomo == "" {
		t.Skip("SING_BOX_BIN and MIHOMO_BIN required for real two-client HY2 interoperability")
	}
	for _, tool := range []struct{ bin, arg string }{{core, "version"}, {mihomo, "-v"}} {
		b, e := exec.Command(tool.bin, tool.arg).CombinedOutput()
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("actual tool: %s", strings.TrimSpace(string(b)))
	}
	for _, tc := range []struct {
		name string
		p    *HY2Performance
	}{
		{"fixed-directional-mbps", &HY2Performance{ServerUpMbps: hyInt(31), ServerDownMbps: hyInt(47), ClientUpMbps: hyInt(11), ClientDownMbps: hyInt(13), ClientMode: "brutal", Client: &HY2Transport{DisableChromeParrot: hyBool(true)}}},
		{"bbr-explicit-windows", &HY2Performance{IgnoreClientBandwidth: hyBool(true), ClientMode: "bbr", Server: &HY2Transport{BBRProfile: "conservative"}, Client: &HY2Transport{DisableChromeParrot: hyBool(true), BBRProfile: "conservative", QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(4 << 20)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := hyFixture(t)
			s.Nodes[0].Port, s.Nodes[0].HY2 = freePort(t), tc.p
			n := s.Nodes[0]
			server, e := Server(s, t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			stopCore := probeTestCore(t, core, server)
			var hits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, "mihomo-real-hy2-controlled-payload")
			}))
			defer origin.Close()
			// Explicit native QUIC maps to Mihomo's native client without an
			// invented Chrome field. These cases must pass the no-loss gate.
			exported, e := ExportWithCapabilities(n, n.Users[0], "mihomo", "1.19.30", nil, false)
			if e != nil {
				t.Fatal(e)
			}
			if len(exported.Warnings) != 0 {
				t.Fatal("native QUIC mapping unexpectedly loses a selected option", exported.Warnings)
			}
			var cfg M
			if e = yaml.Unmarshal(exported.Data, &cfg); e != nil {
				t.Fatal(e)
			}
			port := freePort(t)
			cfg["mixed-port"] = port
			cfg["allow-lan"] = false
			cfg["bind-address"] = "127.0.0.1"
			cfg["external-controller"] = ""
			cfg["log-level"] = "debug"
			data, e := yaml.Marshal(cfg)
			if e != nil {
				t.Fatal(e)
			}
			private := t.TempDir()
			caPath := filepath.Join(private, "fixture-ca.pem")
			if e = os.WriteFile(caPath, []byte(n.Certificate.CertPEM), 0600); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(private, "mihomo.yaml")
			if e = os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			if out, e := exec.Command(mihomo, "-t", "-d", private, "-f", path).CombinedOutput(); e != nil {
				t.Fatalf("official Mihomo parser: %v %s", e, out)
			}
			log, e := os.Create(filepath.Join(private, "mihomo.log"))
			if e != nil {
				t.Fatal(e)
			}
			// Fixed v1.19.30 starts mixed listeners before OnRunning. HTTP
			// requests in that interval are closed by the suspended tunnel and
			// become empty 502 responses. Its official post-up hook runs only
			// after ApplyConfig (including OnRunning) completes. This barrier
			// sends no warm-up request and never retries a failed transfer.
			readyPath := filepath.Join(private, "mihomo-running")
			readyCommand := "umask 077; printf ready > '" + strings.ReplaceAll(readyPath, "'", "'\\''") + "'"
			cmd := exec.Command(mihomo, "-d", private, "-f", path, "-post-up", readyCommand)
			// Linux's Go system pool accepts this child-only CA file. Mihomo's
			// per-proxy "certificate" is a client keypair, not a trust root;
			// do not mislabel it or disable normal certificate verification.
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath, "SSL_CERT_DIR="+private, "DISABLE_SYSTEM_CA=false")
			cmd.Stdout, cmd.Stderr = log, log
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
						t.Error("owned Mihomo failed to exit")
					}
					log.Close()
					if t.Failed() {
						b, _ := os.ReadFile(log.Name())
						t.Logf("Mihomo debug log (post-up barrier: %s): %s", readyPath, Redact(string(b), s))
					}
				})
			}
			defer stop()
			deadline := time.Now().Add(5 * time.Second)
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			for {
				if b, e := os.ReadFile(readyPath); e == nil && string(b) == "ready" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Mihomo did not complete ApplyConfig/OnRunning and official post-up barrier")
				}
				select {
				case <-done:
					t.Fatalf("Mihomo exited before initialization barrier: %v", exitErr)
				case <-time.After(20 * time.Millisecond):
				}
			}
			listenerConfig, e := json.Marshal(M{"inbounds": []any{M{"type": "mixed", "listen_port": port}}})
			if e != nil {
				t.Fatal(e)
			}
			if e = waitCoreListeners(cmd.Process.Pid, listenerConfig, done, 5*time.Second); e != nil {
				t.Fatal("Mihomo post-up completed but its own mixed listener is not ready", e)
			}
			t.Logf("Mihomo PID %d completed post-up after OnRunning; verified its own mixed TCP listener %s before the first and only positive HTTP request", cmd.Process.Pid, address)
			proxy, _ := url.Parse("http://" + address)
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, e := client.Get(origin.URL)
			if e != nil {
				t.Fatal("real Mihomo HY2 TCP", e)
			}
			payload, e := io.ReadAll(io.LimitReader(response.Body, 256))
			response.Body.Close()
			if e != nil || response.StatusCode != http.StatusOK || string(payload) != "mihomo-real-hy2-controlled-payload" || hits.Load() != 1 {
				t.Fatalf("Mihomo HY2 controlled response mismatch: status=%d bytes=%d origin_hits=%d read_error=%v", response.StatusCode, len(payload), hits.Load(), e)
			}
			socksUDP(t, port)
			// MATCH routes only to the selected HY2. A live origin is not
			// sufficient to make a stopped proxy pass via a direct fallback.
			stopCore()
			if response, e = client.Get(origin.URL); e == nil {
				response.Body.Close()
				t.Fatal("Mihomo succeeded after selected HY2 server stopped")
			}
			if hits.Load() != 1 {
				t.Fatal("origin reached after selected HY2 disabled")
			}
		})
	}
}
