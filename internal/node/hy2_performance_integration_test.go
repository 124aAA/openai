package node

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// SING_BOX_BIN selects a separately checksum-verified official 1.14.0 or
// 1.14.3 binary. Test results must report which version actually executed.
func TestOfficialCoreHY2PerformanceTCPUDP(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("SING_BOX_BIN is unset; real HY2 performance transport not run")
	}
	version, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual core: %s", strings.Split(string(version), "\n")[0])
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "controlled-hy2-performance-payload")
	}))
	defer origin.Close()
	for _, tc := range []struct {
		name string
		p    *HY2Performance
	}{
		{"negotiated-brutal", &HY2Performance{ServerUpMbps: hyInt(31), ServerDownMbps: hyInt(47), ClientUpMbps: hyInt(11), ClientDownMbps: hyInt(13), ClientMode: "brutal"}},
		{"non-brutal-explicit-quic", &HY2Performance{IgnoreClientBandwidth: hyBool(true), ClientMode: "bbr", Server: &HY2Transport{BBRProfile: "conservative", QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(4 << 20), IdleTimeout: "45s", KeepAlivePeriod: "2s"}}, Client: &HY2Transport{BBRProfile: "conservative", DisableChromeParrot: hyBool(true), BrutalDebug: hyBool(false), QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(4 << 20), IdleTimeout: "45s", KeepAlivePeriod: "2s", MaxConcurrentStreams: hyInt(64), InitialPacketSize: hyInt(1200), DisablePathMTUDiscovery: hyBool(false)}}}},
		{"chrome-default-preserved", &HY2Performance{ClientMode: "bbr", Client: &HY2Transport{BBRProfile: "standard", DisableChromeParrot: hyBool(false), QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(4 << 20), IdleTimeout: "60s", MaxConcurrentStreams: hyInt(32), InitialPacketSize: hyInt(1200)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := hyFixture(t)
			s.Nodes[0].Port = freePort(t)
			s.Nodes[0].HY2 = tc.p
			n := s.Nodes[0]
			root := t.TempDir()
			server, err := Server(s, root)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, server)
			port := freePort(t)
			client := Client(n, n.Users[0], port)
			out := client["outbounds"].([]any)[0].(M)
			out["tls"].(M)["certificate"] = []string{n.Certificate.CertPEM}
			raw, err := json.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, raw)
			proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			hc := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := hc.Get(origin.URL)
			if err != nil {
				t.Fatal("actual HY2 TCP request failed", err)
			}
			payload, err := io.ReadAll(io.LimitReader(resp.Body, 128))
			resp.Body.Close()
			if err != nil || string(payload) != "controlled-hy2-performance-payload" {
				t.Fatalf("HY2 payload mismatch: HTTP status=%d, received bytes=%d, read error=%v", resp.StatusCode, len(payload), err)
			}
			socksUDP(t, port)
		})
	}
}

func TestMihomoHY2PerformanceMapping(t *testing.T) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Skip("MIHOMO_BIN is unset; actual parser not run")
	}
	s := hyFixture(t)
	n := s.Nodes[0]
	n.HY2 = &HY2Performance{ClientUpMbps: hyInt(11), ClientDownMbps: hyInt(13), ClientMode: "brutal", Client: &HY2Transport{BBRProfile: "standard", QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(4 << 20)}}}
	r, err := ExportWithCapabilities(n, n.Users[0], "mihomo", "1.19.30", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mihomo.yaml")
	if err = os.WriteFile(path, r.Data, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(bin, "-t", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("actual Mihomo rejected the explicit HY2 fields: %v %s", err, output)
	}
}
