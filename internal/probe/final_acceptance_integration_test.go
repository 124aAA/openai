//go:build linux

package probe

// The final workflow invokes the real portable CLI against controlled local
// endpoints. The existing probe engine owns all measurements and validation.
// No manager State, production service, system proxy or host route is touched.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOfficialFinalCLIControlledPerformance(t *testing.T) {
	if os.Getenv("QINGNODE_FINAL_PERFORMANCE") != "1" {
		t.Skip("explicit QINGNODE_FINAL_PERFORMANCE=1 controlled CLI acceptance not requested")
	}
	bin, digest, version := portableOfficialCore(t)
	cli, resultDir := os.Getenv("QINGPROBE_BIN"), os.Getenv("QINGNODE_FINAL_RESULTS")
	if !filepath.IsAbs(cli) || !filepath.IsAbs(resultDir) {
		t.Fatal("explicit absolute QINGPROBE_BIN and new QINGNODE_FINAL_RESULTS are required")
	}
	cliBytes, err := os.ReadFile(cli)
	if err != nil {
		t.Fatal("portable CLI input unavailable", err)
	}
	cliSHA := sha256.Sum256(cliBytes)
	if err = os.Mkdir(resultDir, 0700); err != nil {
		t.Fatal("result directory must be new", err)
	}
	private := t.TempDir()
	clientTemp := filepath.Join(private, "client-temp")
	if err = os.Mkdir(clientTemp, 0700); err != nil {
		t.Fatal(err)
	}
	p, stopServer := portableSSFixture(t, bin, version)
	profilePath := filepath.Join(private, "profile.json")
	if err = WriteProfile(profilePath, p); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(3 * time.Millisecond)
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		chunk := bytes.Repeat([]byte("controlled payload\n"), 2048)
		for sent := 0; sent < 1<<20; {
			n := len(chunk)
			if n > (1<<20)-sent {
				n = (1 << 20) - sent
			}
			if _, e := w.Write(chunk[:n]); e != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			sent += n
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer target.Close()
	caPath := filepath.Join(private, "target-ca.pem")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	udp, _ := udpTestEndpoint(t, func(b []byte) [][]byte {
		// This endpoint only echoes the existing version/token/sequence frame.
		return [][]byte{b}
	})
	text := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(resultDir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name, path, selectedProfile string, success, download bool) Report {
		t.Helper()
		reportPath := filepath.Join(resultDir, name+".json")
		args := []string{"run", "--path", path, "--target", target.URL, "--ca", caPath, "--family", "ipv4",
			"--initiator", "disposable-linux-vm/controlled-loopback", "--out", reportPath,
			"--mode", "download", "--bytes", "1048576", "--samples", "8", "--concurrency", "1", "--timeout", "20s", "--udp", udp, "--udp-timeout", "250ms"}
		if !download {
			args = []string{"run", "--path", path, "--target", target.URL, "--ca", caPath, "--family", "ipv4",
				"--initiator", "disposable-linux-vm/controlled-loopback", "--out", reportPath,
				"--mode", "light", "--bytes", "65536", "--samples", "2", "--concurrency", "1", "--timeout", "3s"}
		}
		if path == "client-proxy" {
			args = append(args, "--profile", selectedProfile, "--core", bin, "--core-sha256", digest)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, cli, args...)
		cmd.Env = append(os.Environ(), "TMPDIR="+clientTemp, "NO_COLOR=1", "TERM=dumb")
		var output limitedOutput
		cmd.Stdout, cmd.Stderr = &output, &output
		err := cmd.Run()
		if ctx.Err() != nil || (err == nil) != success {
			t.Fatalf("real CLI %s unexpected completion (private args/output suppressed): %v", name, err)
		}
		r, err := ReadReport(reportPath)
		if err != nil || (r.Status == "completed") != success {
			t.Fatalf("real CLI report %s invalid/inconsistent: %v", name, err)
		}
		if r.Conditions.Initiator != "disposable-linux-vm/controlled-loopback" || r.Conditions.Path != path {
			t.Fatal("measurement location/path changed")
		}
		if r.Traffic.PayloadBytesReceived+r.Traffic.UDPPayloadBytesSent+r.Traffic.UDPPayloadBytesReceived > r.Conditions.Limits.MaxPayloadBytes {
			t.Fatal("real CLI payload budget exceeded")
		}
		if success && (r.Statistics["idle_request"].Successes != 8 || r.Statistics["load_request"].Values < 1 || r.Statistics["download_throughput"].Values != 1 || r.UDP == nil || r.UDP.Received != 8) {
			t.Fatal("missing actual idle/load/throughput/sequence UDP samples")
		}
		if path == "client-proxy" && success && (r.Connection.Status != "unknown" || r.TLS.Status != "unknown") {
			t.Fatal("proxy hidden timing stages were invented")
		}
		remaining, e := os.ReadDir(clientTemp)
		if e != nil || len(remaining) != 0 {
			t.Fatal("real portable CLI left its private sandbox files", e)
		}
		if r.MetricsAfter.PID > 0 {
			if _, e := os.Stat(fmt.Sprintf("/proc/%d", r.MetricsAfter.PID)); !os.IsNotExist(e) {
				t.Fatal("observed isolated CLI/core process still exists after command returned")
			}
		}
		text(name+".txt", []byte(FormatText(r)))
		return r
	}
	direct := run("direct-control", "controlled-link", "", true, true)
	one := run("proxy-baseline", "client-proxy", profilePath, true, true)
	two := run("proxy-repeat", "client-proxy", profilePath, true, true)
	if direct.Connection.Status != "success" || direct.TLS.Status != "success" {
		t.Fatal("explicit direct control did not retain its measurable connection stages")
	}
	if !Compare(one, two).Comparable {
		t.Fatal("unchanged repeated conditions were not comparable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	comparison, err := exec.CommandContext(ctx, cli, "compare", "--before", filepath.Join(resultDir, "proxy-baseline.json"), "--after", filepath.Join(resultDir, "proxy-repeat.json")).Output()
	cancel()
	var c Comparison
	if err != nil || json.Unmarshal(comparison, &c) != nil || !c.Comparable {
		t.Fatal("actual CLI compare did not accept repeat conditions", err)
	}
	text("proxy-repeat-comparison.json", comparison)
	var wrong map[string]any
	if json.Unmarshal(p.Outbound, &wrong) != nil {
		t.Fatal("private fixture profile invalid")
	}
	originalSecrets := strings.Split(wrong["password"].(string), ":")
	parts := append([]string(nil), originalSecrets...)
	parts[len(parts)-1] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	wrong["password"] = strings.Join(parts, ":")
	raw, _ := json.Marshal(wrong)
	bad, err := NewProfile(p.NodeID, p.CoreVersion, raw)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(private, "wrong-profile.json")
	if err = WriteProfile(wrongPath, bad); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	run("wrong-credential", "client-proxy", wrongPath, false, false)
	if calls.Load() != before {
		t.Fatal("wrong credential reached controlled HTTPS target")
	}
	stopServer()
	// This positive direct control is independent of the removed proxy.
	resp, err := target.Client().Head(target.URL)
	if err != nil {
		t.Fatal("direct target unavailable independently of stopped proxy")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	before = calls.Load()
	run("proxy-stopped", "client-proxy", profilePath, false, false)
	if calls.Load() != before {
		t.Fatal("stopped selected proxy fell back to direct")
	}
	public := map[string]any{"version": 1, "scope": "controlled-loopback-cli; no public ingress or ISP inference", "cli_sha256": hex.EncodeToString(cliSHA[:]),
		"core_sha256": digest, "core_version": version, "protocol": "ss2022", "positive_reports": []string{"direct-control", "proxy-baseline", "proxy-repeat"},
		"negative_reports": []string{"wrong-credential", "proxy-stopped"}, "target_request_proof": "wrong credentials and stopped selected proxy added zero target requests; direct control remained reachable",
		"network_shaping": "none; deterministic target writes 1MiB in bounded chunks with 20ms gaps", "samples": 8, "payload_budget_per_positive_report": 1048576,
		"comparison_interpretation": "repeatability only, no tuning or protocol benefit claim; one download/sample set cannot prove significance",
		"limitations":               []string{"proxy independent DNS/TCP/TLS stages unknown", "8 idle/UDP samples and one download are small samples", "CPU percentage unavailable; standard reports retain cumulative CPU ticks and RSS", "no server resource claim from client metrics", "not a desktop/mobile GUI or real user network test"}}
	b, _ := json.MarshalIndent(public, "", "  ")
	text("controlled-fixture.json", append(b, '\n'))
	for _, name := range []string{"direct-control", "proxy-baseline", "proxy-repeat", "wrong-credential", "proxy-stopped"} {
		b, e := os.ReadFile(filepath.Join(resultDir, name+".json"))
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range append(originalSecrets, parts...) {
			if strings.Contains(string(b), secret) {
				t.Fatal("report leaked a credential")
			}
		}
	}
}
