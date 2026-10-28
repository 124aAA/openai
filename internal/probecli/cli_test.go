package probecli

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qingnode/internal/probe"
)

func TestCLILocalIsReadOnlyAndReportVersioned(t *testing.T) {
	var out bytes.Buffer
	path := filepath.Join(t.TempDir(), "local.json")
	h := Hooks{Out: &out, Version: "fixture", SelectProfile: func(string, string) (probe.Profile, error) {
		t.Fatal("local read managed state")
		return probe.Profile{}, nil
	}}
	if err := Execute(context.Background(), []string{"local", "--out", path}, h); err != nil {
		t.Fatal(err)
	}
	r, err := probe.ReadReport(path)
	if err != nil || r.Conditions.Path != "local" || len(r.Samples) != 0 || r.Status != "completed" {
		t.Fatalf("bad local report: %v", err)
	}
	if err = Execute(context.Background(), []string{"local", "--out", path}, h); err == nil {
		t.Fatal("overwrote existing report")
	}
}
func TestCLIBoundedDownloadAndCanceledReport(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, 8192))
		} else {
			w.WriteHeader(200)
		}
	}))
	defer s.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	var out bytes.Buffer
	h := Hooks{Out: &out, Version: "fixture"}
	args := []string{"run", "--path", "controlled-link", "--target", s.URL + "/secret-path?token=secret", "--mode", "download", "--bytes", "4096", "--samples", "2", "--ca", ca, "--out", path}
	if err := Execute(context.Background(), args, h); err != nil {
		t.Fatal(err)
	}
	r, err := probe.ReadReport(path)
	if err != nil || r.Traffic.PayloadBytesReceived != 4096 {
		t.Fatalf("budget/report: %v %+v", err, r.Traffic)
	}
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte("secret")) || strings.Contains(out.String(), "secret") {
		t.Fatal("target token/path leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path = filepath.Join(dir, "canceled.json")
	args[len(args)-1] = path
	if err = Execute(ctx, args, h); err == nil {
		t.Fatal("cancellation passed")
	}
	r, err = probe.ReadReport(path)
	if err != nil || r.Status != "canceled" {
		t.Fatal("cancellation report invalid", err, r.Status)
	}
}
func TestCLISetupFailureReportsAndUnsafeOptionsRejectedBeforeSelection(t *testing.T) {
	raw := []byte(`{"type":"shadowsocks","tag":"proxy","server":"127.0.0.1","server_port":1,"method":"2022-blake3-aes-256-gcm","password":"private-credential"}`)
	p, err := probe.NewProfile("id", "1.14.0", raw)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var out bytes.Buffer
	h := Hooks{Out: &out, SelectProfile: func(string, string) (probe.Profile, error) { calls++; return p, nil }}
	if err = Execute(context.Background(), []string{"run", "--path", "client-proxy", "--id", "id", "--target", "https://127.0.0.1", "--samples", "65"}, h); err == nil || calls != 0 {
		t.Fatal("invalid input selected profile")
	}
	path := filepath.Join(t.TempDir(), "setup.json")
	if err = Execute(context.Background(), []string{"run", "--path", "client-proxy", "--id", "id", "--target", "https://127.0.0.1/private?token=hidden", "--out", path}, h); err == nil {
		t.Fatal("missing core passed")
	}
	r, err := probe.ReadReport(path)
	if err != nil || r.Status != "failed" || len(r.Samples) != 0 {
		t.Fatal("setup report missing", err)
	}
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte("credential")) || bytes.Contains(b, []byte("hidden")) {
		t.Fatal("profile/target leaked")
	}
	obj := map[string]any{}
	_ = json.Unmarshal(b, &obj)
	obj["future"] = 1
	b, _ = json.Marshal(obj)
	_ = os.WriteFile(path, b, 0600)
	if err = Execute(context.Background(), []string{"compare", "--before", path, "--after", path}, h); err == nil {
		t.Fatal("unknown report field accepted")
	}
}
