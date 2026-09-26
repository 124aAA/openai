package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func dashboardFixture(t *testing.T) (*app, node.State) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if e := run([]string{"--offline", "--root", root, "init", "--server", "203.0.113.8", "--sni", "example.com", "--quiet"}); e != nil {
		t.Fatal(e)
	}
	a := &app{store: &node.Store{Root: root, Backend: node.OfflineBackend{}, GID: -1}, offline: true}
	s, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	return a, s
}

func TestDashboardPublicEvidenceScopeAndInvalidation(t *testing.T) {
	_, s := dashboardFixture(t)
	now := time.Now()
	n := s.Nodes[0]
	r := publicRecord{At: now, Fingerprint: publicFingerprint(s, n), TCP: "pass", UDP: "untested", Source: "Windows sing-box"}
	h := dashboardHistory{Public: map[string]publicRecord{n.ID: r}}
	label := publicLabel(s, n, h, now)
	if !strings.Contains(label, "TCP 通过 / UDP 待验证") || !strings.Contains(label, "管理员登记") {
		t.Fatal(label)
	}
	other := s.Clone()
	other.Nodes = append(other.Nodes, node.Node{ID: "another"})
	if publicFingerprint(other, n) != r.Fingerprint {
		t.Fatal("unrelated node invalidated evidence")
	}
	for _, change := range []func(*node.State){
		func(s *node.State) { s.CoreVersion = "1.14.1" },
		func(s *node.State) { s.Firewall = "ufw" },
		func(s *node.State) { s.Nodes[0].Port = 8443 },
		func(s *node.State) { s.Nodes[0].Users[0].UUID = node.NewUser("new", "reality").UUID },
	} {
		changed := s.Clone()
		change(&changed)
		if label := publicLabel(changed, changed.Nodes[0], h, now); !strings.Contains(label, "配置已改变") || strings.Contains(label, "TCP 通过") {
			t.Fatal(label)
		}
	}
	for _, at := range []time.Time{{}, now.Add(time.Hour)} {
		r.At = at
		h.Public[n.ID] = r
		if label := publicLabel(s, n, h, now); strings.Contains(label, "通过") || !strings.Contains(label, "时间无效") {
			t.Fatal(label)
		}
	}
	r.At = now.Add(-25 * time.Hour)
	h.Public[n.ID] = r
	if !strings.Contains(publicLabel(s, n, h, now), "待复查") {
		t.Fatal("old result not marked")
	}
	if !strings.Contains(publicLabel(s, n, dashboardHistory{}, now), "待验证") {
		t.Fatal("missing evidence passed")
	}
}

type dashboardTransport struct{ t *testing.T }

func (r dashboardTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("homepage attempted network access")
	return nil, errors.New("network forbidden")
}

func TestDashboardHomepageReadOnlyWithPendingRecovery(t *testing.T) {
	a, s := dashboardFixture(t)
	// The malformed transaction would fail or be recovered if homepage used WithLock.
	journal := filepath.Join(a.store.Root, "transaction.json")
	if e := os.WriteFile(journal, []byte("pending-not-json"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := a.updateHistory(func(h *dashboardHistory) {
		h.Diagnostic = &checkRecord{At: time.Now().UTC(), Fingerprint: stateFingerprint(s), Errors: 1}
	}); e != nil {
		t.Fatal(e)
	}
	paths := []string{journal, filepath.Join(a.store.Root, "current", "state.json"), filepath.Join(a.store.Root, "observations.json")}
	before := map[string][]byte{}
	for _, p := range paths {
		before[p], _ = os.ReadFile(p)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = dashboardTransport{t}
	defer func() { http.DefaultTransport = previous }()
	var out bytes.Buffer
	if e := a.overview(&out); e != nil {
		t.Fatal(e)
	}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(b, before[p]) {
			t.Fatalf("homepage changed %s: %v", filepath.Base(p), e)
		}
	}
	for _, text := range []string{"节点：共1个，启用1个", "公网：待验证", "1错误 / 0警告", "首页只读本机", "尚未检查"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("missing %q: %s", text, out.String())
		}
	}
	for _, secret := range []string{s.Nodes[0].Users[0].UUID, s.Nodes[0].Reality.PrivateKey} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("homepage leaked credentials")
		}
	}
	missing := filepath.Join(t.TempDir(), "absent")
	a.store.Root = missing
	if e := a.overview(&out); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("homepage created an absent store")
	}
}

func TestDashboardCorruptAndUnsafeHistory(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "observations.json")
	for _, raw := range []string{"null", "{}", `{"Schema":2}`, `{"Schema":1,"unexpected":1}`, `{"Schema":1} {}`, `{"Schema":1,"Diagnostic":{"Errors":-1}}`, strings.Repeat(" ", (128<<10)+1), `{"Schema":1,"Public":{"x":{"TCP":"pass","UDP":"pass","Source":"bad\u001b[2J"}}}`} {
		if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readDashboardHistory(root); e == nil {
			t.Fatal("accepted malformed history")
		}
	}
	if e := os.WriteFile(p, []byte(`{"Schema":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := readDashboardHistory(root); e == nil {
		t.Fatal("accepted public history")
	}
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "target")
	os.WriteFile(target, []byte(`{"Schema":1}`), 0600)
	if e := os.Symlink(target, p); e != nil {
		t.Fatal(e)
	}
	if _, e := readDashboardHistory(root); e == nil {
		t.Fatal("followed symlink")
	}
}

func TestDashboardRecordsDoNotChangeStateAndKeepPrivate(t *testing.T) {
	a, s := dashboardFixture(t)
	a.offline = false
	p := filepath.Join(a.store.Root, "current", "state.json")
	before, _ := os.ReadFile(p)
	args := []string{"--id", s.Nodes[0].ID, "--tcp", "pass", "--source", "Windows client"}
	if e := a.publicCheck(args); e != nil {
		t.Fatal(e)
	}
	h, e := readDashboardHistory(a.store.Root)
	if e != nil || h.Public[s.Nodes[0].ID].UDP != "untested" {
		t.Fatal("lost partial result", e)
	}
	if i, e := os.Stat(filepath.Join(a.store.Root, "observations.json")); e != nil || i.Mode().Perm() != 0600 {
		t.Fatal("history permissions", e)
	}
	if e := a.publicCheck([]string{"--id", s.Nodes[0].ID, "--tcp", "pass", "--source", s.Nodes[0].Users[0].UUID}); e == nil {
		t.Fatal("accepted credential in source")
	}
	backup := filepath.Join(t.TempDir(), "external.qnbak")
	os.WriteFile(backup, []byte("encrypted fixture"), 0600)
	if e := a.store.Inspect(func() error { a.noteBackup(backup); return nil }); e != nil {
		t.Fatal(e)
	}
	h, e = readDashboardHistory(a.store.Root)
	if e != nil || h.Backup == nil || h.Backup.Path != backup || len(h.Public) != 1 {
		t.Fatal("backup lost other observations", e)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("recording changed State")
	}
	s.Nodes[0].Enabled = false
	if e := a.store.WithLock(func() error { return a.store.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	if e := a.publicCheck(args); e == nil {
		t.Fatal("registered disabled node")
	}
}

func TestDashboardCertificateValidity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		start, end time.Time
		name, want string
	}{
		{now.Add(-time.Hour), now.Add(49 * time.Hour), "example.com", "剩余2天"},
		{now.Add(-time.Hour), now.Add(time.Hour), "example.com", "不足1天"},
		{now.Add(-time.Hour), now, "example.com", "已过期"},
		{now.Add(time.Hour), now.Add(48 * time.Hour), "example.com", "尚未生效"},
		{now.Add(-time.Hour), now.Add(time.Hour), "other.example", "域名不匹配"},
	} {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: tc.start, NotAfter: tc.end, DNSNames: []string{"example.com"}}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if e != nil {
			t.Fatal(e)
		}
		n := node.Node{Certificate: &node.Certificate{Mode: "pem", ServerName: tc.name, CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}
		if label := certificateLabel(n, now); !strings.Contains(label, tc.want) {
			t.Fatal(label)
		}
		n.Certificate.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("ignored")})) + n.Certificate.CertPEM
		if label := certificateLabel(n, now); !strings.Contains(label, tc.want) {
			t.Fatal("PEM prefix changed result:", label)
		}
	}
	if label := certificateLabel(node.Node{Certificate: &node.Certificate{Mode: "acme"}}, now); !strings.Contains(label, "期限未知") {
		t.Fatal(label)
	}
	if label := certificateLabel(node.Node{}, now); !strings.Contains(label, "不适用") {
		t.Fatal(label)
	}
}

func TestDashboardUnknownServiceAndBrokenRecords(t *testing.T) {
	_, s := dashboardFixture(t)
	var out bytes.Buffer
	h := dashboardHistory{Diagnostic: &checkRecord{At: time.Now(), Fingerprint: stateFingerprint(s)}, Public: map[string]publicRecord{s.Nodes[0].ID: {At: time.Now(), Fingerprint: publicFingerprint(s, s.Nodes[0]), TCP: "pass", UDP: "pass", Source: "client"}}}
	if e := renderOverview(&out, s, h, nil, errors.New("broken cache"), node.ServiceOverview{ActiveState: "active", SubState: "exited"}, node.ResourceOverview{}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "服务：运行中") || strings.Contains(out.String(), "TCP 通过") || !strings.Contains(out.String(), "记录不可用，待验证") {
		t.Fatal(out.String())
	}
	// Ensure a valid serialization remains accepted when some categories are absent.
	b, _ := json.Marshal(dashboardHistory{Schema: 1})
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "observations.json"), b, 0600)
	if _, e := readDashboardHistory(root); e != nil {
		t.Fatal(e)
	}
}
