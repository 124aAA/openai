package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNftablesFirewallIsolationForeignGuardAndTransitions(t *testing.T) {
	st := hyFixture(t)
	var err error
	st, err = CanonicalCertificates(st)
	if err != nil {
		t.Fatal(err)
	}
	st.Firewall = "nftables"
	st.Nodes[0].Listen = "0.0.0.0"
	st.Nodes[0].Port = 8443
	st.Nodes[0].HY2 = &HY2Performance{HopPorts: "20000-20010", HopInterval: "30s", HopMode: "nftables"}
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}

	rules := NftablesWanted(st)
	script := RenderNftFirewallScript(rules)
	if !strings.Contains(script, "add table inet qingnode; flush table inet qingnode;") ||
		!strings.Contains(script, "policy accept;") ||
		!strings.Contains(script, "udp dport 8443 accept") ||
		!strings.Contains(script, "udp dport 20000-20010 accept") ||
		strings.Contains(script, "flush ruleset") ||
		strings.Contains(script, "policy drop") {
		t.Fatalf("unexpected nftables script:\n%s", script)
	}

	// Foreign rule lacking qingnode comment must be rejected before overwriting table inet qingnode!
	fwForeign := Firewall{
		SSH: []int{22},
		Execute: func(_ time.Duration, _ string, args ...string) ([]byte, error) {
			if len(args) >= 4 && args[0] == "list" && args[1] == "table" {
				return []byte("table inet qingnode {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 9999 accept comment \"admin-custom\"\n\t}\n}\n"), nil
			}
			return nil, nil
		},
	}
	if err := fwForeign.Check(st); err == nil || !strings.Contains(err.Error(), "非本项目规则") {
		t.Fatalf("expected foreign rule in table inet qingnode to be refused, got %v", err)
	}

	// Owned table passes inspection and runs add-before-remove transition cleanly.
	var scripts []string
	var commands []string
	fwOwned := Firewall{
		SSH: []int{22},
		Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			commands = append(commands, cmd)
			if len(args) >= 4 && args[0] == "list" && args[1] == "table" {
				return []byte("table inet qingnode {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tmeta nfproto ipv4 udp dport 7443 accept comment \"qingnode:1111111111111111:udp\"\n\t}\n}\n"), nil
			}
			if len(args) == 1 && strings.HasPrefix(args[0], "add table inet qingnode;") {
				scripts = append(scripts, args[0])
			}
			return nil, nil
		},
	}

	old := st.Clone()
	old.Nodes[0].Port = 7443
	if err := fwOwned.nftablesSyncTransition(old, st, false); err != nil {
		t.Fatal(err)
	}
	if err := fwOwned.nftablesSyncTransition(old, st, true); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 2 || !strings.Contains(scripts[0], "7443") || !strings.Contains(scripts[0], "8443") || strings.Contains(scripts[1], "7443") {
		t.Fatalf("expected add-before-remove union in step 1 then exact target in step 2: %+v", scripts)
	}

	// Disabling firewall deletes only table inet qingnode.
	disabled := st.Clone()
	disabled.Firewall = ""
	commands = nil
	if err := fwOwned.nftablesSyncTransition(st, disabled, true); err != nil {
		t.Fatal(err)
	}
	foundDelete := false
	for _, c := range commands {
		if c == "nft delete table inet qingnode" {
			foundDelete = true
		}
	}
	if !foundDelete {
		t.Fatalf("expected delete table inet qingnode, got %v", commands)
	}
}

func TestLegacyPre10RejectsNftablesAndTrafficQuotas(t *testing.T) {
	cases := []string{
		`{"schema":9,"core_version":"1.14.0","firewall":"nftables","nodes":[]}`,
		`{"schema":9,"core_version":"1.14.0","traffic_quotas":[],"nodes":[]}`,
		`{"schema":9,"core_version":"1.14.0","Traffic_Quotas":null,"nodes":[]}`,
	}
	for _, raw := range cases {
		if _, err := DecodeState([]byte(raw)); err == nil {
			t.Fatalf("expected legacy schema 9 payload to be rejected: %s", raw)
		}
	}
}

func TestGitHubMirrorValidationAndTamperedDigestRejection(t *testing.T) {
	for _, bad := range []string{
		"http://mirror.example.com",
		"https://user:pass@mirror.example.com",
		"https://mirror.example.com?token=1",
		"https://mirror.example.com#frag",
		"https://mirror.example.com/../etc",
		"ftp://mirror.example.com",
	} {
		if _, err := ValidateGitHubMirror(bad); err == nil {
			t.Fatalf("accepted unsafe mirror %q", bad)
		}
	}
	clean, err := ValidateGitHubMirror("https://mirror.example.com/gh/")
	if err != nil || clean != "https://mirror.example.com/gh" {
		t.Fatalf("unexpected clean mirror: %q %v", clean, err)
	}
	rewritten, err := RewriteGitHubDownloadURL("https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box.tar.gz", clean)
	if err != nil || rewritten != "https://mirror.example.com/gh/SagerNet/sing-box/releases/download/v1.14.0/sing-box.tar.gz" {
		t.Fatalf("unexpected rewritten URL: %q %v", rewritten, err)
	}
	if _, err := RewriteGitHubDownloadURL("https://evil.example.com/sing-box.tar.gz", clean); err == nil {
		t.Fatal("rewrote non-github URL")
	}

	var requestedPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		_, _ = w.Write([]byte("tampered-not-official-archive"))
	}))
	defer srv.Close()
	prevTransport := coreDownloadTransport
	coreDownloadTransport = srv.Client().Transport
	defer func() { coreDownloadTransport = prevTransport }()

	root := t.TempDir()
	goodSum := strings.Repeat("a", 64)
	tamperedSum := sha256.Sum256([]byte("tampered-not-official-archive"))
	if hex.EncodeToString(tamperedSum[:]) == goodSum {
		t.Fatal("unexpected hash collision")
	}
	if err := InstallCoreWithMirror(root, "1.14.3", goodSum, "", srv.URL+"/mirror-prefix"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected SHA-256 verification error on mirrored download, got %v", err)
	}
	if !strings.HasPrefix(requestedPath, "/mirror-prefix/SagerNet/sing-box/releases/download/v1.14.3/") {
		t.Fatalf("mirror prefix was not used: got %q", requestedPath)
	}
	if _, err := os.Lstat(CorePath(root, "1.14.3")); !os.IsNotExist(err) {
		t.Fatal("tampered core installed into cores/")
	}
}

type mockHookBackend struct {
	active bool
	starts int
}

func (b *mockHookBackend) Check(State, string) error { return nil }
func (b *mockHookBackend) Active() bool              { return b.active }
func (b *mockHookBackend) Activate(State) error      { b.active = true; b.starts++; return nil }
func (b *mockHookBackend) Stop() error               { b.active = false; return nil }

func TestTrafficQuotasSharedGuardAndBeforeCoreStopHook(t *testing.T) {
	st := NewState()
	n := ssFixture()
	n.ID = "1111111111111111"
	n.Port = 18388
	u1, u2 := n.Users[0], n.Users[1]
	st.Nodes = []Node{n}
	st.Devices = []DeviceProfile{
		{ID: "dddddddddddd0001", Name: "Phone", Bindings: []DeviceBinding{{NodeID: "1111111111111111", UserID: u1.ID}}},
		{ID: "dddddddddddd0002", Name: "Laptop", Bindings: []DeviceBinding{{NodeID: "1111111111111111", UserID: u1.ID}}},
	}

	// Device-scoped quota on shared credential must block batch apply without partial mutation.
	if err := SetTrafficQuota(&st, TrafficQuota{
		ID:        "aaaaaaaaaaaa0001",
		NodeID:    "1111111111111111",
		UserID:    u1.ID,
		DeviceID:  "dddddddddddd0001",
		WarnBytes: 500,
		HardBytes: 1000,
		ResetDay:  15,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	lookup := func(nodeID, userID string, resetDay int, _ time.Time) (int64, int64, bool) {
		if nodeID == "1111111111111111" && userID == u1.ID {
			return 600, 600, true
		}
		return 0, 0, false
	}
	if _, plan, err := ApplyDueTrafficQuotas(st, lookup, false, now); err == nil || plan.Blocked != 1 {
		t.Fatalf("expected shared credential to block quota disable, got plan=%+v err=%v", plan, err)
	}

	// Remove shared binding from Laptop -> quota apply now cleanly disables u1 and Phone while keeping u2 active!
	st.Devices[1].Bindings = []DeviceBinding{{NodeID: "1111111111111111", UserID: u2.ID}}
	next, plan, err := ApplyDueTrafficQuotas(st, lookup, true, now)
	if err != nil || plan.Ready != 1 || !plan.GapDetected {
		t.Fatalf("expected ready quota apply, got plan=%+v err=%v", plan, err)
	}
	if len(next.Nodes[0].Users) != 1 || next.Nodes[0].Users[0].ID != u2.ID || !next.Devices[0].Disabled || next.Devices[1].Disabled {
		t.Fatalf("unexpected post-quota state: users=%+v devices=%+v", next.Nodes[0].Users, next.Devices)
	}

	// Verify Store.BeforeCoreStop receives the OLD running State and a panic inside BeforeCoreStop never blocks Apply!
	root := filepath.Join(t.TempDir(), "state")
	backend := &mockHookBackend{active: false}
	var hookOldPort int
	store := &Store{
		Root:    root,
		Backend: backend,
		GID:     -1,
		BeforeCoreStop: func(running State) {
			if len(running.Nodes) > 0 {
				hookOldPort = running.Nodes[0].Port
			}
			panic(errors.New("simulated pre-stop hook panic"))
		},
	}
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if hookOldPort != 0 {
		t.Fatalf("BeforeCoreStop must not run when service was not active, got %d", hookOldPort)
	}
	updated := st.Clone()
	updated.Nodes[0].Port = 18389
	if err := store.WithLock(func() error { return store.Apply(updated) }); err != nil {
		t.Fatalf("BeforeCoreStop panic blocked Store.Apply: %v", err)
	}
	if hookOldPort != 18388 {
		t.Fatalf("BeforeCoreStop did not receive old running State (port 18388), got %d", hookOldPort)
	}
}
