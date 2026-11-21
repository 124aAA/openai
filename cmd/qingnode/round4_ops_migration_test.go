package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/coreapi"
	"qingnode/internal/monitor"
	"qingnode/internal/node"
	"qingnode/internal/subscription"
)

func makeExpiringPEMCert(t *testing.T, serverName string, validFor time.Duration) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func monitorWireCustomConn(id, inbound, user string, up, down uint64) []byte {
	connection := monitorWireBytes(1, []byte(id))
	connection = append(connection, monitorWireBytes(2, []byte(inbound))...)
	connection = append(connection, monitorWireBytes(10, []byte(user))...)
	connection = append(connection, monitorWireVarint(16, up)...)
	connection = append(connection, monitorWireVarint(17, down)...)
	event := monitorWireBytes(2, []byte(id))
	event = append(event, monitorWireBytes(3, connection)...)
	return monitorWireBytes(1, event)
}

func TestRound4TrafficLedgerSubscriptionUserinfoQuotaAndAlerts(t *testing.T) {
	a, st, backend, subDir, materials := subscriptionCLIFixture(t)
	backend.active = true
	rawToken := materials[1].Token

	var startedMS atomic.Int64
	var uplinkTotal atomic.Uint64
	var downlinkTotal atomic.Uint64
	var connID atomic.Value
	startedMS.Store(1700000001000)
	uplinkTotal.Store(600)
	downlinkTotal.Store(900)
	connID.Store("11111111-2222-3333-4444-555555555555")

	nodeID := st.Nodes[0].ID
	userID := st.Nodes[0].Users[1].ID
	deviceID := st.Devices[1].ID

	st = monitorFixtureAPI(t, a, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-api-auth-secret-123456789" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		switch {
		case strings.HasSuffix(r.URL.Path, "/GetStartedAt"):
			_, _ = w.Write(monitorWireFrame(0, monitorWireVarint(1, uint64(startedMS.Load()))))
			_, _ = w.Write(monitorWireFrame(0x80, []byte("grpc-status: 0\r\n")))
		case strings.HasSuffix(r.URL.Path, "/SubscribeStatus"):
			up := uplinkTotal.Load()
			down := downlinkTotal.Load()
			payload := append(monitorWireVarint(5, 1), monitorWireVarint(8, up)...)
			payload = append(payload, monitorWireVarint(9, down)...)
			_, _ = w.Write(monitorWireFrame(0, payload))
			_, _ = w.Write(monitorWireFrame(0x80, []byte("grpc-status: 0\r\n")))
		case strings.HasSuffix(r.URL.Path, "/SubscribeConnections"):
			up := uplinkTotal.Load()
			down := downlinkTotal.Load()
			batch := append(monitorWireCustomConn(connID.Load().(string), nodeID, userID, up, down), monitorWireVarint(2, 1)...)
			_, _ = w.Write(monitorWireFrame(0, batch))
			_, _ = w.Write(monitorWireFrame(0x80, []byte("grpc-status: 0\r\n")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// Configure a certificate expiring in 8 days (< 14 days) and a quota (warn=1000, hard=2500).
	certPEM, keyPEM := makeExpiringPEMCert(t, "expiring.example.test", 8*24*time.Hour+2*time.Hour)
	st.Certificates = append(st.Certificates, node.CertificateResource{
		ID:          "cccccccccccc0009",
		Name:        "NearExpiryCert",
		Certificate: node.Certificate{Mode: "pem", ServerName: "expiring.example.test", CertPEM: certPEM, KeyPEM: keyPEM},
	})
	if err := a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}

	// Set traffic quota via CLI: warn=1000, hard=2500, reset-day=1.
	if _, err := wizardOutput(t, func() error {
		return a.quota([]string{"set", "--id", "aaaaaaaaaaaa0099", "--node", nodeID, "--user", userID, "--device", deviceID, "--warn-bytes", "1000", "--hard-bytes", "2500", "--reset-day", "1", "--yes"})
	}); err != nil {
		t.Fatal(err)
	}

	// Configure Feishu webhook notification in private monitor config.
	var feishuAlerts []string
	notifySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		feishuAlerts = append(feishuAlerts, body.Content.Text)
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok"}`))
	}))
	defer notifySrv.Close()

	monCfg := monitor.DefaultConfig()
	monCfg.Enabled = true
	monCfg.Jobs = []monitor.Job{{
		ID:      "job-main",
		NodeID:  nodeID,
		Enabled: true,
		Signals: []monitor.SignalKind{monitor.Disk, monitor.CoreAPI},
	}}
	monCfg.Notifications = monitor.NotificationConfig{
		Enabled:   true,
		Kind:      "feishu",
		Endpoint:  notifySrv.URL + "/open-apis/bot/v2/hook/test",
		Secret:    "feishu-test-secret-01",
		HostLabel: "edge-node-01",
		TimeoutMS: 2000,
		Retries:   0,
	}
	if err := a.monitorStore().SaveConfig(monCfg); err != nil {
		t.Fatal(err)
	}

	// Wire pre-stop traffic flush hook now that fixture setup is complete.
	a.store.BeforeCoreStop = a.flushTrafficBeforeStop

	// Round 1 of monitor run (WITHOUT --apply-quota): records 600+900=1500 bytes (> warn 1000, < hard 2500),
	// syncs Subscription-Userinfo, and delivers cert-expiring + quota-warning alerts!
	if _, err := wizardOutput(t, func() error { return a.monitor([]string{"run"}) }); err != nil {
		t.Fatal(err)
	}

	// Verify Subscription-Userinfo header now reports upload=600; download=900; total=2500; expire=...
	h, err := subscription.NewIndexedHandler(subscription.NewSnapshotCache(subDir).Read, subscription.HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/s/"+rawToken, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 subscription response, got %d", rec.Code)
	}
	userinfo := rec.Header().Get("Subscription-Userinfo")
	if !strings.HasPrefix(userinfo, "upload=600; download=900; total=2500") {
		t.Fatalf("unexpected Subscription-Userinfo header: %q", userinfo)
	}

	// Verify Feishu received both cert-expiring (<14d) and quota-warning alerts!
	joinedAlerts := strings.Join(feishuAlerts, "\n---\n")
	if !strings.Contains(joinedAlerts, "NearExpiryCert") || !strings.Contains(joinedAlerts, "软告警") {
		t.Fatalf("expected cert-expiring and quota-warning notifications, got:\n%s", joinedAlerts)
	}

	// Trigger a controlled runtime change via Store.Apply while traffic grew to 800/1100 in epoch 1:
	// Store.BeforeCoreStop flushes 800/1100 cleanly before restarting into epoch 2!
	uplinkTotal.Store(800)
	downlinkTotal.Store(1100)
	curState, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	curState.Nodes[0].Port += 10
	if err := a.store.WithLock(func() error { return a.store.Apply(curState) }); err != nil {
		t.Fatal(err)
	}

	// Core restarts into epoch 2 with 400/500 new bytes -> cumulative becomes (800+400)+(1100+500) = 1200+1600 = 2800 (> hard 2500) with GapDetected == false!
	startedMS.Store(1700000099000)
	connID.Store("66666666-2222-3333-4444-555555555555")
	uplinkTotal.Store(400)
	downlinkTotal.Store(500)

	// Read-only quota list --json after sampling WITHOUT --apply-quota must NEVER implicitly disable the device!
	if _, err := wizardOutput(t, func() error { return a.monitor([]string{"run"}) }); err != nil {
		t.Fatal(err)
	}
	ledgerOut, err := wizardOutput(t, func() error { return a.monitor([]string{"ledger"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ledgerOut, `"gap_detected": false`) || !strings.Contains(ledgerOut, `"global_upload": 1200`) || !strings.Contains(ledgerOut, `"global_download": 1600`) {
		t.Fatalf("unexpected ledger JSON after clean restart:\n%s", ledgerOut)
	}
	quotaJSON, err := wizardOutput(t, func() error { return a.quota([]string{"list", "--json"}) })
	if err != nil || !strings.Contains(quotaJSON, `"status":"due"`) || !strings.Contains(quotaJSON, `"used_bytes":2800`) {
		t.Fatalf("expected due quota in read-only quota list --json, got %v:\n%s", err, quotaJSON)
	}
	stillEnabled, _ := a.store.Load()
	if stillEnabled.Devices[1].Disabled {
		t.Fatal("read-only monitor/quota list implicitly disabled device without --apply-quota!")
	}

	// Now run monitor run --apply-quota: device and bound user are safely disabled, and subscription is revoked!
	if _, err := wizardOutput(t, func() error { return a.monitor([]string{"run", "--apply-quota"}) }); err != nil {
		t.Fatal(err)
	}
	afterApply, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !afterApply.Devices[1].Disabled || len(afterApply.Nodes[0].Users) != 1 {
		t.Fatalf("expected --apply-quota to disable device and remove exceeded credential: %+v", afterApply.Devices[1])
	}
	recRevoked := httptest.NewRecorder()
	h.ServeHTTP(recRevoked, httptest.NewRequest(http.MethodGet, "/s/"+rawToken, nil))
	if recRevoked.Code != http.StatusNotFound {
		t.Fatalf("expected revoked subscription token to return 404, got %d", recRevoked.Code)
	}
}

func TestRound4QNBK3CompleteMigrationWithMonitorStagingAndExplicitRestore(t *testing.T) {
	srcApp, srcState := batchFixture(t)
	monCfg := monitor.DefaultConfig()
	monCfg.Enabled = true
	monCfg.Notifications = monitor.NotificationConfig{
		Enabled:   true,
		Kind:      "discord",
		Endpoint:  "https://discord.example.com/api/webhooks/123/secret-hook",
		TimeoutMS: 3000,
	}
	if err := srcApp.monitorStore().SaveConfig(monCfg); err != nil {
		t.Fatal(err)
	}
	if _, err := srcApp.monitorStore().RecordTrafficSample(monitor.LedgerSample{
		ObservedAt:           time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC),
		Epoch:                "99/1000",
		Status:               monitorTrafficAvailableStatus(321, 654),
		ConnectionsAvailable: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = srcState

	passFile := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(passFile, []byte("Migration-Strong-Passphrase-2026!\n"), 0600); err != nil {
		t.Fatal(err)
	}
	archiveFile := filepath.Join(t.TempDir(), "full-with-monitor.qnbak")

	// backup --full succeeds in COMPLETE mode WITHOUT --allow-incomplete even when monitor/ is configured!
	backupOut, err := wizardOutput(t, func() error {
		return srcApp.backup("backup", []string{"--full", "--file", archiveFile, "--password-file", passFile})
	})
	if err != nil {
		t.Fatalf("backup --full with monitor/ failed without --allow-incomplete: %v\n%s", err, backupOut)
	}
	if !strings.Contains(backupOut, "模式 complete") {
		t.Fatalf("expected QNBK3 complete mode, got:\n%s", backupOut)
	}

	// Target 1: default restore WITHOUT --restore-monitor stages monitor/ into <root>/monitor-staged (0700) without touching active <root>/monitor!
	dstDefault, _ := batchFixture(t)
	if _, err := wizardOutput(t, func() error {
		return dstDefault.backup("restore", []string{"--file", archiveFile, "--password-file", passFile, "--yes"})
	}); err != nil {
		t.Fatalf("default restore failed: %v", err)
	}
	stagedDir := filepath.Join(dstDefault.store.Root, "monitor-staged")
	if info, err := os.Lstat(stagedDir); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 monitor-staged directory, got %v %v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(dstDefault.store.Root, "monitor")); !os.IsNotExist(err) {
		t.Fatalf("default restore without --restore-monitor must not activate monitor/, got %v", err)
	}
	stagedStore := &monitor.Store{Root: stagedDir}
	if ledger, err := stagedStore.LoadTrafficLedger(); err != nil || ledger.GlobalUpload != 321 || ledger.GlobalDownload != 654 {
		t.Fatalf("staged monitor ledger invalid: %+v err=%v", ledger, err)
	}

	// Target 2: explicit restore WITH --restore-monitor restores <root>/monitor (0700) so monitorStore loads config & ledger directly!
	dstExplicit, _ := batchFixture(t)
	if _, err := wizardOutput(t, func() error {
		return dstExplicit.backup("restore", []string{"--file", archiveFile, "--password-file", passFile, "--restore-monitor", "--yes"})
	}); err != nil {
		t.Fatalf("explicit --restore-monitor failed: %v", err)
	}
	monInfo, err := os.Lstat(filepath.Join(dstExplicit.store.Root, "monitor"))
	if err != nil || !monInfo.IsDir() || monInfo.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 monitor directory, got %v %v", monInfo, err)
	}
	restoredCfg, err := dstExplicit.monitorStore().LoadConfig()
	if err != nil || restoredCfg.Notifications.Kind != "discord" || restoredCfg.Notifications.Endpoint != monCfg.Notifications.Endpoint {
		t.Fatalf("restored monitor config mismatch: %+v err=%v", restoredCfg, err)
	}
	restoredLedger, err := dstExplicit.monitorStore().LoadTrafficLedger()
	if err != nil || restoredLedger.GlobalUpload != 321 || restoredLedger.GlobalDownload != 654 {
		t.Fatalf("restored monitor ledger mismatch: %+v err=%v", restoredLedger, err)
	}
}

func monitorTrafficAvailableStatus(up, down int64) (s coreapi.Status) {
	s.TrafficAvailable = true
	s.UplinkTotal = up
	s.DownlinkTotal = down
	return s
}

type mockNftCLIBackend struct {
	exec node.Runner
}

func (b mockNftCLIBackend) Check(s node.State, _ string) error {
	return (node.Firewall{SSH: []int{22}, Execute: b.exec}).Check(s)
}
func (b mockNftCLIBackend) Active() bool               { return true }
func (b mockNftCLIBackend) Activate(node.State) error  { return nil }
func (b mockNftCLIBackend) Stop() error                { return nil }
func (b mockNftCLIBackend) PrepareEffects(old, next node.State) error {
	return (node.SystemBackend{Execute: b.exec}).PrepareEffects(old, next)
}
func (b mockNftCLIBackend) FinishEffects(old, next node.State) error {
	return (node.SystemBackend{Execute: b.exec}).FinishEffects(old, next)
}

func TestRound4FirewallEnableNftablesAndGitHubMirrorValidationCLI(t *testing.T) {
	a, _ := batchFixture(t)
	var nftCommands []string
	var hasTable bool
	fwExec := func(_ time.Duration, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		nftCommands = append(nftCommands, line)
		if name == "nft" && len(args) >= 4 && args[0] == "list" && args[1] == "table" {
			if hasTable {
				return []byte("table inet qingnode {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"), nil
			}
			return []byte("Error: No such file or directory"), os.ErrNotExist
		}
		if name == "nft" && len(args) == 1 && strings.Contains(args[0], "table inet qingnode") {
			hasTable = true
			return nil, nil
		}
		if name == "nft" && len(args) >= 4 && args[0] == "delete" && args[1] == "table" {
			hasTable = false
			return nil, nil
		}
		return nil, nil
	}
	a.offline = false
	a.lookPath = func(file string) (string, error) { return "", os.ErrNotExist }
	a.store.Backend = mockNftCLIBackend{exec: fwExec}

	if _, err := wizardOutput(t, func() error {
		return a.firewall([]string{"enable", "--backend", "nftables"})
	}); err != nil {
		t.Fatalf("firewall enable --backend nftables failed: %v", err)
	}
	statusOut, err := wizardOutput(t, func() error {
		return a.firewall([]string{"status"})
	})
	if err != nil || !strings.Contains(statusOut, "项目自动防火墙模式：nftables") || !hasTable {
		t.Fatalf("expected nftables firewall mode active, hasTable=%v err=%v out=%s", hasTable, err, statusOut)
	}

	if _, err := wizardOutput(t, func() error {
		return a.firewall([]string{"disable"})
	}); err != nil {
		t.Fatalf("firewall disable failed: %v", err)
	}
	if hasTable {
		t.Fatalf("expected nft delete table inet qingnode on disable, commands=%v", nftCommands)
	}

	// Verify --github-mirror rejects non-HTTPS URLs on both core and self-update CLI paths.
	a.offline = false
	if err := a.selfUpdate([]string{"--github-mirror", "http://mirror.example.test"}); err == nil {
		t.Fatal("expected self-update to reject http:// --github-mirror")
	}
	if err := a.core([]string{"install", "--version", "1.14.0", "--github-mirror", "http://mirror.example.test"}); err == nil {
		t.Fatal("expected core install to reject http:// --github-mirror")
	}
}

