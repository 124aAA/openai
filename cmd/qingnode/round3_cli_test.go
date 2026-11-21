package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func round3WriteCertFiles(t *testing.T, dnsName string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestRound3CLIHY2SetShowAndObfsRedaction(t *testing.T) {
	a, b, before := hy2CLIState(t)
	genBefore, rawBefore := savedBatchState(t, a)

	// 1. --preview leaves state & service completely untouched.
	previewOut, err := wizardOutput(t, func() error {
		return a.hy2([]string{
			"set", "--id", "1111111111111111",
			"--obfs-password", "super-secret-salamander-pw",
			"--hop-ports", "20000-22000",
			"--hop-interval", "25s",
			"--hop-mode", "external",
			"--preview",
		})
	})
	if err != nil {
		t.Fatalf("hy2 set --preview failed: %v", err)
	}
	genAfterPreview, rawAfterPreview := savedBatchState(t, a)
	if genBefore != genAfterPreview || string(rawBefore) != string(rawAfterPreview) || b.starts != 1 {
		t.Fatal("hy2 set --preview mutated state or restarted service")
	}
	if strings.Contains(previewOut, "super-secret-salamander-pw") {
		t.Fatalf("hy2 set --preview leaked obfs password: %s", previewOut)
	}

	// 2. Apply hy2 set and verify show/json redact obfs password while preserving hop config.
	if _, err := wizardOutput(t, func() error {
		return a.hy2([]string{
			"set", "--id", "1111111111111111",
			"--obfs-password", "super-secret-salamander-pw",
			"--hop-ports", "20000-22000",
			"--hop-interval", "25s",
			"--hop-mode", "external",
		})
	}); err != nil {
		t.Fatalf("hy2 set apply failed: %v", err)
	}

	humanShow, err := wizardOutput(t, func() error {
		return a.hy2([]string{"show", "--id", "1111111111111111"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(humanShow, "super-secret-salamander-pw") || strings.Contains(humanShow, before.Nodes[0].Users[0].Password) {
		t.Fatalf("hy2 show leaked secret: %s", humanShow)
	}
	if !strings.Contains(humanShow, "20000-22000") || !strings.Contains(humanShow, "25s") || !strings.Contains(humanShow, "salamander") {
		t.Fatalf("hy2 show missing hop/obfs summary: %s", humanShow)
	}

	jsonShow, err := wizardOutput(t, func() error {
		return a.hy2([]string{"show", "--id", "1111111111111111", "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jsonShow, "super-secret-salamander-pw") || !strings.Contains(jsonShow, "[混淆密码已隐藏]") {
		t.Fatalf("hy2 show --json did not redact obfs password: %s", jsonShow)
	}

	// 3. hy2 plan + hy2 apply preserves existing Obfs without writing Obfs secret into plan.json!
	planPath, _ := hy2CLIPlan(t, a, "custom", "--settings", hy2CLISettings(t, `{"client_mode":"bbr","client":{"bbr_profile":"conservative"},"hop_ports":"20000-22000","hop_interval":"25s","hop_mode":"external"}`))
	planDisk, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(planDisk), "super-secret-salamander-pw") || strings.Contains(string(planDisk), `"obfs"`) {
		t.Fatalf("hy2 plan file leaked obfs field or secret: %s", planDisk)
	}
	if err := a.hy2([]string{"apply", "--file", planPath}); err != nil {
		t.Fatalf("hy2 apply after obfs set failed: %v", err)
	}
	stAfterPlan, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if stAfterPlan.Nodes[0].HY2 == nil || stAfterPlan.Nodes[0].HY2.Obfs == nil || stAfterPlan.Nodes[0].HY2.Obfs.Password != "super-secret-salamander-pw" {
		t.Fatalf("hy2 apply lost existing salamander obfs: %+v", stAfterPlan.Nodes[0].HY2)
	}

	// 4. Clear obfs and hop cleanly.
	if _, err := wizardOutput(t, func() error {
		return a.hy2([]string{"set", "--id", "1111111111111111", "--clear-obfs", "--clear-hop"})
	}); err != nil {
		t.Fatalf("hy2 set --clear-obfs --clear-hop failed: %v", err)
	}
	stCleared, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if stCleared.Nodes[0].HY2 != nil && (stCleared.Nodes[0].HY2.Obfs != nil || stCleared.Nodes[0].HY2.HopPorts != "") {
		t.Fatalf("hy2 set did not clear obfs/hop: %+v", stCleared.Nodes[0].HY2)
	}
}

func TestRound3CLIRealityTargetsCustomCandidates(t *testing.T) {
	got, err := parseRealityCandidates(" WWW.Example.COM. , api.example.org , www.example.com ")
	if err != nil || len(got) != 2 || got[0] != "www.example.com" || got[1] != "api.example.org" {
		t.Fatalf("unexpected parsed candidates: %v (err=%v)", got, err)
	}
	for _, bad := range []string{
		"",
		"198.51.100.1",
		"demo.workers.dev",
		"my-site.vercel.app",
		"d111.cloudfront.net",
		"app.herokuapp.com",
		"web.azurewebsites.net",
		"a1.com,a2.com,a3.com,a4.com,a5.com,a6.com,a7.com,a8.com,a9.com,a10.com,a11.com,a12.com,a13.com,a14.com,a15.com,a16.com,a17.com",
	} {
		if _, err := parseRealityCandidates(bad); err == nil {
			t.Fatalf("parseRealityCandidates accepted invalid input %q", bad)
		}
	}

	ranked := rankRealityTargetPool([]string{"slow.example.com", "fast.example.com", "flaky.example.com"}, func(r *node.Reality) (time.Duration, error) {
		switch r.ServerName {
		case "fast.example.com":
			return 8 * time.Millisecond, nil
		case "slow.example.com":
			return 45 * time.Millisecond, nil
		default:
			return 0, errors.New("CurveID P-256 rejected")
		}
	})
	if len(ranked) != 3 || ranked[0].name != "fast.example.com" || ranked[1].name != "slow.example.com" || ranked[2].err == nil {
		t.Fatalf("unexpected custom candidate ranking: %+v", ranked)
	}
}

func TestRound3CLINodesRotateBatchAndTransports(t *testing.T) {
	a := wizardApp(t, "")
	a.offline = true
	a.store.Backend = &batchBackend{}
	certPath, keyPath := round3WriteCertFiles(t, "cdn.example.com")

	// 1. SS2022 128-bit cipher + yamux multiplex + user-add + rotate --server-key.
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{
			"init", "--protocol", "ss2022", "--method", node.SS2022AES128Method,
			"--name", "ss128-mux", "--server", "198.51.100.10", "--port", "28388",
			"--multiplex", "yamux", "--mux-max-connections", "4", "--mux-padding", "--quiet",
		})
	}); err != nil {
		t.Fatalf("init ss2022-128 + mux failed: %v", err)
	}
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{"user-add", "--id", "ss128-mux", "--name", "bob"})
	}); err != nil {
		t.Fatalf("user-add on ss2022-128 failed: %v", err)
	}
	st, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	ssNode := st.Nodes[0]
	oldServerKey := ssNode.Shadowsocks.ServerKey
	for _, u := range ssNode.Users {
		raw, err := base64.StdEncoding.Strict().DecodeString(u.Password)
		if err != nil || len(raw) != 16 {
			t.Fatalf("expected 16-byte user key for %s, got len=%d err=%v", u.Name, len(raw), err)
		}
	}
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{"rotate", "--id", "ss128-mux", "--server-key", "--yes"})
	}); err != nil {
		t.Fatalf("rotate --server-key on ss2022-128 failed: %v", err)
	}
	stAfterRotate, _ := a.store.Load()
	newKeyRaw, err := base64.StdEncoding.Strict().DecodeString(stAfterRotate.Nodes[0].Shadowsocks.ServerKey)
	if err != nil || len(newKeyRaw) != 16 || stAfterRotate.Nodes[0].Shadowsocks.ServerKey == oldServerKey {
		t.Fatalf("rotate --server-key did not generate fresh 16-byte key")
	}

	// 2. REALITY + gRPC + extended fingerprint + smooth short-id rotation (--keep-old-short-id).
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{
			"add", "--protocol", "reality-grpc", "--name", "r-grpc",
			"--server", "198.51.100.10", "--port", "28443",
			"--sni", "www.apple.com", "--fingerprint", "qq",
			"--service-name", "reality_grpc_svc", "--quiet",
		})
	}); err != nil {
		t.Fatalf("add reality-grpc failed: %v", err)
	}
	stR0, _ := a.store.Load()
	rNode0, _ := stR0.Find("r-grpc")
	firstSID := rNode0.Reality.ShortID

	if _, err := wizardOutput(t, func() error {
		return a.command([]string{"rotate", "--id", "r-grpc", "--short-id", "--keep-old-short-id", "--yes"})
	}); err != nil {
		t.Fatalf("rotate --short-id --keep-old-short-id failed: %v", err)
	}
	stR1, _ := a.store.Load()
	rNode1, _ := stR1.Find("r-grpc")
	if rNode1.Reality.ShortID == firstSID || len(rNode1.Reality.ShortIDs) != 2 || rNode1.Reality.ShortIDs[0] != rNode1.Reality.ShortID || rNode1.Reality.ShortIDs[1] != firstSID {
		t.Fatalf("unexpected REALITY ShortIDs after smooth rotation: primary=%s list=%v", rNode1.Reality.ShortID, rNode1.Reality.ShortIDs)
	}
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{"edit", "--id", "r-grpc", "--short-ids", "clear"})
	}); err != nil {
		t.Fatalf("edit --short-ids clear failed: %v", err)
	}
	stR2, _ := a.store.Load()
	rNode2, _ := stR2.Find("r-grpc")
	if len(rNode2.Reality.ShortIDs) != 0 {
		t.Fatalf("expected ShortIDs cleared, got %v", rNode2.Reality.ShortIDs)
	}

	// 3. Trojan WS Early Data + VLESS H2 + Batch JSON edit.
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{
			"add", "--protocol", "trojan-ws-tls", "--name", "tr-ws-ed",
			"--server", "cdn.example.com", "--port", "29443",
			"--sni", "cdn.example.com", "--cert", certPath, "--key", keyPath,
			"--path", "/trws", "--ws-max-early-data", "2048", "--ws-early-data-header", "X-Early-Data",
			"--multiplex", "h2mux", "--quiet",
		})
	}); err != nil {
		t.Fatalf("add trojan-ws-tls with early data + mux failed: %v", err)
	}
	if _, err := wizardOutput(t, func() error {
		return run([]string{
			"validate-install", "--protocol", "vless-h2-tls", "--name", "vl-h2",
			"--server", "cdn.example.com", "--port", "29444",
			"--sni", "cdn.example.com", "--cert", certPath, "--key", keyPath,
			"--path", "/vlh2", "--transport-host", "cdn.example.com",
		})
	}); err != nil {
		t.Fatalf("validate-install vless-h2-tls failed: %v", err)
	}

	batchPayload := map[string]any{
		"version": 1,
		"edits": []map[string]any{
			{
				"id":                   "tr-ws-ed",
				"ws_max_early_data":    4096,
				"ws_early_data_header": "default",
				"multiplex_protocol":   "smux",
				"mux_min_streams":      8,
			},
		},
	}
	batchBytes, _ := json.Marshal(batchPayload)
	batchFile := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(batchFile, batchBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := wizardOutput(t, func() error {
		return a.command([]string{"batch", "--file", batchFile})
	}); err != nil {
		t.Fatalf("batch edit failed: %v", err)
	}
	stFinal, _ := a.store.Load()
	trNode, _ := stFinal.Find("tr-ws-ed")
	if trNode.Transport.MaxEarlyData != 4096 || trNode.Transport.EarlyDataHeaderName != "" || trNode.Multiplex.Protocol != "smux" || trNode.Multiplex.MinStreams != 8 {
		t.Fatalf("unexpected tr-ws-ed after batch edit: tr=%+v mux=%+v", trNode.Transport, trNode.Multiplex)
	}
}

func TestRound3CLIEgressParityAndSecretRedaction(t *testing.T) {
	a := wizardApp(t, "")
	a.offline = true
	a.store.Backend = &batchBackend{}
	if err := a.store.WithLock(func() error { return a.store.Apply(node.NewState()) }); err != nil {
		t.Fatal(err)
	}

	certPath, _ := round3WriteCertFiles(t, "remote.example.com")
	rSample, err := node.NewReality("www.apple.com", "www.apple.com:443")
	if err != nil {
		t.Fatal(err)
	}
	uuid := node.NewUser("u", "vless-tls").UUID
	ss128Srv, _ := node.NewShadowsocks2022(node.SS2022AES128Method)
	ss128Usr := node.NewUserForNode("u", node.Node{Protocol: "ss2022", Shadowsocks: ss128Srv})
	ss128Joined := ss128Srv.ServerKey + ":" + ss128Usr.Password

	egressCommands := [][]string{
		{"egress", "add", "--name", "e-https", "--protocol", "http", "--server", "198.51.100.21", "--port", "8443", "--username", "corp", "--password", "http-secret-pw-111", "--tls", "--sni", "remote.example.com", "--ca", certPath},
		{"egress", "add", "--name", "e-ss128", "--protocol", "ss2022", "--server", "198.51.100.22", "--port", "8388", "--method", node.SS2022AES128Method, "--password", ss128Joined, "--multiplex", "h2mux"},
		{"egress", "add", "--name", "e-ssaead", "--protocol", "ss-aead", "--server", "198.51.100.23", "--port", "8389", "--method", "chacha20-ietf-poly1305", "--password", "ssaead-secret-pw-222"},
		{"egress", "add", "--name", "e-hy2", "--protocol", "hysteria2", "--server", "198.51.100.24", "--port", "8443", "--sni", "remote.example.com", "--password", "hy2-secret-pw-333", "--obfs-password", "hy2-obfs-pw-444", "--hop-ports", "25000-26000", "--hop-interval", "20s", "--ca", certPath},
		{"egress", "add", "--name", "e-trojan", "--protocol", "trojan-ws-tls", "--server", "198.51.100.25", "--port", "443", "--sni", "remote.example.com", "--password", "trojan-secret-pw-555", "--path", "/tr", "--ws-max-early-data", "2048", "--multiplex", "yamux", "--mux-padding", "--ca", certPath},
		{"egress", "add", "--name", "e-vless", "--protocol", "vless-h2-tls", "--server", "198.51.100.26", "--port", "443", "--sni", "remote.example.com", "--uuid", uuid, "--path", "/vlh2", "--transport-host", "remote.example.com", "--packet-encoding", "xudp", "--ca", certPath},
		{"egress", "add", "--name", "e-vmess", "--protocol", "vmess-httpupgrade-tls", "--server", "198.51.100.27", "--port", "443", "--sni", "remote.example.com", "--uuid", uuid, "--security", "aes-128-gcm", "--path", "/vmup", "--ca", certPath},
		{"egress", "add", "--name", "e-anytls", "--protocol", "anytls", "--server", "198.51.100.28", "--port", "443", "--sni", "remote.example.com", "--password", "anytls-secret-pw-666", "--idle-session-timeout", "60s", "--min-idle-session", "2", "--ca", certPath},
		{"egress", "add", "--name", "e-tuic", "--protocol", "tuic", "--server", "198.51.100.29", "--port", "8443", "--sni", "remote.example.com", "--uuid", uuid, "--password", "tuic-secret-pw-777", "--congestion-control", "bbr", "--udp-relay-mode", "native", "--heartbeat", "10s", "--ca", certPath},
		{"egress", "add", "--name", "e-rgrpc", "--protocol", "reality-grpc", "--server", "198.51.100.30", "--port", "443", "--sni", "www.apple.com", "--uuid", uuid, "--public-key", rSample.PublicKey, "--short-id", "01020304", "--fingerprint", "android", "--service-name", "r_grpc"},
	}
	for _, args := range egressCommands {
		topologyCommand(t, a, args...)
	}

	// Edit HY2 hop-interval and Trojan multiplex, then verify egress list & show redact all secrets.
	topologyCommand(t, a, "egress", "edit", "--id", "e-hy2", "--hop-interval", "45s")
	topologyCommand(t, a, "egress", "edit", "--id", "e-trojan", "--multiplex", "off")

	var combinedOut strings.Builder
	combinedOut.WriteString(topologyCommand(t, a, "egress", "list"))
	combinedOut.WriteString(topologyCommand(t, a, "egress", "list", "--json"))
	for _, name := range []string{"e-https", "e-ss128", "e-ssaead", "e-hy2", "e-trojan", "e-vless", "e-vmess", "e-anytls", "e-tuic", "e-rgrpc"} {
		combinedOut.WriteString(topologyCommand(t, a, "egress", "show", "--id", name))
		combinedOut.WriteString(topologyCommand(t, a, "egress", "show", "--id", name, "--json"))
	}
	showOut := combinedOut.String()
	for _, secret := range []string{
		"http-secret-pw-111", ss128Joined, "ssaead-secret-pw-222",
		"hy2-secret-pw-333", "hy2-obfs-pw-444", "trojan-secret-pw-555",
		uuid, "anytls-secret-pw-666", "tuic-secret-pw-777",
	} {
		if strings.Contains(showOut, secret) {
			t.Fatalf("egress list/show leaked remote secret %q:\n%s", secret, showOut)
		}
	}
	st, err := a.store.Load()
	if err != nil || len(st.Egresses) != 10 {
		t.Fatalf("expected 10 saved remote egresses, got %d (err=%v)", len(st.Egresses), err)
	}
}
