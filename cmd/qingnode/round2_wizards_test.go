package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeWizardTestCertFiles(t *testing.T, domain string) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certfiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(72 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestReadTerminalPasswordHidesEchoAndRestoresTermiosOnPTY(t *testing.T) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("pty unavailable in sandbox: %v", err)
	}
	defer unix.Close(master)
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("TIOCSPTLCK unavailable: %v", err)
	}
	ptyNum, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Skipf("TIOCGPTN unavailable: %v", err)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptyNum)
	slave, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("open slave pty unavailable: %v", err)
	}
	defer unix.Close(slave)

	before, err := unix.IoctlGetTermios(slave, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag&unix.ECHO == 0 {
		before.Lflag |= unix.ECHO
		if err := unix.IoctlSetTermios(slave, unix.TCSETS, before); err != nil {
			t.Fatal(err)
		}
	}

	const secret = "cf-super-secret-dns-token-9988"
	errCh := make(chan error, 1)
	var got []byte
	go func() {
		var readErr error
		got, readErr = readTerminalPassword(slave)
		errCh <- readErr
	}()

	// Wait briefly until readTerminalPassword disables ECHO on the slave TTY.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cur, tErr := unix.IoctlGetTermios(slave, unix.TCGETS)
		if tErr == nil && cur.Lflag&unix.ECHO == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := unix.Write(master, []byte(secret+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("readTerminalPassword failed: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("got password %q, want %q", string(got), secret)
	}

	after, err := unix.IoctlGetTermios(slave, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if after.Lflag&unix.ECHO == 0 {
		t.Fatal("readTerminalPassword did not restore ECHO on slave terminal")
	}

	// Ensure the secret was NOT echoed back onto the master side of the PTY.
	_ = unix.SetNonblock(master, true)
	buf := make([]byte, 256)
	n, _ := unix.Read(master, buf)
	if n > 0 && strings.Contains(string(buf[:n]), secret) {
		t.Fatalf("secret leaked into PTY echo output: %q", string(buf[:n]))
	}
}

func TestCertificateWizardsAllModesUpdateUnbindRemoveAndCancelSafety(t *testing.T) {
	// 1. Cancel / 0 / invalid fields on empty root never create store.Root.
	for _, input := range []string{
		"3\n:cancel\n0\n",
		"3\ncerts\n0\n0\n",
		"3\ncerts\n2\nbad..domain\n0\n",
		"3\ncerts\n1\nedge.example.com\nnot-an-email\n0\n",
	} {
		a := wizardApp(t, input)
		if err := a.certificateTaskMenu(); err != nil {
			t.Fatalf("certificateTaskMenu returned unexpected top-level err for %q: %v", input, err)
		}
		if _, err := os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canceled/invalid certificate wizard created store root for input %q", input)
		}
	}

	// 2. Interactive create across HTTP-01, DNS-01 (cloudflare / alidns / acmedns), TLS-ALPN-01, and file mode.
	a := wizardApp(t, "")
	var secretQueue []string
	var secretPrompts []string
	a.readSecretFn = func(prompt string) ([]byte, error) {
		secretPrompts = append(secretPrompts, prompt)
		if len(secretQueue) == 0 {
			return nil, errors.New("unexpected secret prompt: " + prompt)
		}
		next := secretQueue[0]
		secretQueue = secretQueue[1:]
		return []byte(next), nil
	}

	// (a) ACME HTTP-01: choice 3 -> name -> mode 1 -> domain -> email -> provider "" -> keyType p256 -> altPort 8080 -> 0
	a.in.Reset(strings.NewReader("3\nhttp01-cert\n1\nh1.example.com\nops@example.com\n\np256\n8080\n0\n"))
	stderrOut, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() })
	if err != nil {
		t.Fatalf("HTTP-01 wizard failed: %v", err)
	}
	if !strings.Contains(stderrOut, "本次实际影响") {
		t.Fatalf("expected previewMenuMutation output, got: %s", stderrOut)
	}

	// (b) ACME DNS-01 Cloudflare: choice 3 -> name -> mode 2 -> domain -> email -> ca "" -> key "" -> dns 1 -> 0
	const cfToken = "cf_api_secret_token_value_12345"
	secretQueue = []string{cfToken, ""}
	a.in.Reset(strings.NewReader("3\ncf-dns-cert\n2\ncf.example.com\nops@example.com\n\n\n1\n0\n"))
	stderrCF, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() })
	if err != nil {
		t.Fatalf("DNS-01 cloudflare wizard failed: %v", err)
	}
	if strings.Contains(stderrCF, cfToken) {
		t.Fatalf("Cloudflare API token leaked to stderr: %s", stderrCF)
	}

	// (c) ACME DNS-01 Alidns: choice 3 -> name -> mode 2 -> domain -> email -> ca "" -> key "" -> dns 2 -> akID -> region -> 0
	const aliSecret = "ali_secret_access_key_67890"
	secretQueue = []string{aliSecret}
	a.in.Reset(strings.NewReader("3\nali-dns-cert\n2\nali.example.com\nops@example.com\n\n\n2\nLTAI5tTestKeyId\ncn-shanghai\n0\n"))
	stderrAli, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() })
	if err != nil {
		t.Fatalf("DNS-01 alidns wizard failed: %v", err)
	}
	if strings.Contains(stderrAli, aliSecret) {
		t.Fatalf("Alidns secret leaked to stderr: %s", stderrAli)
	}

	// (d) ACME DNS-01 acme-dns: choice 3 -> name -> mode 2 -> domain -> email -> ca "" -> key "" -> dns 3 -> server -> user -> sub -> 0
	const acmeDNSPass = "acmedns_secret_password_abcde"
	secretQueue = []string{acmeDNSPass}
	a.in.Reset(strings.NewReader("3\nacmedns-cert\n2\nacmedns.example.com\nops@example.com\n\n\n3\nhttps://auth.example.com\nuser-01\nsub-01\n0\n"))
	stderrAcmeDNS, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() })
	if err != nil {
		t.Fatalf("DNS-01 acmedns wizard failed: %v", err)
	}
	if strings.Contains(stderrAcmeDNS, acmeDNSPass) {
		t.Fatalf("acme-dns password leaked to stderr: %s", stderrAcmeDNS)
	}

	// (e) ACME TLS-ALPN-01: choice 3 -> name -> mode 3 -> domain -> email -> ca "" -> key "" -> altPort 8443 -> 0
	a.in.Reset(strings.NewReader("3\nalpn-cert\n3\nalpn.example.com\nops@example.com\n\n\n8443\n0\n"))
	if _, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() }); err != nil {
		t.Fatalf("TLS-ALPN-01 wizard failed: %v", err)
	}

	// (f) Local file mode: choice 3 -> name -> mode 4 -> domain -> certPath -> keyPath -> 0
	certPath, keyPath := writeWizardTestCertFiles(t, "file.example.com")
	a.in.Reset(strings.NewReader("3\nfile-cert\n4\nfile.example.com\n" + certPath + "\n" + keyPath + "\n0\n"))
	if _, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() }); err != nil {
		t.Fatalf("file certificate wizard failed: %v", err)
	}

	st, err := a.store.Load()
	if err != nil || len(st.Certificates) != 6 {
		t.Fatalf("expected 6 certificates in state, got %d (err=%v)", len(st.Certificates), err)
	}
	if len(secretPrompts) != 4 {
		t.Fatalf("expected 4 hidden secret prompts across DNS-01 providers, got %d", len(secretPrompts))
	}

	// 3. Add a TLS node bound to certificate #1, then update certificate #1, replace binding to certificate #2, and remove unreferenced certificate #6!
	if err := a.command([]string{"add", "--name", "hy2-edge", "--protocol", "hysteria2", "--server", "h1.example.com", "--port", "18443", "--certificate-id", st.Certificates[0].ID, "--quiet"}); err != nil {
		t.Fatalf("add hysteria2 node with certificate-id failed: %v", err)
	}

	// Update certificate #1 (HTTP-01 alt port 8080 -> 8081): choice 4 -> select 1 -> name "" -> mode "" -> domain "" -> email "" -> ca "" -> key "" -> port 8081 -> yes -> 0
	a.in.Reset(strings.NewReader("4\n1\n\n\n\n\n\n\n8081\nyes\n0\n"))
	if _, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() }); err != nil {
		t.Fatalf("certificate update wizard failed: %v", err)
	}
	st, err = a.store.Load()
	if err != nil || st.Certificates[0].Certificate.ACME.AlternativeHTTPPort != 8081 {
		t.Fatalf("certificate update did not persist new port: %+v", st.Certificates[0])
	}

	// Replace node certificate (#1 -> #2) via option 6 -> sub 1 -> node 1 (default) -> cert 2 -> yes -> 0
	a.in.Reset(strings.NewReader("6\n1\n1\n2\nyes\n0\n"))
	if _, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() }); err != nil {
		t.Fatalf("certificate replace/unbind wizard failed: %v", err)
	}
	st, err = a.store.Load()
	if err != nil || st.Nodes[0].CertificateID != st.Certificates[1].ID {
		t.Fatalf("expected node bound to cert #2 (%s), got %s", st.Certificates[1].ID, st.Nodes[0].CertificateID)
	}

	// Now remove unreferenced cert #1 via option 6 -> sub 3 -> cert 1 -> yes -> 0
	a.in.Reset(strings.NewReader("6\n3\n1\nyes\n0\n"))
	if _, err := captureProtocolMenuStderr(t, func() error { return a.certificateTaskMenu() }); err != nil {
		t.Fatalf("certificate remove wizard failed: %v", err)
	}
	st, err = a.store.Load()
	if err != nil || len(st.Certificates) != 5 {
		t.Fatalf("expected 5 certificates after removal, got %d (err=%v)", len(st.Certificates), err)
	}
}

func TestTopologyWizardsForwardsRemoteEgressesAndNodeRouteBinding(t *testing.T) {
	a, n := menuFixture(t, "")
	var secretQueue []string
	a.readSecretFn = func(prompt string) ([]byte, error) {
		if len(secretQueue) == 0 {
			return nil, errors.New("unexpected secret prompt: " + prompt)
		}
		v := secretQueue[0]
		secretQueue = secretQueue[1:]
		return []byte(v), nil
	}

	// Generate valid SS2022 32-byte key and X25519 public key for REALITY egress.
	ssKeyBytes := make([]byte, 32)
	if _, err := rand.Read(ssKeyBytes); err != nil {
		t.Fatal(err)
	}
	ssKey := base64.StdEncoding.EncodeToString(ssKeyBytes)

	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	realityPub := base64.RawURLEncoding.EncodeToString(xPriv.PublicKey().Bytes())
	const realityUUID = "11111111-2222-4333-8444-555555555555"
	const socksPass = "socks5_remote_secret_pw"
	const hy2Pass = "hy2_remote_secret_pw"

	// 1. Add SOCKS5 egress (UDP=true so UDP-capable node can route if needed), SS2022 egress, REALITY egress, and Hysteria2 egress via advancedTaskMenu -> 2 (topologyTaskMenu) -> 4.
	secretQueue = []string{socksPass, ssKey, realityUUID, hy2Pass}
	inputs := strings.Join([]string{
		"2", // enter topology submenu from advancedTaskMenu
		// Add SOCKS5 egress
		"4", "1", "eg-socks", "198.51.100.10", "1080", "y", "socksuser",
		// Add SS2022 egress
		"4", "2", "eg-ss2022", "198.51.100.11", "8388", "y",
		// Add REALITY egress
		"4", "3", "eg-reality", "198.51.100.12", "443", "y", "www.example.com", realityPub, "01a2b3", "chrome",
		// Add Hysteria2 egress
		"4", "4", "eg-hy2", "hy2.example.org", "8443", "y", "", "",
		// Add TCP+UDP PortForward routed through eg-ss2022 (option 3 in route list: 1=direct, 2=eg-socks, 3=eg-ss2022)
		"2", "fwd-relay", "127.0.0.1", "20080", "3", "203.0.113.55", "443", "3",
		// Bind entrance node route to eg-hy2 (option 5 in route list)
		"6", "1", "5",
		"0", // exit topology
		"0", // exit advanced
	}, "\n") + "\n"
	a.in.Reset(strings.NewReader(inputs))

	stderrOut, err := captureProtocolMenuStderr(t, func() error { return a.advancedTaskMenu() })
	if err != nil {
		t.Fatalf("advanced/topology wizards failed: %v", err)
	}
	for _, secret := range []string{socksPass, ssKey, realityUUID, hy2Pass} {
		if strings.Contains(stderrOut, secret) {
			t.Fatalf("remote egress secret %q leaked into wizard stderr: %s", secret, stderrOut)
		}
	}
	if !strings.Contains(stderrOut, "端口中转：fwd-relay") {
		t.Fatalf("expected forward impact preview in stderr, got: %s", stderrOut)
	}

	st, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Egresses) != 4 || len(st.Forwards) != 1 {
		t.Fatalf("expected 4 egresses and 1 forward, got %d egresses and %d forwards", len(st.Egresses), len(st.Forwards))
	}
	if st.Forwards[0].Network != "tcp+udp" || st.Forwards[0].EgressID != st.Egresses[1].ID {
		t.Fatalf("unexpected forward state: %+v", st.Forwards[0])
	}
	updatedNode, err := st.Find(n.ID)
	if err != nil || updatedNode.EgressID != st.Egresses[3].ID {
		t.Fatalf("expected entrance node bound to eg-hy2 (%s), got %q (err=%v)", st.Egresses[3].ID, updatedNode.EgressID, err)
	}

	// 2. Switch entrance node route back to direct (1), remove PortForward, and remove eg-hy2!
	cleanupInputs := strings.Join([]string{
		"6", "1", "1", // routeBindWizard -> node 1 -> 1 (direct)
		"3", "1", "yes", // forwardRemoveWizard -> 1 -> yes
		"5", "4", "yes", // egressRemoveWizard -> 4 (eg-hy2) -> yes
		"0",
	}, "\n") + "\n"
	a.in.Reset(strings.NewReader(cleanupInputs))
	if _, err := captureProtocolMenuStderr(t, func() error { return a.topologyTaskMenu() }); err != nil {
		t.Fatalf("topology cleanup wizards failed: %v", err)
	}
	st, err = a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	updatedNode, _ = st.Find(n.ID)
	if updatedNode.EgressID != "" || len(st.Forwards) != 0 || len(st.Egresses) != 3 {
		t.Fatalf("unexpected post-cleanup topology: node.EgressID=%q forwards=%d egresses=%d", updatedNode.EgressID, len(st.Forwards), len(st.Egresses))
	}
}

func TestDeviceMultiNodeWizardAndSubscriptionQRWidthGuard(t *testing.T) {
	a, n1 := menuFixture(t, "")
	if err := a.command([]string{"add", "--name", "second-ss", "--protocol", "ss-aead", "--server", "203.0.113.99", "--port", "19443", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	a.store.AfterCommit = a.refreshPublished
	a.store.BeforeCommit = a.revokeRemovedPublishedDevices
	a.verifyHTTPSFn = func(origin string) error { return nil }

	pubDir := filepath.Join(t.TempDir(), "sub-pub")
	if err := a.command([]string{"subscription", "init", "--dir", pubDir, "--allow-lossy"}); err != nil {
		t.Fatal(err)
	}

	// 1. Create multi-node DeviceProfile via exportTaskMenu -> 2:
	// name="work-laptop" -> node 1 -> more=y -> node 2 -> more=n -> strategy=2(auto) -> testURL -> allowDegraded=n -> routing=3(cn-direct) -> TUN=y -> Controller=y -> port 9095 -> defaultSubFormat="sing-box"
	createInputs := strings.Join([]string{
		"2",
		"work-laptop",
		"1", "y",
		"2", "n",
		"2", "https://cp.cloudflare.com/generate_204", "y",
		"3",
		"y",
		"y", "9095",
		"sing-box",
		"0",
	}, "\n") + "\n"
	a.in.Reset(strings.NewReader(createInputs))
	var createStdout string
	stderrCreate, err := captureProtocolMenuStderr(t, func() error {
		var e error
		createStdout, e = wizardOutput(t, func() error { return a.exportTaskMenu() })
		return e
	})
	if err != nil {
		t.Fatalf("deviceCreateWizard failed: %v", err)
	}
	if !strings.Contains(stderrCreate, "设备配置：work-laptop") || !strings.Contains(createStdout, "设备ID：") {
		t.Fatalf("missing device preview or ID output: stderr=%s stdout=%s", stderrCreate, createStdout)
	}

	st, err := a.store.Load()
	if err != nil || len(st.Devices) != 1 {
		t.Fatalf("expected 1 device profile, got %d (err=%v)", len(st.Devices), err)
	}
	dev := st.Devices[0]
	if len(dev.Bindings) != 2 || dev.Bindings[0].NodeID != n1.ID || dev.Strategy != "auto" || dev.Routing != "cn-direct" || !dev.TUN || dev.Controller == nil || dev.Controller.Port != 9095 || dev.DefaultSubscriptionFormat != "sing-box" {
		t.Fatalf("unexpected created DeviceProfile: %+v", dev)
	}

	// 2. Issue subscription token and render terminal QR when terminal width is sufficient.
	tokenFile1 := filepath.Join(t.TempDir(), "laptop-token-1.json")
	a.termWidth = 120
	issueInputs := strings.Join([]string{
		"5",
		"1",
		"https://sub.example.com",
		tokenFile1,
		"y",
		"0",
	}, "\n") + "\n"
	a.in.Reset(strings.NewReader(issueInputs))
	var qrStdout string
	stderrIssue, err := captureProtocolMenuStderr(t, func() error {
		var e error
		qrStdout, e = wizardOutput(t, func() error { return a.exportTaskMenu() })
		return e
	})
	if err != nil {
		t.Fatalf("subscriptionIssueWizard failed: %v", err)
	}
	rawMat, err := os.ReadFile(tokenFile1)
	if err != nil {
		t.Fatal(err)
	}
	var mat1 tokenMaterial
	if err := json.Unmarshal(rawMat, &mat1); err != nil {
		t.Fatal(err)
	}
	if mat1.UnifiedURL != "https://sub.example.com/s/"+mat1.Token {
		t.Fatalf("unexpected UnifiedURL in token file: %q", mat1.UnifiedURL)
	}
	if strings.Contains(stderrIssue, mat1.Token) {
		t.Fatalf("raw token leaked into stderr: %s", stderrIssue)
	}
	if !strings.Contains(qrStdout, "█") && !strings.Contains(qrStdout, "▀") {
		t.Fatalf("expected terminal QR half-blocks on stdout, got: %q", qrStdout)
	}

	// 3. Narrow terminal (a.termWidth = 20) rotates token safely to private file, then refuses wrapped QR with clear column warning!
	tokenFile2 := filepath.Join(t.TempDir(), "laptop-token-2.json")
	a.termWidth = 20
	rotateInputs := strings.Join([]string{
		"5",
		"1",
		"yes", // confirm rotation of existing device token
		"https://sub.example.com",
		tokenFile2,
		"y", // ask for terminal QR on narrow terminal
		"0",
	}, "\n") + "\n"
	a.in.Reset(strings.NewReader(rotateInputs))
	var narrowStdout string
	stderrNarrow, err := captureProtocolMenuStderr(t, func() error {
		var e error
		narrowStdout, e = wizardOutput(t, func() error { return a.exportTaskMenu() })
		return e
	})
	if err != nil {
		t.Fatalf("exportTaskMenu exited unexpectedly on narrow QR warning: %v", err)
	}
	if narrowStdout != "" {
		t.Fatalf("narrow terminal should not print broken wrapped QR to stdout, got: %q", narrowStdout)
	}
	if !strings.Contains(stderrNarrow, "终端宽度（20 列）不足以完整显示二维码") {
		t.Fatalf("expected narrow terminal width diagnostic in stderr, got: %s", stderrNarrow)
	}
	if _, err := os.Stat(tokenFile2); err != nil {
		t.Fatalf("rotated token file was not saved despite narrow terminal: %v", err)
	}
}
