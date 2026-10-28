package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"qingnode/internal/node"
)

func TestInstallValidatesBeforePreparingCore(t *testing.T) {
	for _, args := range [][]string{
		{"install", "--invalid"},
		{"install", "--port", "0"},
		{"install", "--protocol", "invented"},
		{"install", "--protocol", "ss2022", "--server", "203.0.113.1", "--name", strings.Repeat("x", 300)},
		{"install", "--protocol", "ss2022", "--server", "bad host"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			a := wizardApp(t, "")
			a.offline = false
			calls := 0
			a.installCoreFn = func(_, _, _, _ string) error { calls++; return nil }
			if err := a.command(args); err == nil {
				t.Fatal("invalid install succeeded")
			}
			if calls != 0 {
				t.Fatalf("invalid install prepared core %d times", calls)
			}
		})
	}
}

func TestInstallValidCandidatePreparesCoreOnceAndPreservesIdentityOnRepeat(t *testing.T) {
	a := wizardApp(t, "")
	a.offline = false
	calls := 0
	a.installCoreFn = func(_ string, version, _, _ string) error {
		calls++
		if version != node.DefaultCore {
			t.Fatalf("unexpected core version %s", version)
		}
		return nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{"install", "--protocol", "ss2022", "--server", "203.0.113.1", "--listen", "127.0.0.1", "--port", strconv.Itoa(port), "--quiet"}
	if err := a.command(args); err != nil {
		t.Fatal(err)
	}
	before, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Nodes) != 1 || calls != 1 {
		t.Fatal("install did not prepare and create exactly once")
	}
	for _, invalid := range [][]string{
		{"install", "--name", strings.Repeat("x", 300)},
		{"install", "--protocol", "ss-aead", "--method", "invalid"},
		{"install", "--listen", "not-an-ip"},
		{"install", "--port", "443", "--random-port"},
		{"install", "--protocol", "reality", "--sni", "192.0.2.2"},
		{"install", "--protocol", "reality", "--sni", "example.com", "--target", "invalid-target"},
		{"install", "--protocol", "reality", "--sni", "example.com", "--fingerprint", "invalid"},
		{"install", "--protocol", "hysteria2", "--sni", "example.com", "--cert", "missing-cert", "--key", "missing-key"},
		{"install", "--egress", "nonexistent"},
	} {
		if err := a.command(invalid); err == nil {
			t.Fatalf("existing node accepted invalid arguments: %v", invalid)
		}
		if calls != 1 {
			t.Fatalf("existing node installed core for invalid arguments: %v", invalid)
		}
	}
	if err := a.command(args); err != nil {
		t.Fatal(err)
	}
	after, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(after.Nodes) != 1 || after.Nodes[0].ID != before.Nodes[0].ID || after.Nodes[0].Users[0] != before.Nodes[0].Users[0] {
		t.Fatal("repeat install changed existing identity or did not verify core")
	}
}

func TestInstallHelpBeforeHostBootstrap(t *testing.T) {
	if err := run([]string{"install", "--help"}); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineInstallDoesNotPrepareCore(t *testing.T) {
	a := wizardApp(t, "")
	calls := 0
	a.installCoreFn = func(_, _, _, _ string) error { calls++; return nil }
	if err := a.command([]string{"install", "--protocol", "ss2022", "--server", "203.0.113.1"}); err == nil {
		t.Fatal("offline install accepted")
	}
	if calls != 0 {
		t.Fatal("offline install prepared a core")
	}
}

func TestInstallPendingTransactionIsNotRecovered(t *testing.T) {
	a := wizardApp(t, "")
	if err := a.command([]string{"init", "--protocol", "ss2022", "--server", "203.0.113.1", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	a.offline = false
	journal := filepath.Join(a.store.Root, "transaction.json")
	original := []byte("pending recovery evidence")
	if err := os.WriteFile(journal, original, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.installCoreFn = func(_, _, _, _ string) error { calls++; return nil }
	if err := a.command([]string{"install"}); err == nil {
		t.Fatal("pending transaction accepted")
	}
	after, err := os.ReadFile(journal)
	if err != nil || string(after) != string(original) || calls != 0 {
		t.Fatal("install modified pending transaction or prepared core", err)
	}
}

func TestStatelessInstallValidationMakesNoState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "never-created")
	for _, args := range [][]string{
		{"--protocol", "bad"},
		{"--protocol", "ss2022", "--name", strings.Repeat("x", 300)},
		{"--protocol", "reality", "--sni", "192.0.2.2"},
		{"--protocol", "hysteria2", "--sni", "example.com", "--cert", "missing", "--key", "missing"},
	} {
		argv := append([]string{"--root", root, "--offline", "validate-install"}, args...)
		if err := run(argv); err == nil {
			t.Fatalf("invalid preflight accepted %v", args)
		}
	}
	if err := run([]string{"--root", root, "--offline", "validate-install", "--protocol", "ss2022", "--auto"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("stateless validation created state", err)
	}
}

func TestInstallStaleCandidateDoesNotPrepareCore(t *testing.T) {
	a := wizardApp(t, "")
	if err := a.command([]string{"init", "--protocol", "ss2022", "--server", "203.0.113.1", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	before, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	candidate := before.Clone()
	if err := a.store.WithLock(func() error {
		current, err := a.store.Load()
		if err != nil {
			return err
		}
		current.Nodes[0].Name = "changed-concurrently"
		return a.store.Apply(current)
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.installCoreFn = func(_, _, _, _ string) error { calls++; return nil }
	if err := a.commitInstall(before, candidate); err == nil {
		t.Fatal("stale candidate accepted")
	}
	after, err := a.store.Load()
	if err != nil || after.Nodes[0].Name != "changed-concurrently" || calls != 0 {
		t.Fatal("concurrent change overwritten or core prepared", err)
	}
}

func TestStatelessInstallValidationAcceptsIPCertificateSAN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"validate-install", "--protocol", "hysteria2", "--server", "127.0.0.1", "--sni", "127.0.0.1", "--cert", certFile, "--key", keyFile}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
}

func TestInstallAcceptsOldStateExplicitEmptyArrays(t *testing.T) {
	a := wizardApp(t, "")
	if err := a.command([]string{"init", "--protocol", "ss2022", "--server", "203.0.113.1", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.store.Root, "current", "state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	v["devices"] = []any{}
	raw, err = json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if before.Devices == nil {
		t.Fatal("fixture did not preserve old explicit empty array")
	}
	calls := 0
	a.installCoreFn = func(_, _, _, _ string) error { calls++; return nil }
	if err = a.commitInstall(before.Clone(), before.Clone()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("equivalent State incorrectly rejected")
	}
}

func TestInstallLockedStoreDoesNotChangePermissions(t *testing.T) {
	a := wizardApp(t, "")
	if err := a.command([]string{"init", "--protocol", "ss2022", "--server", "203.0.113.1", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	before, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cores := filepath.Join(a.store.Root, "cores")
	if err = os.Chmod(cores, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(a.store.Root, ".lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	calls := 0
	a.installCoreFn = func(_, _, _, _ string) error { calls++; return nil }
	if err = a.commitInstall(before, before.Clone()); err == nil {
		t.Fatal("held lock accepted")
	}
	info, err := os.Stat(cores)
	if err != nil || info.Mode().Perm() != 0700 || calls != 0 {
		t.Fatal("lock failure modified ownership or prepared core", err)
	}
}

func TestStatelessExistingInstallValidationChecksSuppliedFields(t *testing.T) {
	if err := run([]string{"validate-install", "--existing"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate-install", "--existing", "--protocol", "not-a-protocol"}); err == nil {
		t.Fatal("unsupported existing input accepted")
	}
	if err := run([]string{"validate-install", "--existing", "--protocol", "ss-aead", "--method", "invalid"}); err == nil {
		t.Fatal("invalid method accepted")
	}
}
