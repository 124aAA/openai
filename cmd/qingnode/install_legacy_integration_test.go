package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The final disposable gate supplies the actual fixed historical program and
// requires this test's pass event. Generic unit tests may lack that artifact.
func TestLegacyInstallPreflightActualBinary(t *testing.T) {
	bin := os.Getenv("QINGNODE_LEGACY_BIN")
	if bin == "" {
		t.Skip("requires the fixed v0.2.8 artifact; mandatory in final disposable gate")
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if !filepath.IsAbs(bin) || (digest != "e1634d5bc24123c3c522e2904e8d9bc51fdf7501db778b64d84b5ca43bb99b75" &&
		digest != "ca87b8ad0f11796225676c3cb1d90eb530be861bc920ddbbaa397a6b05735d77") {
		t.Fatal("historical artifact identity mismatch")
	}
	source, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "qn_legacy_install_preflight() {")
	end := strings.Index(text, "\nif [[ -z $WIZARD_PROTOCOL")
	if start < 0 || end <= start {
		t.Fatal("real bootstrap preflight function missing")
	}
	function := text[start:end]
	cert := func(dir string, before, after time.Time) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"hy2.example.test"}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certFile, keyFile := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "private.pem")
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
			t.Fatal(err)
		}
		return certFile, keyFile
	}
	for _, name := range []string{"reality", "reality-auto", "ss2022", "hy2", "expired", "not-yet-valid", "bad-protocol", "bad-address"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bundle, temp := filepath.Join(dir, "bundle"), filepath.Join(dir, "temporary")
			if err := os.Mkdir(bundle, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(temp, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(bin, filepath.Join(bundle, "qingnode")); err != nil {
				t.Fatal(err)
			}
			args := []string{"--protocol", "reality", "--server", "203.0.113.7", "--sni", "example.com"}
			success := true
			switch name {
			case "reality-auto":
				args = []string{"--auto", "--protocol", "reality"}
			case "ss2022":
				args = []string{"--protocol", "ss2022", "--server", "203.0.113.7"}
			case "hy2", "expired", "not-yet-valid":
				before, after := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
				if name == "expired" {
					before, after, success = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), false
				}
				if name == "not-yet-valid" {
					before, after, success = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour), false
				}
				certFile, keyFile := cert(dir, before, after)
				args = []string{"--protocol", "hysteria2", "--server", "203.0.113.7", "--sni", "hy2.example.test", "--cert", certFile, "--key", keyFile}
			case "bad-protocol":
				args, success = []string{"--protocol", "invented", "--server", "203.0.113.7"}, false
			case "bad-address":
				args, success = []string{"--protocol", "ss2022", "--server", "bad host"}, false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", append([]string{"-c", "set -euo pipefail\numask 077\n" + function + "\nINIT_ARGS=(\"$@\")\nqn_legacy_install_preflight\n", "legacy-preflight"}, args...)...)
			command.Env = append(os.Environ(), "BUNDLE="+bundle, "TEMP_DIR="+temp)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil || (err == nil) != success {
				t.Fatalf("legacy preflight outcome mismatch: %v; %s", err, output)
			}
			if success {
				if _, err := os.Lstat(filepath.Join(temp, "legacy-state")); !os.IsNotExist(err) {
					t.Fatal("successful compatibility preflight retained temporary State")
				}
			}
		})
	}
}
