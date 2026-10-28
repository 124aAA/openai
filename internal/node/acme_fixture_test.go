//go:build linux

package node

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestACMEFixtureARISignPaddingNativeRetryBoundary(t *testing.T) {
	const observedCAFailure = "HTTP 500 urn:ietf:params:acme:error:serverInternal - could not find an order for the given certificate: could not find order resulting in the given certificate serial number"
	// This serial was observed in the failed real CA run. The standard DER
	// encoding preserves its positive sign, whereas unsigned magnitude bytes
	// omit that sign byte. Pebble's fixed-version lookup uses these two forms
	// as different keys; this is not evidence of lost QingNode migration data.
	serial, ok := new(big.Int).SetString("8e4b56bccd3d2a", 16)
	if !ok {
		t.Fatal("serial fixture")
	}
	der, err := asn1.Marshal(serial)
	if err != nil || hex.EncodeToString(der[2:]) != "008e4b56bccd3d2a" || hex.EncodeToString(serial.Bytes()) != "8e4b56bccd3d2a" {
		t.Fatalf("observed positive serial encoding boundary: %x %v", der, err)
	}
	for _, tc := range []struct {
		name   string
		serial *big.Int
		log    string
		allow  bool
	}{
		{"observed CA lookup failure", serial, observedCAFailure, true},
		{"unsigned magnitude starts below sign boundary", big.NewInt(0x7f), observedCAFailure, false},
		{"nil serial", nil, observedCAFailure, false},
		{"zero serial", big.NewInt(0), observedCAFailure, false},
		{"negative serial", big.NewInt(-128), observedCAFailure, false},
		{"sign padding without CA failure", serial, "", false},
		{"different server failure", serial, "HTTP 500 urn:ietf:params:acme:error:serverInternal - database unavailable", false},
		{"certificate validation failure", serial, "x509: certificate has expired or is not yet valid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := acmeFixturePebbleARISignPaddingFailure(&x509.Certificate{SerialNumber: tc.serial}, []byte(tc.log)); got != tc.allow {
				t.Fatalf("native retry budget exception=%t, want %t", got, tc.allow)
			}
		})
	}
	if acmeFixturePebbleARISignPaddingFailure(nil, []byte(observedCAFailure)) {
		t.Fatal("missing leaf allowed an extended CA retry budget")
	}
}

func TestACMEFixtureReadsCommittedLeafAfterWriterStops(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certificates", "owned-issuer", "owned-name")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(certDir, "owned-name.crt")
	keyPath := filepath.Join(certDir, "owned-name.key")
	certPEM, keyPEM := makeCert(t)
	block, _ := pem.Decode([]byte(certPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer := key.(crypto.Signer)
	writeLeaf := func(serial int64, before, after time.Time) {
		t.Helper()
		leaf.SerialNumber, leaf.NotBefore, leaf.NotAfter = big.NewInt(serial), before, after
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, signer.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	writeLeaf(41, now.Add(-time.Minute), now.Add(time.Minute))
	startup, _ := acmeFixtureReadCertificate(dir, nil, true)
	if startup == nil || startup.SerialNumber.Int64() != 41 {
		t.Fatal("initial stored leaf not observed")
	}
	// Simulate the official core finishing an asynchronous renewal during the
	// transport check. The stopped-writer baseline must use the committed leaf.
	writeLeaf(42, now.Add(-time.Minute), now.Add(2*time.Minute))
	committed, _ := acmeFixtureReadCertificate(dir, nil, false)
	if committed == nil || committed.SerialNumber.Int64() != 42 || !committed.NotAfter.After(startup.NotAfter) {
		t.Fatal("renewal baseline kept the obsolete startup serial/expiry")
	}
	if renewed, _ := acmeFixtureReadCertificate(dir, startup.SerialNumber.String(), true); renewed == nil || renewed.SerialNumber.Int64() != 42 {
		t.Fatal("a committed new valid serial was not recognized")
	}
	if renewed, _ := acmeFixtureReadCertificate(dir, committed.SerialNumber.String(), true); renewed != nil {
		t.Fatal("unchanged serial was counted as renewal")
	}
	writeLeaf(43, now.Add(-2*time.Minute), now.Add(-time.Minute))
	if baseline, _ := acmeFixtureReadCertificate(dir, nil, false); baseline == nil || baseline.SerialNumber.Int64() != 43 {
		t.Fatal("an expired but committed leaf cannot be used as the startup renewal baseline")
	}
	if renewed, _ := acmeFixtureReadCertificate(dir, nil, true); renewed != nil {
		t.Fatal("expired leaf was counted as a successful renewal")
	}
	writeLeaf(44, now.Add(time.Minute), now.Add(2*time.Minute))
	if renewed, _ := acmeFixtureReadCertificate(dir, nil, true); renewed != nil {
		t.Fatal("not-yet-valid leaf was counted as a successful renewal")
	}
	writeLeaf(45, now.Add(-time.Minute), now.Add(time.Minute))
	_, mismatchedKey := makeCert(t)
	if err := os.WriteFile(keyPath, []byte(mismatchedKey), 0600); err != nil {
		t.Fatal(err)
	}
	if broken, _ := acmeFixtureReadCertificate(dir, nil, false); broken != nil {
		t.Fatal("partially committed or mismatched certificate/key was accepted")
	}
}
