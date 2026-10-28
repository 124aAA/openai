package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func certificateMultiLevelChainFixture(t *testing.T) (CertificateResource, []string, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey
	var encoded []string
	var root *x509.Certificate
	var leafKey string
	for i, name := range []string{"private root", "upper intermediate", "lower intermediate", "leaf"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true}
		if i < 3 {
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			template.MaxPathLen = 2 - i
			template.MaxPathLenZero = i == 2
		} else {
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.DNSNames = []string{"hy2.example.test"}
		}
		issuer, issuerKey := parent, parentKey
		if issuer == nil {
			issuer, issuerKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			root = certificate
		}
		encoded = append([]string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, encoded...)
		if i == 3 {
			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			leafKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
		}
		parent, parentKey = certificate, key
	}
	resource := CertificateResource{ID: "1111111111111111", Name: "multi-level private certificate", Certificate: Certificate{Mode: "pem", ServerName: "hy2.example.test", CertPEM: strings.Join(encoded, ""), KeyPEM: leafKey}}
	return resource, encoded, root
}

func TestCertificateExplicitImportRequiresCompletePathAndKeepsCallerState(t *testing.T) {
	resource, chain, _ := certificateMultiLevelChainFixture(t)
	state := NewState()
	before := state.Clone()
	for _, scenario := range []string{"missing upper intermediate", "private root omitted"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := resource
			if scenario == "missing upper intermediate" {
				candidate.Certificate.CertPEM = strings.Join(chain[:2], "")
			} else {
				candidate.Certificate.CertPEM = strings.Join(chain[:3], "")
			}
			if err := ValidateCertificateResource(candidate, time.Now(), true); err != nil {
				t.Fatal("fixture did not reach the new full-path check", err)
			}
			if _, err := PutCertificateResource(state, candidate); err == nil {
				t.Fatal("explicit import accepted an incomplete or untrusted certificate path")
			}
			if !reflect.DeepEqual(state, before) {
				t.Fatal("rejected certificate import modified original State")
			}
		})
	}
	imported, err := PutCertificateResource(state, resource)
	if err != nil || len(imported.Certificates) != 1 {
		t.Fatal("explicit full private chain was rejected", err)
	}
	if !reflect.DeepEqual(imported.Certificates[0], resource) || !reflect.DeepEqual(state, before) {
		t.Fatal("certificate import changed material or caller State")
	}
}

func TestCertificateImportAllowsOmittedRootOnlyWhenTrusted(t *testing.T) {
	resource, encoded, root := certificateMultiLevelChainFixture(t)
	resource.Certificate.CertPEM = strings.Join(encoded[:3], "")
	leaf, chain, err := parseCertificateChain([]byte(resource.Certificate.CertPEM), []byte(resource.Certificate.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	// This controlled pool models the trust-root input used by the production
	// verifier. It does not install a CA or claim a host/client trust-store test.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if err = verifyCertificateImportChain(leaf, chain, resource.Certificate.ServerName, time.Now(), roots); err != nil {
		t.Fatal("omitted already-trusted root prevented a complete path", err)
	}
	if err = verifyCertificateImportChain(leaf, chain, resource.Certificate.ServerName, time.Now(), x509.NewCertPool()); err == nil {
		t.Fatal("omitted untrusted root was silently accepted")
	}
	fullLeaf, fullChain, err := parseCertificateChain([]byte(strings.Join(encoded, "")), []byte(resource.Certificate.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	empty := x509.NewCertPool()
	if err = verifyCertificateImportChain(fullLeaf, fullChain, resource.Certificate.ServerName, time.Now(), empty); err != nil || len(empty.Subjects()) != 0 {
		t.Fatal("explicit private-root verification failed or changed caller's trust pool", err)
	}
}

func TestCertificateIncompleteLegacyChainRemainsReadableRecoveryMaterial(t *testing.T) {
	resource, chain, _ := certificateMultiLevelChainFixture(t)
	resource.Certificate.CertPEM = strings.Join(chain[:2], "")
	legacy := hyFixture(t)
	legacy.Schema = 5
	legacy.Nodes[0].Certificate = cloneCertificate(resource.Certificate)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), raw...)
	migrated, err := DecodeState(raw)
	if err != nil || migrated.ValidateForRestore() != nil || ValidateCertificateDates(migrated) != nil {
		t.Fatal("new explicit-import trust rule leaked into legacy reading or date checks", err)
	}
	if migrated.Nodes[0].ID != legacy.Nodes[0].ID || !reflect.DeepEqual(migrated.Nodes[0].Users, legacy.Nodes[0].Users) || !reflect.DeepEqual(migrated.Nodes[0].Certificate, legacy.Nodes[0].Certificate) || URI(migrated.Nodes[0], migrated.Nodes[0].Users[0]) != URI(legacy.Nodes[0], legacy.Nodes[0].Users[0]) || !bytes.Equal(raw, original) {
		t.Fatal("legacy recovery identity, certificate bytes or original input changed")
	}
	for _, format := range []string{"QNBK1", "QNBK2"} {
		var backup []byte
		if format == "QNBK1" {
			backup, err = Backup(legacy, "incomplete-chain-recovery-password")
		} else {
			backup, err = BackupSnapshot(Snapshot{Format: 2, State: migrated}, "incomplete-chain-recovery-password")
		}
		if err != nil {
			t.Fatal(err)
		}
		restored, err := RestoreSnapshot(backup, "incomplete-chain-recovery-password")
		if err != nil || !reflect.DeepEqual(restored.State, migrated) {
			t.Fatal(format, "legacy incomplete recovery chain became unreadable", err)
		}
	}
	before := migrated.Clone()
	if _, err = PutCertificateResource(migrated, migrated.Certificates[0]); err == nil || !reflect.DeepEqual(migrated, before) {
		t.Fatal("new explicit update bypassed full-chain validation or modified old State", err)
	}
}
