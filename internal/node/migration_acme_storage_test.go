package node

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func migrationACMEFixture(t *testing.T, legacy bool) MigrationPackage {
	t.Helper()
	m := migrationFixture(t)
	original := m.Snapshot.State.Certificates[0].Certificate
	r := &m.Snapshot.State.Certificates[0]
	r.Certificate = Certificate{Mode: "acme", ServerName: "localhost", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01", Provider: "https://ca.example.test:8443/dir/path"}}
	if legacy {
		r.LegacyStorage = true
		r.Certificate.ACME = nil
	}
	for i := range m.Snapshot.State.Nodes {
		m.Snapshot.State.Nodes[i].Certificate = nil
	}
	var e error
	m.Snapshot.State, e = CanonicalCertificates(m.Snapshot.State)
	if e != nil {
		t.Fatal(e)
	}
	cert, key, account, accountKey := migrationACMEPaths(m.Snapshot.State.Certificates[0])
	reg, _ := json.Marshal(map[string]any{"status": "valid", "contact": []string{"mailto:owner@example.test"}, "location": "https://accounts.other-ca-host.test/account/42", "preservedFutureField": map[string]any{"keep": true}})
	m.Roots = []MigrationRoot{{ID: "acme", Kind: "acme-storage", Source: "/source/acme", OwnerID: os.Geteuid(), GroupID: -1}}
	m.Consistency = "stopped-owned-core"
	m.Files = []MigrationFile{migrationAsset("acme", cert, []byte(original.CertPEM), 0600), migrationAsset("acme", key, []byte(original.KeyPEM), 0600), migrationAsset("acme", strings.TrimSuffix(cert, ".crt")+".json", []byte("{}"), 0600), migrationAsset("acme", account, reg, 0600), migrationAsset("acme", accountKey, []byte(original.KeyPEM), 0600), migrationAsset("acme", "unrecognized-original-asset", []byte("keep original storage"), 0600)}
	if e = m.Validate(); e != nil {
		t.Fatal("complete fixture is invalid", e)
	}
	return m
}

func TestMigrationACMEFixedStorageKeysRespectProviderEmailAndLegacy(t *testing.T) {
	r := CertificateResource{ID: "1111111111111111", Certificate: Certificate{Mode: "acme", ServerName: "Example.TEST", Email: "Owner+Tag@EXAMPLE.TEST", ACME: &ACMESettings{Provider: "https://CA.Example.TEST:8443/dir/path/"}}}
	c, k, a, ak := migrationACMEPaths(r)
	if c != "resources/1111111111111111/certificates/ca.example.test-8443-dir-path/example.test/example.test.crt" || k != "resources/1111111111111111/certificates/ca.example.test-8443-dir-path/example.test/example.test.key" || a != "resources/1111111111111111/acme/ca.example.test-8443-dir-path/users/owner_plus_tag@example.test/owner_plus_tag.json" || ak != "resources/1111111111111111/acme/ca.example.test-8443-dir-path/users/owner_plus_tag@example.test/owner_plus_tag.key" {
		t.Fatal("fixed storage key compatibility changed", c, k, a, ak)
	}
	for _, provider := range []string{"", "letsencrypt", "zerossl"} {
		r.Certificate.ACME.Provider = provider
		c, _, a, _ = migrationACMEPaths(r)
		issuer := "acme-v02.api.letsencrypt.org-directory"
		if provider == "zerossl" {
			issuer = "acme.zerossl.com-v2-dv90"
		}
		if !strings.Contains(c, "/certificates/"+issuer+"/") || !strings.Contains(a, "/acme/"+issuer+"/") {
			t.Fatal("provider alias used wrong storage issuer", provider, c, a)
		}
	}
	r.LegacyStorage = true
	r.Certificate.ACME = nil
	c, _, a, _ = migrationACMEPaths(r)
	if strings.HasPrefix(c, "resources/") || !strings.HasPrefix(c, "certificates/acme-v02.api.letsencrypt.org-directory/") || !strings.HasPrefix(a, "acme/acme-v02.api.letsencrypt.org-directory/users/") {
		t.Fatal("legacy storage was relocated", c, a)
	}
}

func TestMigrationACMECoverageRejectsWrongCAEmailAndEmptyRegistration(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, kind := range []string{"wrong CA", "wrong email", "empty registration", "mismatched contact", "missing certificate metadata", "arbitrary certificate directory", "nested other resource"} {
			t.Run(strings.Join([]string{map[bool]string{true: "legacy", false: "resource"}[legacy], kind}, "/"), func(t *testing.T) {
				m := migrationACMEFixture(t, legacy)
				switch kind {
				case "wrong CA":
					for i := range m.Files {
						if strings.Contains(m.Files[i].Path, "/users/") {
							m.Files[i].Path = strings.Replace(m.Files[i].Path, "/users/", "/different-ca/users/", 1)
						}
					}
				case "wrong email":
					for i := range m.Files {
						m.Files[i].Path = strings.ReplaceAll(m.Files[i].Path, "owner@example.test", "other@example.test")
					}
				case "empty registration":
					m.Files[3] = migrationAsset("acme", m.Files[3].Path, []byte("{}"), 0600)
				case "mismatched contact":
					reg, _ := json.Marshal(map[string]any{"status": "valid", "contact": []string{"mailto:other@example.test"}, "location": "https://account.example.test/42"})
					m.Files[3] = migrationAsset("acme", m.Files[3].Path, reg, 0600)
				case "missing certificate metadata":
					m.Files = append(m.Files[:2], m.Files[3:]...)
				case "arbitrary certificate directory":
					for i := 0; i < 3; i++ {
						m.Files[i].Path = "unrelated/" + m.Files[i].Path
					}
				case "nested other resource":
					for i := range m.Files {
						m.Files[i].Path = "resources/ffffffffffffffff/" + m.Files[i].Path
					}
				}
				if m.Validate() == nil {
					t.Fatal("unrelated storage falsely counted as complete")
				}
				m.Mode = "limited"
				m.External = []string{"explicit incomplete ACME identity or certificate storage"}
				if e := m.Validate(); e != nil {
					t.Fatal("limited recovery evidence was discarded", e)
				}
			})
		}
	}
}

func TestMigrationACMECompletenessPreservesExpiredAndInactiveRecoveryAssets(t *testing.T) {
	m := migrationACMEFixture(t, false)
	keyBlock, _ := pem.Decode(m.Files[1].Data)
	keyAny, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	key := keyAny.(crypto.Signer)
	now := time.Now()
	expired := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, expired, expired, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	m.Files[0] = migrationAsset("acme", m.Files[0].Path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	for _, status := range []string{"valid", "deactivated", "revoked"} {
		reg, _ := json.Marshal(map[string]any{"status": status, "contact": []string{"mailto:owner@example.test"}, "location": "https://different-account-host.example.test/account/42", "unknownFutureField": "preserve"})
		m.Files[3] = migrationAsset("acme", m.Files[3].Path, reg, 0600)
		if e = m.Validate(); e != nil {
			t.Fatal("expired/inactive original material was thrown away", status, e)
		}
	}
	original := append([]byte{}, m.Files[5].Data...)
	b, e := BackupMigration(m, "expired-recovery-material-password")
	if e != nil {
		t.Fatal(e)
	}
	got, e := RestoreMigration(b, "expired-recovery-material-password")
	if e != nil {
		t.Fatal(e)
	}
	if string(got.Files[5].Data) != string(original) || string(got.Files[3].Data) != string(m.Files[3].Data) {
		t.Fatal("unknown storage/provider metadata was normalized or deleted")
	}
}
