package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func certificateCLIInput(t *testing.T, resource node.CertificateResource) string {
	t.Helper()
	raw, err := json.Marshal(certificateRequest{Version: 1, Resource: resource})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-certificate.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCertificateCLIProbePreservesExplicitChromeChoice(t *testing.T) {
	a, _, st := hy2CLIState(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(79), DNSNames: []string{"hy2.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	r := st.Certificates[0]
	r.LegacyStorage = false
	r.Certificate = node.Certificate{Mode: "pem", ServerName: "hy2.example.test", CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	st, err = node.PutCertificateResource(st, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	generation, raw := savedBatchState(t, a)
	if _, err := a.probeProfile(st.Nodes[0].ID, ""); err == nil || !strings.Contains(err.Error(), "Chrome") {
		t.Fatal("probe generated a known-incompatible default Chrome profile", err)
	}
	if _, err := hy2ClientSHA(st.Nodes[0], st.Nodes[0].Users[0], st.CoreVersion); err == nil {
		t.Fatal("performance comparison accepted a known-incompatible client")
	}
	if current, bytesNow := savedBatchState(t, a); current != generation || !bytes.Equal(bytesNow, raw) {
		t.Fatal("compatibility query changed State or silently disabled Chrome")
	}
	disabled := true
	st.Nodes[0].HY2 = &node.HY2Performance{Client: &node.HY2Transport{DisableChromeParrot: &disabled}}
	if err := a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if _, err := a.probeProfile(st.Nodes[0].ID, ""); err != nil {
		t.Fatal("explicit existing Chrome choice was rejected", err)
	}
	if _, err := hy2ClientSHA(st.Nodes[0], st.Nodes[0].Users[0], st.CoreVersion); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateCLIConvertsLegacyACMEToPEMWithoutChangingIdentity(t *testing.T) {
	a, backend, original := hy2CLIState(t)
	r := original.Certificates[0]
	if !r.LegacyStorage {
		t.Fatal("fixture did not retain old ACME storage")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(77), DNSNames: []string{r.Certificate.ServerName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	r.Certificate = node.Certificate{Mode: "pem", ServerName: r.Certificate.ServerName,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	// The old storage flag is owned metadata. Inputs cannot invent or clear it.
	r.LegacyStorage = false
	input := certificateCLIInput(t, r)
	if err := a.command([]string{"certificate", "update", "--id", r.ID, "--file", input, "--yes"}); err != nil {
		t.Fatal("legacy ACME could not be replaced by a validated PEM resource:", err)
	}
	loaded, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Certificates[0].LegacyStorage || loaded.Certificates[0].ID != r.ID || loaded.Nodes[0].ID != original.Nodes[0].ID || loaded.Nodes[0].CertificateID != r.ID || !reflect.DeepEqual(loaded.Nodes[0].Users, original.Nodes[0].Users) {
		t.Fatal("certificate mode update changed authentication, identity or retained inapplicable legacy storage")
	}
	previousGeneration, previousBytes := savedBatchState(t, a)
	// A valid replacement that fails activation must restore the former
	// certificate and State, rather than leaving a new key pair half applied.
	template.SerialNumber = big.NewInt(78)
	template.NotAfter = now.Add(72 * time.Hour)
	replacementDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	r.Certificate.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: replacementDER}))
	replacementInput := certificateCLIInput(t, r)
	backend.failStarts = 1
	if err := a.command([]string{"certificate", "update", "--id", r.ID, "--file", replacementInput, "--yes"}); err == nil {
		t.Fatal("activation failure falsely reported certificate update success")
	}
	if current, raw := savedBatchState(t, a); current != previousGeneration || !bytes.Equal(raw, previousBytes) || !backend.active {
		t.Fatal("failed certificate activation did not restore the previous State and running service")
	}
}

func TestCertificateRequestRejectsUnspecifiedAndInjectedFields(t *testing.T) {
	for _, raw := range []string{
		`{"version":2,"resource":{}}`,
		`{"version":1,"resource":{},"execute":"arbitrary"}`,
		`{"version":1,"resource":null}`,
		`{"version":1,"resource":{},"RESOURCE":{}}`,
		`{"version":1,"resource":{"certificate":{"mode":"acme","dns_token":"hidden"}}}`,
		`{"version":1,"resource":{}} {}`,
	} {
		if _, err := decodeCertificateRequest([]byte(raw)); err == nil {
			t.Errorf("unsafe certificate request accepted: %s", raw)
		}
	}
}

func TestCertificateCLIImportPreviewBindUpdateAndReferenceGuard(t *testing.T) {
	a, backend, st := hy2CLIState(t)
	resource := node.CertificateResource{ID: "aaaaaaaaaaaaaaa1", Name: "shared TLS", Certificate: node.Certificate{Mode: "acme", ServerName: "new.example.test", Email: "owner@example.test"}}
	input := certificateCLIInput(t, resource)
	generation, before := savedBatchState(t, a)
	service := *backend
	if _, err := wizardOutput(t, func() error { return a.command([]string{"certificate", "import", "--file", input, "--preview"}) }); err != nil {
		t.Fatal(err)
	}
	next, after := savedBatchState(t, a)
	if generation != next || !bytes.Equal(before, after) || *backend != service {
		t.Fatal("certificate preview changed State or lifecycle")
	}
	if err := a.command([]string{"certificate", "import", "--file", input}); err != nil {
		t.Fatal(err)
	}
	if backend.starts != service.starts || backend.stops != service.stops {
		t.Fatal("unused certificate import changed proxy lifecycle")
	}
	if err := a.command([]string{"certificate", "import", "--file", input}); err == nil {
		t.Fatal("import silently replaced an existing resource")
	}
	if err := a.command([]string{"certificate", "bind", "--id", resource.ID, "--node", st.Nodes[0].ID}); err != nil {
		t.Fatal(err)
	}
	bound, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if bound.Nodes[0].CertificateID != resource.ID || bound.Nodes[0].Users[0] != st.Nodes[0].Users[0] {
		t.Fatal("bind lost reference or changed proxy authentication")
	}
	generation, before = savedBatchState(t, a)
	service = *backend
	if err := a.command([]string{"certificate", "remove", "--id", resource.ID, "--yes"}); err == nil {
		t.Fatal("removed a referenced certificate")
	}
	if err := a.command([]string{"certificate", "unbind", "--id", resource.ID, "--node", st.Nodes[0].ID, "--yes"}); err == nil {
		t.Fatal("made a TLS-less HY2 node")
	}
	resource.Certificate.Email = "updated@example.test"
	updated := certificateCLIInput(t, resource)
	if err := a.command([]string{"certificate", "update", "--id", resource.ID, "--file", updated}); err == nil {
		t.Fatal("shared update did not require confirmation")
	}
	next, after = savedBatchState(t, a)
	if generation != next || !bytes.Equal(before, after) || *backend != service {
		t.Fatal("rejected operations changed State or lifecycle")
	}
	if err := a.command([]string{"certificate", "update", "--id", resource.ID, "--file", updated, "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := a.store.Load()
	if err != nil || loaded.Nodes[0].CertificateID != resource.ID || loaded.Nodes[0].Certificate.Email != "updated@example.test" || !reflect.DeepEqual(loaded.Nodes[0].Users, st.Nodes[0].Users) {
		t.Fatal("shared update did not preserve resource identity and proxy users", err)
	}
}

func TestCertificateCLIStatusIsReadOnlyAndContainsNoCertificateSecrets(t *testing.T) {
	a, backend, _ := hy2CLIState(t)
	generation, before := savedBatchState(t, a)
	service := *backend
	output, err := wizardOutput(t, func() error { return a.command([]string{"certificate", "status"}) })
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if json.Unmarshal([]byte(output), &report) != nil || report["issuance_triggered"] != false {
		t.Fatal("status did not provide an explicit read-only report")
	}
	for _, forbidden := range []string{"key_pem", "certificate_pem", "api_token", "access_key_secret", "private_key"} {
		if strings.Contains(output, forbidden) {
			t.Fatal("status exposed a private configuration field")
		}
	}
	next, after := savedBatchState(t, a)
	if generation != next || !bytes.Equal(before, after) || *backend != service {
		t.Fatal("certificate status changed State or runtime")
	}
}
