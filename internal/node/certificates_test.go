package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCertificateResourceMigrationIdentityStorageAndSingleSecret(t *testing.T) {
	for _, mode := range []string{"pem", "acme"} {
		t.Run(mode, func(t *testing.T) {
			s := hyFixture(t)
			if mode == "acme" {
				s.Nodes[0].Certificate = &Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test"}
			}
			second := s.Nodes[0]
			second.ID = "3333333333333333"
			second.Name = "second"
			second.Port++
			s.Nodes = append(s.Nodes, second)
			s.Schema = 5
			raw, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			original := append([]byte(nil), raw...)
			oldRuntime := s
			oldRuntime.Schema = Schema
			beforeServer, e := Server(oldRuntime, "/owned/root")
			if e != nil {
				t.Fatal(e)
			}
			got, e := DecodeState(raw)
			if e != nil {
				t.Fatal(e)
			}
			again, e := DecodeState(raw)
			if e != nil {
				t.Fatal(e)
			}
			if got.Schema != Schema || len(got.Certificates) != 1 || got.Nodes[0].CertificateID == "" || got.Nodes[0].CertificateID != got.Nodes[1].CertificateID || !reflect.DeepEqual(got, again) {
				t.Fatal("migration did not deterministically deduplicate certificates")
			}
			if got.Nodes[0].ID != s.Nodes[0].ID || !reflect.DeepEqual(got.Nodes[0].Users, s.Nodes[0].Users) || URI(got.Nodes[0], got.Nodes[0].Users[0]) != URI(s.Nodes[0], s.Nodes[0].Users[0]) {
				t.Fatal("migration changed authentication or URI")
			}
			afterServer, e := Server(got, "/owned/root")
			if e != nil || !bytes.Equal(beforeServer, afterServer) {
				t.Fatal("migration changed actual runtime configuration", e)
			}
			if mode == "acme" && (!got.Certificates[0].LegacyStorage || CertificateACMEDirectory("/owned/root", got.Certificates[0]) != "/owned/root/acme") {
				t.Fatal("legacy ACME storage moved")
			}
			encoded, e := json.Marshal(got)
			if e != nil {
				t.Fatal(e)
			}
			var wire map[string]json.RawMessage
			_ = json.Unmarshal(encoded, &wire)
			var nodes []map[string]json.RawMessage
			_ = json.Unmarshal(wire["nodes"], &nodes)
			for _, n := range nodes {
				if _, present := n["certificate"]; present {
					t.Fatal("node persisted duplicate certificate")
				}
			}
			if mode == "pem" && bytes.Count(encoded, []byte(`"key_pem"`)) != 1 {
				t.Fatal("private key stored more than once")
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("readonly migration changed original bytes")
			}
			round, e := DecodeState(encoded)
			if e != nil || !reflect.DeepEqual(round, got) {
				t.Fatal("current schema roundtrip failed", e)
			}
		})
	}
}

func TestCertificateSchemaRejectsHiddenExtensionsAndInlineSecrets(t *testing.T) {
	for _, declared := range []State{NewState(), {Schema: Schema, CoreVersion: DefaultCore, Nodes: nil}} {
		encoded, err := json.Marshal(declared)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(encoded, &raw)
		if declared.Nodes != nil && string(raw["nodes"]) != "[]" || declared.Nodes == nil && string(raw["nodes"]) != "null" {
			t.Fatal("canonicalization changed empty versus absent node collection", string(encoded))
		}
		decoded, err := DecodeState(encoded)
		if err != nil || !reflect.DeepEqual(declared.Nodes, decoded.Nodes) {
			t.Fatal("empty node collection changed across codec", err)
		}
	}
	invalid := NewState()
	invalid.Nodes = []Node{{ID: "1111111111111111", CertificateID: "missing-resource"}}
	cloned := invalid.Clone()
	if !reflect.DeepEqual(cloned, invalid) {
		t.Fatal("cloning invalid candidate discarded recovery evidence")
	}
	if _, err := CanonicalCertificates(cloned); err == nil {
		t.Fatal("dangling reference silently accepted")
	}
	for schema := 1; schema <= 5; schema++ {
		for _, field := range []string{"certificates", "CERTIFICATEſ"} {
			for _, value := range []string{"null", "[]"} {
				raw := `{"schema":` + string(rune('0'+schema)) + `,"core_version":"1.14.0","nodes":[],"` + field + `":` + value + `}`
				if _, e := DecodeState([]byte(raw)); e == nil {
					t.Fatal("legacy accepted certificate resource", raw)
				}
			}
		}
		for _, field := range []string{"certificate_id", "CERTIFICATE_ID"} {
			if _, e := DecodeState([]byte(`{"schema":` + string(rune('0'+schema)) + `,"nodes":[{"` + field + `":null}]}`)); e == nil {
				t.Fatal("legacy accepted certificate reference")
			}
		}
		for _, field := range []string{"acme", "certificate_path", "key_path"} {
			if _, e := DecodeState([]byte(`{"schema":` + string(rune('0'+schema)) + `,"nodes":[{"certificate":{"` + field + `":null}}]}`)); e == nil {
				t.Fatal("legacy accepted new certificate setting")
			}
		}
	}
	for _, raw := range []string{`{"schema":6,"nodes":[{"certificate":null}]}`, `{"schema":6,"nodes":[{"CERTIFICATE":{}}]}`, `{"schema":` + strconv.Itoa(Schema+1) + `,"nodes":[]}`, `{"schema":6,"certificates":[],"CERTIFICATEſ":[]}`, `{"schema":6,"certificates":[{"id":"1111111111111111","name":"x","certificate":{"mode":"acme","server_name":"example.test","email":"owner@example.test","unexpected_dns_token":"private"}}]}`} {
		if _, e := DecodeState([]byte(raw)); e == nil {
			t.Fatal("unsupported or ambiguous format accepted", raw)
		}
	}
}

func TestCertificateSharingCopyOnWriteAndExplicitResourceUpdate(t *testing.T) {
	s := hyFixture(t)
	second := s.Nodes[0]
	second.ID = "3333333333333333"
	second.Name = "second"
	second.Port++
	s.Nodes = append(s.Nodes, second)
	s, e := CanonicalCertificates(s)
	if e != nil {
		t.Fatal(e)
	}
	originalID := s.Nodes[0].CertificateID
	oldKey := s.Nodes[1].Certificate.KeyPEM
	inPlace := s.Clone()
	inPlace.Nodes[0].Certificate.ServerName = "127.0.0.1"
	inPlace, e = CanonicalCertificates(inPlace)
	if e != nil {
		t.Fatal(e)
	}
	if inPlace.Nodes[0].CertificateID == originalID || inPlace.Nodes[1].CertificateID != originalID || inPlace.Nodes[1].Certificate.ServerName != "localhost" {
		t.Fatal("in-place legacy edit changed shared certificate")
	}
	if _, e = RemoveCertificateResource(s, originalID); e == nil {
		t.Fatal("deleted shared certificate")
	}
	next := s.Clone()
	cert, key := makeCert(t)
	replacement := *next.Nodes[0].Certificate
	replacement.CertPEM, replacement.KeyPEM = cert, key
	next.Nodes[0].Certificate = &replacement
	next, e = CanonicalCertificates(next)
	if e != nil {
		t.Fatal(e)
	}
	if next.Nodes[0].CertificateID == originalID || next.Nodes[1].CertificateID != originalID || next.Nodes[1].Certificate.KeyPEM != oldKey {
		t.Fatal("ordinary edit rotated shared credential")
	}
	r := s.Certificates[0]
	r.Certificate = replacement
	shared, e := PutCertificateResource(s, r)
	if e != nil {
		t.Fatal(e)
	}
	if shared.Nodes[0].CertificateID != originalID || shared.Nodes[1].CertificateID != originalID || shared.Nodes[0].Certificate.KeyPEM != key || shared.Nodes[1].Certificate.KeyPEM != key {
		t.Fatal("explicit resource update did not update exact references")
	}
	if s.Nodes[0].Certificate.KeyPEM != oldKey {
		t.Fatal("candidate mutation altered original")
	}
	acme := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "cloudflare", APIToken: "original-token", Resolvers: []string{"1.1.1.1:53"}}}}
	deep := s.Clone()
	deep.Nodes[0].Certificate = &acme
	deep.Nodes[1].Certificate = &acme
	deep.Nodes[0].CertificateID = ""
	deep.Nodes[1].CertificateID = ""
	deep, e = CanonicalCertificates(deep)
	if e != nil {
		t.Fatal(e)
	}
	acmeID := deep.Nodes[0].CertificateID
	deep.Nodes[0].Certificate.ACME.DNS01.APIToken = "new-node-token"
	deep.Nodes[0].Certificate.ACME.DNS01.Resolvers[0] = "8.8.8.8:53"
	deep, e = CanonicalCertificates(deep)
	if e != nil || deep.Nodes[0].CertificateID == acmeID || deep.Nodes[1].Certificate.ACME.DNS01.APIToken != "original-token" || deep.Nodes[1].Certificate.ACME.DNS01.Resolvers[0] != "1.1.1.1:53" {
		t.Fatal("nested legacy edit altered shared resource", e)
	}
	impact, e := compareImpact(s, shared, "/owned/root")
	if e != nil || !impact.NeedsRestart || len(impact.Nodes) != 2 {
		t.Fatal("shared update omitted runtime affected nodes", e)
	}
	r = shared.Certificates[0]
	r.Name = "display name"
	renamed, e := PutCertificateResource(shared, r)
	if e != nil {
		t.Fatal(e)
	}
	impact, e = compareImpact(shared, renamed, "/owned/root")
	if e != nil || impact.NeedsRestart {
		t.Fatal("certificate display name restarted core", e)
	}
}

func TestCertificateACMEExactCapabilitiesAndChallenges(t *testing.T) {
	providers := []*ACMEDNS01{{Provider: "alidns", AccessKeyID: "access-id", AccessKeySecret: "access-secret", RegionID: "cn-hangzhou", SecurityToken: "sts-secret"}, {Provider: "cloudflare", APIToken: "scoped-api-token", ZoneToken: "read-zone-token"}, {Provider: "acmedns", Username: "owned-user", Password: "owned-password", Subdomain: "registered-subdomain", ServerURL: "https://auth.example.test"}}
	for _, dns := range providers {
		dns.TTL = "60s"
		dns.PropagationDelay = "2s"
		dns.PropagationTimeout = "2m"
		dns.Resolvers = []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"}
		dns.OverrideDomain = "delegated.example.test"
		c := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "dns-01", KeyType: "p256", DNS01: dns}}
		if e := ValidateCertificateResource(CertificateResource{Certificate: c}, time.Now(), true); e != nil {
			t.Fatal(dns.Provider, e)
		}
		n := hyFixture(t).Nodes[0]
		n.Certificate = &c
		n.CertificateID = "1111111111111111"
		in := hysteriaInbound(n, "/owned/root")
		tls := in["tls"].(M)
		acme := tls["certificate_provider"].(M)
		if acme["data_directory"] != "/owned/root/acme/resources/1111111111111111" || acme["key_type"] != "p256" || acme["disable_http_challenge"] != true || acme["disable_tls_alpn_challenge"] != true {
			t.Fatal("new ACME provider fields wrong")
		}
		d := acme["dns01_challenge"].(M)
		if d["provider"] != dns.Provider || d["override_domain"] != "delegated.example.test" || d["propagation_timeout"] != "2m" {
			t.Fatal("DNS fields dropped")
		}
		s := NewState()
		s.Nodes = []Node{n}
		if len(CertificateChallengeBindings(s)) != 0 {
			t.Fatal("DNS01 demanded inbound port")
		}
		redacted := Redact("raw "+dns.AccessKeySecret+" "+dns.APIToken+" "+dns.Password, s)
		for _, secret := range []string{dns.AccessKeySecret, dns.APIToken, dns.Password} {
			if secret != "" && strings.Contains(redacted, secret) {
				t.Fatal("DNS credential leaked")
			}
		}
	}
	for _, challenge := range []string{"http-01", "tls-alpn-01"} {
		c := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: challenge, KeyType: "rsa2048"}}
		if challenge == "http-01" {
			c.ACME.AlternativeHTTPPort = 18080
		} else {
			c.ACME.AlternativeTLSPort = 18443
		}
		n := hyFixture(t).Nodes[0]
		n.ID = "3333333333333333"
		n.Certificate = &c
		n.CertificateID = "1111111111111111"
		s := NewState()
		s.Certificates = []CertificateResource{{ID: n.CertificateID, Name: "challenge-" + challenge, Certificate: c}}
		s.Nodes = []Node{n}
		if err := s.Validate(); err != nil {
			t.Fatal("challenge collision fixture must be valid before adding the conflicting TCP listener", err)
		}
		bindings := CertificateChallengeBindings(s)
		if len(bindings) != 1 || bindings[0].Port != map[string]int{"http-01": 18080, "tls-alpn-01": 18443}[challenge] {
			t.Fatal("local challenge port wrong")
		}
		reality := fixture(t).Nodes[0]
		reality.ID = "4444444444444444"
		reality.Port = bindings[0].Port
		reality.Listen = "127.0.0.1"
		s.Nodes = append(s.Nodes, reality)
		if e := s.Validate(); e == nil || !strings.Contains(e.Error(), "挑战端口") {
			t.Fatal("challenge collision with managed TCP listener accepted", e)
		}
	}
	base := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test"}
	for _, a := range []*ACMESettings{{Challenge: "dns-01"}, {Challenge: "http-01", KeyType: "ed25519"}, {Challenge: "http-01", AlternativeTLSPort: 443}, {Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "route53"}}, {Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "cloudflare", APIToken: "token", AccessKeySecret: "other"}}, {Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "cloudflare", APIToken: "token", PropagationTimeout: "-1"}}, {Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "cloudflare", APIToken: "token", PropagationDelay: "2m", PropagationTimeout: "1m"}}, {Challenge: "http-01", Provider: "http://production.example.test"}} {
		base.ACME = a
		if e := ValidateCertificateResource(CertificateResource{Certificate: base}, time.Now(), true); e == nil {
			t.Fatal("invalid ACME field or capability accepted", a)
		}
	}
}

func certificateTestPair(t *testing.T, now time.Time, expired, ed bool) (string, string) {
	t.Helper()
	var private any
	var public any
	if ed {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		public, private = pub, key
	} else {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		private, public = key, &key.PublicKey
	}
	end := now.Add(90 * 24 * time.Hour)
	if expired {
		end = now.Add(-time.Hour)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "ignored-cn.example.test"}, DNSNames: []string{"hy2.example.test"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}

func TestCertificateValidationDatesSANKeyAlgorithmAndChain(t *testing.T) {
	now := time.Now()
	cert, key := certificateTestPair(t, now, false, false)
	resource := CertificateResource{Certificate: Certificate{Mode: "pem", ServerName: "hy2.example.test", CertPEM: cert, KeyPEM: key}}
	if e := ValidateCertificateResource(resource, now, true); e != nil {
		t.Fatal(e)
	}
	wrong := resource
	wrong.Certificate.ServerName = "wrong.example.test"
	if ValidateCertificateResource(wrong, now, true) == nil {
		t.Fatal("wrong SAN accepted")
	}
	_, otherKey := certificateTestPair(t, now, false, false)
	wrong = resource
	wrong.Certificate.KeyPEM = otherKey
	if ValidateCertificateResource(wrong, now, true) == nil {
		t.Fatal("wrong private key accepted")
	}
	expiredCert, expiredKey := certificateTestPair(t, now, true, false)
	wrong = resource
	wrong.Certificate.CertPEM, wrong.Certificate.KeyPEM = expiredCert, expiredKey
	if ValidateCertificateResource(wrong, now, true) == nil || ValidateCertificateResource(wrong, now, false) != nil {
		t.Fatal("expired certificate not repairable but rejected for update")
	}
	edCert, edKey := certificateTestPair(t, now, false, true)
	wrong = resource
	wrong.Certificate.CertPEM, wrong.Certificate.KeyPEM = edCert, edKey
	if e := ValidateCertificateResource(wrong, now, true); e != nil {
		t.Fatal("valid Ed25519 server certificate rejected by client-specific restriction", e)
	}
	n := hyFixture(t).Nodes[0]
	n.Certificate = &wrong.Certificate
	if e := ValidateHY2ClientCertificate(n, "sing-box"); e == nil || !strings.Contains(e.Error(), "Ed25519") {
		t.Fatal("Chrome QUIC incompatible client accepted", e)
	}
	n.HY2 = &HY2Performance{Client: &HY2Transport{DisableChromeParrot: hyBool(true)}}
	if e := ValidateHY2ClientCertificate(n, "sing-box"); e != nil {
		t.Fatal("explicit native QUIC Ed25519 client rejected", e)
	}
	wrong = resource
	wrong.Certificate.CertPEM = cert + cert
	if ValidateCertificateResource(wrong, now, true) == nil {
		t.Fatal("invalid duplicated chain accepted")
	}
	wrong = resource
	wrong.Certificate.CertPEM = cert + "garbage"
	if ValidateCertificateResource(wrong, now, true) == nil {
		t.Fatal("trailing certificate junk accepted")
	}
	status, e := InspectCertificateResource(resource, "/unused", now)
	if e != nil || status.Status != "available" || status.Algorithm != "ECDSA" || status.NotAfter == nil || status.DaysRemaining == nil {
		t.Fatal("certificate observation incorrect", status, e)
	}
	status, e = InspectCertificateResource(resource, "/unused", now.Add(80*24*time.Hour))
	if e != nil || status.Status != "expiring" {
		t.Fatal("expiry warning missing", status, e)
	}
}

func TestCertificateExternalFilesNoMutationAndRuntimeDigest(t *testing.T) {
	cert, key := makeCert(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if e := os.WriteFile(certPath, []byte(cert), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(keyPath, []byte(key), 0600); e != nil {
		t.Fatal(e)
	}
	c := Certificate{Mode: "file", ServerName: "localhost", CertificatePath: certPath, KeyPath: keyPath}
	r := CertificateResource{ID: "1111111111111111", Name: "external", Certificate: c}
	if e := ValidateCertificateResource(r, time.Now(), true); e != nil {
		t.Fatal(e)
	}
	s := NewState()
	s.Certificates = []CertificateResource{r}
	s.Nodes = hyFixture(t).Nodes
	s.Nodes[0].CertificateID = r.ID
	s.Nodes[0].Certificate = nil
	ids, e := CertificateFileIdentities(s)
	if e != nil || len(ids) != 2 {
		t.Fatal(e)
	}
	nextCert, nextKey := makeCert(t)
	_ = os.WriteFile(certPath, []byte(nextCert), 0644)
	_ = os.WriteFile(keyPath, []byte(nextKey), 0600)
	after, e := CertificateFileIdentities(s)
	if e != nil || reflect.DeepEqual(ids, after) {
		t.Fatal("external content replacement invisible", e)
	}
	unreferenced := s.Clone()
	unreferenced.Nodes = nil
	if _, e = RemoveCertificateResource(unreferenced, r.ID); e != nil {
		t.Fatal(e)
	}
	if got, e := os.ReadFile(keyPath); e != nil || string(got) != nextKey {
		t.Fatal("removing reference modified external file")
	}
	_ = os.Chmod(keyPath, 0644)
	if ValidateCertificateResource(r, time.Now(), true) == nil {
		t.Fatal("world-readable private key accepted")
	}
	_ = os.Chmod(keyPath, 0600)
	_ = os.Chmod(keyPath, 0660)
	if ValidateCertificateResource(r, time.Now(), true) == nil {
		t.Fatal("group-writable private key accepted")
	}
	_ = os.Chmod(keyPath, 0600)
	link := filepath.Join(dir, "linked.pem")
	if e = os.Symlink(keyPath, link); e != nil {
		t.Fatal(e)
	}
	r.Certificate.KeyPath = link
	if ValidateCertificateResource(r, time.Now(), true) == nil {
		t.Fatal("symlink private key accepted")
	}
	r.Certificate.KeyPath = keyPath
	hard := filepath.Join(dir, "hard.pem")
	if e = os.Link(keyPath, hard); e != nil {
		t.Fatal(e)
	}
	if _, e = CertificateFileIdentities(s); e == nil {
		t.Fatal("hardlinked private key accepted for runtime")
	}
}

func TestCertificateACMEStatusDoesNotInventIssuance(t *testing.T) {
	r := CertificateResource{ID: "1111111111111111", Name: "managed", Certificate: Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01"}}}
	root := t.TempDir()
	now := time.Now()
	status, e := InspectCertificateResource(r, root, now)
	if e != nil || status.Status != "configured" || status.NotAfter != nil || status.Evidence != "configuration-only" {
		t.Fatal("configured mistaken for issued", status, e)
	}
	certificateRelative, keyRelative, _, _ := migrationACMEPaths(r)
	certificatePath := filepath.Join(root, "acme", filepath.FromSlash(certificateRelative))
	keyPath := filepath.Join(root, "acme", filepath.FromSlash(keyRelative))
	metadataPath := strings.TrimSuffix(certificatePath, ".crt") + ".json"
	if e = os.MkdirAll(filepath.Dir(certificatePath), 0700); e != nil {
		t.Fatal(e)
	}
	cert, key := certificateTestPair(t, now, false, false)
	if e = os.WriteFile(certificatePath, []byte(cert), 0600); e != nil {
		t.Fatal(e)
	}
	status, e = InspectCertificateResource(r, root, now)
	if e != nil || status.Status != "failed" {
		t.Fatal("orphan certificate mistaken for issued and usable", status, e)
	}
	if e = os.WriteFile(keyPath, []byte(key), 0600); e != nil {
		t.Fatal(e)
	}
	status, e = InspectCertificateResource(r, root, now)
	if e != nil || status.Status != "failed" {
		t.Fatal("certificate without issuer metadata mistaken for available", status, e)
	}
	if e = os.WriteFile(metadataPath, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	status, e = InspectCertificateResource(r, root, now)
	if e != nil || status.Status != "available" || !strings.Contains(status.Evidence, "not issuance") {
		t.Fatal("actual certificate observation missing", status, e)
	}
	if e = os.Symlink(certificatePath, filepath.Join(filepath.Dir(certificatePath), "alias.crt")); e != nil {
		t.Fatal(e)
	}
	if _, e = InspectCertificateResource(r, root, now); e == nil {
		t.Fatal("unsafe ACME storage accepted")
	}
}

func TestCertificateACMEStatusOnlyObservesConfiguredResourceAndIssuer(t *testing.T) {
	now := time.Now()
	cert, key := certificateTestPair(t, now, false, false)
	for _, scenario := range []string{"legacy nested resource", "legacy other issuer", "new other resource", "changed provider cache"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			resource := CertificateResource{ID: "1111111111111111", Name: "selected", Certificate: Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01"}}}
			other := resource
			other.Certificate = *cloneCertificate(resource.Certificate)
			switch scenario {
			case "legacy nested resource":
				resource.LegacyStorage = true
				resource.Certificate.ACME = nil
				other.ID = "2222222222222222"
			case "legacy other issuer":
				resource.LegacyStorage = true
				resource.Certificate.ACME = nil
				other.LegacyStorage = true
				other.Certificate.ACME.Provider = "https://other-ca.example.test/directory"
			case "new other resource":
				other.ID = "2222222222222222"
			case "changed provider cache":
				resource.Certificate.ACME.Provider = "https://new-ca.example.test/directory"
			}
			certificateRelative, keyRelative, _, _ := migrationACMEPaths(other)
			certificatePath := filepath.Join(root, "acme", filepath.FromSlash(certificateRelative))
			if e := os.MkdirAll(filepath.Dir(certificatePath), 0700); e != nil {
				t.Fatal(e)
			}
			for path, data := range map[string][]byte{
				certificatePath: []byte(cert),
				filepath.Join(root, "acme", filepath.FromSlash(keyRelative)): []byte(key),
				strings.TrimSuffix(certificatePath, ".crt") + ".json":        []byte("{}"),
			} {
				if e := os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			status, e := InspectCertificateResource(resource, root, now)
			if e != nil || status.Status != "configured" || status.NotAfter != nil || status.Evidence != "configuration-only" {
				t.Fatal("another resource or issuer's same-SAN certificate was attributed to this resource", status, e)
			}
		})
	}
}

func TestCertificateNewACMEResourceHasOneSharedProviderAndLegacyKeepsDirectory(t *testing.T) {
	s := hyFixture(t)
	first := s.Nodes[0]
	first.Certificate = &Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "cloudflare", APIToken: "private-dns-token"}}}
	second := first
	second.ID = "3333333333333333"
	second.Name = "second"
	second.Port++
	s.Nodes = []Node{first, second}
	var err error
	s, err = CanonicalCertificates(s)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Server(s, "/owned/root")
	if err != nil {
		t.Fatal(err)
	}
	var config M
	_ = json.Unmarshal(raw, &config)
	providers := config["certificate_providers"].([]any)
	if len(providers) != 1 {
		t.Fatal("shared resource created duplicate ACME managers")
	}
	provider := providers[0].(map[string]any)
	tag := "certificate-" + s.Certificates[0].ID
	if provider["tag"] != tag || provider["data_directory"] != "/owned/root/acme/resources/"+s.Certificates[0].ID {
		t.Fatal("resource identity or new storage path changed")
	}
	for _, value := range config["inbounds"].([]any) {
		if value.(map[string]any)["tls"].(map[string]any)["certificate_provider"] != tag {
			t.Fatal("node does not reference shared provider")
		}
	}
	resource := s.Certificates[0]
	resource.LegacyStorage = true
	updated, err := PutCertificateResource(s, resource)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = Server(updated, "/owned/root")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &config)
	provider = config["certificate_providers"].([]any)[0].(map[string]any)
	if provider["data_directory"] != "/owned/root/acme" {
		t.Fatal("explicit legacy settings update moved ACME accounts")
	}
	updated.Nodes[0].Enabled = false
	updated.Nodes[1].Enabled = false
	raw, err = Server(updated, "/owned/root")
	if err != nil {
		t.Fatal(err)
	}
	config = M{}
	_ = json.Unmarshal(raw, &config)
	if _, ok := config["certificate_providers"]; ok {
		t.Fatal("unreferenced/disabled resource triggered certificate manager")
	}
}

func TestCertificateCanonicalOwnsNestedResourceAndCallerInput(t *testing.T) {
	certificate := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "cloudflare", APIToken: "original-private-token", Resolvers: []string{"1.1.1.1:53"}}}}
	original := NewState()
	original.Certificates = []CertificateResource{{ID: "1111111111111111", Name: "owned", Certificate: certificate}}
	cloned, err := CanonicalCertificates(original)
	if err != nil {
		t.Fatal(err)
	}
	original.Certificates[0].Certificate.ACME.DNS01.APIToken = "outside-mutated-token"
	original.Certificates[0].Certificate.ACME.DNS01.Resolvers[0] = "8.8.8.8:53"
	if cloned.Certificates[0].Certificate.ACME.DNS01.APIToken != "original-private-token" || cloned.Certificates[0].Certificate.ACME.DNS01.Resolvers[0] != "1.1.1.1:53" {
		t.Fatal("canonical resource aliases original resource")
	}
	fixture := hyFixture(t)
	fixture.Nodes[0].Certificate = cloneCertificate(cloned.Certificates[0].Certificate)
	next, err := CanonicalCertificates(fixture)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Nodes[0].Certificate.ACME.DNS01.APIToken = "outside-node-mutated-token"
	if next.Certificates[0].Certificate.ACME.DNS01.APIToken != "original-private-token" {
		t.Fatal("new resource aliases caller node projection")
	}
	input := CertificateResource{ID: "2222222222222222", Name: "input", Certificate: *cloneCertificate(cloned.Certificates[0].Certificate)}
	put, err := PutCertificateResource(NewState(), input)
	if err != nil {
		t.Fatal(err)
	}
	input.Certificate.ACME.DNS01.APIToken = "outside-input-mutated-token"
	input.Certificate.ACME.DNS01.Resolvers[0] = "8.8.4.4:53"
	if put.Certificates[0].Certificate.ACME.DNS01.APIToken != "original-private-token" || put.Certificates[0].Certificate.ACME.DNS01.Resolvers[0] != "1.1.1.1:53" {
		t.Fatal("resource management result aliases mutable request")
	}
}

func TestCertificateDNSSecretsAndURLCredentialsAreRejectedOrRedacted(t *testing.T) {
	for _, provider := range []string{"https://ca.example.test/dir?token=secret-ca-query", "https://ca.example.test/dir?"} {
		c := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01", Provider: provider}}
		err := ValidateCertificateResource(CertificateResource{Certificate: c}, time.Now(), true)
		if err == nil || strings.Contains(err.Error(), "secret-ca-query") {
			t.Fatal("CA query credential accepted or echoed", err)
		}
	}
	for _, serverURL := range []string{"https://auth.example.test?token=secret-dns-query", "https://auth.example.test?"} {
		c := Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "dns-01", DNS01: &ACMEDNS01{Provider: "acmedns", Username: "secret-dns-user", Password: "secret-dns-password", Subdomain: "registered-id", ServerURL: serverURL}}}
		err := ValidateCertificateResource(CertificateResource{Certificate: c}, time.Now(), true)
		if err == nil || strings.Contains(err.Error(), "secret-dns-query") {
			t.Fatal("ACME-DNS query credential accepted or echoed", err)
		}
	}
	secrets := []string{"secret-access-id", "secret-access-key", "secret-sts-token", "secret-api-token", "secret-zone-token", "secret-dns-user", "secret-dns-password", "secret-subdomain-id"}
	dns := &ACMEDNS01{Provider: "cloudflare", AccessKeyID: secrets[0], AccessKeySecret: secrets[1], SecurityToken: secrets[2], APIToken: secrets[3], ZoneToken: secrets[4], Username: secrets[5], Password: secrets[6], Subdomain: secrets[7]}
	st := NewState()
	st.Certificates = []CertificateResource{{ID: "1111111111111111", Name: "private", Certificate: Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "dns-01", DNS01: dns}}}}
	encoded, _ := json.Marshal(dns)
	redacted := Redact(string(encoded)+"\nraw "+strings.Join(secrets, " "), st)
	for _, secret := range secrets {
		if strings.Contains(redacted, secret) {
			t.Fatal("certificate DNS secret escaped redaction", secret)
		}
	}
	invalid := NewState()
	invalid.Nodes = []Node{{CertificateID: "missing-resource", Certificate: &st.Certificates[0].Certificate}}
	if _, err := CanonicalCertificates(invalid); err == nil {
		t.Fatal("test candidate must remain invalid")
	}
	redacted = Redact("raw "+strings.Join(secrets, " "), invalid)
	for _, secret := range secrets {
		if strings.Contains(redacted, secret) {
			t.Fatal("invalid candidate DNS credential escaped redaction", secret)
		}
	}
	for _, field := range []string{"access_key_id", "access_key_secret", "security_token", "api_token", "zone_token", "account_key", "mac_key"} {
		raw := `{"` + field + `":"secret-json-value"}`
		if strings.Contains(Redact(raw), "secret-json-value") {
			t.Fatal("new certificate secret field missing generic JSON redaction", field)
		}
	}
}

func TestCertificateRestoreValidationDefersOnlyExternalFileMaterial(t *testing.T) {
	s := hyFixture(t)
	directory := t.TempDir()
	certificatePath, keyPath := filepath.Join(directory, "missing.crt"), filepath.Join(directory, "missing.key")
	s.Nodes[0].Certificate = &Certificate{Mode: "file", ServerName: "localhost", CertificatePath: certificatePath, KeyPath: keyPath}
	var err error
	s, err = CanonicalCertificates(s)
	if err != nil {
		t.Fatal(err)
	}
	before := s.Clone()
	if s.Validate() == nil {
		t.Fatal("normal validation accepted missing external certificate")
	}
	if err = s.ValidateForRestore(); err != nil {
		t.Fatal("restore cannot preview an explicit missing external reference", err)
	}
	if !reflect.DeepEqual(s, before) {
		t.Fatal("restore validation mutated source fields or identity")
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(encoded)
	if err != nil || !reflect.DeepEqual(decoded, s) {
		t.Fatal("strict pure decoding touched unavailable external files", err)
	}
	if _, err = Server(s, directory); err == nil {
		t.Fatal("runtime rendering bypassed actual certificate validation")
	}
	if err = ValidateCertificateDates(s); err == nil {
		t.Fatal("runtime application accepted missing external files")
	}
	if _, err = PutCertificateResource(NewState(), s.Certificates[0]); err == nil {
		t.Fatal("import/update accepted missing external files")
	}
	invalid := s.Clone()
	invalid.Certificates[0].Certificate.KeyPath = "relative.key"
	_ = ResolveCertificates(&invalid)
	if invalid.ValidateForRestore() == nil {
		t.Fatal("restore structural validation accepted relative external path")
	}
	invalid = s.Clone()
	invalid.Nodes[0].Users[0].Password = "short"
	if invalid.ValidateForRestore() == nil {
		t.Fatal("restore weakened proxy authentication validation")
	}
	invalid = hyFixture(t)
	invalid.Nodes[0].Certificate.KeyPEM = "broken-private-key"
	if invalid.ValidateForRestore() == nil {
		t.Fatal("restore weakened embedded PEM key validation")
	}
	invalid = s.Clone()
	invalid.Nodes[0].CertificateID = "9999999999999999"
	if invalid.ValidateForRestore() == nil {
		t.Fatal("restore weakened certificate reference validation")
	}
}

type certificateIdentityBackend struct {
	fakeBackend
	root string
}

func (b *certificateIdentityBackend) RuntimeIdentity(s State) ([]byte, error) {
	return (SystemBackend{Root: b.root}).RuntimeIdentity(s)
}

func TestCertificateRuntimeIdentityTracksOnlyActiveReferences(t *testing.T) {
	for _, mode := range []string{"active", "disabled", "unused"} {
		t.Run(mode, func(t *testing.T) {
			cert, key := makeCert(t)
			directory := t.TempDir()
			certPath, keyPath := filepath.Join(directory, "external.crt"), filepath.Join(directory, "external.key")
			if err := os.WriteFile(certPath, []byte(cert), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
				t.Fatal(err)
			}
			s := hyFixture(t)
			s.Nodes[0].Certificate = &Certificate{Mode: "file", ServerName: "localhost", CertificatePath: certPath, KeyPath: keyPath}
			var err error
			s, err = CanonicalCertificates(s)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "disabled" {
				s.Nodes[0].Enabled = false
			}
			if mode == "unused" {
				s.Nodes = []Node{}
			}
			identities, err := CertificateFileIdentities(s)
			if err != nil {
				t.Fatal(err)
			}
			expected := 0
			if mode == "active" {
				expected = 2
			}
			if len(identities) != expected {
				t.Fatal("runtime identity included wrong certificate files", mode, len(identities))
			}
			backend := &certificateIdentityBackend{root: filepath.Join(directory, "state")}
			store := &Store{Root: backend.root, Backend: backend, GID: -1}
			if err = store.WithLock(func() error { return store.Apply(s) }); err != nil {
				t.Fatal(err)
			}
			activations := backend.activations
			loaded, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			before, err := backend.RuntimeIdentity(loaded)
			if err != nil {
				t.Fatal(err)
			}
			nextCert, nextKey := makeCert(t)
			if err = os.WriteFile(certPath, []byte(nextCert), 0644); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(keyPath, []byte(nextKey), 0600); err != nil {
				t.Fatal(err)
			}
			after, err := backend.RuntimeIdentity(loaded)
			if err != nil {
				t.Fatal(err)
			}
			impact, err := store.Preview(loaded)
			if err != nil {
				t.Fatal(err)
			}
			changed := mode == "active"
			if bytes.Equal(before, after) == changed || impact.NeedsRestart != changed {
				t.Fatal("unrelated external file change misclassified", mode, impact)
			}
			if err = store.WithLock(func() error { return store.Apply(loaded) }); err != nil {
				t.Fatal(err)
			}
			want := activations
			if changed {
				want++
			}
			if backend.activations != want {
				t.Fatal("wrong restart count after external file change", mode, backend.activations, want)
			}
		})
	}
}
