package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
)

func osMkdirWriteCertFixture(certPath, keyPath, metaPath, certPEM, keyPEM string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return err
	}
	return os.WriteFile(metaPath, []byte("{}"), 0600)
}

func makeEd25519CertPair(t *testing.T, host string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: host},
		Issuer:       pkix.Name{CommonName: "QingNode Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey}))
	return certPEM, keyPEM
}

func certificateJournalFixture(at time.Time, invocation, message string) string {
	data, _ := json.Marshal(map[string]string{"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_SYSTEMD_INVOCATION_ID": invocation, "MESSAGE": message})
	return string(data) + "\n"
}
func TestCertificateJournalOnlyActualBoundedAttributedEvents(t *testing.T) {
	now := time.Now().UTC()
	invocation := "11111111111111111111111111111111"
	old := "22222222222222222222222222222222"
	s := NewState()
	r := CertificateResource{ID: "1111111111111111", Name: "owned", Certificate: Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01"}}}
	s.Certificates = []CertificateResource{r}
	s.Nodes = []Node{{CertificateID: r.ID, Certificate: cloneCertificate(r.Certificate), Enabled: true}}
	successAt, failureAt, startAt := now.Add(-time.Hour), now.Add(-time.Minute), now.Add(-time.Second)
	lines := certificateJournalFixture(successAt, old, `INFO[0000] certificate-provider/acme[certificate-1111111111111111]: obtain: certificate obtained successfully: {"identifier":"hy2.example.test","issuer":"owned-ca"}`) + certificateJournalFixture(failureAt, invocation, `ERROR[0001] certificate-provider/acme[certificate-1111111111111111]: renew: could not get certificate from issuer: {"identifier":"hy2.example.test","error":"propagation timeout DNS api_token secret-dns-credential"}`) + certificateJournalFixture(startAt, invocation, `INFO[0002] certificate-provider/acme[certificate-1111111111111111]: renew: renewing certificate: {"identifier":"hy2.example.test","remaining":12}`)
	queries := []string{}
	b := SystemBackend{Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		queries = append(queries, name+" "+strings.Join(args, " "))
		if name == "systemctl" {
			return []byte("InvocationID=" + invocation + "\nActiveState=active\nMainPID=123\n"), nil
		}
		return []byte(lines), nil
	}}
	result, e := b.InspectCertificateJournal(s, r, now)
	if e != nil || result.LastSuccess == nil || !result.LastSuccess.Equal(successAt.Truncate(time.Microsecond)) || result.LastFailure == nil || !result.LastFailure.Equal(failureAt.Truncate(time.Microsecond)) || result.Issuing == nil || !*result.Issuing || result.FailureCategory != "dns_validation" {
		t.Fatal("real event attribution failed", result, e)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "secret-dns-credential") || strings.Contains(string(data), "api_token") {
		t.Fatal("raw DNS error leaked")
	}
	if len(queries) != 2 || !strings.Contains(queries[1], "--lines=128") {
		t.Fatal("unexpected service mutation or unbounded query", queries)
	}
	lines += certificateJournalFixture(now, invocation, `INFO[0003] certificate-provider/acme[certificate-1111111111111111]: renew: certificate renewed successfully: {"identifier":"hy2.example.test"}`)
	result, e = b.InspectCertificateJournal(s, r, now)
	if e != nil || result.Issuing == nil || *result.Issuing {
		t.Fatal("success did not terminate observed issuance", result, e)
	}
}

func TestCertificateJournalMissingOrSpoofedEventsStayUnknown(t *testing.T) {
	now := time.Now().UTC()
	invocation := "11111111111111111111111111111111"
	cases := map[string]string{
		"default warn no events":    "",
		"different domain":          certificateJournalFixture(now, invocation, `ERROR[0000] certificate-provider/acme[certificate-1111111111111111]: obtain: could not get certificate from issuer: {"identifier":"other.example.test","error":"secret"}`),
		"fake embedded prefix":      certificateJournalFixture(now, invocation, `ERROR[0000] request says certificate-provider/acme[certificate-1111111111111111]: obtain: certificate obtained successfully: {"identifier":"hy2.example.test"}`),
		"wrong phase":               certificateJournalFixture(now, invocation, `INFO[0000] certificate-provider/acme[certificate-1111111111111111]: renew: certificate obtained successfully: {"identifier":"hy2.example.test"}`),
		"future timestamp":          certificateJournalFixture(now.Add(time.Hour), invocation, `INFO[0000] certificate-provider/acme[certificate-1111111111111111]: obtain: certificate obtained successfully: {"identifier":"hy2.example.test"}`),
		"old timestamp":             certificateJournalFixture(now.Add(-8*24*time.Hour), invocation, `INFO[0000] certificate-provider/acme[certificate-1111111111111111]: obtain: certificate obtained successfully: {"identifier":"hy2.example.test"}`),
		"stale start":               certificateJournalFixture(now.Add(-3*time.Minute), invocation, `INFO[0000] certificate-provider/acme[certificate-1111111111111111]: obtain: obtaining certificate: {"identifier":"hy2.example.test"}`),
		"previous invocation start": certificateJournalFixture(now, "22222222222222222222222222222222", `INFO[0000] certificate-provider/acme[certificate-1111111111111111]: obtain: obtaining certificate: {"identifier":"hy2.example.test"}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			result, e := parseCertificateJournal([]byte(data), "hy2.example.test", invocation, "active", 123, now, CertificateJournalObservation{})
			if e != nil || result.LastSuccess != nil || result.LastFailure != nil || result.Issuing != nil {
				t.Fatal("missing evidence invented event", result, e)
			}
		})
	}
	for _, data := range []string{strings.Repeat("x", (1<<20)+1), strings.Repeat("x", 33<<10), strings.Repeat("{}\n", 129)} {
		if _, e := parseCertificateJournal([]byte(data), "hy2.example.test", invocation, "active", 123, now, CertificateJournalObservation{}); e == nil {
			t.Fatal("unbounded journal accepted")
		}
	}
}

func TestCertificateJournalAmbiguousDomainAndUnavailableReader(t *testing.T) {
	now := time.Now()
	r := CertificateResource{ID: "1111111111111111", Name: "a", Certificate: Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01"}}}
	second := r
	second.ID = "2222222222222222"
	second.Name = "b"
	s := NewState()
	s.Certificates = []CertificateResource{r, second}
	s.Nodes = []Node{{Enabled: true, CertificateID: r.ID, Certificate: cloneCertificate(r.Certificate)}, {Enabled: true, CertificateID: second.ID, Certificate: cloneCertificate(second.Certificate)}}
	b := SystemBackend{Execute: func(time.Duration, string, ...string) ([]byte, error) {
		t.Fatal("ambiguous resources must not query attribution")
		return nil, nil
	}}
	result, e := b.InspectCertificateJournal(s, r, now)
	if e != nil || result.Issuing != nil || !strings.Contains(result.Limitation, "多个资源") {
		t.Fatal("ambiguous domain attributed", result, e)
	}
	s.Nodes = s.Nodes[:1]
	b.Execute = func(time.Duration, string, ...string) ([]byte, error) {
		return nil, errors.New("raw-api-token-private-error")
	}
	result, e = b.InspectCertificateJournal(s, r, now)
	if e == nil || strings.Contains(e.Error(), "private-error") || result.LastSuccess != nil {
		t.Fatal("unavailable journal invented success or leaked error", e)
	}
	for _, raw := range []string{"InvocationID=bad\nActiveState=active\nMainPID=10", "InvocationID=\nActiveState=active\nMainPID=0", "InvocationID=\nInvocationID=\nActiveState=inactive\nMainPID=0", "InvocationID=\nActiveState=garbage\nMainPID=0"} {
		if _, _, _, e := parseCertificateInvocation([]byte(raw)); e == nil {
			t.Fatal("ambiguous invocation accepted", raw)
		}
	}
}

func TestObserveCertificateX509DiskAcrossWarnLogsOpenRCMultiResourceAndKeyMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	invocation := "11111111111111111111111111111111"
	root := t.TempDir()

	r1 := CertificateResource{
		ID:   "1111111111111111",
		Name: "acme-primary",
		Certificate: Certificate{
			Mode:       "acme",
			ServerName: "hy2.example.test",
			Email:      "owner@example.test",
			ACME:       &ACMESettings{Challenge: "http-01"},
		},
	}
	cert1, key1 := certificateTestPair(t, now, false, false)
	certRel1, keyRel1, _, _ := migrationACMEPaths(r1)
	certPath1 := root + "/acme/" + certRel1
	keyPath1 := root + "/acme/" + keyRel1
	metaPath1 := strings.TrimSuffix(certPath1, ".crt") + ".json"
	if err := osMkdirWriteCertFixture(certPath1, keyPath1, metaPath1, cert1, key1); err != nil {
		t.Fatal(err)
	}

	st := NewState()
	st.Certificates = []CertificateResource{r1}
	st.Nodes = []Node{{ID: "aaaa1111bbbb2222", Protocol: "vless-tls", Enabled: true, CertificateID: r1.ID, Certificate: cloneCertificate(r1.Certificate)}}

	// 1. Default warn log level (empty journal, zero INFO lines): X.509 on-disk truth is valid.
	warnBackend := SystemBackend{Execute: func(_ time.Duration, name string, _ ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("InvocationID=" + invocation + "\nActiveState=active\nMainPID=321\n"), nil
		}
		return []byte(""), nil
	}}
	obs, statusErr, journalErr := ObserveCertificate(st, r1, root, warnBackend, true, now)
	if statusErr != nil || journalErr != nil {
		t.Fatalf("unexpected errors: status=%v journal=%v", statusErr, journalErr)
	}
	if !obs.DiskValid || obs.PrimarySource != "x509-disk" || obs.RecentCAEventState != "none_observed" {
		t.Fatalf("unexpected warn-level observation: %+v", obs)
	}
	if obs.Certificate.Subject == "" || obs.Certificate.Issuer == "" || len(obs.Certificate.SANs) == 0 || obs.Certificate.NotBefore == nil || obs.Certificate.NotAfter == nil || obs.Certificate.DaysRemaining == nil || obs.Certificate.KeyMatched == nil || !*obs.Certificate.KeyMatched || obs.Certificate.ChainLength != 1 {
		t.Fatalf("missing X.509 metadata in CertificateStatus: %+v", obs.Certificate)
	}
	if !strings.Contains(obs.Summary, "磁盘证书有效") || !strings.Contains(obs.Summary, "warn") {
		t.Fatalf("unexpected summary for warn-level valid cert: %s", obs.Summary)
	}

	// 2. Valid on-disk certificate + recent CA renewal failure in journalctl: honestly separated.
	failLines := certificateJournalFixture(now.Add(-30*time.Second), invocation, `ERROR[0005] certificate-provider/acme[certificate-1111111111111111]: renew: could not get certificate from issuer: {"identifier":"hy2.example.test","error":"rateLimited"}`)
	renewFailBackend := SystemBackend{Execute: func(_ time.Duration, name string, _ ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("InvocationID=" + invocation + "\nActiveState=active\nMainPID=321\n"), nil
		}
		return []byte(failLines), nil
	}}
	obs, statusErr, journalErr = ObserveCertificate(st, r1, root, renewFailBackend, true, now)
	if statusErr != nil || journalErr != nil || !obs.DiskValid || obs.RecentCAEventState != "failure" {
		t.Fatalf("expected valid disk cert + failure CA event, got: %+v (%v, %v)", obs, statusErr, journalErr)
	}
	if !strings.Contains(obs.Summary, "磁盘证书有效") || !strings.Contains(obs.Summary, "ca_rate_limit") {
		t.Fatalf("summary did not distinguish valid disk cert from recent CA failure: %s", obs.Summary)
	}

	// 3. OpenRC init: journal unavailable, but on-disk X.509 status remains completely valid.
	openrcBackend := SystemBackend{Execute: func(time.Duration, string, ...string) ([]byte, error) {
		t.Fatal("OpenRC should not invoke systemctl/journalctl")
		return nil, nil
	}}
	openrcBackend.ManagerKind = "openrc"
	obs, statusErr, journalErr = ObserveCertificate(st, r1, root, openrcBackend, true, now)
	if statusErr != nil || journalErr != nil || !obs.DiskValid || obs.RecentCAEventState != "unavailable" {
		t.Fatalf("OpenRC X.509 observation failed: %+v", obs)
	}

	// 4. Same-domain multi-resource setup: r1 has issued X.509 on disk, r2 is unissued; each observed accurately.
	r2 := r1
	r2.ID = "2222222222222222"
	r2.Name = "acme-secondary"
	st.Certificates = []CertificateResource{r1, r2}
	st.Nodes = append(st.Nodes, Node{ID: "cccc3333dddd4444", Protocol: "vmess-tls", Enabled: true, CertificateID: r2.ID, Certificate: cloneCertificate(r2.Certificate)})
	obs1, _, _ := ObserveCertificate(st, r1, root, warnBackend, true, now)
	obs2, _, _ := ObserveCertificate(st, r2, root, warnBackend, true, now)
	if !obs1.DiskValid || obs2.DiskValid || obs2.Certificate.Status != "configured" {
		t.Fatalf("multi-resource X.509 separation failed: obs1=%+v obs2=%+v", obs1, obs2)
	}

	// 5. Mismatched private key on disk: KeyMatched == false while leaf Subject/Issuer/NotAfter are still parsed.
	_, wrongKey := certificateTestPair(t, now, false, false)
	if err := osMkdirWriteCertFixture(certPath1, keyPath1, metaPath1, cert1, wrongKey); err != nil {
		t.Fatal(err)
	}
	mismatchStatus, err := InspectCertificateResource(r1, root, now)
	if err != nil || mismatchStatus.Status != "failed" || mismatchStatus.KeyMatched == nil || *mismatchStatus.KeyMatched || mismatchStatus.Subject == "" || mismatchStatus.NotAfter == nil {
		t.Fatalf("mismatched key inspection did not preserve X.509 metadata and KeyMatched=false: %+v err=%v", mismatchStatus, err)
	}
}

func TestProtocolWordingFixesTask4(t *testing.T) {
	edCert, edKey := makeEd25519CertPair(t, "edge.example.test")
	for _, tc := range []struct {
		proto  string
		format string
		want   string
	}{
		{"trojan", "uri", "Trojan"},
		{"vless-tls", "uri", "VLESS+TLS"},
		{"vmess-tls", "uri", "VMess+TLS"},
		{"vmess-tls", "vmess-v2rayn", "VMess+TLS"},
	} {
		n := Node{
			ID:          "1111222233334444",
			Protocol:    tc.proto,
			Certificate: &Certificate{Mode: "pem", ServerName: "edge.example.test", CertPEM: edCert, KeyPEM: edKey},
		}
		warnings := ProtocolExportWarnings(n, tc.format)
		if len(warnings) != 1 || !strings.Contains(warnings[0], tc.want) {
			t.Fatalf("ProtocolExportWarnings(%s, %s) = %v, want substring %q", tc.proto, tc.format, warnings, tc.want)
		}
		if tc.proto != "trojan" && strings.Contains(warnings[0], "Trojan") {
			t.Fatalf("ProtocolExportWarnings(%s, %s) leaked hardcoded Trojan: %v", tc.proto, tc.format, warnings)
		}
		broken := Node{
			ID:          "1111222233334444",
			Protocol:    tc.proto,
			Certificate: &Certificate{Mode: "pem", ServerName: "edge.example.test", CertPEM: "invalid", KeyPEM: "invalid"},
		}
		brokenWarnings := ProtocolExportWarnings(broken, tc.format)
		if len(brokenWarnings) != 1 || !strings.Contains(brokenWarnings[0], tc.want) || (tc.proto != "trojan" && strings.Contains(brokenWarnings[0], "Trojan")) {
			t.Fatalf("broken cert warning(%s, %s) = %v", tc.proto, tc.format, brokenWarnings)
		}
	}

	acmeErr := validateACME(ACMESettings{Challenge: "http-01", KeyType: "ed25519"})
	if acmeErr == nil || strings.Contains(acmeErr.Error(), "HY2") || !strings.Contains(acmeErr.Error(), "ACME证书算法仅支持") {
		t.Fatalf("unexpected validateACME KeyType error: %v", acmeErr)
	}

	s := hyFixture(t)
	_, exportErr := Export(s.Nodes[0], s.Nodes[0].Users[0], "nonexistent-format")
	if exportErr == nil || !strings.Contains(exportErr.Error(), "vmess-v2rayn") {
		t.Fatalf("Export unknown format error missing vmess-v2rayn: %v", exportErr)
	}
}

