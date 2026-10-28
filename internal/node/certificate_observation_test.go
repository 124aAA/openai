package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

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
