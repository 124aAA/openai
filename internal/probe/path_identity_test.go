package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeclaredServerPathProfileV2AndLegacyBytes(t *testing.T) {
	p := testProfile(t)
	legacy := struct {
		Version      int             `json:"version"`
		NodeID       string          `json:"node_id"`
		CoreVersion  string          `json:"server_core_version"`
		ConfigSHA256 string          `json:"config_sha256"`
		Outbound     json.RawMessage `json:"outbound"`
	}{p.Version, p.NodeID, p.CoreVersion, p.ConfigSHA256, p.Outbound}
	want, _ := json.Marshal(legacy)
	got, _ := json.Marshal(p)
	if p.Version != 1 || !bytes.Equal(got, want) {
		t.Fatal("default private profile v1 bytes changed")
	}
	digest := strings.Repeat("a", 64)
	bound, err := WithServerPathDigest(p, digest)
	if err != nil || bound.Version != 2 || bound.ServerPathSHA256 != digest || bound.ConfigSHA256 != p.ConfigSHA256 || !bytes.Equal(bound.Outbound, p.Outbound) || p.Version != 1 {
		t.Fatal("path binding changed entry credentials or the caller's v1 profile", err)
	}
	path := filepath.Join(t.TempDir(), "profile-v2.json")
	if err = WriteProfile(path, bound); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadProfile(path)
	if err != nil || loaded.Version != 2 || loaded.ServerPathSHA256 != digest {
		t.Fatal("v2 private profile did not round trip", err)
	}
	raw, _ := json.Marshal(bound)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&legacy) == nil {
		t.Fatal("the legacy typed reader silently accepted the new field")
	}
	for _, bad := range []string{"", "remote-password", strings.Repeat("A", 64), strings.Repeat("f", 63)} {
		if _, err = WithServerPathDigest(p, bad); err == nil {
			t.Fatal("accepted malformed declared path digest")
		}
	}
}

func TestDeclaredServerPathProfileRejectsVersionDisguise(t *testing.T) {
	p := testProfile(t)
	raw, _ := json.Marshal(p)
	for _, field := range []string{`"server_path_sha256":null`, `"server_path_sha256":""`, `"Server_Path_SHA256":null`, `"server_path_sha256":"` + strings.Repeat("a", 64) + `"`} {
		path := filepath.Join(t.TempDir(), "invalid-v1.json")
		bad := append(append([]byte{}, raw[:len(raw)-1]...), []byte(","+field+"}")...)
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadProfile(path); err == nil {
			t.Fatal("legacy profile accepted a new path field", field)
		}
	}
	for _, version := range []int{0, 2, 3} {
		bad := p
		bad.Version = version
		if bad.Validate() == nil {
			t.Fatal("unsupported or incomplete profile version accepted", version)
		}
	}
}

func TestDeclaredPathDoesNotEnterCoreConfiguration(t *testing.T) {
	p := testProfile(t)
	bound, err := WithServerPathDigest(p, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	before, err := sandboxConfig(p, 10001, "test-user", "test-owned-listener-secret")
	if err != nil {
		t.Fatal(err)
	}
	after, err := sandboxConfig(bound, 10001, "test-user", "test-owned-listener-secret")
	if err != nil || !bytes.Equal(before, after) || bytes.Contains(after, []byte("server_path_sha256")) {
		t.Fatal("declared identity changed the selected client route", err)
	}
}

func TestOfficialCorePortableV2DeclaredPathIdentity(t *testing.T) {
	bin, digest, version := portableOfficialCore(t)
	p, _ := portableSSFixture(t, bin, version)
	p, err := WithServerPathDigest(p, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	s := portableSandbox(t, context.Background(), p, bin, digest)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	transport := s.Transport()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	o := testOptions(target.URL)
	o.Path, o.NodeID, o.CoreVersion, o.ConfigSHA256, o.ServerPathSHA256 = "client-proxy", p.NodeID, p.CoreVersion, p.ConfigSHA256, p.ServerPathSHA256
	r, err := Run(context.Background(), o, Dependencies{Transport: transport})
	if err != nil || r.Status != "completed" || r.Version != 2 || r.Conditions.ServerPathSHA256 != p.ServerPathSHA256 || ValidateReport(r) != nil {
		t.Fatal("official portable core could not use a v2 entry profile", err)
	}
	// The fixture path is intentionally ordinary SS. Its opaque declaration is
	// metadata, not evidence that any particular remote topology was installed.
	portableAssertClean(t, s)
}

func declaredPathReport(t *testing.T) Report {
	t.Helper()
	o := testOptions("https://controlled.example.test/private-token?secret=query")
	o.Path, o.NodeID, o.ConfigSHA256, o.ServerPathSHA256 = "client-proxy", "entry-node", strings.Repeat("b", 64), strings.Repeat("a", 64)
	r, err := Run(context.Background(), o, Dependencies{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		// The Windows clock can otherwise observe an in-memory response as zero
		// elapsed time, correctly leaving no measured comparison values.
		time.Sleep(time.Millisecond)
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})})
	if err != nil || r.Status != "completed" || r.Version != 2 || r.Conditions.ServerPathSHA256 != o.ServerPathSHA256 {
		t.Fatal("engine did not retain the declared path in an explicit v2 report", err)
	}
	if err = ValidateReport(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDeclaredServerPathReportRoundtripAndComparison(t *testing.T) {
	a := declaredPathReport(t)
	path := filepath.Join(t.TempDir(), "report-v2.json")
	if err := WriteReport(path, a); err != nil {
		t.Fatal(err)
	}
	b, err := ReadReport(path)
	if c := Compare(a, b); err != nil || b.Version != 2 || b.Conditions.ServerPathSHA256 != a.Conditions.ServerPathSHA256 || !c.Comparable {
		t.Fatal("matching declared paths were not comparable after report round trip", err, c)
	}
	b.Conditions.ServerPathSHA256 = strings.Repeat("c", 64)
	if c := Compare(a, b); c.Comparable || len(c.Reasons) == 0 {
		t.Fatal("different internal paths were treated as the same entry test")
	}
	for _, invalid := range []Report{func() Report { r := a; r.Version = 1; return r }(), func() Report { r := a; r.Version = 2; r.Conditions.ServerPathSHA256 = ""; return r }(), func() Report { r := a; r.Version = 3; return r }()} {
		if ValidateReport(invalid) == nil {
			t.Fatal("path field and explicit report version did not agree")
		}
	}
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "private-token") || strings.Contains(string(raw), "secret=query") || !strings.Contains(FormatText(a), "只声明导出Profile时") {
		t.Fatal("report leaked its target or omitted the declared-path limitation")
	}
	legacy := a
	legacy.Version, legacy.Conditions.ServerPathSHA256 = 1, ""
	if err = ValidateReport(legacy); err != nil {
		t.Fatal("legacy report was no longer accepted", err)
	}
	if Compare(a, legacy).Comparable {
		t.Fatal("unbound legacy report was compared with a declared internal path")
	}
}

func TestDeclaredServerPathReportRejectsNewFieldInV1(t *testing.T) {
	r := declaredPathReport(t)
	r.Version, r.Conditions.ServerPathSHA256 = 1, ""
	raw, _ := json.Marshal(r)
	for _, field := range []string{`"server_path_sha256":null`, `"server_path_sha256":""`, `"Server_Path_SHA256":null`} {
		bad := bytes.Replace(raw, []byte(`"conditions":{`), []byte(`"conditions":{`+field+","), 1)
		path := filepath.Join(t.TempDir(), "v1-disguised.json")
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadReport(path); err == nil {
			t.Fatal("legacy report accepted a disguised v2 identity")
		}
	}
}
