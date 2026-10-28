package probecli

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/probe"
)

func TestDeclaredPathSurvivesProxyCAOverride(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := probe.NewProfile("node", "1.14.0", []byte(`{"type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":443,"password":"entry-password","tls":{"enabled":true,"server_name":"controlled.example.test"}}`))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := probe.WithServerPathDigest(p, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := withProxyCA(bound, path)
	if err != nil || updated.Version != 2 || updated.ServerPathSHA256 != bound.ServerPathSHA256 || updated.ConfigSHA256 == bound.ConfigSHA256 {
		t.Fatal("proxy CA override lost the declared internal path or old outbound identity", err)
	}
	legacy, err := withProxyCA(p, path)
	if err != nil || legacy.Version != 1 || legacy.ServerPathSHA256 != "" {
		t.Fatal("legacy proxy CA override changed the profile format", err)
	}
}

func TestSetupFailureRetainsV2DeclaredPath(t *testing.T) {
	o, err := probe.NormalizeOptions(probe.Options{Path: "client-proxy", TargetURL: "https://controlled.example.test/health", NodeID: "entry", ConfigSHA256: strings.Repeat("a", 64), ServerPathSHA256: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	r := setupFailure(o, time.Now().UTC(), context.Background())
	if r.Version != 2 || r.Conditions.ServerPathSHA256 != o.ServerPathSHA256 || probe.ValidateReport(r) != nil || !strings.Contains(probe.FormatText(r), "只声明导出Profile时") {
		t.Fatal("setup failure lost the path identity or claimed measurement success")
	}
	o.ServerPathSHA256 = ""
	if setupFailure(o, time.Now().UTC(), context.Background()).Version != 1 {
		t.Fatal("legacy setup failure changed report version")
	}
}
