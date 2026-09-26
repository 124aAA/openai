package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func TestDashboardUpdateSelection(t *testing.T) {
	manager := func(v string) node.Release {
		return node.Release{Tag: "v" + v, Prerelease: true, Assets: []node.ReleaseAsset{
			{Name: "qingnode-" + v + "-linux-" + runtime.GOARCH + ".tar.gz"}, {Name: "SHA256SUMS"},
		}}
	}
	releases := []node.Release{manager("0.2.9"), manager("0.2.10"), manager("0.2.99"), manager("0.2.100")}
	releases[2].Assets = releases[2].Assets[:1]
	releases[3].Assets[0].Name = "qingnode-0.2.100-linux-unsupported.tar.gz"
	releases = append(releases, node.Release{Tag: "v1.15.0"}, node.Release{Tag: "v1.14.3"}, node.Release{Tag: "v1.14.12"},
		node.Release{Tag: "v1.14.13", Prerelease: true}, node.Release{Tag: "v9.0.0", Draft: true}, node.Release{Tag: "v9.0.0-rc.1"}, node.Release{Tag: "v99999999999999999999.0.0"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("per_page") != "100" || !strings.HasPrefix(r.URL.Path, "/repos/") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		_ = json.NewEncoder(w).Encode(releases)
	}))
	defer srv.Close()
	for _, tc := range []struct {
		manager            bool
		latest, compatible string
	}{{true, "0.2.10", ""}, {false, "1.15.0", "1.14.12"}} {
		r, e := fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", tc.manager)
		if e != nil || r.Latest != tc.latest || r.Compatible != tc.compatible {
			t.Fatalf("manager=%t: %+v, %v", tc.manager, r, e)
		}
	}
}

func TestDashboardUpdateFailuresAndLimits(t *testing.T) {
	for _, body := range []string{"[]", "null", "{}", "[]{}", strings.Repeat(" ", (2<<20)+1)} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		_, e := fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", false)
		srv.Close()
		if e == nil {
			t.Fatal("accepted empty, malformed or oversized response")
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	if _, e := fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", false); e == nil {
		t.Fatal("accepted HTTP 403")
	}
	client := dashboardHTTPClient()
	for _, address := range []string{"http://api.github.com/x", "https://example.com/x"} {
		req, _ := http.NewRequest(http.MethodGet, address, nil)
		if client.CheckRedirect(req, nil) == nil {
			t.Fatalf("accepted redirect %s", address)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/x", nil)
	if client.Timeout != 9*time.Second || client.CheckRedirect(req, []*http.Request{req, req, req}) == nil {
		t.Fatal("missing timeout/redirect bound")
	}
}

func TestDashboardUpdateHistoryPreservesSuccess(t *testing.T) {
	before, now := time.Unix(100, 0), time.Unix(200, 0)
	old := updateRecord{At: before, CheckedAt: before, Installed: "1.14.0", Latest: "1.15.0", Compatible: "1.14.2"}
	got := mergeDashboardUpdate(old, updateRecord{}, "1.14.1", now, true)
	if !got.Failed || got.CheckedAt != now || got.At != old.At || got.Installed != old.Installed || got.Latest != old.Latest || got.Compatible != old.Compatible {
		t.Fatalf("failed request destroyed prior success: %+v", got)
	}
	got = mergeDashboardUpdate(got, updateRecord{Latest: "1.16.0", Compatible: "1.14.3"}, "1.14.1", now, false)
	if got.Failed || got.At != now || got.CheckedAt != now || got.Installed != "1.14.1" || got.Latest != "1.16.0" || got.Compatible != "1.14.3" {
		t.Fatalf("success did not replace cache: %+v", got)
	}
	if e := (&app{offline: true}).checkUpdates(); e == nil {
		t.Fatal("offline query allowed")
	}
}
