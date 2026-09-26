package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
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

func TestDashboardUpdateLargeCompressedCoreResponse(t *testing.T) {
	body := `[{"tag_name":"v1.15.0","body":"` + strings.Repeat("x", 3<<20) + `"},{"tag_name":"v1.14.12"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(w)
		_, _ = io.WriteString(compressed, body)
		_ = compressed.Close()
	}))
	defer srv.Close()
	r, e := fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", false)
	if e != nil || r.Latest != "1.15.0" || r.Compatible != "1.14.12" {
		t.Fatalf("large core response: %+v, %v", r, e)
	}
	if _, e = fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", true); e == nil || !strings.Contains(e.Error(), "超过 2 MiB") {
		t.Fatalf("manager accepted oversized decompressed response: %v", e)
	}
}

func TestDashboardUpdateResponseSizeLimits(t *testing.T) {
	prefix := `[{"tag_name":"v1.14.12","assets":[{"name":"qingnode-1.14.12-linux-` + runtime.GOARCH + `.tar.gz"},{"name":"SHA256SUMS"}]}]`
	padding := strings.Repeat(" ", 32<<10)
	for _, tc := range []struct {
		name, want string
		manager    bool
		limit      int
	}{{"manager", "超过 2 MiB", true, 2 << 20}, {"core", "超过 64 MiB", false, 64 << 20}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, e := io.WriteString(w, prefix); e != nil {
					return
				}
				// Valid JSON with trailing whitespace, streamed without Content-Length.
				for remaining := tc.limit + 1 - len(prefix); remaining > 0; {
					n := min(remaining, len(padding))
					if _, e := io.WriteString(w, padding[:n]); e != nil {
						return
					}
					remaining -= n
				}
			}))
			defer srv.Close()
			if _, e := fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", tc.manager); e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("oversized response was not rejected at the expected bound: %v", e)
			}
		})
	}
}

func TestDashboardUpdateFailuresAndLimits(t *testing.T) {
	for _, body := range []string{"[]", "null", "{}", "[]{}"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		_, e := fetchDashboardUpdates(srv.Client(), srv.URL, "test/repo", false)
		srv.Close()
		if e == nil {
			t.Fatal("accepted empty or malformed response")
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
