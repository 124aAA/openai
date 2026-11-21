//go:build linux

package subscription

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestUnifiedEndpointNegotiationMetadataHeadersAndSnapshotCache(t *testing.T) {
	dir := t.TempDir() + "/pub"
	if err := Initialize(dir, -1); err != nil {
		t.Fatal(err)
	}
	raw, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	tokenExp := now.Add(30 * 24 * time.Hour)
	credExp := now.Add(7 * 24 * time.Hour).Unix()

	snap := Snapshot{
		Version:     Version,
		GeneratedAt: now,
		Records: []Record{{
			DeviceID:            "1111111111111111",
			DeviceName:          "主力手机 Phone",
			DefaultFormat:       "sing-box",
			EffectiveExpireUnix: credExp,
			TokenID:             "2222222222222222",
			TokenSHA256:         hash,
			IssuedAt:            now,
			ExpiresAt:           tokenExp,
			Revoked:             false,
			Outputs: map[string]Payload{
				"sing-box": {ContentType: "application/json; charset=utf-8", Content: []byte("{\"outbounds\":[]}\n")},
				"mihomo":   {ContentType: "application/yaml; charset=utf-8", Content: []byte("proxies: []\n")},
				"base64":   {ContentType: "text/plain; charset=utf-8", Content: []byte("dHVpYzovL2RlbW8=\n")},
				"uri":      {ContentType: "text/plain; charset=utf-8", Content: []byte("tuic://demo\n")},
			},
		}},
	}
	if err := Publish(dir, snap, -1); err != nil {
		t.Fatal(err)
	}

	cache := NewSnapshotCache(dir)
	h, err := NewIndexedHandler(cache.Read, HandlerOptions{Clock: func() time.Time { return now }, MaxConcurrent: 4})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(h)
	defer ts.Close()
	client := ts.Client()

	doReq := func(path, ua, auth string) (int, string, http.Header) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(b), resp.Header
	}

	cases := []struct {
		name     string
		path     string
		ua       string
		auth     string
		wantBody string
		wantExt  string
	}{
		{"SFA UA", "/s/" + raw, "SFA/1.14.0 (Android)", "", "{\"outbounds\":[]}\n", "json"},
		{"SFI UA", "/s/" + raw, "SFI/1.14.3", "", "{\"outbounds\":[]}\n", "json"},
		{"SFM UA", "/s/" + raw, "SFM/1.14.0", "", "{\"outbounds\":[]}\n", "json"},
		{"sing-box UA", "/s/" + raw, "sing-box 1.14.0", "", "{\"outbounds\":[]}\n", "json"},
		{"Mihomo UA", "/s/" + raw, "mihomo/1.19.30", "", "proxies: []\n", "yaml"},
		{"Clash.Meta UA", "/s/" + raw, "Clash.Meta/v1.19.0", "", "proxies: []\n", "yaml"},
		{"FlClash UA", "/s/" + raw, "FlClash/0.8.70", "", "proxies: []\n", "yaml"},
		{"Clash Verge UA", "/s/" + raw, "Clash Verge/2.0.2", "", "proxies: []\n", "yaml"},
		{"Stash UA", "/s/" + raw, "Stash/2.6.4", "", "proxies: []\n", "yaml"},
		{"v2rayN UA", "/s/" + raw, "v2rayN/6.45", "", "dHVpYzovL2RlbW8=\n", "txt"},
		{"v2rayNG UA", "/s/" + raw, "v2rayNG/1.8.38", "", "dHVpYzovL2RlbW8=\n", "txt"},
		{"Shadowrocket UA", "/s/" + raw, "Shadowrocket/2070", "", "dHVpYzovL2RlbW8=\n", "txt"},
		{"NekoBox UA", "/s/" + raw, "NekoBox/Android", "", "dHVpYzovL2RlbW8=\n", "txt"},
		{"Streisand UA", "/s/" + raw, "Streisand/1.60", "", "dHVpYzovL2RlbW8=\n", "txt"},
		{"Unknown UA uses DefaultFormat", "/s/" + raw, "curl/8.5.0", "", "{\"outbounds\":[]}\n", "json"},
		{"Query format overrides UA", "/s/" + raw + "?format=mihomo&flag=v2rayn", "SFA/1.14.0", "", "proxies: []\n", "yaml"},
		{"Flag hint selects mihomo", "/s/" + raw + "?flag=clash", "curl/8.5.0", "", "proxies: []\n", "yaml"},
		{"Bearer unified /s", "/s", "Stash/2.6.4", "Bearer " + raw, "proxies: []\n", "yaml"},
		{"Explicit /s/<TOKEN>/<FORMAT> wins over UA", "/s/" + raw + "/uri", "Clash.Meta/1.19.30", "", "tuic://demo\n", "txt"},
	}

	wantTitle := "base64:" + base64.StdEncoding.EncodeToString([]byte("主力手机 Phone"))
	wantUserInfo := "expire=" + strconv.FormatInt(credExp, 10)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, hdr := doReq(tc.path, tc.ua, tc.auth)
			if code != 200 || body != tc.wantBody {
				t.Fatalf("got %d %q, want 200 %q", code, body, tc.wantBody)
			}
			if hdr.Get("Profile-Title") != wantTitle {
				t.Fatalf("Profile-Title=%q, want %q", hdr.Get("Profile-Title"), wantTitle)
			}
			if hdr.Get("Profile-Update-Interval") != "24" {
				t.Fatalf("Profile-Update-Interval=%q", hdr.Get("Profile-Update-Interval"))
			}
			wantDisp := `attachment; filename="qingnode-1111111111111111.` + tc.wantExt + `"`
			if hdr.Get("Content-Disposition") != wantDisp {
				t.Fatalf("Content-Disposition=%q, want %q", hdr.Get("Content-Disposition"), wantDisp)
			}
			if hdr.Get("Subscription-Userinfo") != wantUserInfo {
				t.Fatalf("Subscription-Userinfo=%q, want %q", hdr.Get("Subscription-Userinfo"), wantUserInfo)
			}
		})
	}

	// Verify SnapshotCache decoded snapshot.json ONLY ONCE across all 19 HTTP requests!
	if got := cache.Decodes(); got != 1 {
		t.Fatalf("expected 1 snapshot JSON decode on unchanged (dev,ino,mtime,size), got %d", got)
	}

	// Reject disallowed query params, bare trailing '?', duplicate keys, or unknown formats.
	for _, bad := range []string{
		"/s/" + raw + "?",
		"/s/" + raw + "?unknown=1",
		"/s/" + raw + "?format=invalid",
		"/s/" + raw + "?format=mihomo&format=uri",
		"/s/" + raw + "?flag=bad/value",
		"/s/" + raw + "/mihomo?flag=clash",
	} {
		code, _, _ := doReq(bad, "curl/8.5.0", "")
		if code != 404 {
			t.Fatalf("expected 404 for %s, got %d", bad, code)
		}
	}

	// Atomic Publish revocation changes (dev, ino) and invalidates cache on the VERY NEXT request!
	snap.Records[0].Revoked = true
	snap.Records[0].DeviceName = ""
	snap.Records[0].DefaultFormat = ""
	snap.Records[0].EffectiveExpireUnix = 0
	snap.Records[0].Outputs = map[string]Payload{}
	snap.GeneratedAt = now.Add(time.Minute)
	if err := Publish(dir, snap, -1); err != nil {
		t.Fatal(err)
	}
	code, _, _ := doReq("/s/"+raw, "SFA/1.14.0", "")
	if code != 404 {
		t.Fatalf("revoked snapshot served stale cache: %d", code)
	}
	if got := cache.Decodes(); got != 2 {
		t.Fatalf("expected cache miss & re-decode after atomic Publish, got decodes=%d", got)
	}
}
