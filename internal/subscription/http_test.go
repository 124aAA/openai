package subscription

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSHTTPDeviceIsolationAndRevocation(t *testing.T) {
	s, raw := fixture()
	now := s.GeneratedAt
	var mu sync.RWMutex
	var reads atomic.Int32
	h, err := NewHandler(func() (Snapshot, error) {
		reads.Add(1)
		mu.RLock()
		defer mu.RUnlock()
		b, e := Encode(s)
		if e != nil {
			return Snapshot{}, e
		}
		return Decode(b)
	}, HandlerOptions{Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(h)
	defer ts.Close()
	client := ts.Client()
	request := func(method, path, auth string) (int, string, http.Header) {
		t.Helper()
		r, e := http.NewRequest(method, ts.URL+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal(e)
		}
		return resp.StatusCode, string(b), resp.Header
	}
	status, body, headers := request("GET", "/s/"+raw+"/uri", "")
	if status != 200 || body != "ss://private-device-a\n" {
		t.Fatal(status, body)
	}
	if headers.Get("Cache-Control") != "private, no-store, max-age=0" || headers.Get("Vary") != "Authorization" || headers.Get("Subscription-Userinfo") != "" || headers.Get("ETag") != "" {
		t.Fatal("cache or invented accounting headers", headers)
	}
	if status, body, _ = request("HEAD", "/s/uri", "Bearer "+raw); status != 200 || body != "" {
		t.Fatal("HEAD", status, body)
	}
	for _, path := range []string{"/s/" + strings.Repeat("0", 64) + "/uri", "/s/" + raw + "/provider", "/s/" + raw + "/uri?token=" + raw, "/s/" + raw + "/uri?", "/s/" + raw + "/uri/../uri", "/s/" + raw + "/uri%2f"} {
		status, body, _ = request("GET", path, "")
		if status != 404 || strings.Contains(body, raw) || strings.Contains(body, "private-device") {
			t.Fatal("unauthorized or malformed request leaked", status, body)
		}
	}
	if status, _, _ = request("GET", "/s/uri", ""); status != 404 {
		t.Fatal("missing auth", status)
	}
	if status, _, _ = request("POST", "/s/"+raw+"/uri", ""); status != 405 {
		t.Fatal("write method", status)
	}
	mu.Lock()
	s.Records[0].Revoked = true
	mu.Unlock()
	if status, _, _ = request("GET", "/s/"+raw+"/uri", ""); status != 404 {
		t.Fatal("revocation cached", status)
	}
	mu.Lock()
	s.Records[0].Revoked = false
	s.Records[0].ExpiresAt = now
	mu.Unlock()
	if status, _, _ = request("GET", "/s/"+raw+"/uri", ""); status != 404 {
		t.Fatal("expiry boundary", status)
	}
	mu.Lock()
	s.Records[0].ExpiresAt = now.Add(time.Hour)
	s.Records[0].IssuedAt = now.Add(time.Second)
	mu.Unlock()
	if status, _, _ = request("GET", "/s/"+raw+"/uri", ""); status != 404 {
		t.Fatal("future issued token", status)
	}
	if reads.Load() < 7 {
		t.Fatal("requests did not reload registry", reads.Load())
	}
}

func TestConcurrencyLimit(t *testing.T) {
	s, raw := fixture()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	h, err := NewHandler(func() (Snapshot, error) { once.Do(func() { entered <- struct{}{} }); <-release; return s, nil }, HandlerOptions{Clock: func() time.Time { return s.GeneratedAt }, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(first, httptest.NewRequest("GET", "/s/"+raw+"/uri", nil)); close(done) }()
	<-entered
	busy := httptest.NewRecorder()
	h.ServeHTTP(busy, httptest.NewRequest("GET", "/s/"+raw+"/uri", nil))
	if busy.Code != 503 {
		t.Fatal("concurrency unbounded", busy.Code)
	}
	close(release)
	<-done
	if first.Code != 200 {
		t.Fatal(first.Code)
	}
	for _, limit := range []int{-1, 17, 65} {
		if _, err := NewHandler(func() (Snapshot, error) { return s, nil }, HandlerOptions{MaxConcurrent: limit}); err == nil {
			t.Fatal("invalid concurrency accepted")
		}
	}
}
