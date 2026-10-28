package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testOptions(target string) Options {
	return Options{Path: "server-outbound", TargetURL: target, Timeout: 3 * time.Second, Samples: 3, MaxBytes: 4096, Initiator: "controlled-test", ToolVersions: map[string]string{"qingprobe": "test"}}
}

func TestHTTPSLightAndPayloadBudget(t *testing.T) {
	var get atomic.Int64
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			get.Add(1)
			time.Sleep(2 * time.Millisecond)
			w.Header().Set("Content-Length", "32768")
			w.WriteHeader(200)
			_, _ = w.Write(make([]byte, 32768))
		} else {
			time.Sleep(2 * time.Millisecond)
			w.WriteHeader(204)
		}
	}))
	defer s.Close()
	o := testOptions(s.URL)
	r, err := Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Status != "completed" {
		t.Fatalf("light: %+v %v", r, err)
	}
	if get.Load() != 0 || len(r.Samples) != 3 || r.Statistics["idle_request"].Values != 3 {
		t.Fatalf("light downloaded or lost samples: %+v", r)
	}
	if r.Connection.Status != "success" || r.TLS.Status != "success" {
		t.Fatalf("direct stages not observed: %+v %+v", r.Connection, r.TLS)
	}
	o.Mode = "download"
	o.Concurrency = 4
	r, err = Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Status != "completed" {
		t.Fatalf("download: %+v %v", r, err)
	}
	if r.Traffic.PayloadBytesReceived != 4096 || get.Load() != 4 {
		t.Fatalf("not one GET per connection, or budget exceeded: %+v gets=%d", r.Traffic, get.Load())
	}
	for _, sample := range r.Samples {
		if sample.Kind == "download" && (sample.PayloadBytes != 1024 || !sample.BudgetLimited || sample.ThroughputMbps == nil) {
			t.Fatalf("incorrect bounded sample: %+v", sample)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxyFailureCannotFallBackAndDoesNotExposeCredentials(t *testing.T) {
	var reached atomic.Int64
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(200) }))
	defer s.Close()
	o := testOptions(s.URL + "/secret-path-token?password=secret-query-token")
	o.Path = "client-proxy"
	if _, err := Run(context.Background(), o, Dependencies{}); err == nil {
		t.Fatal("proxy accepted without an isolated transport")
	}
	r, err := Run(context.Background(), o, Dependencies{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("authentication password=super-secret full-link vless://private")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "failed" || reached.Load() != 0 || r.DNS.Status != "unknown" || r.Connection.Status != "unknown" {
		t.Fatalf("proxy failed open: %+v target=%d", r, reached.Load())
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{"secret-path-token", "secret-query-token", "super-secret", "vless://private"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("report leaked %s", secret)
		}
	}
	if r.Samples[0].ErrorCategory != "proxy_transport_or_auth_unknown" || len(r.Conditions.TargetSHA256) != 64 {
		t.Fatalf("unreliable auth classification or missing target identity: %+v", r)
	}
}

func TestDNSConnectionTLSAndHTTPFailureCategories(t *testing.T) {
	o := testOptions("https://target.invalid/")
	r, err := Run(context.Background(), o, Dependencies{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "controlled missing", Name: "target.invalid"}
	}})
	if err != nil || r.Status != "failed" || r.DNS.Category != "dns_failed" || len(r.Samples) != 0 {
		t.Fatalf("DNS not separated: %+v %v", r, err)
	}
	o.Family = "ipv6"
	r, err = Run(context.Background(), o, Dependencies{Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}})
	if err != nil || r.DNS.Category != "address_family_unavailable" {
		t.Fatalf("family failure hidden: %+v %v", r, err)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	o = testOptions("https://" + address)
	r, err = Run(context.Background(), o, Dependencies{})
	if err != nil || r.Samples[0].ErrorCategory != "connection_failed" {
		t.Fatalf("connection category: %+v %v", r, err)
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer s.Close()
	o = testOptions(s.URL)
	r, err = Run(context.Background(), o, Dependencies{})
	if err != nil || r.Samples[0].ErrorCategory != "tls_failed" {
		t.Fatalf("TLS category: %+v %v", r, err)
	}
	r, err = Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Samples[0].ErrorCategory != "http_status" || *r.Samples[0].HTTPStatus != 503 {
		t.Fatalf("HTTP category: %+v %v", r, err)
	}
}

func TestControlledLatencyAndThroughputDirection(t *testing.T) {
	var active atomic.Int64
	var slow atomic.Bool
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			delay := 2 * time.Millisecond
			if active.Load() > 0 {
				delay = 25 * time.Millisecond
			}
			time.Sleep(delay)
			w.WriteHeader(200)
			return
		}
		active.Add(1)
		defer active.Add(-1)
		w.Header().Set("Content-Length", "8192")
		for i := 0; i < 8; i++ {
			if slow.Load() {
				// Keep the controlled transfer slower than QEMU scheduling noise:
				// this still tests measured direction with the original 2x assertion.
				time.Sleep(200 * time.Millisecond)
			} else {
				time.Sleep(time.Millisecond)
			}
			_, _ = w.Write(make([]byte, 1024))
			w.(http.Flusher).Flush()
		}
	}))
	defer s.Close()
	o := testOptions(s.URL)
	o.Mode = "download"
	o.MaxBytes = 8192
	o.Samples = 4
	fast, e := Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if e != nil || fast.Status != "completed" {
		t.Fatalf("fast %+v %v", fast, e)
	}
	slow.Store(true)
	limited, e := Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if e != nil || limited.Status != "completed" {
		t.Fatalf("slow %+v %v", limited, e)
	}
	f, l := fast.Statistics["download_throughput"], limited.Statistics["download_throughput"]
	if f.Median == nil || l.Median == nil || *l.Median >= *f.Median/2 {
		t.Fatalf("rate direction incorrect: fast=%+v slow=%+v", f, l)
	}
	idle, load := limited.Statistics["idle_request"], limited.Statistics["load_request"]
	if load.Median == nil || *load.Median <= *idle.Median {
		t.Fatalf("loaded request elapsed direction incorrect: %+v %+v", idle, load)
	}
	if len(limited.Limitations) == 0 {
		t.Fatal("small sample confidence warning missing")
	}
}

func TestCancellationAndTimeoutCloseActiveRequests(t *testing.T) {
	var active atomic.Int64
	started := make(chan struct{}, 1)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		active.Add(1)
		defer active.Add(-1)
		select {
		case started <- struct{}{}:
		default:
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	o := testOptions(s.URL)
	o.Mode = "download"
	o.Samples = 1
	o.Concurrency = 2
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Report, 1)
	go func() {
		r, err := Run(ctx, o, Dependencies{Transport: s.Client().Transport})
		if err != nil {
			panic(err)
		}
		done <- r
	}()
	<-started
	cancel()
	r := <-done
	if r.Status != "canceled" {
		t.Fatalf("cancel counted as success: %+v", r)
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatalf("requests left active: %d", active.Load())
	}
	o.Timeout = 50 * time.Millisecond
	r, err := Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Status != "timeout" {
		t.Fatalf("timeout not distinct: %+v %v", r, err)
	}
}

func TestRedirectDoesNotContactAnotherTarget(t *testing.T) {
	var reached atomic.Int64
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(200) }))
	defer other.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer s.Close()
	r, err := Run(context.Background(), testOptions(s.URL), Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Status != "completed" || reached.Load() != 0 || *r.Samples[0].HTTPStatus != 302 {
		t.Fatalf("redirect escaped: %+v %v", r, err)
	}
}

func TestOptionsLimitsAndLocalDiagnostics(t *testing.T) {
	for _, edit := range []func(*Options){func(o *Options) { o.Timeout = 121 * time.Second }, func(o *Options) { o.MaxBytes = MaxDownloadBytes + 1 }, func(o *Options) { o.Concurrency = 5 }, func(o *Options) { o.Samples = 65 }, func(o *Options) { o.TargetURL = "https://user:password@localhost/" }, func(o *Options) { o.UDPAddress = "localhost:0" }, func(o *Options) { o.UDPAddress = "localhost:9000"; o.UDPTimeout = 5 * time.Second; o.Samples = 64 }} {
		o := testOptions("https://localhost/")
		edit(&o)
		if _, e := NormalizeOptions(o); e == nil {
			t.Fatalf("invalid options accepted: %+v", o)
		}
	}
	r, e := Run(context.Background(), Options{}, Dependencies{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("local diagnostics contacted network")
		return nil, nil
	})})
	if e != nil || r.Status != "completed" || len(r.Samples) != 0 {
		t.Fatalf("local %+v %v", r, e)
	}
}

func TestPrivateReportFileCannotOverwrite(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "result.json")
	r, e := Run(context.Background(), Options{}, Dependencies{})
	if e != nil {
		t.Fatal(e)
	}
	if e = WriteReport(p, r); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	r.Status = "failed"
	if e = WriteReport(p, r); e == nil {
		t.Fatal("overwrote existing report")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("existing result changed")
	}
	if !strings.Contains(FormatText(r), "自动测量") {
		t.Fatal("text does not distinguish public-check")
	}
	if !json.Valid(after) {
		t.Fatal(fmt.Sprintf("invalid JSON: %s", after))
	}
}
