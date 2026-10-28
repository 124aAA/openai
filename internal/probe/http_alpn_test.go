package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPProbeDoesNotNegotiateDisabledHTTP2FromClonedTransport(t *testing.T) {
	var hits, wrongProtocol atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.ProtoMajor != 1 {
			wrongProtocol.Add(1)
		}
		w.Header().Set("Content-Length", "1024")
		if r.Method != http.MethodHead {
			_, _ = w.Write(make([]byte, 1024))
		}
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	transport := target.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	defer transport.CloseIdleConnections()
	for _, path := range []string{"client-proxy", "server-outbound"} {
		r, e := Run(context.Background(), Options{Path: path, Mode: "download", TargetURL: target.URL, Family: "ipv4", Timeout: 3 * time.Second, MaxBytes: 4096, Samples: 2, Concurrency: 1, Initiator: "local-alpn-fixture"}, Dependencies{Transport: transport})
		if e != nil {
			t.Fatal(e)
		}
		if r.Status != "completed" || r.Statistics["idle_request"].Successes != 2 || r.Traffic.PayloadBytesReceived != 1024 {
			t.Fatalf("HTTP/2 capable target failed bounded HTTP/1.1 probe: %+v", r.Errors)
		}
		if e = ValidateReport(r); e != nil {
			t.Fatal(e)
		}
	}
	if hits.Load() < 6 || wrongProtocol.Load() != 0 {
		t.Fatal("expected real TLS requests using explicitly selected HTTP/1.1")
	}
	// The caller's reusable transport remains untouched.
	if len(transport.TLSClientConfig.NextProtos) != 2 || transport.TLSClientConfig.NextProtos[0] != "h2" {
		t.Fatal("probe modified supplied transport ALPN")
	}
}
