package probe

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportRejectsTamperedEvidence(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(2 * time.Millisecond); w.WriteHeader(200) }))
	defer s.Close()
	r, err := Run(context.Background(), testOptions(s.URL), Dependencies{Transport: s.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateReport(r); err != nil {
		t.Fatalf("real result rejected: %v", err)
	}
	d := t.TempDir()
	path := filepath.Join(d, "actual.json")
	if err = WriteReport(path, r); err != nil {
		t.Fatal(err)
	}
	saved, err := ReadReport(path)
	if err != nil || !Compare(r, saved).Comparable {
		t.Fatalf("valid report round-trip failed: %v %+v", err, Compare(r, saved))
	}
	clone := func() Report {
		b, _ := json.Marshal(r)
		var v Report
		if e := json.Unmarshal(b, &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, tamper := range []func(*Report){func(v *Report) { v.Version = 2 }, func(v *Report) { v.Samples[0].Status = "failed"; v.Samples[0].ErrorCategory = "timeout" }, func(v *Report) {
		stat := v.Statistics["idle_request"]
		fake := 0.01
		stat.Median = &fake
		v.Statistics["idle_request"] = stat
	}, func(v *Report) { v.Traffic.PayloadBytesReceived = 100 }, func(v *Report) { v.Samples[0].HTTPStatus = nil }, func(v *Report) { v.Conditions.Limits.Samples = 64 }, func(v *Report) { v.Conditions.Target += "/private-token" }, func(v *Report) { v.FinishedAt = v.StartedAt.Add(-time.Second) }} {
		v := clone()
		tamper(&v)
		if ValidateReport(v) == nil {
			t.Fatalf("tampered evidence accepted: %+v", v)
		}
		if Compare(r, v).Comparable {
			t.Fatal("tampered report compared")
		}
	}
	b, _ := json.Marshal(r)
	for _, invalid := range [][]byte{[]byte(`{"version":1,"version":1}`), []byte(`{"version":2}`), append([]byte(`{"unrecognized":true,`), b[1:]...), append(b, []byte(`{}`)...), []byte(strings.Repeat(" ", (1<<20)+1))} {
		p := filepath.Join(d, "tampered.json")
		if e := os.WriteFile(p, invalid, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := ReadReport(p); e == nil {
			t.Fatal("invalid/unknown/oversized report accepted")
		}
	}
}

func TestCombinedHTTPUDPBudgetAndBlockedUDPRemainSeparate(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			time.Sleep(3 * time.Millisecond)
			w.Header().Set("Content-Length", "65536")
			w.WriteHeader(200)
			_, _ = w.Write(make([]byte, 65536))
		} else {
			time.Sleep(time.Millisecond)
			w.WriteHeader(200)
		}
	}))
	defer s.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ServeUDPEcho(ctx, pc, EchoOptions{MaxPackets: 64, MaxBytes: 65536, IdleTimeout: time.Second})
	}()
	o := testOptions(s.URL)
	o.Mode = "download"
	o.Concurrency = 2
	o.UDPAddress = pc.LocalAddr().String()
	o.UDPTimeout = 50 * time.Millisecond
	r, err := Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Status != "completed" || r.UDP == nil || r.UDP.Status != "passed" {
		t.Fatalf("combined result: %+v %v", r, err)
	}
	if total := r.Traffic.PayloadBytesReceived + r.Traffic.UDPPayloadBytesSent + r.Traffic.UDPPayloadBytesReceived; total > o.MaxBytes {
		t.Fatalf("combined payload budget exceeded: %d", total)
	}
	if err = ValidateReport(r); err != nil {
		t.Fatalf("combined evidence validation: %v", err)
	}
	if !strings.Contains(FormatText(r), "UDP相邻") {
		t.Fatal("UDP jitter missing from text")
	}
	blocked, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	o.UDPAddress = blocked.LocalAddr().String()
	o.Mode = "light"
	o.Concurrency = 1
	r, err = Run(context.Background(), o, Dependencies{Transport: s.Client().Transport})
	if err != nil || r.Status != "failed" || r.UDP == nil || r.UDP.Lost != o.Samples || r.Statistics["idle_request"].Successes != o.Samples {
		t.Fatalf("UDP failure hidden by HTTP success: %+v %v", r, err)
	}
	if err = ValidateReport(r); err != nil {
		t.Fatalf("loss evidence rejected: %v", err)
	}
	cancel()
	pc.Close()
	<-done
}
