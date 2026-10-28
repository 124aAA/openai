package monitor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/probe"
)

func TestPolicyRevokedDuringCollection(t *testing.T) {
	c := recoveryConfig()
	s := testStore(t)
	e := Engine{Store: s}
	a := &testActor{}
	run(t, e, c, constantCollector(localFailures), a)
	col := CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
		revoked := c
		revoked.Recovery.Mode = "observe"
		if err := s.SaveConfig(revoked); err != nil {
			t.Error(err)
		}
		return observation(j, localFailures), nil
	})
	v := run(t, e, c, col, a)
	if a.calls != 0 || v.Jobs[0].RecoveryReason != "policy_revoked" {
		t.Fatalf("revoked action ran %+v", v)
	}
}

func TestConfigAndSourceFingerprintResetConsecutiveFailures(t *testing.T) {
	for _, mode := range []string{"policy", "job", "core_configuration", "path"} {
		t.Run(mode, func(t *testing.T) {
			c := recoveryConfig()
			s := testStore(t)
			e := Engine{Store: s}
			a := &testActor{}
			source := strings.Repeat("a", 64)
			col := CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
				o := observation(j, localFailures)
				o.ConfigSHA256 = source
				if mode == "path" {
					o.ServerPathSHA256 = source
				}
				return o, nil
			})
			run(t, e, c, col, a)
			switch mode {
			case "policy":
				c.Recovery.CooldownSeconds++
			case "job":
				c.Jobs[0].EndpointID = "default"
			case "core_configuration", "path":
				source = strings.Repeat("b", 64)
			}
			if err := s.SaveConfig(c); err != nil {
				t.Fatal(err)
			}
			v := run(t, e, c, col, a)
			if a.calls != 0 || v.Jobs[0].ConsecutiveFailures != 1 {
				t.Fatalf("stale failure count reused %+v", v)
			}
		})
	}
}

func TestCoreAPIIndependentEvidence(t *testing.T) {
	for _, sameGroup := range []bool{false, true} {
		t.Run(map[bool]string{false: "independent", true: "correlated"}[sameGroup], func(t *testing.T) {
			c := recoveryConfig()
			c.Jobs[0].Signals = []SignalKind{Process, Listener, CoreAPI}
			a := &testActor{}
			e := Engine{Store: testStore(t)}
			col := CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
				o := observation(j, map[SignalKind]Status{Listener: Failed, CoreAPI: Failed})
				if sameGroup {
					for i := range o.Signals {
						if o.Signals[i].Kind != Process {
							o.Signals[i].EvidenceGroup = "same_local_failure"
						}
					}
				}
				return o, nil
			})
			run(t, e, c, col, a)
			run(t, e, c, col, a)
			want := 1
			if sameGroup {
				want = 0
			}
			if a.calls != want {
				t.Fatalf("calls %d want %d", a.calls, want)
			}
		})
	}
}

func TestMetadataTrafficAndUDPSanitization(t *testing.T) {
	c := testConfig()
	c.MaxBytes = 129
	now := time.Now()
	rtt := 1.25
	wire := int64(999)
	zero := float64(0)
	o := observation(c.Jobs[0], nil)
	o.ConfigSHA256 = strings.Repeat("a", 64)
	o.ServerPathSHA256 = "bad"
	o.TargetSHA256 = "https://secret.example/token"
	o.CoreVersion = strings.Repeat("x", 129)
	o.ClientVersion = "1.2.3"
	o.AddressFamily = "guessed"
	o.MeasurementLocation = "client-proxy"
	o.PublicReachability = Healthy
	o.Traffic = probe.Traffic{PayloadBytesReceived: 1, UDPPayloadBytesSent: 64, UDPPayloadBytesReceived: 64, WireBytes: &wire, Accounting: "secret"}
	o.UDP = &probe.UDPResult{Status: "passed", Target: "secret.example:1234", Path: "proxy_socks5_udp", AddressFamily: "ipv4", Sent: 1, Received: 1, SentBytes: 64, ReceivedBytes: 64, Samples: []probe.UDPSample{{Sequence: 0, RTTMS: &rtt, Error: "https://secret/token"}}, LossPercent: &zero}
	v := normalizeObservation(o, c.Jobs[0], now, now, nil, 129)
	if v.PublicReachability != Unknown || v.Traffic.WireBytes != nil || v.ConfigSHA256 == "" || v.ServerPathSHA256 != "" || v.TargetSHA256 != "" || v.CoreVersion != "" || v.ClientVersion != "1.2.3" || v.AddressFamily != "" {
		t.Fatalf("bad metadata %+v", v)
	}
	if v.UDP == nil || v.UDP.Target != "" || v.UDP.Path != "client-proxy" || v.UDP.Samples[0].Error != "details_redacted" || v.UDP.LossPercent == nil {
		t.Fatalf("bad UDP %+v", v.UDP)
	}
	o.UDP = &probe.UDPResult{Status: "failed", Sent: 1, Unfinished: 1, Error: "cancelled", LossPercent: &zero}
	v = normalizeObservation(o, c.Jobs[0], now, now, nil, 129)
	if v.UDP.LossPercent != nil {
		t.Fatal("cancelled became zero loss")
	}
	o.UDP = nil
	v = normalizeObservation(o, c.Jobs[0], now, now, nil, 128)
	if v.UDP != nil || Evaluate(v.Signals) != Unknown {
		t.Fatal("missing UDP or excessive budget became success")
	}
	o.UDP = &probe.UDPResult{Status: "passed", Sent: 2}
	if got := sanitizeUDP(o.UDP, 129); got.Status != "unknown" {
		t.Fatal("accepted multiple periodic samples")
	}
}

func TestNotificationRevokedDuringRetry(t *testing.T) {
	s := testStore(t)
	var calls atomic.Int32
	var c Config
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		revoked := c
		revoked.Notifications.Enabled = false
		if err := s.SaveConfig(revoked); err != nil {
			t.Error(err)
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	c = privateNotificationConfig(t, s, server.URL, "webhook")
	if got := (&Notifier{}).Send(context.Background(), c, Event{JobID: "job-1", From: Healthy, To: Failed}); got != "disabled" || calls.Load() != 1 {
		t.Fatalf("revoked retry %s %d", got, calls.Load())
	}
}

func TestInterruptedWriteCleanupIsBoundedAndReadOnlySafe(t *testing.T) {
	s := testStore(t)
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(s.Root, ".monitor-write-status.json")
	if err := os.WriteFile(stale, []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivate(stale, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadStatus(); err == nil {
		t.Fatal("missing status accepted")
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("read-only status removed temporary file")
	}
	l, err := s.acquire()
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("confirmed interrupted write not reclaimed")
	}
	foreign := filepath.Join(s.Root, ".monitor-write-foreign")
	if err := os.WriteFile(foreign, []byte("do-not-delete"), 0600); err != nil {
		t.Fatal(err)
	}
	if l, err = s.acquire(); err == nil {
		l.Close()
		t.Fatal("unconfirmed temp silently accepted")
	}
	if b, err := os.ReadFile(foreign); err != nil || string(b) != "do-not-delete" {
		t.Fatal("foreign prefix file deleted")
	}
}

func TestControlledActionErrorKeepsOnlyTrustedCategory(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{errors.New("https://secret.example/token-value"), "action_failed"}, {RedactedError("trusted_core_digest_mismatch"), "action_trusted_core_digest_mismatch"}} {
		c := recoveryConfig()
		e := Engine{Store: testStore(t)}
		a := &testActor{act: func(context.Context, Job, string) error { return tc.err }}
		run(t, e, c, constantCollector(localFailures), a)
		v := run(t, e, c, constantCollector(localFailures), a)
		if got := v.Actions[0].VerificationCause; got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}
