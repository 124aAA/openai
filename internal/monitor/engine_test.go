package monitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.Jobs = []Job{{ID: "job-1", NodeID: "node-1", Enabled: true, Signals: []SignalKind{Process, Listener, Authentication}}}
	return c
}
func testStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Root: filepath.Join(t.TempDir(), "monitor")}
}
func observation(j Job, values map[SignalKind]Status) Observation {
	o := Observation{}
	for _, k := range j.Signals {
		s, ok := values[k]
		if !ok {
			s = Healthy
		}
		o.Signals = append(o.Signals, Signal{Kind: k, Status: s, Location: "local", MeasuredAt: time.Now().UTC()})
	}
	return o
}
func constantCollector(values map[SignalKind]Status) Collector {
	return CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) { return observation(j, values), nil })
}
func run(t *testing.T, e Engine, c Config, col Collector, v ActionVerifier) Snapshot {
	t.Helper()
	if c.Recovery.Mode == "restart" {
		if _, err := os.Stat(filepath.Join(e.Store.Root, "config.json")); os.IsNotExist(err) {
			if err = e.Store.SaveConfig(c); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err := e.RunOnce(context.Background(), c, col, v)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEvaluateIndependentSignals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		signals []Signal
		want    Status
	}{
		{"empty", nil, Unknown},
		{"tcp_pass_udp_fail", []Signal{{Kind: TCP, Status: Healthy}, {Kind: UDP, Status: Failed}}, Degraded},
		{"target_only_failure", []Signal{{Kind: Process, Status: Healthy}, {Kind: Target, Status: Failed}}, Degraded},
		{"unmeasured_public", []Signal{{Kind: TCP, Status: Healthy}, {Kind: UDP, Status: Unknown}}, Unknown},
		{"all_failed", []Signal{{Kind: TCP, Status: Failed}}, Failed},
		{"partially_degraded", []Signal{{Kind: TCP, Status: Degraded}}, Degraded},
		{"disabled", []Signal{{Kind: TCP, Status: Disabled}}, Disabled},
		{"unrecognized", []Signal{{Status: Status("invented")}}, Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Evaluate(tc.signals); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestUnknownAndCancellationNeverSucceed(t *testing.T) {
	for _, mode := range []string{"missing", "bad_status", "no_time", "bad_location", "error", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			c := testConfig()
			c.TimeoutMS = 30
			e := Engine{Store: testStore(t)}
			col := CollectorFunc(func(ctx context.Context, j Job, _ Budget) (Observation, error) {
				o := observation(j, nil)
				switch mode {
				case "missing":
					o.Signals = nil
				case "bad_status":
					o.Signals[0].Status = "success"
				case "no_time":
					o.Signals[0].MeasuredAt = time.Time{}
				case "bad_location":
					o.Signals[0].Location = "guessed_public"
				case "error":
					return o, errors.New("token-secret https://secret/path")
				case "timeout":
					<-ctx.Done()
					return o, ctx.Err()
				}
				return o, nil
			})
			s := run(t, e, c, col, nil)
			if s.Jobs[0].Status != Unknown {
				t.Fatalf("not unknown: %+v", s.Jobs[0])
			}
			if s.Jobs[0].Observation.PublicReachability != Unknown {
				t.Fatal("local check implied public reachability")
			}
		})
	}
}

func TestGlobalBudgetAndConcurrency(t *testing.T) {
	c := testConfig()
	c.Concurrency = 2
	c.MaxBytes = 101
	c.Jobs = nil
	for i := 0; i < 4; i++ {
		c.Jobs = append(c.Jobs, Job{ID: fmt.Sprintf("job-%d", i), NodeID: fmt.Sprintf("node-%d", i), Enabled: true, Signals: []SignalKind{Process}})
	}
	var active, maxActive atomic.Int32
	var total atomic.Int64
	col := CollectorFunc(func(ctx context.Context, j Job, b Budget) (Observation, error) {
		if b.Concurrency != 1 {
			t.Errorf("adapter concurrency %d", b.Concurrency)
		}
		total.Add(b.MaxBytes)
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			return Observation{}, ctx.Err()
		}
		return observation(j, nil), nil
	})
	run(t, Engine{Store: testStore(t)}, c, col, nil)
	if total.Load() != 101 || maxActive.Load() != 2 {
		t.Fatalf("total=%d max=%d", total.Load(), maxActive.Load())
	}
}

func TestSingleInstanceAndWatchCancellation(t *testing.T) {
	c := testConfig()
	s := testStore(t)
	e := Engine{Store: s}
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	col := CollectorFunc(func(ctx context.Context, j Job, _ Budget) (Observation, error) {
		close(started)
		select {
		case <-release:
			return observation(j, nil), nil
		case <-ctx.Done():
			return Observation{}, ctx.Err()
		}
	})
	go func() { _, err := e.RunOnce(context.Background(), c, col, nil); done <- err }()
	<-started
	if _, err := e.RunOnce(context.Background(), c, constantCollector(nil), nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("wanted busy got %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := atomic.Int32{}
	seen := make(chan struct{})
	go func() {
		_, err := e.Watch(ctx, c, CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
			calls.Add(1)
			close(seen)
			return observation(j, nil), nil
		}), nil, 10)
		done <- err
	}()
	<-seen
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not stop")
	}
	if calls.Load() != 1 {
		t.Fatalf("queued calls: %d", calls.Load())
	}
}

func TestSlowCancelledAdapterIsNotDetached(t *testing.T) {
	c := testConfig()
	c.TimeoutMS = 15
	s := testStore(t)
	e := Engine{Store: s}
	exited := make(chan struct{})
	done := make(chan error, 1)
	col := CollectorFunc(func(ctx context.Context, j Job, _ Budget) (Observation, error) {
		<-ctx.Done()
		time.Sleep(25 * time.Millisecond)
		close(exited)
		return observation(j, nil), nil
	})
	go func() { _, err := e.RunOnce(context.Background(), c, col, nil); done <- err }()
	select {
	case <-done:
		select {
		case <-exited:
		default:
			t.Fatal("adapter detached")
		}
	case <-time.After(time.Second):
		t.Fatal("timed task stuck")
	}
}

type testActor struct {
	mu     sync.Mutex
	calls  int
	act    func(context.Context, Job, string) error
	verify func(context.Context, Job, Budget) (Observation, error)
}

func (a *testActor) Act(ctx context.Context, j Job, s string) error {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	if a.act != nil {
		return a.act(ctx, j, s)
	}
	return nil
}
func (a *testActor) Verify(ctx context.Context, j Job, b Budget) (Observation, error) {
	if a.verify != nil {
		return a.verify(ctx, j, b)
	}
	return observation(j, nil), nil
}
func recoveryConfig() Config {
	c := testConfig()
	c.Recovery.Mode = "restart"
	c.Recovery.ConsecutiveFailures = 2
	return c
}

var localFailures = map[SignalKind]Status{Listener: Failed, Authentication: Failed}

func TestRecoveryThresholdVerificationAndNoDuplicateAlert(t *testing.T) {
	c := recoveryConfig()
	s := testStore(t)
	e := Engine{Store: s}
	a := &testActor{}
	a.act = func(_ context.Context, _ Job, _ string) error {
		v, err := s.LoadStatus()
		if err != nil {
			return err
		}
		if len(v.Actions) != 1 || v.Actions[0].AttemptStatus != "attempted" {
			return errors.New("attempt not durable")
		}
		return nil
	}
	a.verify = func(_ context.Context, j Job, b Budget) (Observation, error) {
		if b.MaxBytes != 0 {
			t.Errorf("verification network budget %d", b.MaxBytes)
		}
		return observation(j, nil), nil
	}
	first := run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 0 || first.Jobs[0].ConsecutiveFailures != 1 {
		t.Fatal("short failure triggered action")
	}
	second := run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 1 || second.Jobs[0].Status != Healthy || len(second.Actions) != 1 || second.Actions[0].Verification != Healthy {
		t.Fatalf("missing verified recovery: %+v", second)
	}
	if len(second.Events) != 1 || second.Events[0].Kind != "recovery" {
		t.Fatalf("recovery event missing %+v", second.Events)
	}
	third := run(t, e, c, constantCollector(nil), a)
	if len(third.Events) != 0 || a.calls != 1 {
		t.Fatalf("duplicate alert/action %+v", third)
	}
	run(t, e, c, constantCollector(localFailures), a)
	fifth := run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 1 || fifth.Jobs[0].RecoveryReason != "cooldown" {
		t.Fatalf("cooldown ignored %+v", fifth.Jobs[0])
	}
}

func TestShortFlapAndSafetyStops(t *testing.T) {
	for _, mode := range []string{"flap", "manual", "maintenance", "inactive", "crash", "target", "same_target_transport", "egress", "missing_process"} {
		t.Run(mode, func(t *testing.T) {
			c := recoveryConfig()
			a := &testActor{}
			e := Engine{Store: testStore(t)}
			col := CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
				o := observation(j, localFailures)
				switch mode {
				case "manual":
					o.ManualStopped = true
				case "maintenance":
					o.Maintenance = true
				case "inactive":
					o.Inactive = true
				case "crash":
					o.Signals[0].Status = Failed
				case "missing_process":
					o.Signals[0].Status = Unknown
				}
				return o, nil
			})
			switch mode {
			case "target":
				c.Jobs[0].Signals = []SignalKind{Process, Target}
				col = CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
					o := observation(j, map[SignalKind]Status{Target: Failed})
					o.Signals[1].Location = "public"
					return o, nil
				})
			case "same_target_transport":
				c.Jobs[0].Signals = []SignalKind{Process, TCP, UDP}
				col = CollectorFunc(func(_ context.Context, j Job, _ Budget) (Observation, error) {
					return observation(j, map[SignalKind]Status{TCP: Failed, UDP: Failed}), nil
				})
			case "egress":
				c.Jobs[0].NodeID = ""
				c.Jobs[0].EgressID = "egress-1"
			}
			run(t, e, c, col, a)
			if mode == "flap" {
				run(t, e, c, constantCollector(nil), a)
			}
			run(t, e, c, col, a)
			if a.calls != 0 {
				t.Fatalf("unsafe action for %s", mode)
			}
		})
	}
}

func TestSharedServiceLimitsSurviveJobRemoval(t *testing.T) {
	c := recoveryConfig()
	c.Jobs = append(c.Jobs, Job{ID: "job-2", NodeID: "node-2", Enabled: true, Signals: c.Jobs[0].Signals})
	a := &testActor{}
	e := Engine{Store: testStore(t)}
	run(t, e, c, constantCollector(localFailures), a)
	s := run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 1 || len(s.Actions) != 1 || s.Jobs[1].RecoveryReason != "shared_service_action_deferred" {
		t.Fatalf("per-job limit bypass %+v", s)
	}
	c.Jobs = c.Jobs[1:]
	s = run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 1 || s.Jobs[0].RecoveryReason != "cooldown" {
		t.Fatalf("removed job lost global cooldown %+v", s)
	}
}

func TestRollingWindowAndFailedAction(t *testing.T) {
	c := recoveryConfig()
	c.Recovery.MaxActions = 1
	s := testStore(t)
	e := Engine{Store: s}
	a := &testActor{act: func(context.Context, Job, string) error { return errors.New("secret transport detail") }}
	run(t, e, c, constantCollector(localFailures), a)
	v := run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 1 || v.Actions[0].AttemptStatus != "failed" || v.Actions[0].Verification != Unknown {
		t.Fatalf("attempt treated as success %+v", v)
	}
	v.Actions[0].At = time.Now().Add(-time.Duration(c.Recovery.CooldownSeconds+1) * time.Second)
	if err := s.save(v, c.History); err != nil {
		t.Fatal(err)
	}
	v = run(t, e, c, constantCollector(localFailures), a)
	if a.calls != 1 || v.Jobs[0].RecoveryReason != "rolling_window_limit" {
		t.Fatalf("rolling limit ignored %+v", v)
	}
}

func TestMetricCounterResetStaysUnknown(t *testing.T) {
	a, b := uint64(10), uint64(3)
	if CounterDelta(&a, &b) != nil || CounterDelta(nil, &a) != nil {
		t.Fatal("reset or missing sample became a value")
	}
	if d := CounterDelta(&b, &a); d == nil || *d != 7 {
		t.Fatal("valid delta missing")
	}
}

func TestHistoryStrictCapsAndForeignFiles(t *testing.T) {
	c := testConfig()
	c.History = HistoryLimits{Records: 3, Bytes: 3500, Events: 2}
	s := testStore(t)
	e := Engine{Store: s}
	if err := s.Initialize(); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(s.Root, "unowned.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		run(t, e, c, constantCollector(nil), nil)
	}
	h, err := s.LoadHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(h) > 3 {
		t.Fatalf("history count %d", len(h))
	}
	info, err := os.Stat(filepath.Join(s.Root, "history.json"))
	if err != nil || info.Size() > c.History.Bytes {
		t.Fatalf("history bytes %v %v", info, err)
	}
	if b, err := os.ReadFile(foreign); err != nil || string(b) != "keep" {
		t.Fatal("foreign file changed")
	}
	c.History.Bytes = 256
	run(t, e, c, constantCollector(nil), nil)
	info, _ = os.Stat(filepath.Join(s.Root, "history.json"))
	if info.Size() > 256 {
		t.Fatal("small cap exceeded")
	}
}
