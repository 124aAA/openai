package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/probe"
)

type healthRoundTripper func(*http.Request) (*http.Response, error)

func (f healthRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEgressHealthConsumesActualProbeStatusesAndSeparatesUDP(t *testing.T) {
	r, err := probe.Run(context.Background(), probe.Options{Path: "client-proxy", TargetURL: "https://example.org/check", Samples: 1}, probe.Dependencies{Transport: healthRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2, Request: r}, nil
	})})
	if err != nil || classifyEgressProbe(r, false) != "healthy" {
		t.Fatalf("actual successful probe misclassified: status=%s samples=%v err=%v", r.Status, r.Samples, err)
	}
	if classifyEgressProbe(r, true) != "unhealthy" {
		t.Fatal("TCP success fabricated UDP availability")
	}
	r.Status = "canceled"
	if classifyEgressProbe(r, false) != "unknown" {
		t.Fatal("canceled sample counted as remote failure")
	}
}

func healthFixture(t *testing.T) (*app, node.State, node.EgressPolicy, *batchBackend) {
	t.Helper()
	a, st := batchFixture(t)
	b := &batchBackend{active: true}
	a.store.Backend = b
	st.Egresses = []node.Egress{topologyRemoteSS(strings.Repeat("a", 16)), topologyRemoteSS(strings.Repeat("b", 16))}
	st.Egresses[1].Port++
	p := node.EgressPolicy{ID: strings.Repeat("c", 16), Name: "policy", Mode: "failover", Primary: st.Egresses[0].ID, Backup: st.Egresses[1].ID, Health: &node.EgressHealth{URL: "https://example.org/check", UDPAddress: "203.0.113.55:40000", FailureThreshold: 2, RecoveryThreshold: 2, CooldownSeconds: 30, TimeoutSeconds: 2}}
	st.EgressPolicies = []node.EgressPolicy{p}
	st.Nodes[0].EgressID = p.ID
	if err := a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	st, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	b.starts, b.checks = 0, 0
	return a, st, p, b
}

func TestEgressHealthThresholdApplicationAndStaleMeasurements(t *testing.T) {
	a, st, p, backend := healthFixture(t)
	now := time.Now().UTC()
	oldGeneration, _ := savedBatchState(t, a)
	d, applied, err := a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now)
	if err != nil || applied == nil || *applied || d.Changed || backend.starts != 0 {
		t.Fatalf("first failure changed service: %+v %v %v", d, applied, err)
	}
	newGeneration, _ := savedBatchState(t, a)
	if oldGeneration != newGeneration {
		t.Fatal("counter-only observation created a State generation")
	}
	d, applied, err = a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now.Add(time.Second))
	if err != nil || applied == nil || !*applied || !d.Changed || d.To != "backup" || backend.starts != 1 {
		t.Fatalf("threshold failed: %+v %v %v", d, applied, err)
	}
	after, err := a.store.Load()
	if err != nil || after.EgressPolicies[0].Selected != "backup" || after.Nodes[1].EgressID != "" {
		t.Fatal("selection or unrelated route changed", err)
	}
	if _, _, err = a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now.Add(2*time.Second)); err == nil {
		t.Fatal("stale pre-switch measurement applied")
	}
	h, err := readEgressHealthHistory(a.store.Root)
	if err != nil || h.Policies[p.ID].Selected != "backup" {
		t.Fatal("choice observation missing", err)
	}
}

func TestEgressHealthFailureRestoresOldChoiceAndHistory(t *testing.T) {
	a, st, p, backend := healthFixture(t)
	now := time.Now().UTC()
	if _, _, err := a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.store.Root, "egress-health.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backend.failStarts = 1
	d, applied, err := a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now.Add(time.Second))
	if err == nil || applied != nil || !d.Changed {
		t.Fatalf("failed activation declared applied: %+v %v %v", d, applied, err)
	}
	after, err := a.store.Load()
	if err != nil || after.EgressPolicies[0].Selected == "backup" {
		t.Fatal("old choice not restored", err)
	}
	retained, err := os.ReadFile(path)
	if err != nil || string(retained) != string(original) {
		t.Fatal("failed switch overwrote health observation", err)
	}
}

func TestEgressHealthBindingAndUnknownHistoryRefuseOverwrite(t *testing.T) {
	a, st, p, _ := healthFixture(t)
	changed := st.Clone()
	changed.Egresses[0].Port++
	if err := a.store.WithLock(func() error { return a.store.Apply(changed) }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", time.Now().UTC()); err == nil {
		t.Fatal("changed endpoint accepted an old measurement")
	}
	path := filepath.Join(a.store.Root, "egress-health.json")
	original := []byte(`{"version":2,"policies":{}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.commitHealthDecision(context.Background(), changed, p, "unhealthy", "healthy", time.Now().UTC()); err == nil {
		t.Fatal("future observation version overwritten")
	}
	retained, _ := os.ReadFile(path)
	if string(retained) != string(original) {
		t.Fatal("future observation original lost")
	}
}

func TestEgressGraphUsesProjectResolverAndHealthRefusesUnsafeInvocation(t *testing.T) {
	a, st, _, _ := healthFixture(t)
	port := 5353
	st.DNS = &node.DNSSettings{Type: "udp", Server: "192.0.2.53", Port: &port}
	p, err := makeEgressGraph(st, st.Egresses[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	if !strings.Contains(string(raw), "192.0.2.53") {
		t.Fatal("project DNS missing from isolated test graph")
	}
	before, _ := savedBatchState(t, a)
	for _, args := range [][]string{{"--id", "a"}, {"--id", "a", "--watch"}, {"--id", "a", "--budget", "121s"}, {"--id", "a", "--rounds", "17"}} {
		if err := a.egressHealth(args); err == nil {
			t.Fatal("unsafe/offline health invocation accepted", args)
		}
	}
	after, _ := savedBatchState(t, a)
	if before != after {
		t.Fatal("refused test changed State")
	}
}

func TestEgressHealthCanceledBeforeCommitDoesNotWrite(t *testing.T) {
	a, st, p, backend := healthFixture(t)
	before, _ := savedBatchState(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, applied, err := a.commitHealthDecision(ctx, st, p, "unhealthy", "healthy", time.Now().UTC())
	if err != context.Canceled || applied == nil || *applied {
		t.Fatalf("cancellation was applied: %v %v", applied, err)
	}
	after, _ := savedBatchState(t, a)
	if before != after || backend.starts != 0 {
		t.Fatal("cancellation changed State or service")
	}
	if _, err = os.Stat(filepath.Join(a.store.Root, "egress-health.json")); !os.IsNotExist(err) {
		t.Fatal("cancellation saved a health observation")
	}
}

func TestEgressHealthInvalidHistoryPreservesOriginal(t *testing.T) {
	a, _, _, _ := healthFixture(t)
	path := filepath.Join(a.store.Root, "egress-health.json")
	for _, raw := range []string{`{"version":1,"policies":null}`, `{"version":2,"Version":1,"policies":{}}`, `{"version":1,"policies":{},"policies":{}}`, `{"version":1,"policies":{"not-an-id":{}}}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readEgressHealthHistory(a.store.Root); err == nil {
			t.Fatal("invalid history accepted", raw)
		}
		retained, err := os.ReadFile(path)
		if err != nil || string(retained) != raw {
			t.Fatal("invalid history rewritten", err)
		}
	}
}

func TestEgressHealthStableIDWinsAcrossObjectKinds(t *testing.T) {
	_, st, p, _ := healthFixture(t)
	st.EgressPolicies[0].Name = st.Egresses[0].ID
	if _, err := healthPolicy(&st, st.Egresses[0].ID); err == nil {
		t.Fatal("display name shadowed an exact remote ID")
	}
	if found, err := healthPolicy(&st, p.ID); err != nil || found.ID != p.ID {
		t.Fatal("exact policy ID no longer selects the policy", err)
	}
}

func TestEgressHealthReportWriteFailureStillExposesCommittedChoice(t *testing.T) {
	a, st, p, _ := healthFixture(t)
	now := time.Now().UTC()
	if _, _, err := a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now); err != nil {
		t.Fatal(err)
	}
	d, applied, err := a.commitHealthDecision(context.Background(), st, p, "unhealthy", "healthy", now.Add(time.Second))
	if err != nil || applied == nil || !*applied {
		t.Fatal("choice not committed", err)
	}
	path := filepath.Join(t.TempDir(), "result.json")
	output, err := pinNewOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer output.root.Close()
	// A competing file must remain untouched. Report failure cannot hide an
	// already committed State change or overwrite another writer's result.
	if err = os.WriteFile(path, []byte("foreign-result"), 0600); err != nil {
		t.Fatal(err)
	}
	report := egressHealthReport{Version: 1, Status: "completed", Rounds: []egressHealthRound{{Decision: &d, Applied: applied}}}
	text, err := wizardOutput(t, func() error { return emitEgressHealthReport(report, output, path, true) })
	if err == nil {
		t.Fatal("file save failure returned success")
	}
	var observed egressHealthReport
	if err = json.Unmarshal([]byte(text), &observed); err != nil || len(observed.Rounds) != 1 || observed.Rounds[0].Applied == nil || !*observed.Rounds[0].Applied || len(observed.Limitations) == 0 {
		t.Fatal("committed choice hidden by file failure", err, text)
	}
	retained, _ := os.ReadFile(path)
	after, err := a.store.Load()
	if err != nil || string(retained) != "foreign-result" || after.EgressPolicies[0].Selected != "backup" {
		t.Fatal("output failure changed committed State or foreign file", err)
	}
}

func TestEgressHealthBudgetAndCancellationRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		err    error
		failed bool
		want   string
	}{{nil, false, "completed"}, {nil, true, "failed"}, {context.Canceled, false, "canceled"}, {context.DeadlineExceeded, false, "timeout"}, {errors.New("io"), false, "failed"}} {
		if got := egressHealthStatus(test.err, test.failed); got != test.want {
			t.Fatalf("status %s wanted %s", got, test.want)
		}
	}
}
