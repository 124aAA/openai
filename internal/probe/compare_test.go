package probe

import (
	"testing"
	"time"
)

func TestStatisticsPreserveMissingAndRawOutliers(t *testing.T) {
	one, five, hundred := 1.0, 5.0, 100.0
	samples := []Sample{{Kind: "idle", Status: "success", ElapsedMS: &one}, {Kind: "idle", Status: "failed"}, {Kind: "idle", Status: "success", ElapsedMS: &five}, {Kind: "idle", Status: "success", ElapsedMS: &hundred}}
	s := summarize(samples, "idle", "elapsed", "ms")
	if s.Attempts != 4 || s.Successes != 3 || s.Values != 3 || *s.SuccessRate != .75 || *s.Median != 5 || *s.P95 != 100 {
		t.Fatalf("wrong statistics: %+v", s)
	}
	m := summarize([]Sample{{Kind: "idle", Status: "failed"}}, "idle", "elapsed", "ms")
	if m.Median != nil || m.P95 != nil || m.SuccessRate == nil || *m.SuccessRate != 0 {
		t.Fatalf("missing converted to zero: %+v", m)
	}
}

func TestCompareRejectsChangedConditionsAndFailures(t *testing.T) {
	o, _ := NormalizeOptions(testOptions("https://example.invalid/object?token=one"))
	v := 10.0
	code := 200
	a := Report{Version: 1, Source: "qingnode-automatic-probe", Status: "completed", StartedAt: time.Now().UTC(), Conditions: conditions(o), DNS: Stage{Status: "unknown"}, Connection: Stage{Status: "unknown"}, TLS: Stage{Status: "unknown"}}
	a.FinishedAt = a.StartedAt.Add(time.Second)
	for i := 1; i <= 3; i++ {
		a.Samples = append(a.Samples, Sample{Sequence: i, Kind: "idle", Status: "success", HTTPStatus: &code, ElapsedMS: &v})
	}
	a.Statistics = statistics(a.Samples)
	b := a
	if c := Compare(a, b); !c.Comparable || len(c.Limitations) < 2 {
		t.Fatalf("valid comparable small sample: %+v", c)
	}
	for _, change := range []func(*Report){func(r *Report) { r.Status = "canceled" }, func(r *Report) { r.Conditions.Initiator = "different ISP" }, func(r *Report) { r.Conditions.ConfigSHA256 = "changed" }, func(r *Report) { r.Conditions.TargetSHA256 = "different signed URL" }, func(r *Report) { r.StartedAt = r.StartedAt.Add(25 * time.Hour) }, func(r *Report) { r.Version = 2 }, func(r *Report) { r.Source = "manual-public-check" }} {
		b = a
		change(&b)
		if c := Compare(a, b); c.Comparable || len(c.Reasons) == 0 {
			t.Fatalf("incomparable passed: %+v", c)
		}
	}
	b = a
	b.Statistics = map[string]Statistics{"idle_request": {Median: nil, Values: 0, Unit: "ms"}}
	if c := Compare(a, b); c.Comparable {
		t.Fatalf("missing value compared: %+v", c)
	}
}
