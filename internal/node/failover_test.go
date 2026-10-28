package node

import (
	"strings"
	"testing"
	"time"
)

func TestFailoverThresholdCooldownRecoveryAndUnknown(t *testing.T) {
	p := EgressPolicy{ID: "pair", Mode: "failover", Primary: "one", Backup: "two", Health: &EgressHealth{URL: "https://example.org/check", FailureThreshold: 2, RecoveryThreshold: 2, CooldownSeconds: 30, TimeoutSeconds: 2}}
	binding := strings.Repeat("a", 64)
	now := time.Unix(1000, 0).UTC()
	var observed FailoverObservation
	step := func(offset int, first, second, want string) {
		t.Helper()
		d, err := EvaluateFailover(p, observed, binding, first, second, now.Add(time.Duration(offset)*time.Second))
		if err != nil || d.To != want {
			t.Fatalf("t=%d got %+v err=%v", offset, d, err)
		}
		observed, p.Selected = d.Observation, d.To
	}
	step(0, "unhealthy", "healthy", "primary")
	step(1, "unknown", "healthy", "primary") // An incomplete sample breaks a streak.
	step(2, "unhealthy", "healthy", "primary")
	step(3, "unhealthy", "unhealthy", "primary") // No implicit direct fallback.
	step(4, "unhealthy", "healthy", "backup")
	step(5, "healthy", "healthy", "backup")
	step(6, "healthy", "healthy", "backup") // Recovered, still in cooldown.
	step(34, "healthy", "healthy", "primary")
	step(35, "unhealthy", "healthy", "primary")
	step(36, "unhealthy", "healthy", "primary") // A new cooldown after recovery.
	if err := observed.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFailoverRestoredBackupAndExternalChoiceResetWindow(t *testing.T) {
	p := EgressPolicy{Mode: "failover", Primary: "one", Backup: "two", Selected: "backup", Health: &EgressHealth{URL: "https://example.org/check", FailureThreshold: 1, RecoveryThreshold: 1, CooldownSeconds: 10, TimeoutSeconds: 1}}
	now := time.Unix(2000, 0).UTC()
	d, err := EvaluateFailover(p, FailoverObservation{}, strings.Repeat("b", 64), "healthy", "unhealthy", now)
	if err != nil || d.Changed || d.Observation.LastSwitch != now {
		t.Fatalf("restored backup flapped: %+v %v", d, err)
	}
	if _, err = EvaluateFailover(p, d.Observation, strings.Repeat("b", 64), "healthy", "healthy", now.Add(-time.Second)); err == nil {
		t.Fatal("backwards clock allowed")
	}
	if _, err = EvaluateFailover(p, d.Observation, strings.Repeat("b", 64), "canceled", "healthy", now); err == nil {
		t.Fatal("canceled fabricated as health result")
	}
}
