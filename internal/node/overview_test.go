package node

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOverviewResourceParsers(t *testing.T) {
	total, available := parseOverviewMemory("MemTotal: 2048 kB\nMemFree: 10 kB\nMemAvailable: 0 kB\n")
	if total == nil || *total != 2097152 || available == nil || *available != 0 {
		t.Fatalf("memory units or known zero lost: %v %v", total, available)
	}
	for _, raw := range []string{"", "MemTotal: bad kB\nMemAvailable: -1 kB", "MemTotal: 3 MB\nMemAvailable: 4", "MemTotal: 18446744073709551615 kB", "MemTotal: 0 kB"} {
		if total, available := parseOverviewMemory(raw); total != nil || available != nil {
			t.Fatalf("malformed memory should remain unknown: %q", raw)
		}
	}
	if _, available := parseOverviewMemory("MemTotal: 1 kB\nMemAvailable: 2 kB"); available != nil {
		t.Fatal("impossible available memory accepted")
	}
	if total, available := parseOverviewMemory("MemTotal: 10 kB\nMemFree: 5 kB"); total == nil || available != nil {
		t.Fatal("MemFree must not substitute for MemAvailable")
	}
	if load := parseOverviewLoad("1.25 2.00 3.00 1/12 123"); load == nil || *load != 1.25 {
		t.Fatal("one-minute load parsed incorrectly")
	}
	for _, raw := range []string{"", "oops", "-1", "NaN", "+Inf", "1e999"} {
		if parseOverviewLoad(raw) != nil {
			t.Fatalf("invalid load accepted: %q", raw)
		}
	}
}

func TestOverviewServiceKnownAndUnknown(t *testing.T) {
	raw := "ActiveState=active\nSubState=running\nUnitFileState=enabled\nActiveEnterTimestampMonotonic=2000000\nNRestarts=0\n"
	s := parseOverviewService(raw, 5*time.Second)
	if s.Runtime == nil || *s.Runtime != 3*time.Second || s.AutoRestarts == nil || *s.AutoRestarts != 0 || s.UnitFileState != "enabled" {
		t.Fatalf("unexpected active state: %+v", s)
	}
	for _, value := range []string{"0", "", "-1", "bad", "6000000", "18446744073709551615"} {
		if parseOverviewService(strings.Replace(raw, "2000000", value, 1), 5*time.Second).Runtime != nil {
			t.Fatalf("invalid/future start accepted: %q", value)
		}
	}
	for _, state := range []string{"inactive", "failed", "activating", "deactivating", ""} {
		if parseOverviewService(strings.Replace(raw, "ActiveState=active", "ActiveState="+state, 1), 5*time.Second).Runtime != nil {
			t.Fatalf("stopped service has running duration: %q", state)
		}
	}
	if parseOverviewService(raw, -1).Runtime != nil || parseOverviewService("NRestarts=bad", 0).AutoRestarts != nil {
		t.Fatal("unknown clock or restart count became a normal reading")
	}
	if s := parseOverviewService("", 0); s.Runtime != nil || s.AutoRestarts != nil || s.ActiveState != "" {
		t.Fatal("missing service data became known")
	}
}

func TestOverviewServiceOneBoundedRead(t *testing.T) {
	calls := 0
	s := OverviewService(func(timeout time.Duration, command string, args ...string) ([]byte, error) {
		calls++
		if timeout <= 0 || timeout > 700*time.Millisecond || command != "systemctl" || len(args) != 4 || args[0] != "show" || args[1] != "qingnode.service" {
			t.Fatalf("unexpected service read: %v %s %v", timeout, command, args)
		}
		return []byte("ActiveState=active\nSubState=running\nNRestarts=0"), errors.New("timeout")
	})
	if calls != 1 || s.ActiveState != "" || s.AutoRestarts != nil || s.Runtime != nil {
		t.Fatalf("failed read must be wholly unknown: %+v, calls %d", s, calls)
	}
}

func TestOverviewResourcesUsesExistingAncestor(t *testing.T) {
	r := OverviewResources(filepath.Join(t.TempDir(), "missing", "state"))
	if r.CPUs < 1 || r.DiskTotal == nil || *r.DiskTotal == 0 || r.DiskAvailable == nil || *r.DiskAvailable > *r.DiskTotal {
		t.Fatalf("local filesystem reading unavailable for absent root: %+v", r)
	}
}
