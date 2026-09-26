package node

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ResourceOverview reports local readings only; nil means unavailable, not zero.
// Load1 is the one-minute load average, not CPU utilization.
type ResourceOverview struct {
	CPUs                         int
	Load1                        *float64
	MemoryTotal, MemoryAvailable *uint64
	DiskTotal, DiskAvailable     *uint64
}

type ServiceOverview struct {
	ActiveState, SubState, UnitFileState string
	Runtime                              *time.Duration
	AutoRestarts                         *uint64 // systemd NRestarts, not all historical failures
}

func OverviewResources(root string) ResourceOverview {
	r := ResourceOverview{CPUs: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		r.Load1 = parseOverviewLoad(string(b))
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		r.MemoryTotal, r.MemoryAvailable = parseOverviewMemory(string(b))
	}
	path, err := filepath.Abs(root)
	if err != nil {
		return r
	}
	for {
		if _, err = os.Stat(path); err == nil {
			var fs unix.Statfs_t
			if unix.Statfs(path, &fs) == nil && fs.Bsize > 0 {
				r.DiskTotal = overviewProduct(fs.Blocks, uint64(fs.Bsize))
				r.DiskAvailable = overviewProduct(fs.Bavail, uint64(fs.Bsize))
			}
			return r
		}
		parent := filepath.Dir(path)
		if !os.IsNotExist(err) || parent == path {
			return r
		}
		path = parent
	}
}

// OverviewService makes one bounded local systemctl call. It does not probe
// the node or establish that clients can connect through it.
func OverviewService(runner Runner) ServiceOverview {
	if runner == nil {
		runner = Run
	}
	b, err := runner(650*time.Millisecond, "systemctl", "show", "qingnode.service", "--no-pager", "--property=ActiveState,SubState,UnitFileState,ActiveEnterTimestampMonotonic,NRestarts")
	if err != nil {
		return ServiceOverview{}
	}
	var clock unix.Timespec
	now := time.Duration(-1)
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock) == nil {
		now = time.Duration(clock.Nano())
	}
	return parseOverviewService(string(b), now)
}

func parseOverviewService(raw string, now time.Duration) ServiceOverview {
	p := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			p[k] = v
		}
	}
	s := ServiceOverview{ActiveState: p["ActiveState"], SubState: p["SubState"], UnitFileState: p["UnitFileState"], AutoRestarts: overviewUint(p["NRestarts"])}
	if start := overviewUint(p["ActiveEnterTimestampMonotonic"]); s.ActiveState == "active" && s.SubState == "running" && start != nil && *start > 0 && now >= 0 && *start <= uint64(now/time.Microsecond) {
		d := now - time.Duration(*start)*time.Microsecond
		s.Runtime = &d
	}
	return s
}

func parseOverviewLoad(raw string) *float64 {
	f := strings.Fields(raw)
	if len(f) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return nil
	}
	return &v
}

func parseOverviewMemory(raw string) (total, available *uint64) {
	for _, line := range strings.Split(raw, "\n") {
		key, value, _ := strings.Cut(line, ":")
		fields := strings.Fields(value)
		if (key != "MemTotal" && key != "MemAvailable") || len(fields) != 2 || fields[1] != "kB" {
			continue
		}
		if n := overviewUint(fields[0]); n != nil {
			bytes := overviewProduct(*n, 1024)
			if key == "MemTotal" {
				total = bytes
			} else {
				available = bytes
			}
		}
	}
	if total != nil && *total == 0 {
		total = nil
	}
	if total != nil && available != nil && *available > *total {
		available = nil
	}
	return
}

func overviewUint(value string) *uint64 {
	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

func overviewProduct(a, b uint64) *uint64 {
	if b != 0 && a > math.MaxUint64/b {
		return nil
	}
	v := a * b
	return &v
}
