package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func memoryFixture(t *testing.T, version int, group, mountRoot string) (proc, sys, cgroup string) {
	t.Helper()
	base := t.TempDir()
	proc = filepath.Join(base, "proc")
	sys = filepath.Join(base, "sys")
	cgroup = filepath.Join(sys, "fs", "cgroup")
	if e := os.MkdirAll(filepath.Join(proc, "self"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(cgroup, 0700); e != nil {
		t.Fatal(e)
	}
	relative := group
	if mountRoot != "/" {
		relative = strings.TrimPrefix(relative, mountRoot)
	}
	if e := os.MkdirAll(filepath.Join(cgroup, strings.TrimPrefix(relative, "/")), 0700); e != nil {
		t.Fatal(e)
	}
	memoryWrite(t, filepath.Join(proc, "meminfo"), "MemTotal: 8388608 kB\nMemAvailable: 4194304 kB\n")
	line := "0::" + group + "\n"
	fs := "cgroup2"
	super := "rw"
	if version == 1 {
		line = "5:cpu,memory:" + group + "\n"
		fs = "cgroup"
		super = "rw,memory"
	}
	memoryWrite(t, filepath.Join(proc, "self", "cgroup"), line)
	memoryWrite(t, filepath.Join(proc, "self", "mountinfo"), "29 23 0:26 "+mountRoot+" /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - "+fs+" cgroup "+super+"\n")
	if version == 2 {
		memoryWrite(t, filepath.Join(cgroup, "cgroup.controllers"), "cpu memory pids\n")
		memoryWrite(t, filepath.Join(cgroup, "memory.max"), "max\n")
	}
	return
}
func memoryWrite(t *testing.T, path, value string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(value), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestAvailableMemoryUsesContainerHeadroomAndAncestorLimit(t *testing.T) {
	proc, sys, cgroup := memoryFixture(t, 2, "/slice/app", "/")
	memoryWrite(t, filepath.Join(cgroup, "slice", "memory.max"), "134217728\n")
	memoryWrite(t, filepath.Join(cgroup, "slice", "memory.current"), "33554432\n")
	memoryWrite(t, filepath.Join(cgroup, "slice", "app", "memory.max"), "max\n")
	available, e := AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 96<<20 {
		t.Fatalf("host RAM substituted for inherited 128MiB quota: %v %v", available, e)
	}
	memoryWrite(t, filepath.Join(cgroup, "slice", "memory.current"), "134217729\n")
	available, e = AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 0 {
		t.Fatal("usage over quota became underflow/unknown rather than zero", available, e)
	}
	memoryWrite(t, filepath.Join(cgroup, "slice", "memory.max"), "max\n")
	available, e = AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 4<<30 {
		t.Fatal("unlimited cgroup did not retain MemAvailable", available, e)
	}
}

func TestAvailableMemoryMapsActualMountRootAndV1Limits(t *testing.T) {
	proc, sys, cgroup := memoryFixture(t, 2, "/containers/test/app", "/containers/test")
	memoryWrite(t, filepath.Join(cgroup, "memory.max"), "134217728\n")
	memoryWrite(t, filepath.Join(cgroup, "memory.current"), "33554432\n")
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.max"), "max\n")
	available, e := AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 96<<20 {
		t.Fatalf("mount root was duplicated or ignored: %v %v", available, e)
	}
	proc, sys, cgroup = memoryFixture(t, 1, "/app", "/")
	memoryWrite(t, filepath.Join(cgroup, "memory.limit_in_bytes"), "9223372036854771712\n")
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.limit_in_bytes"), "134217728\n")
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.usage_in_bytes"), "67108864\n")
	available, e = AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 64<<20 {
		t.Fatal("v1 memory quota not applied", available, e)
	}
}

func TestAvailableMemoryRejectsMalformedUnavailableAndEscapingCgroups(t *testing.T) {
	for _, mode := range []string{"path", "missing-limit", "bad-limit", "bad-usage", "unreadable-controller", "invisible-mount"} {
		t.Run(mode, func(t *testing.T) {
			proc, sys, cgroup := memoryFixture(t, 2, "/app", "/")
			memoryWrite(t, filepath.Join(cgroup, "app", "memory.max"), "134217728\n")
			memoryWrite(t, filepath.Join(cgroup, "app", "memory.current"), "1\n")
			switch mode {
			case "path":
				memoryWrite(t, filepath.Join(proc, "self", "cgroup"), "0::/app/../../outside\n")
			case "missing-limit":
				os.Remove(filepath.Join(cgroup, "app", "memory.max"))
			case "bad-limit":
				memoryWrite(t, filepath.Join(cgroup, "app", "memory.max"), "many\n")
			case "bad-usage":
				memoryWrite(t, filepath.Join(cgroup, "app", "memory.current"), "-1\n")
			case "unreadable-controller":
				os.Remove(filepath.Join(cgroup, "cgroup.controllers"))
				os.Mkdir(filepath.Join(cgroup, "cgroup.controllers"), 0700)
			case "invisible-mount":
				memoryWrite(t, filepath.Join(proc, "self", "mountinfo"), "")
			}
			if available, e := AvailableMemory(proc, sys); e == nil || available != nil {
				t.Fatalf("unavailable constraints were silently replaced by host RAM: %v %v", available, e)
			}
		})
	}
}

func TestAvailableMemoryNoMemoryControllerAndMissingMembership(t *testing.T) {
	proc, sys, cgroup := memoryFixture(t, 2, "/app", "/")
	memoryWrite(t, filepath.Join(cgroup, "cgroup.controllers"), "cpu pids\n")
	available, e := AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 4<<30 {
		t.Fatal("known absent memory controller incorrectly invented a quota", available, e)
	}
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.max"), "134217728\n")
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.current"), "67108864\n")
	available, e = AvailableMemory(proc, sys)
	if e != nil || available == nil || *available != 64<<20 {
		t.Fatal("child-controller availability incorrectly erased an existing own memory quota", available, e)
	}
	os.Remove(filepath.Join(proc, "self", "cgroup"))
	if available, e = AvailableMemory(proc, sys); e == nil || available != nil {
		t.Fatal("missing membership was treated as an unrestricted host", available, e)
	}
}

func TestAvailableMemoryMissingV1LimitRemainsUnknown(t *testing.T) {
	proc, sys, cgroup := memoryFixture(t, 1, "/app", "/")
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.limit_in_bytes"), "134217728\n")
	memoryWrite(t, filepath.Join(cgroup, "app", "memory.usage_in_bytes"), "67108864\n")
	if available, e := AvailableMemory(proc, sys); e == nil || available != nil {
		t.Fatal("missing v1 ancestor quota was treated as known unlimited", available, e)
	}
}
