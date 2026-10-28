package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func capabilityFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for path, value := range map[string]string{
		"proc/1/comm":                  "systemd\n",
		"proc/self/status":             "CapEff:\t0000000000201400\nNoNewPrivs:\t1\nSeccomp:\t2\n",
		"proc/meminfo":                 "MemTotal: 8388608 kB\nMemAvailable: 4194304 kB\n",
		"proc/self/cgroup":             "4:cpu:/\n",
		"proc/sys/net/ipv6/bindv6only": "1\n",
		"proc/sys/net/ipv4/tcp_available_congestion_control": "reno cubic bbr\n",
		"dev/net/tun": "ordinary file, not a TUN device\n",
	} {
		memoryWrite(t, filepath.Join(root, filepath.FromSlash(path)), value)
	}
	return root
}

func TestCapabilitiesSeparateFamilyFactsAndNeverReadOrChangeState(t *testing.T) {
	root := capabilityFixture(t)
	secret := "deliberately-unlabeled-state-secret-that-must-not-be-read"
	memoryWrite(t, filepath.Join(root, "var/lib/qingnode/state.json"), secret)
	memoryWrite(t, filepath.Join(root, "var/lib/qingnode/transaction.json"), "pending-preserve")
	before, err := os.ReadFile(filepath.Join(root, "var/lib/qingnode/state.json"))
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	r := ProbeCapabilities(CapabilityOptions{RootDir: root, Paths: []string{"/var/lib/qingnode/state.json", "/missing/deep/output.json"}, LoopbackProbe: func(ctx context.Context, network string, exchange bool) CapabilityCheck {
		calls[network]++
		if !exchange {
			t.Fatal("default did not exercise the small exchange")
		}
		if strings.HasSuffix(network, "6") {
			return CapabilityCheck{Available: capabilityBool(false), Exercised: true, Reason: "injected IPv6 unavailable", ErrorCategory: "family_unavailable"}
		}
		return CapabilityCheck{Available: capabilityBool(true), Exercised: true, ExchangeExercised: true, ExchangeSucceeded: capabilityBool(true)}
	}})
	if r.Version != 1 || r.Source != "qingnode-local-capabilities" || len(calls) != 4 {
		t.Fatal("wrong version or missing independent checks", r, calls)
	}
	for _, network := range []string{"tcp4", "udp4"} {
		if r.Loopback[network].Available == nil || !*r.Loopback[network].Available {
			t.Fatal("IPv6 failure obscured IPv4", network, r.Loopback)
		}
	}
	for _, network := range []string{"tcp6", "udp6"} {
		if r.Loopback[network].Available == nil || *r.Loopback[network].Available || r.Loopback[network].Reason == "" {
			t.Fatal("IPv6 unavailability was guessed away", network, r.Loopback)
		}
	}
	if r.RemotePath.Available != nil || r.RemotePath.Exercised || r.RemotePath.Reason == "" {
		t.Fatal("loopback claimed a remote path", r.RemotePath)
	}
	if r.SystemdPID1 == nil || !*r.SystemdPID1 || r.Memory.EffectiveAvailableBytes == nil || *r.Memory.EffectiveAvailableBytes != 4<<30 {
		t.Fatal("fixed local facts missing", r)
	}
	if r.Privileges.NetAdmin == nil || !*r.Privileges.NetAdmin || r.Privileges.SysAdmin == nil || !*r.Privileges.SysAdmin || r.Privileges.NoNewPrivileges == nil || !*r.Privileges.NoNewPrivileges {
		t.Fatal("capability/sandbox fields lost", r.Privileges)
	}
	if r.TUN.Available == nil || *r.TUN.Available || r.TUN.Exercised {
		t.Fatal("ordinary file claimed usable TUN", r.TUN)
	}
	if len(r.Paths) != 2 || r.Paths[1].Exists == nil || *r.Paths[1].Exists || r.Paths[1].CheckedPath != root {
		t.Fatal("missing-path nearest ancestor not reported", r.Paths)
	}
	for _, path := range r.Paths {
		if path.WriteExercised {
			t.Fatal("access check claimed a write", path)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatal("capabilities created the missing path", err)
	}
	after, _ := os.ReadFile(filepath.Join(root, "var/lib/qingnode/state.json"))
	if string(after) != string(before) {
		t.Fatal("state changed")
	}
	pending, _ := os.ReadFile(filepath.Join(root, "var/lib/qingnode/transaction.json"))
	if string(pending) != "pending-preserve" {
		t.Fatal("read-only report repaired a pending transaction")
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("report read credential contents")
	}
	var wire map[string]any
	if err = json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	remote := wire["remote_path"].(map[string]any)
	if v, ok := remote["available"]; !ok || v != nil {
		t.Fatal("unknown is absent or converted to zero/false", remote)
	}
}

func TestCapabilitiesReuseCgroupHeadroomAndKeepMissingFactsUnknown(t *testing.T) {
	proc, sys, cgroup := memoryFixture(t, 2, "/slice/app", "/")
	memoryWrite(t, filepath.Join(cgroup, "slice", "memory.max"), "134217728\n")
	memoryWrite(t, filepath.Join(cgroup, "slice", "memory.current"), "33554432\n")
	memoryWrite(t, filepath.Join(cgroup, "slice", "app", "memory.max"), "max\n")
	r := ProbeCapabilities(CapabilityOptions{RootDir: t.TempDir(), ProcRoot: proc, SysRoot: sys, SkipLoopback: true})
	if r.Memory.EffectiveAvailableBytes == nil || *r.Memory.EffectiveAvailableBytes != 96<<20 {
		t.Fatal("host memory substituted for inherited quota", r.Memory)
	}
	if r.PID1.Value != nil || r.PID1.Reason == "" || r.Privileges.NetAdmin != nil || r.Privileges.Reason == "" || r.Container.Detected != nil {
		t.Fatal("missing evidence was inferred", r)
	}
	for network, value := range r.Loopback {
		if value.Exercised || value.Available != nil || value.Reason == "" {
			t.Fatal("skipped check became success/failure", network, value)
		}
	}
	if err := os.Remove(filepath.Join(cgroup, "slice", "memory.current")); err != nil {
		t.Fatal(err)
	}
	r = ProbeCapabilities(CapabilityOptions{RootDir: t.TempDir(), ProcRoot: proc, SysRoot: sys, SkipLoopback: true})
	if r.Memory.EffectiveAvailableBytes != nil || r.Memory.Reason == "" {
		t.Fatal("missing cgroup reading silently used host RAM", r.Memory)
	}
}

func TestCapabilitiesRefuseDangerousReadSourcesAndDanglingPaths(t *testing.T) {
	root := capabilityFixture(t)
	secret := filepath.Join(root, "outside-secret")
	memoryWrite(t, secret, "never-leak-bare-secret")
	status := filepath.Join(root, "proc/self/status")
	if err := os.Remove(status); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, status); err != nil {
		t.Fatal(err)
	}
	valuePath := filepath.Join(root, "proc/sys/net/ipv6/bindv6only")
	if err := os.Remove(valuePath); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(valuePath, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "never-created"), alias); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	r := ProbeCapabilities(CapabilityOptions{RootDir: root, SkipLoopback: true, Paths: []string{"/dangling/child", "/escape/child", "relative", "/invalid\npath"}})
	if r.Privileges.EffectiveMask != nil || r.Privileges.Reason == "" {
		t.Fatal("followed secret symlink", r.Privileges)
	}
	if r.Sysctl["net.ipv6.bindv6only"].Value != nil || r.Sysctl["net.ipv6.bindv6only"].Reason == "" {
		t.Fatal("FIFO produced a sysctl value", r.Sysctl)
	}
	for _, value := range r.Paths {
		if value.Writable != nil || value.WriteExercised || value.Reason == "" {
			t.Fatal("dangerous path was declared writable", value)
		}
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "never-leak-bare-secret") {
		t.Fatal("secret source leaked")
	}
	if _, err := os.Stat(filepath.Join(root, "never-created")); !os.IsNotExist(err) {
		t.Fatal("dangling target created", err)
	}
	if info, err := os.Lstat(valuePath); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("FIFO modified", err)
	}
}

func TestCapabilitiesBoundsAndCancellation(t *testing.T) {
	root := t.TempDir()
	paths := make([]string, 40)
	for i := range paths {
		paths[i] = "/not-created"
	}
	calls := 0
	r := ProbeCapabilities(CapabilityOptions{RootDir: root, Paths: paths, Timeout: time.Hour, LoopbackProbe: func(ctx context.Context, network string, exchange bool) CapabilityCheck {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("unbounded check")
		}
		return CapabilityCheck{Reason: "injected unexercised result"}
	}})
	if calls != 4 || len(r.Paths) != 32 || r.PathsOmitted != 8 {
		t.Fatal("unbounded path traversal/probe count", calls, r.PathsOmitted)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value := capabilityLoopback(ctx, "tcp4", true)
	if value.Available != nil || value.Exercised || value.ErrorCategory != "canceled" {
		t.Fatal("canceled check exercised network or claimed failure", value)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	value = capabilityLoopback(expired, "udp6", true)
	if value.Available != nil || value.Exercised || value.ErrorCategory != "timeout" {
		t.Fatal("expired check claimed an unavailable family", value)
	}
	r = ProbeCapabilities(CapabilityOptions{RootDir: "relative", SkipLoopback: true})
	if len(r.Loopback) != 0 || r.Memory.EffectiveAvailableBytes != nil {
		t.Fatal("invalid isolated root fell back to real host", r)
	}
}

func TestCapabilitiesActualLoopbackResponsesAndCleanup(t *testing.T) {
	probeAll := func() {
		for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			value := capabilityLoopback(ctx, network, true)
			cancel()
			if value.Available == nil || !value.Exercised {
				t.Fatal("real check lacks a binding result", network, value)
			}
			if *value.Available {
				if !value.ExchangeExercised || value.ExchangeSucceeded == nil || !*value.ExchangeSucceeded {
					t.Fatal("bound loopback failed actual payload", network, value)
				}
			} else if network == "tcp4" || network == "udp4" {
				t.Fatal("required local IPv4 unavailable", network, value)
			} else {
				if value.Reason == "" {
					t.Fatal("unavailable IPv6 has no reason")
				}
				t.Logf("%s unavailable in this environment: %s (%s); IPv4 verified separately", network, value.Reason, value.ErrorCategory)
			}
		}
	}
	probeAll() // initialize Go's process-wide network poller before counting fds
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		probeAll()
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Fatalf("loopback sockets leaked: before=%d after=%d", len(before), len(after))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bindOnly := capabilityLoopback(ctx, "tcp4", false)
	if bindOnly.Available == nil || !*bindOnly.Available || bindOnly.ExchangeExercised || bindOnly.ExchangeSucceeded != nil {
		t.Fatal("bind-only claimed transfer", bindOnly)
	}
}
