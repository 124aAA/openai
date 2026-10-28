package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNetworkRecoveryFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.json")
	if e := syscall.Mkfifo(path, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := networkRead(path, true); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("named pipe accepted as a recovery record")
		}
	case <-time.After(time.Second):
		t.Fatal("reading recovery FIFO blocked before checking its file type")
	}
}

func TestNetworkPlanRejectsUnsupportedOriginalFilePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0666, 0755, 0620, 0200} {
		t.Run(mode.String(), func(t *testing.T) {
			h, f := newNetworkFixture(t)
			original := networkRender(map[string]string{"net.ipv4.tcp_congestion_control": "cubic"})
			if e := os.WriteFile(h.SysctlFile, original, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(h.SysctlFile, mode); e != nil {
				t.Fatal(e)
			}
			if _, e := h.Plan(NetworkRequest{TCP: "bbr"}); e == nil {
				t.Errorf("preview accepted original permissions %04o which its own recovery validator rejects", mode)
			}
			if len(f.writes) != 0 || f.values["net.ipv4.tcp_congestion_control"] != "cubic" {
				t.Fatal("rejected original file caused kernel writes")
			}
			if _, e := os.Lstat(h.StateDir); !os.IsNotExist(e) {
				t.Fatal("invalid read-only preview initialized recovery state", e)
			}
			info, e := os.Stat(h.SysctlFile)
			if e != nil || info.Mode().Perm() != mode {
				t.Fatal("preview changed original permissions", e)
			}
			// Restore read permission only after checking the preview's effects,
			// so this fixture also works when tests run as an unprivileged user.
			if e := os.Chmod(h.SysctlFile, 0600); e != nil {
				t.Fatal(e)
			}
			data, e := os.ReadFile(h.SysctlFile)
			if e != nil || !bytes.Equal(data, original) {
				t.Fatal("preview changed original file contents", e)
			}
		})
	}
}

func TestNetworkSupportedOriginalFilePermissionsRemainRestorable(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0600, 0640, 0644} {
		t.Run(mode.String(), func(t *testing.T) {
			h, f := newNetworkFixture(t)
			original := networkRender(map[string]string{"net.ipv4.tcp_congestion_control": "cubic"})
			if e := os.WriteFile(h.SysctlFile, original, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(h.SysctlFile, mode); e != nil {
				t.Fatal(e)
			}
			result := mustNetworkApply(t, h, NetworkRequest{TCP: "bbr"})
			if _, e := h.RestorePlan(result.SnapshotID); e != nil {
				t.Fatal("supported original permissions were not previewable for recovery", e)
			}
			if _, e := h.Restore(result.SnapshotID); e != nil {
				t.Fatal("supported original permissions were not restorable", e)
			}
			data, e := os.ReadFile(h.SysctlFile)
			info, statErr := os.Stat(h.SysctlFile)
			if e != nil || statErr != nil || !bytes.Equal(data, original) || info.Mode().Perm() != mode || f.values["net.ipv4.tcp_congestion_control"] != "cubic" {
				t.Fatalf("restore did not preserve supported original permissions/content/runtime: %v %v", e, statErr)
			}
		})
	}
}

type networkFixture struct {
	mu      sync.Mutex
	values  map[string]string
	writes  []string
	fail    func(string, string) error
	tcError bool
}

func newNetworkFixture(t *testing.T) (NetworkHost, *networkFixture) {
	t.Helper()
	base := t.TempDir()
	proc := filepath.Join(base, "proc")
	sys := filepath.Join(base, "sys")
	for _, dir := range []string{proc, filepath.Join(proc, "self"), filepath.Join(proc, "net"), filepath.Join(proc, "123"), filepath.Join(sys, "class", "net", "eth0"), filepath.Join(base, "sysctl.d")} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(proc, "self", "cgroup"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(proc, "net", "snmp6"), []byte("Udp6InErrors 7\nUdp6RcvbufErrors 8\n"), 0600); e != nil {
		t.Fatal(e)
	}
	for p, data := range map[string]string{filepath.Join(proc, "meminfo"): "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n", filepath.Join(proc, "loadavg"): "0.25 0.30 0.20 1/20 123\n", filepath.Join(proc, "stat"): "cpu 1 2 3 4 5 6 7 8 9 10\n", filepath.Join(proc, "123", "status"): "Name:\tsing-box\nVmRSS:\t4096 kB\n", filepath.Join(proc, "net", "snmp"): "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors\nUdp: 10 2 3 11 4 5 6\n", filepath.Join(sys, "class", "net", "eth0", "mtu"): "1500\n"} {
		if e := os.WriteFile(p, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	f := &networkFixture{values: map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.ipv4.tcp_available_congestion_control": "reno cubic bbr", "net.core.default_qdisc": "fq_codel", "net.core.rmem_default": "212992", "net.core.rmem_max": "212992", "net.core.wmem_default": "212992", "net.core.wmem_max": "212992", "net.ipv4.udp_rmem_min": "4096", "net.ipv4.udp_wmem_min": "4096", "net.ipv4.udp_mem": "100 200 300"}}
	h := NetworkHost{StateDir: filepath.Join(base, "state"), SysctlFile: filepath.Join(base, "sysctl.d", "90-qingnode-network.conf"), ProcRoot: proc, SysRoot: sys, ProcessPID: 123}
	h.Execute = func(_ time.Duration, name string, args ...string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if name == "tc" {
			if f.tcError {
				return nil, os.ErrPermission
			}
			if strings.Join(args, " ") != "-j qdisc show" {
				t.Errorf("unexpected modifying tc args: %v", args)
			}
			return []byte(`[{"kind":"mq","dev":"eth0","root":true},{"kind":"fq_codel","dev":"eth0","root":false}]`), nil
		}
		if name != "sysctl" || len(args) != 2 {
			t.Errorf("unexpected host command: %s %v", name, args)
			return nil, errors.New("unexpected command")
		}
		if args[0] == "-n" {
			v, ok := f.values[args[1]]
			if !ok {
				return nil, os.ErrPermission
			}
			return []byte(v), nil
		}
		if args[0] != "-w" {
			t.Errorf("unexpected sysctl command: %v", args)
			return nil, errors.New("unexpected command")
		}
		key, value, ok := strings.Cut(args[1], "=")
		if !ok {
			return nil, errors.New("bad write")
		}
		f.writes = append(f.writes, args[1])
		if f.fail != nil {
			if e := f.fail(key, value); e != nil {
				return nil, e
			}
		}
		f.values[key] = value
		return []byte(args[1]), nil
	}
	return h, f
}
func mustNetworkPlan(t *testing.T, h NetworkHost, r NetworkRequest) NetworkPlan {
	t.Helper()
	p, e := h.Plan(r)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func mustNetworkApply(t *testing.T, h NetworkHost, r NetworkRequest) NetworkApplyResult {
	t.Helper()
	p := mustNetworkPlan(t, h, r)
	result, e := h.Apply(p)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func TestNetworkStatusAndPreviewDoNotInitializeOrModify(t *testing.T) {
	h, f := newNetworkFixture(t)
	before := map[string]string{}
	for k, v := range f.values {
		before[k] = v
	}
	s := h.Status()
	if s.UDP6Counters["RcvbufErrors"] != 8 {
		t.Fatal("IPv6 UDP counters were omitted or mixed into IPv4 counters")
	}
	if s.Sysctl["net.core.default_qdisc"].Value != "fq_codel" || len(s.Qdiscs) != 2 || s.Qdiscs[0].Kind != "mq" || s.MemoryAvailable == nil || *s.MemoryAvailable != 524288*1024 || s.CPUStealTicks == nil || *s.CPUStealTicks != 8 || s.ProcessRSS == nil || *s.ProcessRSS != 4096*1024 || s.UDPCounters["RcvbufErrors"] != 4 || len(s.Interfaces) != 1 || *s.Interfaces[0].MTU != 1500 {
		t.Fatalf("diagnostic layers mixed/missing: %#v", s)
	}
	p := mustNetworkPlan(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"})
	text := FormatNetworkPlan(p)
	if !strings.Contains(text, "cubic → 请求 bbr") || !strings.Contains(text, p.RecoveryFile) || len(f.writes) != 0 || !reflect.DeepEqual(before, f.values) {
		t.Fatalf("preview changed values or omitted actual originals: %s", text)
	}
	if _, e := os.Lstat(h.StateDir); !os.IsNotExist(e) {
		t.Fatal("read-only status/plan created state directory", e)
	}
	if _, e := os.Lstat(h.SysctlFile); !os.IsNotExist(e) {
		t.Fatal("read-only preview wrote sysctl persistence", e)
	}
	p = mustNetworkPlan(t, h, NetworkRequest{})
	r, e := h.Apply(p)
	if e != nil || r.Changed || len(f.writes) != 0 {
		t.Fatal("empty request silently tuned host", e)
	}
}

func TestNetworkApplySnapshotsReadbackAndRestoreChain(t *testing.T) {
	h, f := newNetworkFixture(t)
	first := mustNetworkApply(t, h, NetworkRequest{RmemMax: 4 << 20})
	second := mustNetworkApply(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"})
	for _, path := range []string{first.RecoveryFile, second.RecoveryFile, filepath.Join(h.StateDir, "active.json")} {
		i, e := os.Stat(path)
		if e != nil || i.Mode().Perm() != 0600 {
			t.Fatal("private recovery material missing/wide", path, e)
		}
	}
	before, e := os.ReadFile(first.RecoveryFile)
	if e != nil {
		t.Fatal(e)
	}
	if f.values["net.core.rmem_max"] != "4194304" || f.values["net.ipv4.tcp_congestion_control"] != "bbr" {
		t.Fatal("apply did not read back requested values")
	}
	if _, e = h.RestorePlan(second.SnapshotID); e != nil {
		t.Fatal(e)
	}
	if _, e = h.Restore(first.SnapshotID); e == nil {
		t.Fatal("old snapshot crossed subsequent apply")
	}
	if _, e = h.Restore(second.SnapshotID); e != nil {
		t.Fatal(e)
	}
	if f.values["net.ipv4.tcp_congestion_control"] != "cubic" || f.values["net.core.rmem_max"] != "4194304" {
		t.Fatal("restore discarded previous managed settings")
	}
	if _, e = h.Restore(first.SnapshotID); e != nil {
		t.Fatal(e)
	}
	if f.values["net.core.rmem_max"] != "212992" {
		t.Fatal("original buffer not restored")
	}
	if _, e = os.Stat(h.SysctlFile); !os.IsNotExist(e) {
		t.Fatal("new owned file remained after restoring original absence")
	}
	after, _ := os.ReadFile(first.RecoveryFile)
	if !bytes.Equal(before, after) {
		t.Fatal("restore rewrote immutable original snapshot")
	}
}

func TestNetworkPartialFailureRestoresEveryAppliedField(t *testing.T) {
	h, f := newNetworkFixture(t)
	failed := false
	f.fail = func(key, value string) error {
		if key == "net.ipv4.tcp_congestion_control" && value == "bbr" && !failed {
			failed = true
			return os.ErrPermission
		}
		return nil
	}
	r, e := h.Apply(mustNetworkPlan(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"}))
	if e == nil || f.values["net.core.default_qdisc"] != "fq_codel" || f.values["net.ipv4.tcp_congestion_control"] != "cubic" || len(r.Restored) != 1 {
		t.Fatalf("partial failure left tuned settings: %#v %v", r, e)
	}
	if _, e = os.Stat(h.SysctlFile); !os.IsNotExist(e) {
		t.Fatal("failed application left persistence")
	}
	if _, e = os.Stat(r.RecoveryFile); e != nil {
		t.Fatal("failure deleted original material")
	}
	if _, e = os.Stat(filepath.Join(h.StateDir, "pending.json")); !os.IsNotExist(e) {
		t.Fatal("successful recovery left pending journal")
	}
}

func TestNetworkRestoreFailureLeavesJournalForExplicitRecovery(t *testing.T) {
	h, f := newNetworkFixture(t)
	failures := 2
	f.fail = func(key, value string) error {
		if key == "net.ipv4.tcp_congestion_control" && value == "bbr" {
			return os.ErrPermission
		}
		if key == "net.core.default_qdisc" && value == "fq_codel" && failures > 0 {
			failures--
			return os.ErrPermission
		}
		return nil
	}
	r, e := h.Apply(mustNetworkPlan(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"}))
	if e == nil || !strings.Contains(e.Error(), "恢复未完成") || f.values["net.core.default_qdisc"] != "fq" {
		t.Fatalf("recovery failure hidden: %#v %v", r, e)
	}
	pendingBefore, _ := os.ReadFile(filepath.Join(h.StateDir, "pending.json"))
	s := h.Status()
	pendingAfter, _ := os.ReadFile(filepath.Join(h.StateDir, "pending.json"))
	if s.PendingSnapshot != r.SnapshotID || !bytes.Equal(pendingBefore, pendingAfter) {
		t.Fatal("status repaired pending transaction")
	}
	if _, e = h.Plan(NetworkRequest{Qdisc: "fq_codel"}); e == nil {
		t.Fatal("new write ignored pending recovery")
	}
	f.fail = nil
	if _, e = h.Restore(r.SnapshotID); e != nil {
		t.Fatal(e)
	}
	if f.values["net.core.default_qdisc"] != "fq_codel" {
		t.Fatal("explicit recovery did not restore original")
	}
}

func TestNetworkRestorePreservesManualKernelAndFileChanges(t *testing.T) {
	t.Run("kernel", func(t *testing.T) {
		h, f := newNetworkFixture(t)
		r := mustNetworkApply(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"})
		f.values["net.ipv4.tcp_congestion_control"] = "reno"
		restored, e := h.Restore(r.SnapshotID)
		if e != nil || f.values["net.ipv4.tcp_congestion_control"] != "reno" || f.values["net.core.default_qdisc"] != "fq_codel" || !reflect.DeepEqual(restored.Preserved, []string{"net.ipv4.tcp_congestion_control"}) {
			t.Fatalf("manual kernel change overwritten: %#v %v", restored, e)
		}
	})
	t.Run("file", func(t *testing.T) {
		h, f := newNetworkFixture(t)
		r := mustNetworkApply(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"})
		manual := []byte("# administrator now owns this file\nnet.core.default_qdisc = noqueue\n")
		if e := os.WriteFile(h.SysctlFile, manual, 0644); e != nil {
			t.Fatal(e)
		}
		writes := len(f.writes)
		if _, e := h.Restore(r.SnapshotID); e == nil {
			t.Fatal("modified persistence accepted")
		}
		after, _ := os.ReadFile(h.SysctlFile)
		if !bytes.Equal(after, manual) || len(f.writes) != writes || f.values["net.core.default_qdisc"] != "fq" {
			t.Fatal("external file change was overwritten or triggered kernel restoration")
		}
	})
}

func TestNetworkStalePreviewUnownedFilesAndBounds(t *testing.T) {
	h, f := newNetworkFixture(t)
	p := mustNetworkPlan(t, h, NetworkRequest{TCP: "bbr"})
	f.values["net.ipv4.tcp_congestion_control"] = "reno"
	if _, e := h.Apply(p); e == nil || len(f.writes) != 0 {
		t.Fatal("stale preview applied")
	}
	if e := os.WriteFile(h.SysctlFile, []byte("# foreign sysctl\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Plan(NetworkRequest{Qdisc: "fq"}); e == nil {
		t.Fatal("foreign sysctl file accepted")
	}
	os.Remove(h.SysctlFile)
	for _, r := range []NetworkRequest{{TCP: "unavailable"}, {Qdisc: "fq\nmalicious"}, {RmemMax: 64 << 20}, {WmemMax: 1}, {RmemMax: 4096}} {
		if _, e := h.Plan(r); e == nil {
			t.Fatalf("invalid request accepted: %#v", r)
		}
	}
	os.WriteFile(filepath.Join(h.ProcRoot, "meminfo"), []byte("MemAvailable: 16 kB\n"), 0600)
	if _, e := h.Plan(NetworkRequest{RmemMax: 4 << 20}); e == nil {
		t.Fatal("buffer modification without resource evidence accepted")
	}
}

func TestNetworkConcurrentApplyAndUnsafePermissions(t *testing.T) {
	h, f := newNetworkFixture(t)
	p := mustNetworkPlan(t, h, NetworkRequest{Qdisc: "fq"})
	entered, release := make(chan struct{}), make(chan struct{})
	f.fail = func(key, value string) error {
		if key == "net.core.default_qdisc" && value == "fq" {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, e := h.Apply(p); done <- e }()
	<-entered
	if _, e := h.Apply(p); e == nil {
		t.Fatal("concurrent host mutation did not lock")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	os.Chmod(filepath.Join(h.StateDir, "active.json"), 0644)
	if _, e := h.Restore(p.SnapshotID); e == nil {
		t.Fatal("wide private pointer accepted")
	}
	other, _ := newNetworkFixture(t)
	if e := os.Mkdir(other.StateDir, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := other.Apply(mustNetworkPlan(t, other, NetworkRequest{Qdisc: "fq"})); e == nil {
		t.Fatal("unprotected host state directory accepted")
	}
}

func TestNetworkUnknownSnapshotVersionAndWriteFailure(t *testing.T) {
	h, f := newNetworkFixture(t)
	r := mustNetworkApply(t, h, NetworkRequest{TCP: "bbr"})
	original, _ := os.ReadFile(r.RecoveryFile)
	var raw map[string]any
	json.Unmarshal(original, &raw)
	raw["version"] = 2
	modified, _ := json.Marshal(raw)
	os.WriteFile(r.RecoveryFile, modified, 0600)
	writes := len(f.writes)
	if _, e := h.Restore(r.SnapshotID); e == nil || len(f.writes) != writes {
		t.Fatal("future snapshot format was guessed or migrated")
	}
	os.WriteFile(r.RecoveryFile, original, 0600)
	h2, f2 := newNetworkFixture(t)
	h2.Write = func(path string, data []byte, mode os.FileMode) error {
		if path == h2.SysctlFile {
			return os.ErrPermission
		}
		return AtomicWrite(path, data, mode)
	}
	res, e := h2.Apply(mustNetworkPlan(t, h2, NetworkRequest{TCP: "bbr"}))
	if e == nil || len(f2.writes) != 0 || res.RecoveryFile == "" {
		t.Fatalf("persistence write failure changed kernel or lost original: %#v %v", res, e)
	}
}

func TestNetworkNeverRestoresUnattemptedKernelFieldAfterPersistenceFailure(t *testing.T) {
	h, f := newNetworkFixture(t)
	h.Write = func(path string, b []byte, mode os.FileMode) error {
		if path == h.SysctlFile {
			f.values["net.ipv4.tcp_congestion_control"] = "bbr"
			return os.ErrPermission
		}
		return AtomicWrite(path, b, mode)
	}
	r, e := h.Apply(mustNetworkPlan(t, h, NetworkRequest{TCP: "bbr"}))
	if e == nil || f.values["net.ipv4.tcp_congestion_control"] != "bbr" || len(f.writes) != 0 || len(r.Preserved) != 1 {
		t.Fatalf("failed persistence undid an external value without any project sysctl attempt: %#v %v", r, e)
	}
}

func TestNetworkInterruptedSelectiveRestoreResumesAndPreservesEarlierHistory(t *testing.T) {
	h, f := newNetworkFixture(t)
	first := mustNetworkApply(t, h, NetworkRequest{TCP: "cubic", RmemMax: 4 << 20})
	second := mustNetworkApply(t, h, NetworkRequest{TCP: "bbr", Qdisc: "fq"})
	f.values["net.ipv4.tcp_congestion_control"] = "reno"
	crashed := false
	h.Write = func(path string, b []byte, mode os.FileMode) error {
		if path == filepath.Join(h.StateDir, "active.json") {
			crashed = true
			panic("simulated process termination after restored file write")
		}
		return AtomicWrite(path, b, mode)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("termination injection did not run")
			}
		}()
		h.Restore(second.SnapshotID)
	}()
	if !crashed {
		t.Fatal("restore never reached interrupted stage")
	}
	pending, _, e := h.pointer("pending.json")
	if e != nil || pending.Version != 2 || pending.RestoreFile == nil {
		t.Fatal("restored file ownership was not journaled", e)
	}
	h.Write = nil
	if _, e = h.RestorePlan(second.SnapshotID); e != nil {
		t.Fatal("resumable interrupted state rejected", e)
	}
	if _, e = h.Restore(second.SnapshotID); e != nil {
		t.Fatal(e)
	}
	if f.values["net.ipv4.tcp_congestion_control"] != "reno" || f.values["net.core.default_qdisc"] != "fq_codel" {
		t.Fatal("resume overwrote external field or failed eligible field")
	}
	if _, e = h.Restore(first.SnapshotID); e != nil {
		t.Fatal("project's own selective file restore blocked earlier original snapshot", e)
	}
	if f.values["net.core.rmem_max"] != "212992" || f.values["net.ipv4.tcp_congestion_control"] != "reno" {
		t.Fatal("earlier restore lost original buffer or external TCP choice")
	}
}

func TestNetworkUnavailableContainerReadingsRemainUnknown(t *testing.T) {
	h, f := newNetworkFixture(t)
	f.tcError = true
	delete(f.values, "net.ipv4.tcp_available_congestion_control")
	os.Remove(filepath.Join(h.ProcRoot, "stat"))
	os.Remove(filepath.Join(h.ProcRoot, "123", "status"))
	s := h.Status()
	if s.Sysctl["net.ipv4.tcp_available_congestion_control"].Available || s.QdiscUnavailable == "" || s.CPUStealTicks != nil || s.ProcessRSS != nil {
		t.Fatal("restricted readings reported as actual zero or usable")
	}
	if _, e := h.Plan(NetworkRequest{TCP: "bbr"}); e == nil {
		t.Fatal("missing kernel capability silently modprobed or guessed")
	}
	if len(f.writes) != 0 {
		t.Fatal("read-only diagnostics modified runtime")
	}
}

func TestNetworkRealLinuxStatusReadOnly(t *testing.T) {
	h := NetworkHost{StateDir: filepath.Join(t.TempDir(), "not-created"), SysctlFile: filepath.Join(t.TempDir(), "not-created.conf"), ProcessPID: os.Getpid()}
	s := h.Status()
	if s.Version != 1 {
		t.Fatal("missing diagnostic version")
	}
	if _, e := os.Stat(h.StateDir); !os.IsNotExist(e) {
		t.Fatal("real Linux read-only status wrote state")
	}
	if s.MemoryTotal == nil || s.Load1 == nil || s.ProcessRSS == nil {
		t.Log("procfs resources are restricted; missing values remain unknown")
	}
}

// This opt-in test must only run inside the disposable QEMU namespace. Its
// persistence is still confined to t.TempDir; kernel writes require the gate.
func TestNetworkDisposableLinuxApplyReadbackRestore(t *testing.T) {
	if os.Getenv("QINGNODE_HOST_NETWORK_DISPOSABLE") != "1" {
		t.Skip("requires explicitly authorized disposable Linux kernel namespace")
	}
	pid1, e := os.ReadFile("/proc/1/cmdline")
	hasInit := false
	for _, arg := range bytes.Split(pid1, []byte{0}) {
		if bytes.Equal(arg, []byte("/init")) {
			hasInit = true
		}
	}
	cmdline, ce := os.ReadFile("/proc/cmdline")
	if e != nil || !hasInit || ce != nil || !strings.Contains(" "+strings.TrimSpace(string(cmdline))+" ", " qingnode-disposable-hostnet=1 ") {
		t.Fatal("refusing kernel-write test outside the disposable /init VM")
	}
	base := t.TempDir()
	h := NetworkHost{StateDir: filepath.Join(base, "state"), SysctlFile: filepath.Join(base, "owned.conf")}
	before, e := h.value("net.core.rmem_max")
	if e != nil {
		t.Fatal(e)
	}
	request := uint64(2 << 20)
	if before == "2097152" {
		request = 4 << 20
	}
	result, e := h.Apply(mustNetworkPlan(t, h, NetworkRequest{RmemMax: request}))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Restore(result.SnapshotID) })
	applied, e := h.value("net.core.rmem_max")
	if e != nil || applied == before {
		t.Fatal("real sysctl write/readback did not change requested value", e)
	}
	if _, e = h.Restore(result.SnapshotID); e != nil {
		t.Fatal(e)
	}
	after, e := h.value("net.core.rmem_max")
	if e != nil || after != before {
		t.Fatal("real kernel original value not restored", e)
	}
}
