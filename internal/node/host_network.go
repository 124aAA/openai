package node

// Host network settings are an independent, explicitly requested transaction.
// They never enter node State or proxy configuration generations.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const NetworkSysctlFile = "/etc/sysctl.d/90-qingnode-network.conf"
const NetworkStateDir = "/var/lib/qingnode-host-network"
const networkFileHeader = "# QingNode host-network v1\n"
const maxNetworkBuffer = 16 << 20

type NetworkHost struct {
	Execute                                 Runner
	StateDir, SysctlFile, ProcRoot, SysRoot string
	ProcessPID                              int
	// Write is an isolated-test fault injection point. Production uses AtomicWrite.
	Write func(string, []byte, os.FileMode) error
}
type NetworkRequest struct {
	TCP     string `json:"tcp,omitempty"`
	Qdisc   string `json:"qdisc,omitempty"`
	RmemMax uint64 `json:"rmem_max,omitempty"`
	WmemMax uint64 `json:"wmem_max,omitempty"`
}
type NetworkChange struct {
	Key    string `json:"key"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type NetworkPlan struct {
	Version            int             `json:"version"`
	SnapshotID         string          `json:"snapshot_id"`
	RecoveryFile       string          `json:"recovery_file"`
	SysctlFile         string          `json:"sysctl_file"`
	Request            NetworkRequest  `json:"request"`
	Changes            []NetworkChange `json:"changes"`
	PersistenceChanged bool            `json:"persistence_changed"`
	Notes              []string        `json:"notes"`
	before             networkFile
	after              []byte
}
type NetworkApplyResult struct {
	Version      int      `json:"version"`
	SnapshotID   string   `json:"snapshot_id,omitempty"`
	RecoveryFile string   `json:"recovery_file,omitempty"`
	Changed      bool     `json:"changed"`
	Restored     []string `json:"restored,omitempty"`
	Preserved    []string `json:"preserved_external_changes,omitempty"`
}
type NetworkValue struct {
	Value     string `json:"value,omitempty"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}
type NetworkInterface struct {
	Name string  `json:"name"`
	MTU  *uint64 `json:"mtu"`
}
type NetworkQdisc struct {
	Kind      string `json:"kind"`
	Interface string `json:"dev"`
	Root      bool   `json:"root"`
}
type NetworkStatus struct {
	Version             int                     `json:"version"`
	Sysctl              map[string]NetworkValue `json:"sysctl"`
	Qdiscs              []NetworkQdisc          `json:"interface_qdiscs"`
	QdiscUnavailable    string                  `json:"qdisc_unavailable,omitempty"`
	Interfaces          []NetworkInterface      `json:"interfaces"`
	Load1               *float64                `json:"load1"`
	MemoryTotal         *uint64                 `json:"memory_total_bytes"`
	MemoryAvailable     *uint64                 `json:"memory_available_bytes"`
	HostMemoryAvailable *uint64                 `json:"host_memory_available_bytes"`
	CPUStealTicks       *uint64                 `json:"cpu_steal_ticks"`
	ProcessPID          int                     `json:"process_pid"`
	ProcessRSS          *uint64                 `json:"process_rss_bytes"`
	UDPCounters         map[string]uint64       `json:"namespace_udp_counters"`
	UDP6Counters        map[string]uint64       `json:"namespace_udp6_counters"`
	PendingSnapshot     string                  `json:"pending_snapshot,omitempty"`
	ActiveSnapshot      string                  `json:"active_snapshot,omitempty"`
	Notes               []string                `json:"notes"`
}
type networkFile struct {
	Exists bool   `json:"exists"`
	Data   []byte `json:"data,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
}
type networkSnapshot struct {
	Version       int             `json:"version"`
	ID            string          `json:"id"`
	CreatedAt     time.Time       `json:"created_at"`
	SysctlFile    string          `json:"sysctl_file"`
	Changes       []NetworkChange `json:"changes"`
	BeforeFile    networkFile     `json:"before_file"`
	AppliedSHA256 string          `json:"applied_sha256"`
	BeforeActive  []byte          `json:"before_active,omitempty"`
}
type networkPointer struct {
	Version     int          `json:"version"`
	SnapshotID  string       `json:"snapshot_id"`
	Touched     []string     `json:"touched,omitempty"`
	RestoreFile *networkFile `json:"restore_file,omitempty"`
}

var networkIDRE = regexp.MustCompile(`^n-[a-f0-9]{32}$`)
var networkKeys = []string{"net.core.default_qdisc", "net.core.rmem_max", "net.core.wmem_max", "net.ipv4.tcp_congestion_control"}

func (h NetworkHost) paths() (string, string) {
	dir, file := h.StateDir, h.SysctlFile
	if dir == "" {
		dir = NetworkStateDir
	}
	if file == "" {
		file = NetworkSysctlFile
	}
	return dir, file
}
func (h NetworkHost) run(name string, args ...string) ([]byte, error) {
	r := h.Execute
	if r == nil {
		r = Run
	}
	return r(2*time.Second, name, args...)
}
func (h NetworkHost) value(key string) (string, error) {
	b, e := h.run("sysctl", "-n", key)
	v := strings.TrimSpace(string(b))
	if e == nil && (v == "" || len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00")) {
		e = errors.New("sysctl 返回值为空或格式不支持")
	}
	return v, e
}
func (h NetworkHost) write(path string, b []byte, mode os.FileMode) error {
	if h.Write != nil {
		return h.Write(path, b, mode)
	}
	return AtomicWrite(path, b, mode)
}
func networkHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func networkRead(path string, private bool) (networkFile, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if os.IsNotExist(e) {
		return networkFile{}, nil
	}
	if e != nil {
		return networkFile{}, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return networkFile{}, e
	}
	if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Size() > 1<<20 {
		return networkFile{}, errors.New("宿主网络文件不是普通文件或超过 1 MiB，拒绝操作")
	}
	if private && i.Mode().Perm()&0077 != 0 {
		return networkFile{}, errors.New("宿主网络恢复文件权限过宽，拒绝读取")
	}
	if st, ok := i.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Geteuid()) {
		return networkFile{}, errors.New("宿主网络文件不属于当前管理用户，拒绝接管")
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(b) > 1<<20 {
		return networkFile{}, errors.New("宿主网络文件超过 1 MiB，拒绝读取")
	}
	return networkFile{true, b, uint32(i.Mode().Perm())}, e
}
func networkParse(data []byte) (map[string]string, error) {
	m := map[string]string{}
	if !strings.HasPrefix(string(data), networkFileHeader) {
		return nil, errors.New("同名 sysctl 文件不属于本功能，拒绝覆盖")
	}
	for _, line := range strings.Split(strings.TrimPrefix(string(data), networkFileHeader), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, " = ")
		if !ok || !networkKey(k) || m[k] != "" || v == "" || len(v) > 128 || strings.ContainsAny(v, "\r\n\x00") {
			return nil, errors.New("受管 sysctl 文件含未知、重复或无效字段，保留原件")
		}
		m[k] = v
	}
	return m, nil
}
func networkKey(k string) bool {
	for _, allowed := range networkKeys {
		if k == allowed {
			return true
		}
	}
	return false
}
func networkRender(m map[string]string) []byte {
	var b strings.Builder
	b.WriteString(networkFileHeader)
	for _, k := range networkKeys {
		if v, ok := m[k]; ok {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	return []byte(b.String())
}

// Plan only reads the live kernel and existing files. Its random snapshot ID
// reserves no path and creates no lock, directory, transaction or sysctl file.
func (h NetworkHost) Plan(request NetworkRequest) (NetworkPlan, error) {
	dir, file := h.paths()
	p := NetworkPlan{Version: 1, SnapshotID: "n-" + Token(16), SysctlFile: file, Request: request, Changes: []NetworkChange{}, Notes: []string{"TCP 算法只作用于新建 TCP 连接，不切换 Hysteria2 的用户态 QUIC 算法。", "default_qdisc 是新建队列的默认值，不代表现有网卡队列已经改变；本功能不运行 tc 修改接口。", "UDP 缓冲上限不等于每条连接实际分配；没有自动放大缓冲或按测速结果调参。"}}
	p.RecoveryFile = filepath.Join(dir, "snapshots", p.SnapshotID+".json")
	if f, e := networkRead(filepath.Join(dir, "pending.json"), true); e != nil {
		return p, e
	} else if f.Exists {
		return p, errors.New("有未完成的宿主网络事务；请先查看 network status，再显式 restore 对应快照")
	}
	before, e := networkRead(file, false)
	if e != nil {
		return p, e
	}
	p.before = before
	settings := map[string]string{}
	if before.Exists {
		// Never create a transaction whose original file its own recovery
		// validator would reject. Preview must leave unsafe originals intact.
		if e = validateNetworkFile(before); e != nil {
			return p, e
		}
		settings, e = networkParse(before.Data)
		if e != nil {
			return p, e
		}
	}
	requested := map[string]string{}
	if request.TCP != "" {
		if len(request.TCP) > 32 || strings.ContainsAny(request.TCP, " /\t\r\n=\x00") {
			return p, errors.New("TCP 算法名称无效")
		}
		available, e := h.value("net.ipv4.tcp_available_congestion_control")
		if e != nil {
			return p, errors.New("无法读取内核可用 TCP 算法；可能受容器或权限限制")
		}
		if !strings.Contains(" "+available+" ", " "+request.TCP+" ") {
			return p, errors.New("内核尚未列出请求的 TCP 算法；不会自动加载模块或安装内核")
		}
		requested["net.ipv4.tcp_congestion_control"] = request.TCP
	}
	if request.Qdisc != "" {
		if request.Qdisc != "fq" && request.Qdisc != "fq_codel" {
			return p, errors.New("默认队列只支持显式选择 fq 或 fq_codel")
		}
		requested["net.core.default_qdisc"] = request.Qdisc
	}
	for _, entry := range []struct {
		key, def string
		value    uint64
	}{{"net.core.rmem_max", "net.core.rmem_default", request.RmemMax}, {"net.core.wmem_max", "net.core.wmem_default", request.WmemMax}} {
		if entry.value == 0 {
			continue
		}
		if entry.value < 4096 || entry.value > maxNetworkBuffer {
			return p, errors.New("显式缓冲上限必须在 4096 字节到 16 MiB 之间；不自动放大")
		}
		def, e := h.value(entry.def)
		if e != nil {
			return p, errors.New("无法读取当前 socket 默认缓冲；拒绝猜测新的上限")
		}
		minimum, e := strconv.ParseUint(def, 10, 64)
		if e != nil || entry.value < minimum {
			return p, errors.New("请求的缓冲上限不能低于当前 socket 默认缓冲")
		}
		proc := h.ProcRoot
		if proc == "" {
			proc = "/proc"
		}
		available, e := AvailableMemory(proc, h.SysRoot)
		if e != nil {
			return p, e
		}
		if available == nil || *available < entry.value*16 {
			return p, errors.New("可用内存依据不足：缓冲上限不得超过当前 MemAvailable 的 1/16")
		}
		requested[entry.key] = strconv.FormatUint(entry.value, 10)
	}
	for _, key := range networkKeys {
		after, ok := requested[key]
		if !ok {
			continue
		}
		before, e := h.value(key)
		if e != nil {
			return p, fmt.Errorf("无法读取 %s；本次不应用任何字段", key)
		}
		p.Changes = append(p.Changes, NetworkChange{key, before, after})
		settings[key] = after
	}
	p.after = networkRender(settings)
	p.PersistenceChanged = len(requested) > 0 && (!before.Exists || !bytes.Equal(before.Data, p.after))
	return p, nil
}

func networkPrivateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	i, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
		return errors.New("宿主网络恢复目录必须为本用户的私有普通目录")
	}
	if st, ok := i.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Geteuid()) {
		return errors.New("宿主网络目录不属于当前管理用户")
	}
	return nil
}
func (h NetworkHost) locked(fn func() error) error {
	dir, _ := h.paths()
	if e := networkPrivateDir(dir); e != nil {
		return e
	}
	p := filepath.Join(dir, ".lock")
	if i, e := os.Lstat(p); e == nil && (!i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0) {
		return errors.New("宿主网络锁文件不安全，拒绝操作")
	}
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("另一个宿主网络操作正在运行，请稍后重试")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}
func networkDecode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					t, e = d.Token()
					if e != nil {
						return e
					}
					k, ok := t.(string)
					if !ok || seen[k] {
						return errors.New("恢复记录出现重复 JSON 字段")
					}
					seen[k] = true
					if e = walk(); e != nil {
						return e
					}
				}
			} else if delim == '[' {
				for d.More() {
					if e = walk(); e != nil {
						return e
					}
				}
			} else {
				return errors.New("恢复记录 JSON 格式无效")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("恢复记录含多余 JSON 内容")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func (h NetworkHost) writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return h.write(path, append(b, '\n'), 0600)
}
func (h NetworkHost) pointer(name string) (networkPointer, []byte, error) {
	dir, _ := h.paths()
	f, e := networkRead(filepath.Join(dir, name), true)
	if e != nil || !f.Exists {
		return networkPointer{}, nil, e
	}
	var p networkPointer
	if e = networkDecode(f.Data, &p); e != nil {
		return p, nil, e
	}
	validVersion := p.Version == 2
	if name != "pending.json" {
		validVersion = (p.Version == 1 && p.RestoreFile == nil) || (p.Version == 2 && p.RestoreFile != nil)
		validVersion = validVersion && len(p.Touched) == 0
	}
	if !validVersion || !networkIDRE.MatchString(p.SnapshotID) {
		return p, nil, errors.New("宿主网络记录版本或快照 ID 不受支持")
	}
	seen := map[string]bool{}
	for _, key := range p.Touched {
		if !networkKey(key) || seen[key] {
			return p, nil, errors.New("宿主网络事务含未知或重复的已触及字段")
		}
		seen[key] = true
	}
	if p.RestoreFile != nil {
		if e := validateNetworkFile(*p.RestoreFile); e != nil {
			return p, nil, e
		}
	}
	return p, f.Data, nil
}
func (h NetworkHost) Apply(plan NetworkPlan) (result NetworkApplyResult, err error) {
	result.Version = 1
	err = h.locked(func() error {
		if plan.Version != 1 || !networkIDRE.MatchString(plan.SnapshotID) {
			return errors.New("宿主网络计划格式不受支持")
		}
		fresh, e := h.Plan(plan.Request)
		if e != nil {
			return e
		}
		if plan.SysctlFile != fresh.SysctlFile || plan.RecoveryFile != filepath.Join(filepath.Dir(filepath.Dir(fresh.RecoveryFile)), "snapshots", plan.SnapshotID+".json") || plan.PersistenceChanged != fresh.PersistenceChanged || !reflect.DeepEqual(plan.Changes, fresh.Changes) || !reflect.DeepEqual(plan.before, fresh.before) || !bytes.Equal(plan.after, fresh.after) {
			return errors.New("预览后宿主参数或文件已变化，请重新生成计划；没有应用任何字段")
		}
		runtimeChanged := false
		for _, c := range plan.Changes {
			runtimeChanged = runtimeChanged || c.Before != c.After
		}
		if !runtimeChanged && !plan.PersistenceChanged {
			return nil
		}
		dir, file := h.paths()
		if e = networkPrivateDir(filepath.Join(dir, "snapshots")); e != nil {
			return e
		}
		_, active, e := h.pointer("active.json")
		if e != nil {
			return e
		}
		snapshot := networkSnapshot{1, plan.SnapshotID, time.Now().UTC(), file, plan.Changes, plan.before, networkHash(plan.after), active}
		if f, e := networkRead(plan.RecoveryFile, true); e != nil {
			return e
		} else if f.Exists {
			return errors.New("同名恢复快照已存在，拒绝覆盖")
		}
		if e = h.writeJSON(plan.RecoveryFile, snapshot); e != nil {
			return e
		}
		result.SnapshotID, result.RecoveryFile = plan.SnapshotID, plan.RecoveryFile
		pending := networkPointer{Version: 2, SnapshotID: plan.SnapshotID}
		if e = h.writeJSON(filepath.Join(dir, "pending.json"), pending); e != nil {
			return e
		}
		failed := func(cause error) error {
			recovered, re := h.restoreSnapshot(snapshot, false)
			result.Restored, result.Preserved = recovered.Restored, recovered.Preserved
			if re != nil {
				return fmt.Errorf("宿主网络应用失败：%v；恢复未完成：%w；材料：%s", cause, re, plan.RecoveryFile)
			}
			if len(result.Preserved) > 0 {
				return fmt.Errorf("宿主网络应用失败；可恢复字段已恢复，外部手动变更已保留：%w；材料：%s", cause, plan.RecoveryFile)
			}
			return fmt.Errorf("宿主网络应用失败，已逐项恢复原值：%w；材料：%s", cause, plan.RecoveryFile)
		}
		latest, e := networkRead(file, false)
		if e != nil {
			return failed(e)
		}
		if !reflect.DeepEqual(latest, plan.before) {
			return failed(errors.New("写入前受管 sysctl 文件发生外部变化"))
		}
		if e = h.write(file, plan.after, 0644); e != nil {
			return failed(e)
		}
		for _, c := range plan.Changes {
			if c.Before == c.After {
				continue
			}
			v, e := h.value(c.Key)
			if e != nil || v != c.Before {
				return failed(fmt.Errorf("写入前 %s 已发生变化", c.Key))
			}
			pending.Touched = append(pending.Touched, c.Key)
			if e = h.writeJSON(filepath.Join(dir, "pending.json"), pending); e != nil {
				return failed(e)
			}
			if _, e = h.run("sysctl", "-w", c.Key+"="+c.After); e != nil {
				return failed(fmt.Errorf("写入 %s 未成功", c.Key))
			}
			v, e = h.value(c.Key)
			if e != nil || v != c.After {
				return failed(fmt.Errorf("%s 应用后读回不一致", c.Key))
			}
		}
		if e = h.writeJSON(filepath.Join(dir, "active.json"), networkPointer{Version: 1, SnapshotID: plan.SnapshotID}); e != nil {
			return failed(e)
		}
		if e = os.Remove(filepath.Join(dir, "pending.json")); e != nil {
			return e
		}
		if e = SyncDir(dir); e != nil {
			return e
		}
		result.Changed = true
		return nil
	})
	return
}

func (h NetworkHost) Restore(id string) (result NetworkApplyResult, err error) {
	result.Version = 1
	err = h.locked(func() error {
		if !networkIDRE.MatchString(id) {
			return errors.New("恢复需要预览或应用结果中的完整快照 ID")
		}
		dir, file := h.paths()
		pending, _, e := h.pointer("pending.json")
		if e != nil {
			return e
		}
		active, _, e := h.pointer("active.json")
		if e != nil {
			return e
		}
		if pending.SnapshotID != "" && pending.SnapshotID != id {
			return errors.New("先恢复当前未完成的宿主网络事务")
		}
		if pending.SnapshotID == "" && active.SnapshotID != id {
			return errors.New("只能恢复当前最新宿主网络快照；不会越过后续变更")
		}
		f, e := networkRead(filepath.Join(dir, "snapshots", id+".json"), true)
		if e != nil {
			return e
		}
		if !f.Exists {
			return errors.New("宿主网络原始恢复快照缺失")
		}
		var snapshot networkSnapshot
		if e = networkDecode(f.Data, &snapshot); e != nil {
			return e
		}
		if e = validateNetworkSnapshot(snapshot, id, file); e != nil {
			return e
		}
		if pending.SnapshotID == "" {
			pending = networkPointer{Version: 2, SnapshotID: id}
			if active.Version == 2 {
				pending.RestoreFile = active.RestoreFile
			}
			for _, c := range snapshot.Changes {
				if c.Before != c.After {
					pending.Touched = append(pending.Touched, c.Key)
				}
			}
			if e = h.writeJSON(filepath.Join(dir, "pending.json"), pending); e != nil {
				return e
			}
		}
		result, e = h.restoreSnapshot(snapshot, true)
		return e
	})
	return
}

// RestorePlan reads the saved original and current values without repairing
// pending work. Actual restore repeats every guard while holding its own lock.
func (h NetworkHost) RestorePlan(id string) (p NetworkPlan, err error) {
	dir, file := h.paths()
	p = NetworkPlan{Version: 1, SnapshotID: id, SysctlFile: file, RecoveryFile: filepath.Join(dir, "snapshots", id+".json"), Changes: []NetworkChange{}, Notes: []string{"只有当前仍等于本项目应用值的字段才恢复；外部手动变更保留。", "受管文件被外部修改时，全部恢复停止，原始恢复材料保留。"}}
	if !networkIDRE.MatchString(id) {
		return p, errors.New("恢复需要完整快照 ID")
	}
	pending, _, e := h.pointer("pending.json")
	if e != nil {
		return p, e
	}
	active, _, e := h.pointer("active.json")
	if e != nil {
		return p, e
	}
	if (pending.SnapshotID != "" && pending.SnapshotID != id) || (pending.SnapshotID == "" && active.SnapshotID != id) {
		return p, errors.New("只能预览当前最新或未完成的宿主网络快照")
	}
	f, e := networkRead(p.RecoveryFile, true)
	if e != nil {
		return p, e
	}
	if !f.Exists {
		return p, errors.New("原始恢复快照缺失")
	}
	var s networkSnapshot
	if e = networkDecode(f.Data, &s); e != nil {
		return p, e
	}
	if e = validateNetworkSnapshot(s, id, file); e != nil {
		return p, e
	}
	current, e := networkRead(file, false)
	if e != nil {
		return p, e
	}
	if !reflect.DeepEqual(current, s.BeforeFile) && (!current.Exists || networkHash(current.Data) != s.AppliedSHA256 || current.Mode != 0644) && (pending.RestoreFile == nil || !reflect.DeepEqual(current, *pending.RestoreFile)) && (active.Version != 2 || active.RestoreFile == nil || !reflect.DeepEqual(current, *active.RestoreFile)) {
		return p, errors.New("受管文件已被外部修改；不会覆盖文件或运行参数")
	}
	p.PersistenceChanged = !reflect.DeepEqual(current, s.BeforeFile)
	for _, c := range s.Changes {
		v, e := h.value(c.Key)
		if e != nil {
			return p, e
		}
		after := v
		wasTouched := pending.SnapshotID == ""
		for _, key := range pending.Touched {
			if key == c.Key {
				wasTouched = true
			}
		}
		if v == c.After && wasTouched {
			after = c.Before
		} else if v != c.Before {
			p.Notes = append(p.Notes, c.Key+" 已被外部改为 "+v+"，保持不变")
		}
		p.Changes = append(p.Changes, NetworkChange{c.Key, v, after})
	}
	return p, nil
}
func validateNetworkSnapshot(s networkSnapshot, id, file string) error {
	if s.Version != 1 || s.ID != id || s.SysctlFile != file || len(s.AppliedSHA256) != 64 || strings.Trim(s.AppliedSHA256, "0123456789abcdef") != "" || len(s.Changes) > len(networkKeys) {
		return errors.New("恢复快照版本、归属或格式无效")
	}
	seen := map[string]bool{}
	for _, c := range s.Changes {
		if !networkKey(c.Key) || seen[c.Key] || c.Before == "" || c.After == "" || strings.ContainsAny(c.Before+c.After, "\r\n\x00=") {
			return errors.New("恢复快照含未知或重复参数，拒绝猜测")
		}
		seen[c.Key] = true
	}
	if e := validateNetworkFile(s.BeforeFile); e != nil {
		return e
	}
	if len(s.BeforeActive) > 0 {
		var p networkPointer
		if e := networkDecode(s.BeforeActive, &p); e != nil {
			return e
		}
		validVersion := (p.Version == 1 && p.RestoreFile == nil) || (p.Version == 2 && p.RestoreFile != nil)
		if !validVersion || !networkIDRE.MatchString(p.SnapshotID) || len(p.Touched) > 0 {
			return errors.New("前序宿主快照格式不支持")
		}
		if p.RestoreFile != nil {
			if e := validateNetworkFile(*p.RestoreFile); e != nil {
				return e
			}
		}
	}
	return nil
}

func validateNetworkFile(f networkFile) error {
	if !f.Exists {
		if len(f.Data) > 0 || f.Mode != 0 {
			return errors.New("不存在的恢复文件却带有内容或权限")
		}
		return nil
	}
	if _, e := networkParse(f.Data); e != nil {
		return e
	}
	if f.Mode&0022 != 0 || f.Mode&0111 != 0 || f.Mode&0400 == 0 {
		return errors.New("恢复快照中的受管文件权限不支持")
	}
	return nil
}
func (h NetworkHost) restoreSnapshot(s networkSnapshot, explicit bool) (result NetworkApplyResult, err error) {
	dir, file := h.paths()
	result = NetworkApplyResult{Version: 1, SnapshotID: s.ID, RecoveryFile: filepath.Join(dir, "snapshots", s.ID+".json")}
	current, e := networkRead(file, false)
	if e != nil {
		return result, e
	}
	pending, _, e := h.pointer("pending.json")
	if e != nil {
		return result, e
	}
	if pending.SnapshotID != s.ID {
		return result, errors.New("当前宿主事务与原始恢复材料不一致")
	}
	fileIsBefore := reflect.DeepEqual(current, s.BeforeFile)
	if !fileIsBefore && (!current.Exists || networkHash(current.Data) != s.AppliedSHA256 || current.Mode != 0644) && (pending.RestoreFile == nil || !reflect.DeepEqual(current, *pending.RestoreFile)) {
		return result, errors.New("受管 sysctl 文件已被外部修改；保留文件和全部运行参数，请人工核对恢复材料")
	}
	var failures []error
	for i := len(s.Changes) - 1; i >= 0; i-- {
		c := s.Changes[i]
		value, e := h.value(c.Key)
		if e != nil {
			failures = append(failures, fmt.Errorf("无法读回 %s", c.Key))
			continue
		}
		if value == c.Before {
			continue
		}
		wasTouched := false
		for _, key := range pending.Touched {
			if key == c.Key {
				wasTouched = true
			}
		}
		if value != c.After || !wasTouched {
			result.Preserved = append(result.Preserved, c.Key)
			continue
		}
		if _, e = h.run("sysctl", "-w", c.Key+"="+c.Before); e != nil {
			failures = append(failures, fmt.Errorf("%s 恢复写入失败", c.Key))
			continue
		}
		value, e = h.value(c.Key)
		if e != nil || value != c.Before {
			failures = append(failures, fmt.Errorf("%s 恢复后读回不一致", c.Key))
			continue
		}
		result.Restored = append(result.Restored, c.Key)
	}
	if len(failures) > 0 {
		return result, errors.Join(failures...)
	}
	before := s.BeforeFile
	if len(result.Preserved) > 0 && before.Exists {
		settings, e := networkParse(before.Data)
		if e != nil {
			return result, e
		}
		for _, key := range result.Preserved {
			delete(settings, key)
		}
		before.Data = networkRender(settings)
		if len(settings) == 0 {
			before = networkFile{}
		}
	}
	// Re-read immediately before replacing persistence: a manual file edit
	// during recovery must not be overwritten by the saved original.
	latest, e := networkRead(file, false)
	if e != nil {
		return result, e
	}
	if !reflect.DeepEqual(latest, current) {
		return result, errors.New("恢复期间受管 sysctl 文件发生外部变化，已停止覆盖")
	}
	pending.RestoreFile = &before
	if e = h.writeJSON(filepath.Join(dir, "pending.json"), pending); e != nil {
		return result, e
	}
	if before.Exists {
		if !reflect.DeepEqual(latest, before) {
			if e = h.write(file, before.Data, os.FileMode(before.Mode)); e != nil {
				return result, e
			}
		}
	} else if latest.Exists {
		if e = os.Remove(file); e != nil {
			return result, e
		}
		if e = SyncDir(filepath.Dir(file)); e != nil {
			return result, e
		}
	}
	if len(s.BeforeActive) > 0 {
		previousActive := s.BeforeActive
		if len(result.Preserved) > 0 {
			var pointer networkPointer
			if e = networkDecode(s.BeforeActive, &pointer); e != nil {
				return result, e
			}
			pointer.Version = 2
			pointer.RestoreFile = &before
			previousActive, e = json.Marshal(pointer)
			if e != nil {
				return result, e
			}
			previousActive = append(previousActive, '\n')
		}
		if e = h.write(filepath.Join(dir, "active.json"), previousActive, 0600); e != nil {
			return result, e
		}
	} else {
		if e = os.Remove(filepath.Join(dir, "active.json")); e != nil && !os.IsNotExist(e) {
			return result, e
		}
	}
	if e = os.Remove(filepath.Join(dir, "pending.json")); e != nil && !os.IsNotExist(e) {
		return result, e
	}
	if e = SyncDir(dir); e != nil {
		return result, e
	}
	result.Changed = len(result.Restored) > 0 || !reflect.DeepEqual(current, before)
	_ = explicit
	return result, nil
}

// Status deliberately does not acquire a write lock or repair pending work.
func (h NetworkHost) Status() NetworkStatus {
	s := NetworkStatus{Version: 1, Sysctl: map[string]NetworkValue{}, Qdiscs: []NetworkQdisc{}, Interfaces: []NetworkInterface{}, UDPCounters: map[string]uint64{}, ProcessPID: h.ProcessPID, Notes: []string{"拥塞算法是 TCP 的默认选择，不代表 Hysteria2 用户态 QUIC 算法。", "默认队列与实际接口队列分开；已有接口不会因 default_qdisc 值自动变更。", "UDP 计数是当前网络命名空间累计值，不能当成本节点丢包；CPU steal 为累计时钟计数，不能当成当前百分比。", "容器/LXC 可能只暴露宿主的部分数值或拒绝修改；缺失值按未知显示，不推测资源配额或自动调整。"}}
	for _, key := range []string{"net.ipv4.tcp_available_congestion_control", "net.ipv4.tcp_congestion_control", "net.core.default_qdisc", "net.core.rmem_default", "net.core.rmem_max", "net.core.wmem_default", "net.core.wmem_max", "net.ipv4.udp_rmem_min", "net.ipv4.udp_wmem_min", "net.ipv4.udp_mem"} {
		v, e := h.value(key)
		if e == nil {
			s.Sysctl[key] = NetworkValue{Value: v, Available: true}
		} else {
			s.Sysctl[key] = NetworkValue{Reason: "不可读取；内核、命名空间或权限可能受限"}
		}
	}
	if b, e := h.run("tc", "-j", "qdisc", "show"); e == nil {
		if e = json.Unmarshal(b, &s.Qdiscs); e != nil {
			s.QdiscUnavailable = "tc 输出无法解析，实际接口队列未知"
			s.Qdiscs = []NetworkQdisc{}
		}
	} else {
		s.QdiscUnavailable = "tc 不可用或查询被拒绝，实际接口队列未知"
	}
	proc, sys := h.ProcRoot, h.SysRoot
	if proc == "" {
		proc = "/proc"
	}
	if sys == "" {
		sys = "/sys"
	}
	if b, e := os.ReadFile(filepath.Join(proc, "loadavg")); e == nil {
		s.Load1 = parseOverviewLoad(string(b))
	}
	if b, e := os.ReadFile(filepath.Join(proc, "meminfo")); e == nil {
		s.MemoryTotal, s.HostMemoryAvailable = parseOverviewMemory(string(b))
	}
	if available, e := AvailableMemory(proc, sys); e == nil {
		s.MemoryAvailable = available
	} else {
		s.Notes = append(s.Notes, "有效可用内存未知："+e.Error())
	}
	if b, e := os.ReadFile(filepath.Join(proc, "stat")); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) > 8 && f[0] == "cpu" {
				if v, e := strconv.ParseUint(f[8], 10, 64); e == nil {
					s.CPUStealTicks = &v
				}
				break
			}
		}
	}
	if h.ProcessPID > 0 {
		if b, e := os.ReadFile(filepath.Join(proc, strconv.Itoa(h.ProcessPID), "status")); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Fields(line)
				if len(f) == 3 && f[0] == "VmRSS:" && f[2] == "kB" {
					if v, e := strconv.ParseUint(f[1], 10, 64); e == nil && v < (^uint64(0))/1024 {
						v *= 1024
						s.ProcessRSS = &v
					}
				}
			}
		}
	}
	if b, e := os.ReadFile(filepath.Join(proc, "net", "snmp")); e == nil {
		lines := strings.Split(string(b), "\n")
		for i := 0; i+1 < len(lines); i++ {
			keys, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
			if len(keys) > 1 && len(keys) == len(values) && keys[0] == "Udp:" && values[0] == "Udp:" {
				for j := 1; j < len(keys); j++ {
					if v, e := strconv.ParseUint(values[j], 10, 64); e == nil {
						s.UDPCounters[keys[j]] = v
					}
				}
			}
		}
	}
	s.UDP6Counters = map[string]uint64{}
	if b, e := os.ReadFile(filepath.Join(proc, "net", "snmp6")); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && strings.HasPrefix(f[0], "Udp6") {
				if value, e := strconv.ParseUint(f[1], 10, 64); e == nil {
					s.UDP6Counters[strings.TrimPrefix(f[0], "Udp6")] = value
				}
			}
		}
	}
	if entries, e := os.ReadDir(filepath.Join(sys, "class", "net")); e == nil {
		for _, entry := range entries {
			n := NetworkInterface{Name: entry.Name()}
			if b, e := os.ReadFile(filepath.Join(sys, "class", "net", entry.Name(), "mtu")); e == nil {
				if v, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); e == nil {
					n.MTU = &v
				}
			}
			s.Interfaces = append(s.Interfaces, n)
		}
	}
	if p, _, e := h.pointer("pending.json"); e == nil {
		s.PendingSnapshot = p.SnapshotID
	} else {
		s.Notes = append(s.Notes, "宿主网络 pending 记录损坏或版本不受支持；本次只读，不自动恢复。")
	}
	if p, _, e := h.pointer("active.json"); e == nil {
		s.ActiveSnapshot = p.SnapshotID
	} else {
		s.Notes = append(s.Notes, "宿主网络 active 记录损坏或版本不受支持。")
	}
	return s
}

func FormatNetworkPlan(p NetworkPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "宿主网络计划 v%d（预览不写入）\n受管文件：%s\n原始恢复材料：%s\n", p.Version, p.SysctlFile, p.RecoveryFile)
	for _, c := range p.Changes {
		fmt.Fprintf(&b, "%s：当前 %s → 请求 %s\n", c.Key, c.Before, c.After)
	}
	if len(p.Changes) == 0 {
		b.WriteString("没有请求修改参数；不会自动选择缓冲或算法。\n")
	}
	for _, note := range p.Notes {
		fmt.Fprintf(&b, "说明：%s\n", note)
	}
	return b.String()
}
func FormatNetworkStatus(s NetworkStatus) string {
	var b strings.Builder
	b.WriteString("宿主网络只读状态\n")
	keys := make([]string, 0, len(s.Sysctl))
	for k := range s.Sysctl {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := s.Sysctl[k]
		if v.Available {
			fmt.Fprintf(&b, "%s：%s\n", k, v.Value)
		} else {
			fmt.Fprintf(&b, "%s：未知（%s）\n", k, v.Reason)
		}
	}
	for _, q := range s.Qdiscs {
		fmt.Fprintf(&b, "实际接口队列：%s = %s（root=%t）\n", q.Interface, q.Kind, q.Root)
	}
	if s.QdiscUnavailable != "" {
		fmt.Fprintln(&b, s.QdiscUnavailable)
	}
	for _, n := range s.Interfaces {
		if n.MTU != nil {
			fmt.Fprintf(&b, "接口 MTU：%s = %d（不等于公网路径 MTU）\n", n.Name, *n.MTU)
		}
	}
	if s.Load1 != nil {
		fmt.Fprintf(&b, "1 分钟负载：%.2f（不是 CPU 使用率）\n", *s.Load1)
	} else {
		b.WriteString("1 分钟负载：未知\n")
	}
	if s.MemoryAvailable != nil {
		fmt.Fprintf(&b, "内存：考虑可见 cgroup 约束后可用 %d bytes\n", *s.MemoryAvailable)
	} else {
		b.WriteString("内存：有效可用量未知，不据宿主 RAM 推荐缓冲\n")
	}
	if s.HostMemoryAvailable != nil {
		fmt.Fprintf(&b, "MemAvailable 原始读数：%d bytes（不代表容器配额）\n", *s.HostMemoryAvailable)
	}
	if s.CPUStealTicks != nil {
		fmt.Fprintf(&b, "CPU steal 累计计数：%d（当前百分比未知）\n", *s.CPUStealTicks)
	} else {
		b.WriteString("CPU steal 累计计数：未知\n")
	}
	if s.ProcessRSS != nil {
		fmt.Fprintf(&b, "进程 %d RSS：%d bytes\n", s.ProcessPID, *s.ProcessRSS)
	} else {
		b.WriteString("代理进程 RSS：未知\n")
	}
	for _, k := range []string{"InErrors", "RcvbufErrors", "SndbufErrors", "InCsumErrors", "NoPorts"} {
		if v, ok := s.UDPCounters[k]; ok {
			fmt.Fprintf(&b, "网络命名空间 IPv4 UDP 累计 %s：%d\n", k, v)
		} else {
			fmt.Fprintf(&b, "网络命名空间 IPv4 UDP 累计 %s：未知\n", k)
		}
		if value, ok := s.UDP6Counters[k]; ok {
			fmt.Fprintf(&b, "网络命名空间 IPv6 UDP 累计 %s：%d\n", k, value)
		} else {
			fmt.Fprintf(&b, "网络命名空间 IPv6 UDP 累计 %s：未知\n", k)
		}
	}
	if s.PendingSnapshot != "" {
		fmt.Fprintf(&b, "未完成宿主事务：%s；需显式 network restore --snapshot %s\n", s.PendingSnapshot, s.PendingSnapshot)
	}
	if s.ActiveSnapshot != "" {
		fmt.Fprintf(&b, "当前宿主快照：%s\n", s.ActiveSnapshot)
	}
	for _, note := range s.Notes {
		fmt.Fprintf(&b, "说明：%s\n", note)
	}
	return b.String()
}
