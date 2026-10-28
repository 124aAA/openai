package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const OwnerMarker = "QingNode managed directory v1\n"
const maxStateBytes = 8 << 20

type Backend interface {
	Check(State, string) error
	Active() bool
	Activate(State) error
	Stop() error
}
type Effects interface {
	PrepareEffects(State, State) error
	FinishEffects(State, State) error
}

// ActivityBackend is optional for existing isolated backends. A production
// service backend must distinguish a stopped service from a failed observation.
type ActivityBackend interface {
	ActiveState() (bool, error)
}
type OfflineBackend struct{}

func (OfflineBackend) Check(State, string) error { return nil }
func (OfflineBackend) Active() bool              { return false }
func (OfflineBackend) Activate(State) error      { return nil }
func (OfflineBackend) Stop() error               { return nil }

type Store struct {
	Root    string
	Backend Backend
	GID     int
	// AfterCommit publishes derived device material only after a successful
	// configuration commit. Failure cannot undo a committed proxy transaction.
	AfterCommit func(State) error
	// Authorization revocations are fail-closed and intentionally not restored
	// if the following proxy transaction fails or is rolled back.
	BeforeCommit func(State) error
}
type journal struct {
	Previous  string `json:"previous"`
	Next      string `json:"next"`
	WasActive bool   `json:"was_active"`
}

// The envelope deliberately has none of the legacy top-level pointer fields.
// A legacy manager therefore rejects a pending v2 transaction instead of
// interpreting an unknown restart policy and interrupting a live connection.
type transactionEnvelope struct {
	Transaction journalV2 `json:"transaction_v2"`
}
type journalV2 struct {
	Version        int    `json:"version"`
	Previous       string `json:"previous"`
	Next           string `json:"next"`
	WasActive      bool   `json:"was_active"`
	RuntimeChanged bool   `json:"runtime_changed"`
	HostEffects    bool   `json:"host_effects"`
}

var generationRE = regexp.MustCompile(`^generations/g-[a-f0-9]{32}$`)

func SyncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".write-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return SyncDir(filepath.Dir(path))
}
func ReadState(p string) (State, error) {
	var s State
	f, e := os.Open(p)
	if e != nil {
		return s, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if e != nil {
		return s, e
	}
	if len(b) > maxStateBytes {
		return s, errors.New("状态文件超过 8 MiB 上限")
	}
	return DecodeState(b)
}
func (s *Store) ensure() error {
	if !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) == "/" {
		return errors.New("状态目录须为绝对路径且不能是根目录")
	}
	if i, e := os.Lstat(s.Root); e == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
		return errors.New("拒绝使用符号链接或非目录作为状态目录")
	}
	if e := os.MkdirAll(s.Root, 0750); e != nil {
		return e
	}
	marker := filepath.Join(s.Root, ".qingnode-owner")
	b, e := os.ReadFile(marker)
	if errors.Is(e, os.ErrNotExist) {
		entries, e := os.ReadDir(s.Root)
		if e != nil {
			return e
		}
		if len(entries) != 0 {
			return errors.New("目标目录非空且没有 QingNode 所有权标记，拒绝接管")
		}
		if e = AtomicWrite(marker, []byte(OwnerMarker), 0600); e != nil {
			return e
		}
	} else if e != nil || string(b) != OwnerMarker {
		return errors.New("QingNode 所有权标记无效")
	}
	for _, p := range []string{s.Root, filepath.Join(s.Root, "generations"), filepath.Join(s.Root, "cores")} {
		if i, e := os.Lstat(p); e == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
			return errors.New("管理子目录不能是符号链接")
		}
		if p == filepath.Join(s.Root, "cores") {
			_, trashErr := os.Lstat(filepath.Join(s.Root, ".uninstall-cores"))
			_, journalErr := os.Lstat(filepath.Join(s.Root, "uninstall.json"))
			if trashErr == nil && journalErr == nil {
				continue // Let removal recovery rename the original directory back first.
			}
		}
		if e := os.MkdirAll(p, 0750); e != nil {
			return e
		}
		if s.GID >= 0 {
			if e := os.Chown(p, 0, s.GID); e != nil {
				return e
			}
		}
		// MkdirAll applies the caller's umask; the service group needs traversal.
		if e := os.Chmod(p, 0750); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) WithLock(fn func() error) error {
	return s.withLock(true, false, fn)
}

// WithLockNoRecovery prepares an owned directory and takes the management lock,
// but never repairs pending transactions. The caller must reject pending work.
func (s *Store) WithLockNoRecovery(fn func() error) error {
	if !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) == "/" {
		return errors.New("状态目录须为绝对路径且不能是根目录")
	}
	if err := os.Mkdir(s.Root, 0750); err != nil {
		if errors.Is(err, os.ErrExist) {
			return s.withLock(false, true, fn)
		}
		return err
	}
	// We exclusively created this root; establish and hold its lock before
	// writing the owner marker or changing any managed directory permissions.
	fd, err := syscall.Open(filepath.Join(s.Root, ".lock"), syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(s.Root, ".lock"))
	defer f.Close()
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("另一个 QingNode 操作正在运行，请稍后重试")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	if err = AtomicWrite(filepath.Join(s.Root, ".qingnode-owner"), []byte(OwnerMarker), 0600); err != nil {
		return err
	}
	if err = s.ensure(); err != nil {
		return err
	}
	return fn()
}

// Inspect holds the management lock without repairing or restarting a broken service.
func (s *Store) Inspect(fn func() error) error { return s.withLock(false, false, fn) }

// InspectExisting requires a managed directory and never calls fn without its lock.
func (s *Store) InspectExisting(fn func() error) error { return s.withLock(false, true, fn) }
func (s *Store) withLock(recover, requireExisting bool, fn func() error) error {
	if !recover {
		i, e := os.Lstat(s.Root)
		if errors.Is(e, os.ErrNotExist) {
			if requireExisting {
				return fmt.Errorf("状态目录不存在：%w", e)
			}
			return fn()
		}
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("状态目录无效")
		}
		marker, e := os.ReadFile(filepath.Join(s.Root, ".qingnode-owner"))
		if e != nil || string(marker) != OwnerMarker {
			return errors.New("QingNode 所有权标记无效")
		}
	} else {
		if e := s.ensure(); e != nil {
			return e
		}
	}
	p := filepath.Join(s.Root, ".lock")
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("另一个 QingNode 操作正在运行，请稍后重试")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	if recover {
		if e = MigrationPending(s.Root); e != nil {
			return e
		}
		if b, ok := s.Backend.(interface{ RecoverRemoval() error }); ok {
			if e = b.RecoverRemoval(); e != nil {
				return e
			}
		}
		if e = s.Recover(); e != nil {
			return e
		}
	}
	return fn()
}
func (s *Store) current() (string, error) {
	p, e := os.Readlink(filepath.Join(s.Root, "current"))
	if errors.Is(e, os.ErrNotExist) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	if !generationRE.MatchString(p) {
		return "", errors.New("current 指向了非管理目录")
	}
	i, e := os.Lstat(filepath.Join(s.Root, p))
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("配置代目录无效")
	}
	return p, nil
}
func (s *Store) Load() (State, error) {
	p, e := s.current()
	if e != nil {
		return State{}, e
	}
	if p == "" {
		return NewState(), nil
	}
	return ReadState(filepath.Join(s.Root, p, "state.json"))
}
func (s *Store) switchTo(p string) error {
	if p == "" {
		e := os.Remove(filepath.Join(s.Root, "current"))
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return SyncDir(s.Root)
	}
	if !generationRE.MatchString(p) {
		return errors.New("非法配置代名称")
	}
	temp := filepath.Join(s.Root, ".current-"+Token(8))
	if e := os.Symlink(p, temp); e != nil {
		return e
	}
	defer os.Remove(temp)
	if e := os.Rename(temp, filepath.Join(s.Root, "current")); e != nil {
		return e
	}
	return SyncDir(s.Root)
}
func (s *Store) activate(st State) error {
	if HasEnabled(st) {
		return s.Backend.Activate(st)
	}
	return s.Backend.Stop()
}
func (s *Store) Apply(st State) error {
	var resolveErr error
	st, resolveErr = CanonicalCertificates(st)
	if resolveErr != nil {
		return resolveErr
	}
	if e := st.Validate(); e != nil {
		return e
	}
	previous, e := s.current()
	if e != nil {
		return e
	}
	old, e := s.Load()
	if e != nil {
		return e
	}
	st = normalizeCandidate(st, old)
	var candidateIdentity []byte
	if provider, ok := s.Backend.(RuntimeIdentityBackend); ok {
		candidateIdentity, e = provider.RuntimeIdentity(st)
		if e != nil {
			return e
		}
	}
	impact, e := s.Preview(st)
	if e != nil {
		return e
	}
	if !impact.Changed {
		if s.BeforeCommit != nil {
			if e = s.BeforeCommit(st); e != nil {
				return e
			}
		}
		return s.afterCommit(st)
	}
	// Own the candidate: updating timestamps must not mutate caller slices.
	st = st.Clone()
	// Preserve unknown legacy creation times; no-op runs never alter timestamps.
	for i := range st.Nodes {
		n := &st.Nodes[i]
		before, e := old.Find(n.ID)
		if e == nil {
			x, _ := json.Marshal(*before)
			y, _ := json.Marshal(*n)
			if bytes.Equal(x, y) {
				continue
			}
			n.CreatedAt = before.CreatedAt
		} else if n.CreatedAt == "" {
			n.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		n.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(st)
	if len(b) > maxStateBytes {
		return errors.New("状态超过 8 MiB 上限，原配置保持有效")
	}
	g := "generations/g-" + Token(16)
	dir := filepath.Join(s.Root, g)
	if e = os.Mkdir(dir, 0750); e != nil {
		return e
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	if s.GID >= 0 {
		if e = os.Chown(dir, 0, s.GID); e != nil {
			return e
		}
	}
	// The bootstrap uses umask 0077, so explicitly grant service-group traversal.
	if e = os.Chmod(dir, 0750); e != nil {
		return e
	}
	config, e := Server(st, s.Root)
	if e != nil {
		return e
	}
	for name, data := range map[string][]byte{"state.json": b, "server.json": config, "core-version": []byte(st.CoreVersion), "parent": []byte(previous)} {
		mode := os.FileMode(0600)
		readable := name == "server.json" || name == "core-version"
		if readable {
			mode = 0640
		}
		p := filepath.Join(dir, name)
		if e = AtomicWrite(p, data, mode); e != nil {
			return e
		}
		if readable && s.GID >= 0 {
			if e = os.Chown(p, 0, s.GID); e != nil {
				return e
			}
		}
	}
	if e = SyncDir(filepath.Join(s.Root, "generations")); e != nil {
		return e
	}
	if e = s.Backend.Check(st, filepath.Join(dir, "server.json")); e != nil {
		return fmt.Errorf("候选配置校验失败，原配置保持有效：%w", e)
	}
	if provider, ok := s.Backend.(RuntimeIdentityBackend); ok {
		identity, err := provider.RuntimeIdentity(st)
		if err != nil {
			return err
		}
		if !bytes.Equal(identity, candidateIdentity) {
			return errors.New("核心或服务输入在候选验证期间发生变化，原配置保持有效；请检查后重试")
		}
		if e = AtomicWrite(filepath.Join(dir, "runtime-identity"), identity, 0600); e != nil {
			return e
		}
	}
	wasActive := false
	if impact.NeedsRestart {
		wasActive, e = BackendActivity(s.Backend)
		if e != nil {
			return fmt.Errorf("无法确认原服务运行状态，候选尚未提交：%w", e)
		}
	}
	if s.BeforeCommit != nil {
		if e = s.BeforeCommit(st); e != nil {
			return fmt.Errorf("代理配置尚未提交；订阅下载权限预检/撤销未完成：%w", e)
		}
	}
	j := journalV2{Version: 2, Previous: previous, Next: g, WasActive: wasActive, RuntimeChanged: impact.NeedsRestart, HostEffects: impact.HostEffects}
	jb, _ := json.Marshal(transactionEnvelope{Transaction: j})
	if e = AtomicWrite(filepath.Join(s.Root, "transaction.json"), jb, 0600); e != nil {
		return e
	}
	keep = true // referenced by recovery journal; retain even if recovery itself fails
	if fx, ok := s.Backend.(Effects); ok && impact.HostEffects {
		e = fx.PrepareEffects(old, st)
	}
	if e == nil {
		e = s.switchTo(g)
	}
	if e == nil && impact.NeedsRestart {
		e = s.activate(st)
	}
	if e == nil {
		if fx, ok := s.Backend.(Effects); ok && impact.HostEffects {
			e = fx.FinishEffects(old, st)
		}
	}
	if e != nil {
		cause := e
		if re := s.Recover(); re != nil {
			return fmt.Errorf("应用失败：%v；恢复未完成：%w", cause, re)
		}
		return fmt.Errorf("应用失败，已恢复原状态：%w", cause)
	}
	if e = os.Remove(filepath.Join(s.Root, "transaction.json")); e != nil {
		return e
	}
	if e = SyncDir(s.Root); e != nil {
		return e
	}
	return s.afterCommit(st)
}

func (s *Store) afterCommit(st State) error {
	if s.AfterCommit != nil {
		if err := s.AfterCommit(st); err != nil {
			return fmt.Errorf("代理配置已提交；设备订阅发布失败，旧快照保留，请显式重新发布：%w", err)
		}
	}
	return nil
}
func (s *Store) Recover() error {
	if err := MigrationPending(s.Root); err != nil {
		return err
	}
	b, e := os.ReadFile(filepath.Join(s.Root, "transaction.json"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	j, e := decodeJournal(b)
	if e != nil {
		return e
	}
	if !generationRE.MatchString(j.Next) || (j.Previous != "" && !generationRE.MatchString(j.Previous)) {
		return errors.New("恢复记录无效")
	}
	cur, e := s.current()
	if e != nil {
		return e
	}
	if cur != j.Next && cur != j.Previous {
		return errors.New("配置指针发生外部变更，拒绝自动恢复")
	}
	previous := NewState()
	if j.Previous != "" {
		previous, e = ReadState(filepath.Join(s.Root, j.Previous, "state.json"))
		if e != nil {
			return e
		}
	}
	next, e := ReadState(filepath.Join(s.Root, j.Next, "state.json"))
	if e != nil {
		return e
	}
	if j.Version == 2 {
		impact, err := compareImpact(previous, next, s.Root)
		if err != nil {
			return err
		}
		if (!j.RuntimeChanged && impact.ServerRuntime) || (!j.HostEffects && impact.HostEffects) {
			return errors.New("恢复记录的影响分类与配置不一致，拒绝恢复")
		}
		if j.RuntimeChanged && j.Previous != "" {
			if provider, ok := s.Backend.(RuntimeIdentityBackend); ok {
				actual, err := provider.RuntimeIdentity(previous)
				if err != nil {
					return err
				}
				saved, err := os.ReadFile(filepath.Join(s.Root, j.Previous, "runtime-identity"))
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if err == nil && !bytes.Equal(actual, saved) {
					return errors.New("上一代核心或服务输入已被外部替换，无法确认恢复；原始配置与恢复记录已保留")
				}
			}
		}
	}
	if j.RuntimeChanged && j.WasActive && j.Previous != "" {
		// Recovery must never restart from externally damaged derived files.
		// Keep the original generation and journal for an explicit repair.
		expected, err := Server(previous, s.Root)
		if err != nil {
			return err
		}
		actual, configErr := os.ReadFile(filepath.Join(s.Root, j.Previous, "server.json"))
		core, coreErr := os.ReadFile(filepath.Join(s.Root, j.Previous, "core-version"))
		if configErr != nil || coreErr != nil || !bytes.Equal(expected, actual) || string(core) != previous.CoreVersion {
			return errors.New("上一代派生配置已损坏，拒绝用损坏文件恢复运行；原始配置与恢复记录已保留")
		}
	}
	if fx, ok := s.Backend.(Effects); ok && j.HostEffects {
		if e = fx.PrepareEffects(next, previous); e != nil {
			return e
		}
	}
	if e = s.switchTo(j.Previous); e != nil {
		return e
	}
	if j.RuntimeChanged && j.WasActive && j.Previous != "" {
		if e = s.activate(previous); e != nil {
			return e
		}
	} else if j.RuntimeChanged {
		if e = s.Backend.Stop(); e != nil {
			return e
		}
	}
	if fx, ok := s.Backend.(Effects); ok && j.HostEffects {
		if e = fx.FinishEffects(next, previous); e != nil {
			return e
		}
	}
	if e = os.Remove(filepath.Join(s.Root, "transaction.json")); e != nil {
		return e
	}
	return SyncDir(s.Root)
}

func decodeJournal(b []byte) (journalV2, error) {
	if len(b) > 64<<10 {
		return journalV2{}, errors.New("恢复记录超过大小上限")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return journalV2{}, err
	}
	decode := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return err
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return errors.New("恢复记录含多余数据")
		}
		return nil
	}
	if _, ok := top["transaction_v2"]; ok {
		var envelope transactionEnvelope
		if err := decode(&envelope); err != nil {
			return journalV2{}, err
		}
		if envelope.Transaction.Version != 2 {
			return journalV2{}, fmt.Errorf("不支持恢复记录版本 %d", envelope.Transaction.Version)
		}
		return envelope.Transaction, nil
	}
	var legacy journal
	if err := decode(&legacy); err != nil {
		return journalV2{}, err
	}
	// Old transactions always performed effects and service activation.
	return journalV2{Version: 1, Previous: legacy.Previous, Next: legacy.Next, WasActive: legacy.WasActive, RuntimeChanged: true, HostEffects: true}, nil
}
func (s *Store) Rollback() error {
	g, e := s.current()
	if e != nil {
		return e
	}
	if g == "" {
		return errors.New("尚无配置")
	}
	b, e := os.ReadFile(filepath.Join(s.Root, g, "parent"))
	if e != nil {
		return e
	}
	p := string(b)
	if !generationRE.MatchString(p) {
		return errors.New("没有可回退的上一代配置")
	}
	st, e := ReadState(filepath.Join(s.Root, p, "state.json"))
	if e != nil {
		return e
	}
	return s.Apply(st)
}
