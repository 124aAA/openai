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
type OfflineBackend struct{}

func (OfflineBackend) Check(State, string) error { return nil }
func (OfflineBackend) Active() bool              { return false }
func (OfflineBackend) Activate(State) error      { return nil }
func (OfflineBackend) Stop() error               { return nil }

type Store struct {
	Root    string
	Backend Backend
	GID     int
}
type journal struct {
	Previous  string `json:"previous"`
	Next      string `json:"next"`
	WasActive bool   `json:"was_active"`
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
	d := json.NewDecoder(io.LimitReader(f, 8<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&s); e != nil {
		return s, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return s, errors.New("状态文件含多余数据")
	}
	if s.Schema != Schema {
		return s, fmt.Errorf("不支持状态版本 %d", s.Schema)
	}
	return s, nil
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
	return s.withLock(true, fn)
}

// Inspect holds the management lock without repairing or restarting a broken service.
func (s *Store) Inspect(fn func() error) error { return s.withLock(false, fn) }
func (s *Store) withLock(recover bool, fn func() error) error {
	if !recover {
		i, e := os.Lstat(s.Root)
		if errors.Is(e, os.ErrNotExist) {
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
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
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
	for _, n := range st.Nodes {
		if n.Enabled {
			return s.Backend.Activate(st)
		}
	}
	return s.Backend.Stop()
}
func (s *Store) Apply(st State) error {
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
	a, _ := json.Marshal(old)
	b, _ := json.Marshal(st)
	if previous != "" && bytes.Equal(a, b) {
		expected, e := Server(st, s.Root)
		if e != nil {
			return e
		}
		actual, ce := os.ReadFile(filepath.Join(s.Root, previous, "server.json"))
		core, ve := os.ReadFile(filepath.Join(s.Root, previous, "core-version"))
		if ce == nil && ve == nil && bytes.Equal(expected, actual) && string(core) == st.CoreVersion {
			return nil
		}
		// Rebuild damaged derived files using the saved identities. Never regenerate secrets.
	}
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
	b, _ = json.Marshal(st)
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
	j := journal{Previous: previous, Next: g, WasActive: s.Backend.Active()}
	jb, _ := json.Marshal(j)
	if e = AtomicWrite(filepath.Join(s.Root, "transaction.json"), jb, 0600); e != nil {
		return e
	}
	keep = true // referenced by recovery journal; retain even if recovery itself fails
	if fx, ok := s.Backend.(Effects); ok {
		e = fx.PrepareEffects(old, st)
	}
	if e == nil {
		e = s.switchTo(g)
	}
	if e == nil {
		e = s.activate(st)
	}
	if e == nil {
		if fx, ok := s.Backend.(Effects); ok {
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
	return SyncDir(s.Root)
}
func (s *Store) Recover() error {
	b, e := os.ReadFile(filepath.Join(s.Root, "transaction.json"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var j journal
	if e = json.Unmarshal(b, &j); e != nil {
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
	if e = s.switchTo(j.Previous); e != nil {
		return e
	}
	if fx, ok := s.Backend.(Effects); ok {
		previous, e := s.Load()
		if e != nil {
			return e
		}
		next, e := ReadState(filepath.Join(s.Root, j.Next, "state.json"))
		if e != nil {
			return e
		}
		if e = fx.FinishEffects(next, previous); e != nil {
			return e
		}
	}
	if j.WasActive && j.Previous != "" {
		st, e := s.Load()
		if e != nil {
			return e
		}
		if e = s.activate(st); e != nil {
			return e
		}
	} else if e = s.Backend.Stop(); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(s.Root, "transaction.json")); e != nil {
		return e
	}
	return SyncDir(s.Root)
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
