package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const MigrationJournalName = "migration-restore.json"

type migrationSwitch struct {
	ID          string `json:"id"`
	Target      string `json:"target"`
	Staged      string `json:"staged"`
	Previous    string `json:"previous"`
	HadPrevious bool   `json:"had_previous"`
}
type migrationRestoreJournal struct {
	Version            int               `json:"version"`
	ID                 string            `json:"id"`
	PreviousGeneration string            `json:"previous_generation"`
	NextState          State             `json:"next_state"`
	Switches           []migrationSwitch `json:"switches"`
	WasActive          bool              `json:"was_active"`
	Committed          bool              `json:"committed"`
}

// MigrationTargets are selected locally by the operator, never interpreted from
// archived absolute source paths. publisher targets the single config file.
type MigrationTarget struct {
	Path    string
	GroupID int
	OwnerID int
}
type MigrationTargets map[string]MigrationTarget

func MigrationPending(root string) error {
	_, e := os.Lstat(filepath.Join(root, MigrationJournalName))
	if e == nil {
		return errors.New("存在中断的完整迁移；请先运行 qingnode restore --recover-migration --yes。普通写操作不会越过资产恢复记录")
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}

// RestoreMigrationAssets requires the management lock and an already stopped
// owned core. The typed State uses the existing Store validation/application
// transaction; executable service evidence and binaries are never restored.
func (s *Store) RestoreMigrationAssets(m MigrationPackage, targets MigrationTargets, wasActive bool) error {
	if err := PendingAuxiliaryService(s.Root); err != nil {
		return err
	}
	if e := m.Validate(); e != nil {
		return e
	}
	if e := MigrationPending(s.Root); e != nil {
		return e
	}
	if e := ConfirmMigrationStopped(s.Backend); e != nil {
		return e
	}
	previous, e := s.current()
	if e != nil {
		return e
	}
	j := migrationRestoreJournal{Version: 1, ID: Token(16), PreviousGeneration: previous, NextState: m.Snapshot.State.Clone(), WasActive: wasActive, Switches: []migrationSwitch{}}
	cleanup := func() {
		for _, x := range j.Switches {
			_ = removeMigrationPath(x.Staged)
		}
	}
	for _, r := range m.Roots {
		mapping, ok := targets[r.ID]
		target := mapping.Path
		if !ok || !filepath.IsAbs(target) || filepath.Clean(target) == string(os.PathSeparator) || mapping.GroupID < -1 || mapping.OwnerID < 0 {
			cleanup()
			return errors.New("缺少安全的本机资产路径映射")
		}
		target = filepath.Clean(target)
		if r.ID == "publisher" && target != filepath.Join(s.Root, "subscription-publisher.json") {
			cleanup()
			return errors.New("订阅配置仅能恢复到当前State目录")
		}
		if r.ID == "acme" && target != filepath.Join(s.Root, "acme") {
			cleanup()
			return errors.New("ACME仅能恢复到当前State受管目录")
		}
		if r.ID == "subscription" && (strings.HasPrefix(target, s.Root+string(os.PathSeparator)) || strings.HasPrefix(s.Root, target+string(os.PathSeparator)) || target == s.Root) {
			cleanup()
			return errors.New("订阅发布目录必须独立于State目录")
		}
		if e = migrationSafeAncestors(filepath.Dir(target)); e != nil {
			cleanup()
			return e
		}
		x := migrationSwitch{ID: r.ID, Target: target, Staged: target + ".qingnode-stage-" + j.ID, Previous: target + ".qingnode-previous-" + j.ID}
		if info, err := os.Lstat(target); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || r.ID == "publisher" && !info.Mode().IsRegular() || r.ID != "publisher" && !info.IsDir() {
				cleanup()
				return errors.New("目标资产不是预期的普通文件或目录")
			}
			if r.ID == "subscription" {
				b, err := os.ReadFile(filepath.Join(target, ".qingnode-subscription-owner"))
				if err != nil || string(b) != "QingNode subscription publication v1\n" {
					cleanup()
					return errors.New("目标订阅目录没有QingNode所有权标记")
				}
			}
			x.HadPrevious = true
		} else if !errors.Is(err, os.ErrNotExist) {
			cleanup()
			return err
		}
		if r.ID == "publisher" {
			var b []byte
			for _, f := range m.Files {
				if f.RootID == r.ID {
					if f.Path != "subscription-publisher.json" || f.Directory {
						cleanup()
						return errors.New("发布配置迁移条目无效")
					}
					b = f.Data
				}
			}
			if len(b) == 0 {
				cleanup()
				return errors.New("迁移包缺少发布配置")
			}
			if e = writeMigrationExclusive(x.Staged, b, 0600); e != nil {
				cleanup()
				return e
			}
		} else {
			if e = os.Mkdir(x.Staged, 0700); e != nil {
				cleanup()
				return e
			}
			j.Switches = append(j.Switches, x)
			for _, f := range m.Files {
				if f.RootID != r.ID {
					continue
				}
				p := filepath.Join(x.Staged, filepath.FromSlash(f.Path))
				if f.Directory {
					e = os.MkdirAll(p, 0700)
				} else {
					e = os.MkdirAll(filepath.Dir(p), 0700)
					if e == nil {
						e = writeMigrationExclusive(p, f.Data, os.FileMode(f.Mode))
					}
				}
				if e != nil {
					cleanup()
					return e
				}
			}
			// Apply trusted target group, not archived uid/gid values.
			gid := mapping.GroupID
			if r.ID == "acme" {
				gid = s.GID
			}
			if e = filepath.WalkDir(x.Staged, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					if err = os.Chmod(p, 0750); err != nil {
						return err
					}
				}
				if gid >= 0 {
					return os.Chown(p, mapping.OwnerID, gid)
				}
				return nil
			}); e != nil {
				cleanup()
				return e
			}
			if e = SyncDir(x.Staged); e != nil {
				cleanup()
				return e
			}
			if e = syncMigrationTree(x.Staged); e != nil {
				cleanup()
				return e
			}
			continue
		}
		j.Switches = append(j.Switches, x)
	}
	for _, x := range j.Switches {
		if e = validateMigrationSwitch(s.Root, x); e != nil {
			cleanup()
			return e
		}
	}
	if e = writeMigrationJournal(s.Root, j); e != nil {
		cleanup()
		return e
	}
	for _, x := range j.Switches {
		if x.HadPrevious {
			e = os.Rename(x.Target, x.Previous)
		}
		if e == nil {
			e = os.Rename(x.Staged, x.Target)
		}
		if e == nil {
			e = SyncDir(filepath.Dir(x.Target))
		}
		if e != nil {
			return s.migrationFail(j, e)
		}
	}
	// Store.Apply runs under the same lock. The asset journal remains on disk;
	// ordinary recovery cannot restart a candidate before old assets are selected.
	e = s.Apply(m.Snapshot.State)
	if e != nil {
		cur, ce := s.Load()
		_, pending := os.Lstat(filepath.Join(s.Root, "transaction.json"))
		if ce != nil || pending == nil || !errors.Is(pending, os.ErrNotExist) || !migrationSameState(cur, m.Snapshot.State) {
			return s.migrationFail(j, e)
		}
		// Store.AfterCommit can fail after State is committed. Keep committed
		// assets and tell the caller to re-publish, never undo only half the State.
		if fe := s.finishMigration(j); fe != nil {
			return fmt.Errorf("配置已提交：%v；迁移收尾失败：%w", e, fe)
		}
		return e
	}
	return s.finishMigration(j)
}

func migrationSameState(a, b State) bool {
	a = a.Clone()
	b = b.Clone()
	for i := range a.Nodes {
		a.Nodes[i].CreatedAt = ""
		a.Nodes[i].UpdatedAt = ""
	}
	for i := range b.Nodes {
		b.Nodes[i].CreatedAt = ""
		b.Nodes[i].UpdatedAt = ""
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func writeMigrationExclusive(p string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
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
	return e
}
func writeMigrationJournal(root string, j migrationRestoreJournal) error {
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(root, MigrationJournalName), b, 0600)
}
func removeMigrationPath(p string) error {
	if !strings.Contains(filepath.Base(p), ".qingnode-stage-") && !strings.Contains(filepath.Base(p), ".qingnode-previous-") {
		return errors.New("拒绝清理无迁移所有权的路径")
	}
	i, e := os.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSymlink != 0 {
		return errors.New("迁移清理路径被替换为链接")
	}
	return os.RemoveAll(p)
}

func (s *Store) migrationFail(j migrationRestoreJournal, cause error) error {
	if s.Backend.Active() {
		if e := s.Backend.Stop(); e != nil {
			return fmt.Errorf("完整迁移失败：%v；停止候选服务失败：%w", cause, e)
		}
		if s.Backend.Active() {
			return fmt.Errorf("完整迁移失败：%v；未能确认服务停止，保留恢复记录", cause)
		}
	}
	if e := ConfirmMigrationStopped(s.Backend); e != nil {
		return fmt.Errorf("完整迁移失败：%v；无法安全恢复资产：%w", cause, e)
	}
	if e := s.rollbackMigration(j); e != nil {
		return fmt.Errorf("完整迁移失败：%v；资产恢复未完成，请显式recover-migration：%w", cause, e)
	}
	if e := s.Recover(); e != nil {
		return fmt.Errorf("完整迁移资产已恢复；服务事务恢复失败：%w", e)
	}
	return fmt.Errorf("完整迁移失败，已恢复原资产：%w", cause)
}
func (s *Store) rollbackMigration(j migrationRestoreJournal) error {
	for i := len(j.Switches) - 1; i >= 0; i-- {
		x := j.Switches[i]
		if _, e := os.Lstat(x.Previous); e == nil {
			if _, e = os.Lstat(x.Target); e == nil {
				if e = os.Rename(x.Target, x.Staged); e != nil {
					return e
				}
			}
			if e = os.Rename(x.Previous, x.Target); e != nil {
				return e
			}
			if e := SyncDir(filepath.Dir(x.Target)); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if !x.HadPrevious {
			if _, e = os.Lstat(x.Staged); errors.Is(e, os.ErrNotExist) {
				if _, e = os.Lstat(x.Target); e == nil {
					if e = os.Rename(x.Target, x.Staged); e != nil {
						return e
					}
					if e = SyncDir(filepath.Dir(x.Target)); e != nil {
						return e
					}
				}
			}
		}
		if e := removeMigrationPath(x.Staged); e != nil {
			return e
		}
	}
	if e := os.Remove(filepath.Join(s.Root, MigrationJournalName)); e != nil {
		return e
	}
	return SyncDir(s.Root)
}

// Sync children before parents so a durable rename never exposes a tree whose
// file names existed only in an unsynced nested directory.
func syncMigrationTree(root string) error {
	var dirs []string
	if e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	}); e != nil {
		return e
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if e := SyncDir(dirs[i]); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) finishMigration(j migrationRestoreJournal) error {
	j.Committed = true
	if e := writeMigrationJournal(s.Root, j); e != nil {
		return e
	}
	for _, x := range j.Switches {
		if e := removeMigrationPath(x.Previous); e != nil {
			return e
		}
		if e := removeMigrationPath(x.Staged); e != nil {
			return e
		}
	}
	if e := os.Remove(filepath.Join(s.Root, MigrationJournalName)); e != nil {
		return e
	}
	return SyncDir(s.Root)
}

// RecoverMigrationAssets is an explicit write operation. The management lock
// must be held without automatic Store.Recover first: old runtime assets have
// to be selected before an interrupted proxy transaction may restart a core.
func (s *Store) RecoverMigrationAssets() error {
	jp := filepath.Join(s.Root, MigrationJournalName)
	i, e := os.Lstat(jp)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	stat, ok := i.Sys().(*syscall.Stat_t)
	if !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("迁移恢复记录必须为当前用户私有普通文件")
	}
	b, e := os.ReadFile(jp)
	if e != nil {
		return e
	}
	if len(b) > 16<<20 {
		return errors.New("迁移恢复记录过大")
	}
	if e = rejectMigrationJSON(b); e != nil {
		return e
	}
	var j migrationRestoreJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&j); e != nil || j.Version != 1 || !id32(j.ID) || len(j.Switches) > 3 {
		return errors.New("迁移恢复记录无效")
	}
	if j.PreviousGeneration != "" && !generationRE.MatchString(j.PreviousGeneration) {
		return errors.New("迁移恢复原配置代无效")
	}
	if e = j.NextState.ValidateForRestore(); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, x := range j.Switches {
		if seen[x.ID] {
			return errors.New("迁移恢复根重复")
		}
		seen[x.ID] = true
		if !filepath.IsAbs(x.Target) || x.Staged != x.Target+".qingnode-stage-"+j.ID || x.Previous != x.Target+".qingnode-previous-"+j.ID {
			return errors.New("迁移恢复路径无效")
		}
		if x.ID == "acme" && x.Target != filepath.Join(s.Root, "acme") || x.ID == "publisher" && x.Target != filepath.Join(s.Root, "subscription-publisher.json") || x.ID != "acme" && x.ID != "publisher" && x.ID != "subscription" {
			return errors.New("迁移恢复目录不属于本项目")
		}
		if e = validateMigrationSwitch(s.Root, x); e != nil {
			return e
		}
	}
	if s.Backend.Active() {
		if e = s.Backend.Stop(); e != nil {
			return e
		}
		if s.Backend.Active() {
			return errors.New("无法确认服务已停止，未恢复迁移资产")
		}
	}
	if e = ConfirmMigrationStopped(s.Backend); e != nil {
		return e
	}
	current, ce := s.Load()
	generation, ge := s.current()
	_, pending := os.Lstat(filepath.Join(s.Root, "transaction.json"))
	committed := j.Committed || ce == nil && ge == nil && generation != j.PreviousGeneration && errors.Is(pending, os.ErrNotExist) && migrationSameState(current, j.NextState)
	if committed {
		if e = s.finishMigration(j); e != nil {
			return e
		}
	} else {
		if e = s.rollbackMigration(j); e != nil {
			return e
		}
		if e = s.Recover(); e != nil {
			return e
		}
	}
	st, e := s.Load()
	if e != nil {
		return e
	}
	if j.WasActive {
		return s.Backend.Activate(st)
	}
	return s.Backend.Stop()
}
func id32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			if r < 'a' || r > 'f' {
				return false
			}
		}
	}
	return true
}

// ConfirmMigrationStopped never turns a failed process query into a negative.
// OfflineBackend is the only backend with no process by construction.
func ConfirmMigrationStopped(b Backend) error {
	if b.Active() {
		return errors.New("受管核心仍在运行，不能复制或切换运行资产")
	}
	if c, ok := b.(interface{ ConfirmStopped() error }); ok {
		return c.ConfirmStopped()
	}
	switch b.(type) {
	case OfflineBackend, *OfflineBackend:
		return nil
	}
	return errors.New("服务后端没有可验证的停止证明，未复制或切换运行资产")
}

func validateMigrationSwitch(root string, x migrationSwitch) error {
	if e := migrationSafeAncestors(filepath.Dir(x.Target)); e != nil {
		return e
	}
	if x.ID == "subscription" && (x.Target == root || strings.HasPrefix(x.Target, root+string(os.PathSeparator)) || strings.HasPrefix(root, x.Target+string(os.PathSeparator))) {
		return errors.New("迁移订阅目录不独立于State")
	}
	for _, p := range []string{x.Target, x.Staged, x.Previous} {
		i, e := os.Lstat(p)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return errors.New("迁移恢复路径包含符号链接")
		}
		if x.ID == "publisher" {
			if !i.Mode().IsRegular() || i.Mode().Perm() != 0600 {
				return errors.New("迁移发布配置权限无效")
			}
		} else {
			if !i.IsDir() || i.Mode().Perm() != 0750 && i.Mode().Perm() != 0700 {
				return errors.New("迁移资产目录权限无效")
			}
			if x.ID == "subscription" {
				b, e := os.ReadFile(filepath.Join(p, ".qingnode-subscription-owner"))
				if e != nil || string(b) != "QingNode subscription publication v1\n" {
					return errors.New("迁移订阅恢复路径缺少自有标记")
				}
			}
		}
	}
	return nil
}
