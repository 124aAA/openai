package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"qingnode/internal/platform"
)

var errAuxiliaryJournalChanged = errors.New("附属服务事务记录已被外部改写或移除")

type auxiliaryConflict struct {
	Version  int    `json:"version"`
	Original []byte `json:"original_record"`
}

func auxiliaryJournalBytes(j auxiliaryJournal) []byte {
	if j.source != nil {
		return j.source
	}
	b, _ := json.MarshalIndent(j, "", "  ")
	return b
}

func auxiliaryJournalSafe(root string, j auxiliaryJournal) error {
	b, err := auxiliaryReadPrivate(auxiliaryPath(root, j.Before.Settings.Name, ".journal"))
	if err != nil || !bytes.Equal(b, auxiliaryJournalBytes(j)) {
		return errAuxiliaryJournalChanged
	}
	return nil
}

// This guard deliberately uses the original, unwrapped controller for source
// observations. Every actual native call is checked before and after, including
// callbacks which fail after modifying host state. Every file mutation also
// calls check immediately beforehand. It closes controller-wait windows, but
// cannot make the final local check + rename atomic against another root writer.
func auxiliaryGuardedManager(root string, manager platform.Manager, j auxiliaryJournal) (platform.Manager, func() error) {
	original := manager
	original.Kind = manager.ResolvedKind()
	manager.Kind = original.Kind
	check := func() error {
		if err := auxiliaryRecoverySafe(root, original, j); err != nil {
			if errors.Is(err, errAuxiliaryJournalChanged) {
				path, saved := auxiliaryRetainConflict(root, j)
				if saved != nil {
					return fmt.Errorf("%w；原记录另存失败（未覆盖外部内容）：%v", err, saved)
				}
				return fmt.Errorf("%w；外部内容保留，原记录另存%s；请人工核对，未自动接管", err, path)
			}
			return err
		}
		return nil
	}
	manager.Execute = func(timeout time.Duration, command string, args ...string) ([]byte, error) {
		if err := check(); err != nil {
			return nil, err
		}
		out, err := auxiliaryRun(original, timeout, command, args...)
		if changed := check(); changed != nil {
			return out, changed
		}
		return out, err
	}
	return manager, check
}

func auxiliaryFilesystemSafe(root string, manager platform.Manager, j auxiliaryJournal) error {
	if err := auxiliaryValidateRoot(root); err != nil {
		return err
	}
	// Check the journal first so its original evidence survives even when an
	// administrator changed both the unit and journal in the same callback.
	if err := auxiliaryJournalSafe(root, j); err != nil {
		return err
	}
	old, err := NewAuxiliaryServicePlan(manager, j.Before.Settings.Name, j.Before.Settings.PublicURL)
	if err != nil {
		return err
	}
	next, err := NewAuxiliaryServicePlan(manager, j.Candidate.Name, j.Candidate.PublicURL)
	if err != nil {
		return err
	}
	for i, file := range old.Definitions {
		if err := auxiliaryCheckOverrides(manager, file.Name); err != nil {
			return err
		}
		actual, _, gid, err := auxiliaryReadDefinition(manager, file.Name, file.Mode)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, file.Contents) && !bytes.Equal(actual, next.Definitions[i].Contents) {
			return errors.New("服务定义已由外部修改；保留原字节和恢复材料")
		}
		allowedGID := uint32(os.Getegid())
		if j.Before.Present {
			allowedGID = j.Before.Files[i].GID
		}
		if gid != uint32(os.Getegid()) && gid != allowedGID {
			return errors.New("服务定义组属主已由外部修改，未覆盖")
		}
	}
	if err := auxiliaryReceiptSafe(root, j); err != nil {
		return err
	}
	return auxiliaryJournalSafe(root, j)
}

// Only an already-authorized writer creates this witness, and only after its
// exact journal changed. Read-only preview never creates recovery material.
func auxiliaryRetainConflict(root string, j auxiliaryJournal) (string, error) {
	path := auxiliaryPath(root, j.Before.Settings.Name, ".conflict")
	data, err := json.Marshal(auxiliaryConflict{Version: 1, Original: auxiliaryJournalBytes(j)})
	if err != nil {
		return path, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := auxiliaryReadPrivate(path)
		if readErr == nil && bytes.Equal(existing, data) {
			return path, nil
		}
		return path, errors.New("冲突见证路径已有其它内容，未覆盖")
	}
	if err != nil {
		return path, err
	}
	f := os.NewFile(uintptr(fd), path)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err == nil {
		err = closed
	}
	if err == nil {
		err = SyncDir(filepath.Dir(path))
	}
	return path, err
}

func auxiliaryConflictPending(root, name string) (bool, error) {
	b, err := auxiliaryReadPrivate(auxiliaryPath(root, name, ".conflict"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var witness auxiliaryConflict
	if err := auxiliaryDecode(b, &witness); err != nil {
		return false, err
	}
	if witness.Version != 1 {
		return false, errors.New("附属服务冲突见证版本不受支持")
	}
	var original auxiliaryJournal
	if err := auxiliaryDecode(witness.Original, &original); err != nil {
		return false, err
	}
	if original.Before.Settings.Kind != platform.InitSystemd && original.Before.Settings.Kind != platform.InitOpenRC {
		return false, errors.New("附属服务冲突见证init无效")
	}
	if err := auxiliaryValidateJournal(platform.Manager{Kind: original.Before.Settings.Kind}, name, original); err != nil {
		return false, err
	}
	return true, nil
}
