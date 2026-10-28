package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"qingnode/internal/probe"
)

const markerName = ".qingnode-monitor"
const markerContent = "qingnode-monitor-v1\n"

var ErrBusy = errors.New("已有监控任务运行；本轮不排队")

// Initialize claims only a new or empty directory. It never imports arbitrary
// files into the monitor's ownership, follows path links or removes files.
func (s *Store) Initialize() error {
	if err := s.validRoot(); err != nil {
		return err
	}
	if err := rejectPathLinks(filepath.Dir(s.Root)); err != nil {
		return err
	}
	i, err := os.Lstat(s.Root)
	if os.IsNotExist(err) {
		if err = os.Mkdir(s.Root, 0700); err != nil && !os.IsExist(err) {
			return errors.New("无法建立监控私有目录")
		}
		i, err = os.Lstat(s.Root)
	}
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("监控根目录必须是没有链接的普通目录")
	}
	if _, err = os.Lstat(filepath.Join(s.Root, markerName)); err == nil {
		return s.checkRoot(false)
	}
	if !os.IsNotExist(err) {
		return errors.New("无法检查监控目录标记")
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil || len(entries) != 0 {
		return errors.New("没有自有标记的非空目录不能作为监控根目录")
	}
	if err = protectPrivate(s.Root, true); err != nil {
		return errors.New("无法保护监控目录权限")
	}
	f, err := os.OpenFile(filepath.Join(s.Root, markerName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("无法创建监控目录标记")
	}
	defer f.Close()
	if err = protectPrivate(f.Name(), false); err != nil {
		return errors.New("无法保护监控标记权限")
	}
	if _, err = f.WriteString(markerContent); err != nil {
		return errors.New("无法写入监控目录标记")
	}
	return f.Sync()
}

func (s *Store) validRoot() error {
	if s == nil || s.Root == "" {
		return errors.New("监控需要明确的私有根目录")
	}
	abs, err := filepath.Abs(s.Root)
	if err != nil || filepath.Dir(abs) == abs {
		return errors.New("监控根目录不能是磁盘根目录")
	}
	return nil
}

func rejectPathLinks(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return errors.New("监控路径无效")
	}
	for {
		i, e := os.Lstat(abs)
		if e != nil {
			return errors.New("监控路径或父目录不存在或无法读取")
		}
		if i.Mode()&os.ModeSymlink != 0 || !i.IsDir() {
			return errors.New("监控路径不能经过符号链接或非目录")
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return nil
		}
		abs = parent
	}
}

func (s *Store) checkRoot(_ bool) error {
	if err := s.validRoot(); err != nil {
		return err
	}
	if err := rejectPathLinks(s.Root); err != nil {
		return err
	}
	if err := checkPrivate(s.Root); err != nil {
		return errors.New("监控目录权限过宽；只读操作不会自动修复")
	}
	b, err := readOwned(filepath.Join(s.Root, markerName), int64(len(markerContent)), true)
	if err != nil || string(b) != markerContent {
		return errors.New("监控目录没有有效的自有标记；只读操作不会初始化或修复")
	}
	return nil
}

func readOwned(path string, max int64, private bool) ([]byte, error) {
	i, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !i.Mode().IsRegular() || i.Size() > max {
		return nil, errors.New("监控文件必须是大小受限的普通文件，不能是链接或设备")
	}
	f, err := openOwned(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, errors.New("无法打开监控文件")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(i, opened) || !opened.Mode().IsRegular() || opened.Size() > max {
		return nil, errors.New("监控文件在读取时发生变化")
	}
	if err = singleLink(f); err != nil {
		return nil, err
	}
	if private {
		if err = checkPrivate(path); err != nil {
			return nil, errors.New("监控私有配置权限过宽；只读操作不会自动修复")
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("监控文件超过字节上限或读取失败")
	}
	return b, nil
}

func (s *Store) writeOwned(name string, b []byte, max int64) error {
	if name != "status.json" && name != "history.json" && name != "config.json" {
		return errors.New("拒绝写入非监控自有文件")
	}
	if int64(len(b)) > max {
		return errors.New("监控记录超过字节上限")
	}
	if err := s.checkRoot(false); err != nil {
		return err
	}
	path := filepath.Join(s.Root, name)
	if i, err := os.Lstat(path); err == nil {
		if !i.Mode().IsRegular() {
			return errors.New("监控目标文件不能是链接或设备")
		}
		f, e := openOwned(path, os.O_RDONLY, 0)
		if e != nil {
			return errors.New("无法检查监控目标文件")
		}
		e = singleLink(f)
		f.Close()
		if e != nil {
			return e
		}
	} else if !os.IsNotExist(err) {
		return errors.New("无法检查监控目标文件")
	}
	tmp := filepath.Join(s.Root, ".monitor-write-"+name)
	if err := s.removeOwnedTemporary(tmp, max); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("无法建立监控临时文件")
	}
	defer os.Remove(tmp)
	if err = protectPrivate(tmp, false); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("无法写入监控记录")
	}
	// Recheck the ownership boundary immediately before replacement. A link at
	// the final filename is never followed, even if introduced during writing.
	if err = s.checkRoot(false); err != nil {
		return err
	}
	if i, e := os.Lstat(path); e == nil && !i.Mode().IsRegular() {
		return errors.New("监控目标文件在写入期间被替换")
	}
	if err = os.Rename(tmp, path); err != nil {
		return errors.New("无法原子替换监控记录")
	}
	return nil
}

func (s *Store) LoadStatus() (Snapshot, error) {
	var v Snapshot
	if err := s.checkRoot(false); err != nil {
		return v, err
	}
	b, err := readOwned(filepath.Join(s.Root, "status.json"), MaxStatusBytes, false)
	if err != nil {
		return v, err
	}
	if err = probe.StrictJSON(b, &v); err != nil {
		return Snapshot{}, errors.New("监控状态记录无效")
	}
	if err = validateSnapshot(v); err != nil {
		return Snapshot{}, err
	}
	return v, nil
}

func validateSnapshot(v Snapshot) error {
	if v.Version != 1 || len(v.Jobs) > MaxJobs || len(v.Events) > 1024 || len(v.Actions) > 20 {
		return errors.New("监控状态版本或对象数量超过上限")
	}
	seen := map[string]bool{}
	for _, j := range v.Jobs {
		if !validID(j.JobID) || seen[j.JobID] || !validStatus(j.Status) || len(j.Observation.Signals) > 9 || len(j.Actions) > 20 || len(j.Observation.Statistics) > 4 || j.ConsecutiveFailures < 0 || j.ConsecutiveFailures > 100000 || !validDigest(j.ConfigurationSHA256) {
			return errors.New("监控任务状态无效")
		}
		seen[j.JobID] = true
		kinds := map[SignalKind]bool{}
		for _, s := range j.Observation.Signals {
			if !validKind(s.Kind) || kinds[s.Kind] || !validStatus(s.Status) || len(s.Cause) > 64 || len(s.Location) > 32 || len(s.EvidenceGroup) > 64 {
				return errors.New("监控信号记录无效")
			}
			kinds[s.Kind] = true
		}
		if len(j.Observation.Statistics) != len(boundedStatistics(j.Observation.Statistics)) {
			return errors.New("监控统计记录无效")
		}
		for _, a := range j.Actions {
			if !validAttempt(a) {
				return errors.New("监控恢复动作记录无效")
			}
		}
	}
	for _, e := range v.Events {
		if !validID(e.JobID) || !validStatus(e.From) || !validStatus(e.To) || (e.Kind != "status-change" && e.Kind != "recovery") || len(e.Notification) > 32 {
			return errors.New("监控事件记录无效")
		}
	}
	for _, a := range v.Actions {
		if !validAttempt(a) {
			return errors.New("监控全局恢复动作记录无效")
		}
	}
	return nil
}

func validAttempt(a ActionAttempt) bool {
	return a.Action == "restart" && (a.AttemptStatus == "attempted" || a.AttemptStatus == "succeeded" || a.AttemptStatus == "failed") && validStatus(a.Verification) && len(a.Cause) <= 64 && len(a.VerificationCause) <= 64 && !a.At.IsZero()
}

func (s *Store) LoadHistory() ([]Snapshot, error) {
	if err := s.checkRoot(false); err != nil {
		return nil, err
	}
	b, err := readOwned(filepath.Join(s.Root, "history.json"), MaxHistoryBytes, false)
	if err != nil {
		return nil, err
	}
	var v []Snapshot
	if err = probe.StrictJSON(b, &v); err != nil || len(v) > 512 {
		return nil, errors.New("监控历史记录无效或超过条数上限")
	}
	for _, x := range v {
		if err = validateSnapshot(x); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (s *Store) save(v Snapshot, limits HistoryLimits) error {
	if err := validateSnapshot(v); err != nil {
		return err
	}
	if len(v.Events) > limits.Events {
		v.Events = v.Events[len(v.Events)-limits.Events:]
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxStatusBytes {
		return errors.New("监控状态超过1MiB上限")
	}
	history, err := s.LoadHistory()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(history) > 0 && history[len(history)-1].StartedAt.Equal(v.StartedAt) {
		history[len(history)-1] = v
	} else {
		history = append(history, v)
	}
	if len(history) > limits.Records {
		history = history[len(history)-limits.Records:]
	}
	var hb []byte
	for {
		hb, err = json.Marshal(history)
		if err != nil {
			return errors.New("无法编码监控历史")
		}
		if int64(len(hb))+1 <= limits.Bytes {
			break
		}
		if len(history) == 0 {
			return errors.New("监控历史字节上限过小")
		}
		history = history[1:]
	}
	if err = s.writeOwned("history.json", append(hb, '\n'), limits.Bytes); err != nil {
		// Account for the newline within the configured strict byte cap.
		if int64(len(hb))+1 > limits.Bytes && len(history) > 0 {
			history = history[1:]
			hb, _ = json.Marshal(history)
			err = s.writeOwned("history.json", append(hb, '\n'), limits.Bytes)
		}
		if err != nil {
			return err
		}
	}
	return s.writeOwned("status.json", append(bytes.TrimSpace(b), '\n'), MaxStatusBytes)
}

type fileLock struct{ f *os.File }

func (l *fileLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}

func (s *Store) acquire() (*fileLock, error) {
	return s.acquireNamed(".monitor.lock")
}

func (s *Store) acquireNamed(name string) (*fileLock, error) {
	if name != ".monitor.lock" && name != ".monitor-config.lock" {
		return nil, errors.New("不支持的监控锁")
	}
	if err := s.checkRoot(false); err != nil {
		return nil, err
	}
	p := filepath.Join(s.Root, name)
	if i, e := os.Lstat(p); e == nil && !i.Mode().IsRegular() {
		return nil, errors.New("监控锁不能是链接或设备")
	}
	f, err := openOwned(p, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("无法打开监控锁")
	}
	if err = singleLink(f); err == nil {
		err = protectPrivate(p, false)
	}
	if err == nil {
		err = lockFile(f)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	if name == ".monitor.lock" {
		if err = s.cleanupInterruptedWrites(); err != nil {
			f.Close()
			return nil, err
		}
	}
	return &fileLock{f: f}, nil
}

// Fixed temporary filenames cap crash leftovers at three bounded files. Only
// the two runtime files are reclaimed under the runtime lock; config writes
// reclaim their own fixed file under the independent configuration lock.
func (s *Store) cleanupInterruptedWrites() error {
	d, err := os.Open(s.Root)
	if err != nil {
		return errors.New("无法检查监控临时文件")
	}
	defer d.Close()
	entries, err := d.ReadDir(513)
	if err != nil && err != io.EOF {
		return errors.New("无法检查监控临时文件")
	}
	if len(entries) > 512 {
		return errors.New("监控目录超过512个条目，拒绝无界扫描和清理")
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".monitor-write-") {
			continue
		}
		if name == ".monitor-write-config.json" {
			continue
		}
		maxBytes := int64(MaxStatusBytes)
		if name == ".monitor-write-history.json" {
			maxBytes = MaxHistoryBytes
		} else if name != ".monitor-write-status.json" {
			return errors.New("发现无法确认归属的监控临时文件，拒绝删除")
		}
		if err = s.removeOwnedTemporary(filepath.Join(s.Root, name), maxBytes); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) removeOwnedTemporary(path string, maxBytes int64) error {
	i, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !i.Mode().IsRegular() || i.Size() > maxBytes {
		return errors.New("监控临时文件归属或大小无法确认，拒绝删除")
	}
	f, err := openOwned(path, os.O_RDONLY, 0)
	if err != nil {
		return errors.New("监控临时文件无法安全检查")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(i, opened) {
		return errors.New("监控临时文件发生变化，拒绝删除")
	}
	if err = singleLink(f); err != nil {
		return err
	}
	if err = checkPrivate(path); err != nil {
		return errors.New("监控临时文件权限无法确认，拒绝删除")
	}
	if err = os.Remove(path); err != nil {
		return errors.New("无法移除已确认的监控临时文件")
	}
	return nil
}
