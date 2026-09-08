package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Locations are supplied by the installed CLI, never read from a backup or journal.
type Removal struct {
	Root, Unit, Binary, Library string
	Execute                     Runner
}
type removalJournal struct {
	Full    bool `json:"full"`
	Active  bool `json:"active"`
	Enabled bool `json:"enabled"`
}

// Retain an exact account identity so a clean reinstall can distinguish it from an unrelated account.
func (r Removal) RecordAccount(path string) error {
	const marker = "QingNode retained account v1\n"
	if i, e := os.Lstat(path); e == nil {
		old, re := os.ReadFile(path)
		if !i.Mode().IsRegular() || re != nil || !strings.HasPrefix(string(old), marker) {
			return errors.New("账户归属记录不属于 QingNode，拒绝覆盖")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	record := marker
	for _, kind := range []string{"passwd", "group"} {
		b, e := r.run("getent", kind, "qingnode")
		line := strings.TrimSpace(string(b))
		if e != nil || !strings.HasPrefix(line, "qingnode:") || strings.Contains(line, "\n") {
			return errors.New("无法确认专用账户归属，卸载尚未开始")
		}
		record += line + "\n"
	}
	return AtomicWrite(path, []byte(record), 0600)
}

func (r Removal) run(name string, args ...string) ([]byte, error) {
	f := r.Execute
	if f == nil {
		f = Run
	}
	return f(15*time.Second, name, args...)
}
func (r Removal) pairs(full bool) [][2]string {
	p := [][2]string{{filepath.Join(r.Root, "cores"), filepath.Join(r.Root, ".uninstall-cores")}}
	if full {
		p = append(p, [2]string{r.Unit, r.Unit + ".qingnode-uninstall"}, [2]string{r.Binary, r.Binary + ".qingnode-uninstall"}, [2]string{r.Library, r.Library + ".qingnode-uninstall"})
	}
	return p
}
func (r Removal) Recover() error {
	p := filepath.Join(r.Root, "uninstall.json")
	data, e := os.ReadFile(p)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var j removalJournal
	if e = json.Unmarshal(data, &j); e != nil {
		return e
	}
	for _, pair := range r.pairs(j.Full) {
		if _, e = os.Lstat(pair[1]); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil {
			return e
		}
		if _, e = os.Lstat(pair[0]); e == nil {
			return fmt.Errorf("卸载恢复目标已有内容：%s；请先检查，未覆盖", pair[0])
		}
		if e = os.Rename(pair[1], pair[0]); e != nil {
			return e
		}
	}
	if _, e = r.run("systemctl", "daemon-reload"); e != nil {
		return e
	}
	if s, e := ReadState(filepath.Join(r.Root, "current", "state.json")); e == nil && s.Firewall == "ufw" {
		if e = (Firewall{Execute: r.Execute}).Sync(s, true); e != nil {
			return e
		}
	}
	action := "disable"
	if j.Enabled {
		action = "enable"
	}
	if _, e = r.run("systemctl", action, "qingnode.service"); e != nil {
		return e
	}
	if j.Active {
		if _, e = r.run("systemctl", "restart", "qingnode.service"); e != nil {
			return e
		}
	}
	if e = os.Remove(p); e != nil {
		return e
	}
	return SyncDir(r.Root)
}
func (r Removal) Remove(full bool) (err error) {
	b, e := os.ReadFile(r.Unit)
	if e != nil {
		return e
	}
	i, e := os.Lstat(r.Unit)
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() || !strings.HasPrefix(string(b), "# Managed by QingNode\n") {
		return errors.New("服务不属于 QingNode，拒绝卸载")
	}
	if full {
		if i, e := os.Lstat(r.Library); e == nil {
			if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
				return errors.New("辅助目录无效")
			}
			b, e := os.ReadFile(filepath.Join(r.Library, ".qingnode-owner"))
			if e != nil || string(b) != OwnerMarker {
				return errors.New("辅助目录不属于 QingNode")
			}
		}
	}
	for _, pair := range r.pairs(full) {
		if _, e = os.Lstat(pair[1]); !errors.Is(e, os.ErrNotExist) {
			return errors.New("存在未恢复卸载文件，请先运行 recover")
		}
	}
	_, active := r.run("systemctl", "is-active", "--quiet", "qingnode.service")
	_, enabled := r.run("systemctl", "is-enabled", "--quiet", "qingnode.service")
	j := removalJournal{Full: full, Active: active == nil, Enabled: enabled == nil}
	data, _ := json.Marshal(j)
	p := filepath.Join(r.Root, "uninstall.json")
	if e = AtomicWrite(p, data, 0600); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			if re := r.Recover(); re != nil {
				err = fmt.Errorf("卸载失败：%v；恢复未完成：%w（可用安装包内 qingnode recover 重试）", err, re)
			}
		}
	}()
	if _, err = r.run("systemctl", "disable", "--now", "qingnode.service"); err != nil {
		return err
	}
	if s, e := ReadState(filepath.Join(r.Root, "current", "state.json")); e == nil && s.Firewall == "ufw" {
		if err = (Firewall{Execute: r.Execute}).Sync(NewState(), true); err != nil {
			return err
		}
	}
	for _, pair := range r.pairs(full) {
		if _, e = os.Lstat(pair[0]); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if err = os.Rename(pair[0], pair[1]); err != nil {
			return err
		}
	}
	if _, err = r.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Commit only after every fallible service operation succeeds. Trash cleanup can be retried manually.
	if err = os.Remove(p); err != nil {
		return err
	}
	if err = SyncDir(r.Root); err != nil {
		return err
	}
	for _, pair := range r.pairs(full) {
		if e = os.RemoveAll(pair[1]); e != nil {
			return fmt.Errorf("卸载已提交，残留备份目录 %s 需清理：%w", pair[1], e)
		}
	}
	return nil
}
func (b SystemBackend) RecoverRemoval() error {
	return (Removal{Root: b.Root, Unit: "/etc/systemd/system/qingnode.service", Binary: "/usr/local/bin/qingnode", Library: "/usr/local/lib/qingnode", Execute: b.Execute}).Recover()
}
