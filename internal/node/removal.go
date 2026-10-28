package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"qingnode/internal/platform"
)

// Locations are supplied by the installed CLI, never read from a backup or journal.
type Removal struct {
	Root, Unit, Binary, Library string
	Execute                     Runner
	ManagerKind                 platform.InitKind
	Logrotate                   string
	RunlevelRoot                string // optional isolated fixture root
	DefinitionRoot              string // optional isolated fixture root
	ConfigRoot                  string // optional isolated OpenRC override fixture root
}

func (r Removal) manager() platform.Manager {
	m := platform.NewManager(r.ManagerKind, platform.CommandRunner(r.Execute))
	m.RunlevelRoot = r.RunlevelRoot
	m.DefinitionRoot = r.DefinitionRoot
	m.ConfigRoot = r.ConfigRoot
	if m.DefinitionRoot == "" && r.Unit != "" {
		m.DefinitionRoot = filepath.Dir(r.Unit)
	}
	return m
}

// Match the fixed installer rendering. A retained marker does not authorize
// removal of administrator-edited rotation rules or linked external files.
const managedLogrotate = `# Managed by QingNode
/var/log/qingnode/qingnode.log /var/log/qingnode/qingnode-subscription.log /var/log/qingnode/qingnode-monitor.log {
    size 1M
    rotate 3
    missingok
    notifempty
    copytruncate
}
`

func ownedLogrotate(path string) bool {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 || i.Size() != int64(len(managedLogrotate)) {
		return false
	}
	uid, _, e := certificateFileOwner(i)
	if e != nil || uid != 0 && uid != uint32(os.Geteuid()) {
		return false
	}
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) {
		return false
	}
	data, e := io.ReadAll(io.LimitReader(f, int64(len(managedLogrotate))+1))
	return e == nil && bytes.Equal(data, []byte(managedLogrotate))
}

type removalJournal struct {
	Full      bool     `json:"full"`
	Active    bool     `json:"active"`
	Enabled   bool     `json:"enabled"`
	Runlevels []string `json:"openrc_runlevels,omitempty"`
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

// Check the exact definition in its live or transaction-owned staging location.
// Native waits may run administrator hooks, so a preflight marker alone cannot
// authorize a later move, recovery restart, or deletion of changed material.
func (r Removal) serviceMaterialSafe(allowMoved, allowUnloaded bool) error {
	expected, err := ServiceDefinition(r.manager().ResolvedKind())
	if err != nil {
		return err
	}
	local := func() (bool, error) {
		live, liveErr := os.Lstat(r.Unit)
		stored, storedErr := os.Lstat(r.Unit + ".qingnode-uninstall")
		if liveErr != nil && !errors.Is(liveErr, os.ErrNotExist) || storedErr != nil && !errors.Is(storedErr, os.ErrNotExist) {
			return false, errors.New("无法核对卸载服务原件和恢复文件")
		}
		if liveErr == nil && storedErr == nil {
			return false, errors.New("服务原件和恢复文件同时存在；保留两份材料，未覆盖")
		}
		path, info, moved := r.Unit, live, false
		if liveErr != nil {
			if !allowMoved || storedErr != nil {
				return false, errors.New("受管服务定义丢失；未猜测它已安全停止")
			}
			path, info, moved = r.Unit+".qingnode-uninstall", stored, true
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 128<<10 {
			return false, errors.New("卸载服务定义的类型、权限或大小已变化")
		}
		uid, _, err := certificateFileOwner(info)
		if err != nil || uid != 0 && uid != uint32(os.Geteuid()) {
			return false, errors.New("卸载服务定义的属主或链接数已变化")
		}
		f, err := os.Open(path)
		if err != nil {
			return false, err
		}
		opened, statErr := f.Stat()
		contents, readErr := io.ReadAll(io.LimitReader(f, (128<<10)+1))
		closeErr := f.Close()
		if statErr != nil || !os.SameFile(info, opened) || readErr != nil || closeErr != nil || !bytes.Equal(contents, []byte(expected)) {
			return false, errors.New("服务定义已由外部修改；保留原件和恢复材料，未接管")
		}
		manager := r.manager()
		member := "qingnode"
		if manager.ResolvedKind() == platform.InitSystemd {
			member += ".service"
		}
		if err := auxiliaryCheckOverrides(manager, member); err != nil {
			return false, err
		}
		return moved, nil
	}
	moved, err := local()
	if err != nil {
		return err
	}
	if r.manager().ResolvedKind() == platform.InitSystemd {
		// Use the original runner, never the checked wrapper, to avoid recursion.
		out, err := r.run("systemctl", "show", "qingnode.service", "--property=FragmentPath,DropInPaths")
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return errors.New("无法核对卸载服务的加载来源")
			}
			if _, exists := values[key]; exists {
				return errors.New("卸载服务来源字段重复")
			}
			values[key] = value
		}
		fragment := values["FragmentPath"]
		// Some systemctl builds return nonzero for a structured not-found
		// response after our own staged removal. An absent fragment is allowed
		// only in that attested staging/pre-reload phase, never for a live write.
		unknown := err != nil && !(fragment == "" && (moved || allowUnloaded))
		if unknown || len(values) != 2 || values["DropInPaths"] != "" || fragment != r.Unit && (fragment != "" || !moved && !allowUnloaded) {
			return errors.New("卸载服务加载来源或附加配置已变化，未控制其它服务")
		}
	}
	_, err = local() // an external writer can also act during a source query
	return err
}

func (r Removal) libraryMaterialSafe(allowMoved bool) error {
	path := r.Library
	_, liveErr := os.Lstat(path)
	_, storedErr := os.Lstat(path + ".qingnode-uninstall")
	if liveErr == nil && storedErr == nil {
		return errors.New("辅助目录原件和恢复目录同时存在；未覆盖")
	}
	if liveErr != nil && !errors.Is(liveErr, os.ErrNotExist) || storedErr != nil && !errors.Is(storedErr, os.ErrNotExist) {
		return errors.New("无法核对辅助目录及恢复目录")
	}
	if liveErr != nil {
		if storedErr != nil {
			return nil
		}
		if !allowMoved {
			return errors.New("辅助目录意外移入恢复路径，未继续")
		}
		path += ".qingnode-uninstall"
	}
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0022 != 0 {
		return errors.New("辅助目录类型或权限异常")
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return errors.New("辅助目录属主异常，未删除")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	marker := false
	for _, entry := range entries {
		if entry.Name() != ".qingnode-owner" && entry.Name() != "install.sh" {
			return errors.New("辅助目录包含未知文件；保留外部内容，拒绝完整卸载")
		}
		info, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return errors.New("辅助目录成员类型或权限异常，未删除")
		}
		uid, _, err := certificateFileOwner(info)
		if err != nil || uid != 0 && uid != uint32(os.Geteuid()) {
			return errors.New("辅助目录成员属主或链接数异常，未删除")
		}
		if entry.Name() == ".qingnode-owner" {
			b, err := os.ReadFile(filepath.Join(path, entry.Name()))
			if err != nil || string(b) != OwnerMarker {
				return errors.New("辅助目录不属于QingNode，未删除")
			}
			marker = true
		}
	}
	if !marker {
		return errors.New("辅助目录缺少所有权标记，未删除")
	}
	return nil
}

func (r Removal) guardedServiceRunner(allowMoved, allowUnloaded, full bool) (Runner, *removalOwnershipGuard) {
	guard := &removalOwnershipGuard{r: r, allowMoved: allowMoved, allowUnloaded: allowUnloaded, full: full}
	original := r.Execute
	if original == nil {
		original = Run
	}
	return func(timeout time.Duration, name string, args ...string) ([]byte, error) {
		if err := guard.check(); err != nil {
			return nil, err
		}
		out, err := original(timeout, name, args...)
		if changed := guard.check(); changed != nil {
			return out, changed
		}
		return out, err
	}, guard
}

func (r Removal) serviceSnapshot() (active, enabled bool, err error) {
	if r.manager().ResolvedKind() == platform.InitOpenRC {
		active, err = r.manager().Active("qingnode")
		if err != nil {
			return false, false, err
		}
		enabled, err = r.manager().Enabled("qingnode")
		return active, enabled, err
	}
	if r.manager().ResolvedKind() != platform.InitSystemd {
		return false, false, errors.New("服务控制器不可用，不能保存卸载恢复状态")
	}
	out, err := r.run("systemctl", "show", "qingnode.service", "--no-pager", "--property=LoadState,ActiveState,UnitFileState,FragmentPath")
	if err != nil {
		return false, false, errors.New("服务状态查询失败，未把未知状态保存为停止或禁用")
	}
	p := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			return false, false, errors.New("服务状态响应不完整")
		}
		if _, duplicate := p[key]; duplicate {
			return false, false, errors.New("服务状态响应含重复字段")
		}
		p[key] = value
	}
	if len(p) != 4 || p["LoadState"] != "loaded" || p["FragmentPath"] != r.Unit {
		return false, false, errors.New("服务加载状态或来源无法确认，卸载尚未开始")
	}
	switch p["ActiveState"] {
	case "active":
		active = true
	case "inactive", "failed":
	default:
		return false, false, errors.New("服务正在转换或状态未知，卸载尚未开始")
	}
	switch p["UnitFileState"] {
	case "enabled":
		enabled = true
	case "disabled":
	default:
		return false, false, errors.New("服务自启动状态不能无损映射，保留原设置并停止卸载")
	}
	return active, enabled, nil
}
func (r Removal) pairs(full bool) [][2]string {
	p := [][2]string{{filepath.Join(r.Root, "cores"), filepath.Join(r.Root, ".uninstall-cores")}}
	if full {
		p = append(p, [2]string{r.Unit, r.Unit + ".qingnode-uninstall"}, [2]string{r.Binary, r.Binary + ".qingnode-uninstall"}, [2]string{r.Library, r.Library + ".qingnode-uninstall"})
		if r.Logrotate != "" {
			if ownedLogrotate(r.Logrotate) {
				p = append(p, [2]string{r.Logrotate, r.Logrotate + ".qingnode-uninstall"})
			} else if ownedLogrotate(r.Logrotate + ".qingnode-uninstall") {
				p = append(p, [2]string{r.Logrotate, r.Logrotate + ".qingnode-uninstall"})
			}
		}
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
	r.ManagerKind = r.manager().ResolvedKind()
	run, guard := r.guardedServiceRunner(j.Full, true, j.Full)
	check := guard.check
	manager := r.manager()
	manager.Execute = platform.CommandRunner(run)
	if e = check(); e != nil {
		return e
	}
	for _, pair := range r.pairs(j.Full) {
		if e = check(); e != nil {
			return e
		}
		if _, e = os.Lstat(pair[1]); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil {
			return e
		}
		if _, e = os.Lstat(pair[0]); e == nil {
			return fmt.Errorf("卸载恢复目标已有内容：%s；请先检查，未覆盖", pair[0])
		}
		if e = unix.Renameat2(unix.AT_FDCWD, pair[1], unix.AT_FDCWD, pair[0], unix.RENAME_NOREPLACE); e != nil {
			return e
		}
		if e = check(); e != nil {
			return e
		}
	}
	if e = manager.ReloadDefinitions(); e != nil {
		return e
	}
	// Definitions are now loaded. Subsequent enable/restart must attest that
	// exact live path, rather than accept the pre-reload empty source.
	guard.allowMoved, guard.allowUnloaded = false, false
	if e = check(); e != nil {
		return e
	}
	if s, e := ReadState(filepath.Join(r.Root, "current", "state.json")); e == nil && (s.Firewall == "ufw" || s.Firewall == "firewalld") {
		if e = (Firewall{Execute: run}).Sync(s, true); e != nil {
			return e
		}
	}
	action := "disable"
	if j.Enabled {
		action = "enable"
	}
	if manager.ResolvedKind() == platform.InitOpenRC && j.Enabled && len(j.Runlevels) > 0 {
		if e = manager.Disable("qingnode"); e != nil {
			return e
		}
		if e = manager.EnableRunlevels("qingnode", j.Runlevels); e != nil {
			return e
		}
	} else if _, e = manager.Command(action, "qingnode"); e != nil {
		return e
	}
	if j.Active {
		if e = manager.Restart("qingnode"); e != nil {
			return e
		}
	}
	if e = check(); e != nil {
		return e
	}
	if e = os.Remove(p); e != nil {
		return e
	}
	return SyncDir(r.Root)
}
func (r Removal) Remove(full bool) (err error) {
	if full {
		if err := PendingAuxiliaryService(r.Root); err != nil {
			return err
		}
		gaps, err := AuxiliaryServiceMigrationGaps(r.Root)
		if err != nil {
			return err
		}
		if len(gaps) > 0 {
			return errors.New("附属服务仍有受管部署资料；请先service remove --name对应服务，保留恢复材料后再完整卸载")
		}
	}
	if r.manager().ResolvedKind() == platform.InitUnavailable {
		return errors.New("当前init不可用，卸载尚未开始；不会把服务工具存在当成已停用")
	}
	r.ManagerKind = r.manager().ResolvedKind()
	if full && r.Execute == nil {
		// Optional services may retain credential snapshots or root-only monitor
		// state. Do not delete their executable while they still have an installed
		// lifecycle; removal is explicit rather than guessing ownership/settings.
		for _, name := range []string{"qingnode-subscription", "qingnode-monitor"} {
			path, e := r.manager().DefinitionPath(name)
			if e != nil {
				return e
			}
			if _, e := os.Lstat(path); e == nil {
				return fmt.Errorf("附属服务 %s 仍已安装；请先按文档停止、禁用并移除其自有定义，再完整卸载", name)
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if name == "qingnode-monitor" && r.manager().ResolvedKind() == platform.InitSystemd {
				timer := strings.TrimSuffix(path, ".service") + ".timer"
				if _, e := os.Lstat(timer); !errors.Is(e, os.ErrNotExist) {
					return errors.New("监控timer仍存在或无法核对；拒绝删除其程序，请先处理附属服务部署")
				}
			}
		}
	}
	run, guard := r.guardedServiceRunner(full, false, full)
	check := guard.check
	if e := check(); e != nil {
		return fmt.Errorf("服务定义、来源或附加配置已变化，拒绝卸载：%w", e)
	}
	for _, pair := range r.pairs(full) {
		if _, e := os.Lstat(pair[1]); !errors.Is(e, os.ErrNotExist) {
			return errors.New("存在未恢复卸载文件，请先运行 recover")
		}
	}
	observed := r
	observed.Execute = run
	active, enabled, e := observed.serviceSnapshot()
	if e != nil {
		return e
	}
	j := removalJournal{Full: full, Active: active, Enabled: enabled}
	if r.manager().ResolvedKind() == platform.InitOpenRC {
		j.Runlevels, e = r.manager().Runlevels("qingnode")
		if e != nil {
			return e
		}
	}
	data, _ := json.Marshal(j)
	p := filepath.Join(r.Root, "uninstall.json")
	manager := r.manager()
	manager.Execute = platform.CommandRunner(run)
	if e = check(); e != nil {
		return e
	}
	if e = AtomicWrite(p, data, 0600); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			// Do not establish a new recovery baseline from material that changed
			// during this operation, then accidentally execute that foreign copy.
			if unsafe := check(); unsafe != nil {
				err = fmt.Errorf("卸载失败：%v；文件归属或指纹已变化，未自动恢复；保留材料供人工核对：%w", err, unsafe)
				return
			}
			if re := r.Recover(); re != nil {
				err = fmt.Errorf("卸载失败：%v；恢复未完成：%w（可用安装包内 qingnode recover 重试）", err, re)
			}
		}
	}()
	if err = manager.DisableNow("qingnode"); err != nil {
		return err
	}
	if s, e := ReadState(filepath.Join(r.Root, "current", "state.json")); e == nil && (s.Firewall == "ufw" || s.Firewall == "firewalld") {
		if err = (SystemBackend{Execute: run, ManagerKind: r.ManagerKind}).FinishEffects(s, NewState()); err != nil {
			return err
		}
	}
	for _, pair := range r.pairs(full) {
		if err = check(); err != nil {
			return err
		}
		if _, e = os.Lstat(pair[0]); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if err = unix.Renameat2(unix.AT_FDCWD, pair[0], unix.AT_FDCWD, pair[1], unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = check(); err != nil {
			return err
		}
	}
	if err = manager.ReloadDefinitions(); err != nil {
		return err
	}
	// Commit only after every fallible service operation succeeds. Trash cleanup can be retried manually.
	if err = check(); err != nil {
		return err
	}
	if err = os.Remove(p); err != nil {
		return err
	}
	if err = SyncDir(r.Root); err != nil {
		return err
	}
	cleanup := r.pairs(full)
	// Keep the attested service definition until every other staged asset was
	// cleaned, so each potentially destructive cleanup retains its ownership
	// proof. The service itself is removed last, with no later native action.
	for i := range cleanup {
		if cleanup[i][0] == r.Unit {
			cleanup[i], cleanup[len(cleanup)-1] = cleanup[len(cleanup)-1], cleanup[i]
			break
		}
	}
	for _, pair := range cleanup {
		if e = guard.cleanupCheck(); e != nil {
			return fmt.Errorf("卸载已提交，检测到外部服务改动；保留残余恢复文件：%w", e)
		}
		if e = os.RemoveAll(pair[1]); e != nil {
			return fmt.Errorf("卸载已提交，残留备份目录 %s 需清理：%w", pair[1], e)
		}
	}
	return nil
}
func (b SystemBackend) RecoverRemoval() error {
	path, e := b.ServiceManager().DefinitionPath("qingnode")
	if e != nil {
		if _, journalErr := os.Stat(filepath.Join(b.Root, "uninstall.json")); errors.Is(journalErr, os.ErrNotExist) {
			return nil
		}
		return e
	}
	return (Removal{Root: b.Root, Unit: path, Binary: "/usr/local/bin/qingnode", Library: "/usr/local/lib/qingnode", Execute: b.Execute, ManagerKind: b.ServiceManager().ResolvedKind(), Logrotate: "/etc/logrotate.d/qingnode"}).Recover()
}
