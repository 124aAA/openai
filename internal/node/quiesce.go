package node

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"qingnode/internal/platform"
)

// ConfirmStopped is stronger than !Active: an unavailable systemctl, an
// activating process, or a surviving process in the owned cgroup is not proof
// that the ACME writer has stopped. It never changes enable/disable state.
func (b SystemBackend) ConfirmStopped() error {
	switch b.ServiceManager().ResolvedKind() {
	case platform.InitOpenRC:
		return b.confirmOpenRCStopped()
	case platform.InitSystemd: // retain the stronger unified-cgroup proof below.
	default:
		return errors.New("当前init不可用，无法证明证书存储已停止写入")
	}
	out, err := b.run(10*time.Second, "systemctl", "show", "qingnode.service", "--property=ActiveState,SubState,MainPID,ControlPID,ControlGroup")
	if err != nil {
		return errors.New("无法确认本项目证书写入进程已停止，未创建一致快照")
	}
	properties := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			return errors.New("服务停止状态不完整，未创建一致快照")
		}
		if _, duplicate := properties[key]; duplicate {
			return errors.New("服务停止状态含重复字段，未创建一致快照")
		}
		properties[key] = strings.TrimSpace(value)
	}
	for _, key := range []string{"ActiveState", "SubState", "MainPID", "ControlPID", "ControlGroup"} {
		if _, ok := properties[key]; !ok {
			return errors.New("服务停止状态缺少必要字段，未创建一致快照")
		}
	}
	if properties["ActiveState"] != "inactive" && properties["ActiveState"] != "failed" || properties["SubState"] != "dead" && properties["SubState"] != "failed" || properties["MainPID"] != "0" || properties["ControlPID"] != "0" {
		return errors.New("本项目仍有活动服务或控制进程，未创建一致快照")
	}
	group := properties["ControlGroup"]
	if group == "" {
		return nil
	}
	if group != "/system.slice/qingnode.service" {
		return errors.New("无法核实本项目控制组归属，未创建一致快照")
	}
	root := b.CgroupRoot
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return errors.New("无法确认统一控制组状态；此环境不能证明证书存储已静止")
	}
	path := filepath.Join(root, "system.slice", "qingnode.service", "cgroup.procs")
	i, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, groupErr := os.Lstat(filepath.Dir(path)); errors.Is(groupErr, os.ErrNotExist) {
			return nil // systemd removes an empty inactive service's cgroup.
		}
		return errors.New("控制组存在但进程清单缺失，无法证明证书存储已静止")
	}
	if err != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("无法读取本项目控制组进程，未创建一致快照")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("无法读取本项目控制组进程，未创建一致快照")
	}
	defer f.Close()
	contents, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(contents) > 65536 || strings.TrimSpace(string(contents)) != "" {
		return errors.New("本项目控制组仍有进程或无法确认，未创建一致快照")
	}
	// cgroup.procs excludes descendants. The kernel's populated event includes
	// every child cgroup, so an empty parent alone is insufficient proof.
	eventsPath := filepath.Join(filepath.Dir(path), "cgroup.events")
	eventsInfo, err := os.Lstat(eventsPath)
	if err != nil || !eventsInfo.Mode().IsRegular() || eventsInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("无法确认本项目控制组及子组已无进程")
	}
	events, err := os.Open(eventsPath)
	if err != nil {
		return errors.New("无法确认本项目控制组及子组已无进程")
	}
	data, readErr := io.ReadAll(io.LimitReader(events, 4097))
	closeErr := events.Close()
	if readErr != nil || closeErr != nil || len(data) > 4096 {
		return errors.New("控制组事件读取失败或超限")
	}
	populated := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if populated != "" {
				return errors.New("控制组事件含重复populated字段")
			}
			populated = fields[1]
		}
	}
	if populated != "0" {
		return errors.New("本项目控制组或子组仍有进程，或状态未知，未创建一致快照")
	}
	return nil
}

// OpenRC has no systemd cgroup guarantee. Require stopped status, a missing or
// dead supervisor and a complete privileged /proc scan proving no managed core
// (including an orphan after supervisor failure) can still write ACME assets.
func (b SystemBackend) confirmOpenRCStopped() error {
	out, e := b.run(10*time.Second, "rc-service", "qingnode", "status")
	if e == nil || !strings.Contains(string(out), "status: stopped") {
		return errors.New("OpenRC未明确报告停止，未创建一致快照")
	}
	proc := b.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	pidpath := b.OpenRCPIDFile
	if pidpath == "" {
		pidpath = platform.ServicePIDPath("qingnode")
	}
	if info, e := os.Lstat(pidpath); e == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("OpenRC supervisor PID文件不可信")
		}
		contents, e := os.ReadFile(pidpath)
		if e != nil || len(contents) > 32 {
			return errors.New("无法读取OpenRC supervisor PID")
		}
		pid, e := strconv.Atoi(strings.TrimSpace(string(contents)))
		if e != nil || pid <= 0 {
			return errors.New("OpenRC supervisor PID无效")
		}
		if _, e := os.Stat(filepath.Join(proc, strconv.Itoa(pid))); !errors.Is(e, os.ErrNotExist) {
			return errors.New("OpenRC supervisor仍存在或不可确认")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	entries, e := os.ReadDir(proc)
	if e != nil {
		return errors.New("无法读取完整进程清单，未创建一致快照")
	}
	cores := filepath.Join(b.Root, "cores") + string(filepath.Separator)
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		process := filepath.Join(proc, entry.Name())
		exe, e := os.Readlink(filepath.Join(process, "exe"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return errors.New("存在不可读进程，无法证明证书写入已停止")
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if strings.HasPrefix(exe, cores) && filepath.Base(exe) == "sing-box" {
			return errors.New("发现本项目残留核心进程，未创建一致快照")
		}
		// gcompat executes musl as the visible executable. The owned core is
		// still an exact argv element, so checking exe alone misses this writer.
		if strings.HasPrefix(filepath.Base(exe), "ld-musl-") && strings.HasSuffix(exe, ".so.1") {
			args, e := os.Open(filepath.Join(process, "cmdline"))
			if errors.Is(e, os.ErrNotExist) {
				continue // process exited while taking the read-only inventory
			}
			if e != nil {
				return errors.New("无法确认兼容加载器进程用途，未创建一致快照")
			}
			data, readErr := io.ReadAll(io.LimitReader(args, (64<<10)+1))
			closeErr := args.Close()
			if readErr != nil || closeErr != nil || len(data) > 64<<10 {
				return errors.New("兼容加载器参数读取失败或超限，未创建一致快照")
			}
			for _, arg := range strings.Split(string(data), "\x00") {
				if filepath.IsAbs(arg) && strings.HasPrefix(filepath.Clean(arg), cores) && filepath.Base(arg) == "sing-box" {
					return errors.New("发现本项目经兼容加载器运行的残留核心，未创建一致快照")
				}
			}
		}
		if exe == "/usr/local/bin/qingnode" {
			args, e := os.ReadFile(filepath.Join(process, "cmdline"))
			if e != nil || len(args) > 64<<10 {
				return errors.New("无法确认本项目管理器进程用途")
			}
			for _, arg := range strings.Split(string(args), "\x00") {
				if arg == "serve" {
					return errors.New("发现本项目残留服务进程，未创建一致快照")
				}
			}
		}
	}
	return nil
}
