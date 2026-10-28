// Package platform owns small, bounded host adapters. It does not load State.
package platform

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type CommandRunner func(time.Duration, string, ...string) ([]byte, error)
type InitKind string

const (
	InitSystemd     InitKind = "systemd"
	InitOpenRC      InitKind = "openrc"
	InitUnavailable InitKind = "unavailable"
)

// RunCommand never invokes a shell. Callers supply fixed executables and arguments.
func RunCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type HostFact struct {
	Available   *bool  `json:"available"`
	ToolPresent bool   `json:"tool_present,omitempty"`
	Value       string `json:"value,omitempty"`
	Reason      string `json:"reason,omitempty"`
}
type HostInit struct {
	Kind                InitKind `json:"kind"`
	PID1                string   `json:"pid1,omitempty"`
	ToolPresent         bool     `json:"tool_present"`
	ControllerAvailable bool     `json:"controller_available"`
	Reason              string   `json:"reason"`
}
type HostCapabilities struct {
	Version               int                 `json:"version"`
	MeasuredAt            time.Time           `json:"measured_at"`
	Distro                string              `json:"distro"`
	DistroVersion         string              `json:"distro_version"`
	GOOS                  string              `json:"goos"`
	GOARCH                string              `json:"goarch"`
	Init                  HostInit            `json:"init"`
	PackageManager        string              `json:"package_manager,omitempty"`
	PackageManagerPresent bool                `json:"package_manager_present"`
	InstallTarget         string              `json:"install_target"`
	SELinux               HostFact            `json:"selinux"`
	Firewall              map[string]HostFact `json:"firewall"`
	Virtualization        HostFact            `json:"virtualization"`
	Notes                 []string            `json:"notes"`
}
type HostProbeOptions struct {
	RootDir  string
	Execute  CommandRunner
	LookPath func(string) (string, error)
}

func hostBool(v bool) *bool { return &v }
func hostFile(root, name string) ([]byte, error) {
	p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
	i, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !i.Mode().IsRegular() || i.Size() > 64<<10 {
		return nil, errors.New("unsupported host fact")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if len(b) > 64<<10 {
		return nil, errors.New("host fact too large")
	}
	return b, err
}

// os-release commonly is a relative symlink into /usr/lib. Follow only this
// standard alias; never follow an arbitrary host fact outside the probe root.
func hostOSRelease(root string) ([]byte, error) {
	b, err := hostFile(root, "/etc/os-release")
	if err == nil {
		return b, nil
	}
	p := filepath.Join(root, "etc", "os-release")
	i, statErr := os.Lstat(p)
	if os.IsNotExist(statErr) {
		return hostFile(root, "/usr/lib/os-release")
	}
	if statErr != nil || i.Mode()&os.ModeSymlink == 0 {
		return nil, err
	}
	target, readErr := os.Readlink(p)
	if readErr != nil {
		return nil, readErr
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join("/etc", target)
	}
	if filepath.ToSlash(filepath.Clean(target)) != "/usr/lib/os-release" {
		return nil, errors.New("unsupported os-release symlink")
	}
	return hostFile(root, "/usr/lib/os-release")
}

// ProbeHost is read-only. A command on PATH never proves an init controller works.
// Lower-level sockets, TUN, memory, paths and kernel permissions remain in node's
// RuntimeCapabilities report; this host report supplements that report.
func ProbeHost(o HostProbeOptions) HostCapabilities {
	r := HostCapabilities{Version: 1, MeasuredAt: time.Now().UTC(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Init: HostInit{Kind: InitUnavailable, Reason: "未检测到可用服务控制器"}, Firewall: map[string]HostFact{},
		SELinux: HostFact{Reason: "状态未知"}, Virtualization: HostFact{Reason: "未证明是否容器或虚拟机"},
		Notes: []string{"本机探测不改变服务、防火墙、内核参数或软件仓库。", "安装目标候选不等于该系统已经完成真实生命周期验收。", "UDP/TUN/IPv6/有效权限/目录可写性见配套runtime能力报告；未测不是通过。"}}
	root := o.RootDir
	if root == "" {
		root = string(filepath.Separator)
	}
	if !filepath.IsAbs(root) {
		r.Notes = append(r.Notes, "检查根必须为绝对路径")
		return r
	}
	run := o.Execute
	if run == nil {
		run = RunCommand
	}
	lookup := o.LookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	present := func(name string) bool { _, err := lookup(name); return err == nil }
	if b, e := hostOSRelease(root); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if len(value) >= 2 && (value[0] == '\'' && value[len(value)-1] == '\'' || value[0] == '"' && value[len(value)-1] == '"') {
				value = value[1 : len(value)-1]
			}
			if strings.ContainsAny(value, "\x00\r\n") || len(value) > 128 {
				continue
			}
			switch key {
			case "ID":
				r.Distro = value
			case "VERSION_ID":
				r.DistroVersion = value
			}
		}
	}
	if b, e := hostFile(root, "/proc/1/comm"); e == nil {
		r.Init.PID1 = strings.TrimSpace(string(b))
	}
	systemdDir, e := os.Stat(filepath.Join(root, "run/systemd/system"))
	if r.Init.PID1 == "systemd" && e == nil && systemdDir.IsDir() {
		r.Init.Kind = InitSystemd
		r.Init.ToolPresent = present("systemctl")
		if r.Init.ToolPresent {
			_, e = run(3*time.Second, "systemctl", "show", "--property=Version", "--value")
			r.Init.ControllerAvailable = e == nil
		}
	} else if _, e := hostFile(root, "/run/openrc/softlevel"); e == nil && (r.Init.PID1 == "init" || r.Init.PID1 == "openrc-init") {
		r.Init.Kind = InitOpenRC
		r.Init.ToolPresent = present("rc-service") && present("rc-status") && present("rc-update")
		if r.Init.ToolPresent {
			_, e = run(3*time.Second, "rc-status", "--runlevel")
			r.Init.ControllerAvailable = e == nil
		}
	} else {
		r.Init.ToolPresent = present("systemctl") || present("rc-service")
	}
	if r.Init.ControllerAvailable {
		r.Init.Reason = "检测到init运行材料且只读控制器查询成功；未启动或修改服务"
	} else if r.Init.ToolPresent {
		r.Init.Reason = "服务工具已安装，但当前未证明由对应init管理或控制器不可访问"
	}
	switch r.Distro {
	case "debian", "ubuntu":
		r.PackageManager = "apt-get"
	case "rocky":
		r.PackageManager = "dnf"
	case "alpine":
		r.PackageManager = "apk"
	}
	if r.PackageManager != "" {
		r.PackageManagerPresent = present(r.PackageManager)
	}
	if plan, e := DependenciesFor(r.Distro, r.DistroVersion, r.GOARCH); e == nil {
		r.InstallTarget = plan.Target
	} else {
		r.InstallTarget = "unsupported: " + e.Error()
	}
	for tool, name := range map[string]string{"ufw": "ufw", "firewall-cmd": "firewalld", "nft": "nftables", "iptables": "iptables"} {
		f := HostFact{ToolPresent: present(tool), Reason: "仅检查工具存在；未推断运行策略"}
		if f.ToolPresent && tool == "firewall-cmd" {
			out, e := run(3*time.Second, tool, "--state")
			f.Value = strings.TrimSpace(string(out))
			f.Available = hostBool(e == nil && f.Value == "running")
			f.Reason = "工具存在，另行只读查询守护进程；失败不启动防火墙"
		}
		if f.ToolPresent && tool == "ufw" {
			out, e := run(3*time.Second, tool, "status")
			active := e == nil && strings.Contains(string(out), "Status: active")
			f.Value = "inactive_or_unknown"
			if active {
				f.Value = "active"
			}
			f.Available = hostBool(active)
			f.Reason = "工具存在，另行只读查询UFW状态；失败不启用防火墙"
		}
		r.Firewall[name] = f
	}
	if b, e := hostFile(root, "/sys/fs/selinux/enforce"); e == nil {
		v := strings.TrimSpace(string(b))
		if v == "0" || v == "1" {
			r.SELinux = HostFact{Available: hostBool(true), Value: map[string]string{"0": "permissive", "1": "enforcing"}[v], Reason: "读取内核SELinux挂载；未改变策略"}
		}
	} else if present("getenforce") {
		out, e := run(3*time.Second, "getenforce")
		if e == nil {
			value := strings.TrimSpace(string(out))
			if value == "Enforcing" || value == "Permissive" || value == "Disabled" {
				r.SELinux = HostFact{Available: hostBool(value != "Disabled"), Value: strings.ToLower(value), Reason: "只读getenforce结果"}
			}
		}
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, e := hostFile(root, marker); e == nil {
			r.Virtualization = HostFact{Available: hostBool(true), Value: "container", Reason: "检测到容器标记；权限限制须分别检查"}
			break
		}
	}
	if present("systemd-detect-virt") {
		out, e := run(3*time.Second, "systemd-detect-virt")
		v := strings.TrimSpace(string(out))
		if e == nil && len(v) < 64 && !strings.ContainsAny(v, "\r\n\x00") {
			r.Virtualization = HostFact{Available: hostBool(true), Value: v, Reason: "只读systemd-detect-virt；不保证宿主内核修改权限"}
		}
	}
	return r
}

// MajorVersion deliberately rejects shell expressions and malformed os-release.
func MajorVersion(version string) int {
	part, _, _ := strings.Cut(version, ".")
	n, e := strconv.Atoi(part)
	if e != nil {
		return 0
	}
	return n
}

func DetectServiceManager() InitKind {
	b, e := hostFile(string(filepath.Separator), "/proc/1/comm")
	if e != nil {
		return InitUnavailable
	}
	if strings.TrimSpace(string(b)) == "systemd" {
		if i, e := os.Stat("/run/systemd/system"); e == nil && i.IsDir() {
			if _, e := RunCommand(3*time.Second, "systemctl", "show", "--property=Version", "--value"); e == nil {
				return InitSystemd
			}
		}
	}
	if _, e := hostFile(string(filepath.Separator), "/run/openrc/softlevel"); e == nil && (strings.TrimSpace(string(b)) == "init" || strings.TrimSpace(string(b)) == "openrc-init") {
		for _, name := range []string{"rc-service", "rc-update", "rc-status"} {
			if _, e := exec.LookPath(name); e != nil {
				return InitUnavailable
			}
		}
		if _, e := RunCommand(3*time.Second, "rc-status", "--runlevel"); e == nil {
			return InitOpenRC
		}
	}
	return InitUnavailable
}
