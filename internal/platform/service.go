package platform

// Service management is intentionally small: it selects the active host init,
// never installs or replaces init, and never treats a present tool as a running
// service manager. Commands take argument arrays; definitions are rendered from
// validated, local data rather than commands restored from a backup.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Manager is also usable for QingNode's optional subscription/monitor services.
// Kind is explicit for injected tests. An empty real manager uses host detection.
type Manager struct {
	Kind           InitKind
	Execute        CommandRunner
	DefinitionRoot string
	ConfigRoot     string
	RunlevelRoot   string
	ProcRoot       string
	RuntimeRoot    string
}

type ServiceState struct {
	Kind     InitKind `json:"manager"`
	Name     string   `json:"name"`
	Active   *bool    `json:"active,omitempty"`
	Enabled  *bool    `json:"enabled,omitempty"`
	PID      int      `json:"pid,omitempty"`
	State    string   `json:"state"`
	SubState string   `json:"substate,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

var serviceNameRE = regexp.MustCompile(`^qingnode(?:-[a-z0-9]+)*$`)
var runlevelNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func serviceName(name string) (string, error) {
	name = strings.TrimSuffix(name, ".service")
	if !serviceNameRE.MatchString(name) {
		return "", errors.New("只允许控制 QingNode 自有服务名称")
	}
	return name, nil
}

func NewManager(kind InitKind, execute CommandRunner) Manager {
	return Manager{Kind: kind, Execute: execute}
}

func (m Manager) ResolvedKind() InitKind {
	if m.Kind != "" {
		return m.Kind
	}
	// Preserve explicit fake-runner contracts without depending on the test
	// host's init. Real execution always checks the actual host.
	if m.Execute != nil {
		return InitSystemd
	}
	return DetectServiceManager()
}

func (m Manager) run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	if m.Execute != nil {
		return m.Execute(timeout, name, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	out, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, err
}

func (m Manager) command(action, name string) ([]byte, error) {
	n, err := serviceName(name)
	if err != nil {
		return nil, err
	}
	kind := m.ResolvedKind()
	if kind == InitSystemd {
		switch action {
		case "start", "stop", "restart", "try-restart", "enable", "disable", "reset-failed":
			return m.run(35*time.Second, "systemctl", action, n+".service")
		case "disable-now":
			return m.run(35*time.Second, "systemctl", "disable", "--now", n+".service")
		}
	}
	if kind == InitOpenRC {
		switch action {
		case "start", "restart":
			return m.run(35*time.Second, "rc-service", n, action)
		case "stop":
			return nil, m.stopOpenRC(n)
		case "try-restart":
			active, e := m.Active(n)
			if e != nil {
				return nil, e
			}
			if !active {
				return nil, nil
			}
			return m.run(35*time.Second, "rc-service", n, "restart")
		case "enable":
			return m.run(15*time.Second, "rc-update", "add", n, "default")
		case "disable":
			return nil, m.disableOpenRC(n)
		case "disable-now":
			if e := m.stopOpenRC(n); e != nil {
				return nil, e
			}
			return nil, m.disableOpenRC(n)
		}
	}
	return nil, fmt.Errorf("服务管理不可用（%s）；工具存在不代表本机由该 init 管理", kind)
}

func (m Manager) disableOpenRC(name string) error {
	levels, e := m.Runlevels(name)
	if e != nil {
		return e
	}
	// rc-update returns failure when there is nothing to delete. The filesystem
	// proof distinguishes an idempotent no-op from an unknown controller result.
	if len(levels) == 0 {
		return nil
	}
	for _, level := range levels {
		if _, e = m.run(15*time.Second, "rc-update", "del", name, level); e != nil {
			return fmt.Errorf("无法移除本项目在%s的自启动项：%w", level, e)
		}
	}
	remaining, e := m.Runlevels(name)
	if e != nil {
		return e
	}
	if len(remaining) != 0 {
		return errors.New("OpenRC自启动项移除后读回仍存在，未宣称禁用成功")
	}
	return nil
}

func (m Manager) stopOpenRC(name string) error {
	active, e := m.Active(name)
	if e != nil {
		return e
	}
	pid := 0
	if active {
		pid, e = m.PID(name)
		if e != nil || pid <= 0 {
			return errors.New("OpenRC工作进程身份未知，拒绝宣称停止成功")
		}
	}
	if _, e := m.run(35*time.Second, "rc-service", name, "stop"); e != nil {
		return e
	}
	active, e = m.Active(name)
	if e != nil || active {
		return errors.New("OpenRC停止后状态仍活动或无法确认")
	}
	proc := m.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	if pid > 0 {
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, e = os.Stat(filepath.Join(proc, strconv.Itoa(pid)))
			if errors.Is(e, os.ErrNotExist) {
				break
			}
			if e != nil || time.Now().After(deadline) {
				return errors.New("OpenRC已停止但原工作进程仍存在或不可确认")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	runtimeRoot := m.RuntimeRoot
	if runtimeRoot == "" {
		runtimeRoot = "/run/qingnode"
	}
	if data, e := readSmall(filepath.Join(runtimeRoot, name+".supervise.pid"), 32); e == nil {
		pid, e := strconv.Atoi(strings.TrimSpace(string(data)))
		if e != nil || pid <= 0 {
			return errors.New("supervisor PID文件无效")
		}
		if _, e = os.Stat(filepath.Join(proc, strconv.Itoa(pid))); !errors.Is(e, os.ErrNotExist) {
			return errors.New("OpenRC supervisor仍存在或不可确认")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}

func (m Manager) Start(name string) error                     { _, e := m.command("start", name); return e }
func (m Manager) Stop(name string) error                      { _, e := m.command("stop", name); return e }
func (m Manager) Restart(name string) error                   { _, e := m.command("restart", name); return e }
func (m Manager) TryRestart(name string) error                { _, e := m.command("try-restart", name); return e }
func (m Manager) Enable(name string) error                    { _, e := m.command("enable", name); return e }
func (m Manager) Disable(name string) error                   { _, e := m.command("disable", name); return e }
func (m Manager) DisableNow(name string) error                { _, e := m.command("disable-now", name); return e }
func (m Manager) Command(action, name string) ([]byte, error) { return m.command(action, name) }

func (m Manager) ReloadDefinitions() error {
	switch m.ResolvedKind() {
	case InitSystemd:
		_, e := m.run(15*time.Second, "systemctl", "daemon-reload")
		return e
	case InitOpenRC:
		return nil // openrc-run reads its definition on each invocation.
	default:
		return errors.New("当前 init 无法加载服务定义")
	}
}

func (m Manager) Active(name string) (bool, error) {
	n, e := serviceName(name)
	if e != nil {
		return false, e
	}
	switch m.ResolvedKind() {
	case InitSystemd:
		_, e = m.run(10*time.Second, "systemctl", "is-active", "--quiet", n+".service")
		if e == nil {
			return true, nil
		}
		return false, e
	case InitOpenRC:
		out, err := m.run(10*time.Second, "rc-service", n, "status")
		if err == nil && strings.Contains(string(out), "status: started") {
			return true, nil
		}
		if strings.Contains(string(out), "status: stopped") || strings.Contains(string(out), "status: crashed") || strings.Contains(string(out), "status: inactive") {
			return false, nil
		}
		if err == nil {
			err = errors.New("OpenRC 状态缺少已启动证明")
		}
		return false, err
	default:
		return false, errors.New("服务管理不可用；未将工具存在当作运行状态")
	}
}

func (m Manager) Enabled(name string) (bool, error) {
	n, e := serviceName(name)
	if e != nil {
		return false, e
	}
	switch m.ResolvedKind() {
	case InitSystemd:
		_, e = m.run(10*time.Second, "systemctl", "is-enabled", "--quiet", n+".service")
		return e == nil, e
	case InitOpenRC:
		levels, e := m.Runlevels(n)
		return len(levels) > 0, e
	default:
		return false, errors.New("当前 init 无法确认自启动状态")
	}
}

func (m Manager) Runlevels(name string) ([]string, error) {
	n, e := serviceName(name)
	if e != nil {
		return nil, e
	}
	if m.ResolvedKind() != InitOpenRC {
		return nil, errors.New("仅OpenRC使用runlevel清单")
	}
	root := m.RunlevelRoot
	if root == "" {
		root = "/etc/runlevels"
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	var levels []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("OpenRC runlevel目录为外部链接，无法完整确认自启动状态")
		}
		if !entry.IsDir() {
			continue
		}
		if !runlevelNameRE.MatchString(entry.Name()) {
			return nil, errors.New("OpenRC runlevel目录名称无效，未猜测自启动状态")
		}
		p := filepath.Join(root, entry.Name(), n)
		i, e := os.Lstat(p)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if i.Mode()&os.ModeSymlink == 0 {
			return nil, errors.New("OpenRC 自启项不是受管服务链接")
		}
		target, e := filepath.EvalSymlinks(p)
		if e != nil {
			return nil, e
		}
		definition, e := m.DefinitionPath(n)
		if e != nil {
			return nil, e
		}
		if target != definition {
			return nil, errors.New("OpenRC 自启项指向其它服务")
		}
		levels = append(levels, entry.Name())
	}
	return levels, nil
}

func (m Manager) EnableRunlevels(name string, levels []string) error {
	n, e := serviceName(name)
	if e != nil {
		return e
	}
	if m.ResolvedKind() != InitOpenRC {
		return errors.New("仅OpenRC使用runlevel清单")
	}
	for _, level := range levels {
		if !runlevelNameRE.MatchString(level) {
			return errors.New("runlevel名称无效")
		}
	}
	for _, level := range levels {
		if _, e = m.run(15*time.Second, "rc-update", "add", n, level); e != nil {
			return e
		}
	}
	return nil
}

func (m Manager) PID(name string) (int, error) {
	n, e := serviceName(name)
	if e != nil {
		return 0, e
	}
	var out []byte
	switch m.ResolvedKind() {
	case InitSystemd:
		out, e = m.run(8*time.Second, "systemctl", "show", n+".service", "--property=MainPID", "--value")
	case InitOpenRC:
		out, e = m.run(8*time.Second, "rc-service", n, "qingnode_pid")
	default:
		return 0, errors.New("当前 init 无法确认服务 PID")
	}
	if e != nil {
		return 0, e
	}
	p, e := strconv.Atoi(strings.TrimSpace(string(out)))
	if e != nil || p < 0 {
		return 0, errors.New("服务 PID 响应无效")
	}
	return p, nil
}

func (m Manager) State(name string) (ServiceState, error) {
	n, e := serviceName(name)
	if e != nil {
		return ServiceState{}, e
	}
	r := ServiceState{Kind: m.ResolvedKind(), Name: n, State: "unknown"}
	if r.Kind == InitSystemd {
		out, e := m.run(8*time.Second, "systemctl", "show", n+".service", "--no-pager", "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState")
		if e != nil {
			r.Reason = "systemctl 不可用或无法连接当前 init"
			return r, e
		}
		p := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				if _, found := p[k]; found {
					return r, errors.New("服务状态字段重复")
				}
				p[k] = v
			}
		}
		if p["LoadState"] != "loaded" {
			r.Reason = "服务尚未由当前 init 加载"
			return r, errors.New(r.Reason)
		}
		active := p["ActiveState"] == "active"
		enabled := p["UnitFileState"] == "enabled"
		r.Active = &active
		r.Enabled = &enabled
		r.State, r.SubState = p["ActiveState"], p["SubState"]
		var pidError error
		r.PID, pidError = strconv.Atoi(p["MainPID"])
		if r.State == "" || pidError != nil || r.PID < 0 {
			return r, errors.New("服务状态不完整")
		}
		return r, nil
	}
	if r.Kind == InitOpenRC {
		active, e := m.Active(n)
		if e != nil {
			r.Reason = e.Error()
			return r, e
		}
		r.Active = &active
		if active {
			r.State = "active"
			r.SubState = "running"
			r.PID, e = m.PID(n)
			if e != nil || r.PID <= 0 {
				r.Active = nil
				r.State = "unknown"
				return r, errors.New("OpenRC 声称启动但缺少实际工作进程 PID")
			}
		} else {
			r.State = "inactive"
			r.SubState = "stopped"
		}
		enabled, e := m.Enabled(n)
		if e == nil {
			r.Enabled = &enabled
		}
		return r, e
	}
	r.Reason = "没有可用的受支持 init；命令存在不能证明服务受管"
	return r, errors.New(r.Reason)
}

func (m Manager) DefinitionPath(name string) (string, error) {
	n, e := serviceName(name)
	if e != nil {
		return "", e
	}
	root := m.DefinitionRoot
	switch m.ResolvedKind() {
	case InitSystemd:
		if root == "" {
			root = "/etc/systemd/system"
		}
		return filepath.Join(root, n+".service"), nil
	case InitOpenRC:
		if root == "" {
			root = "/etc/init.d"
		}
		return filepath.Join(root, n), nil
	default:
		return "", errors.New("当前 init 没有受管服务路径")
	}
}

func ManagedDefinition(contents []byte) bool {
	return bytes.HasPrefix(contents, []byte("# Managed by QingNode\n")) || bytes.HasPrefix(contents, []byte("#!/sbin/openrc-run\n# Managed by QingNode\n"))
}

// VerifyOwnership rejects administrator overrides rather than taking them over.
func (m Manager) VerifyOwnership(name string, expected []byte) error {
	n, e := serviceName(name)
	if e != nil {
		return e
	}
	path, e := m.DefinitionPath(n)
	if e != nil {
		return e
	}
	i, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Size() > 128<<10 {
		return errors.New("受管服务定义必须是普通文件")
	}
	if e = verifyDefinitionFileOwner(i); e != nil {
		return e
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) || !opened.Mode().IsRegular() || opened.Size() > 128<<10 {
		return errors.New("服务定义在核验期间改变")
	}
	if e = verifyDefinitionFileOwner(opened); e != nil {
		return e
	}
	actual, e := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if e != nil {
		return e
	}
	if len(actual) > 128<<10 {
		return errors.New("服务定义超过128KiB上限")
	}
	if !ManagedDefinition(actual) || expected != nil && !bytes.Equal(actual, expected) {
		return errors.New("服务定义已由外部修改，拒绝接管")
	}
	if m.ResolvedKind() == InitSystemd {
		out, e := m.run(5*time.Second, "systemctl", "show", n+".service", "--property=FragmentPath,DropInPaths")
		if e != nil {
			return e
		}
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return errors.New("无法确认服务加载来源")
			}
			if _, exists := values[k]; exists {
				return errors.New("服务来源字段重复")
			}
			values[k] = v
		}
		if values["FragmentPath"] != path || values["DropInPaths"] != "" || len(values) != 2 {
			return errors.New("服务加载来源或附加配置不属于 QingNode")
		}
	} else {
		root := m.ConfigRoot
		if root == "" {
			root = "/etc/conf.d"
		}
		if _, e := os.Lstat(filepath.Join(root, n)); !errors.Is(e, os.ErrNotExist) {
			return errors.New("存在外部 OpenRC conf.d 覆盖，拒绝自动接管")
		}
	}
	return nil
}

func (m Manager) Logs(name string, lines int) ([]byte, error) {
	n, e := serviceName(name)
	if e != nil {
		return nil, e
	}
	if lines < 1 || lines > 1000 {
		return nil, errors.New("日志行数须在1–1000之间")
	}
	switch m.ResolvedKind() {
	case InitSystemd:
		return m.run(10*time.Second, "journalctl", "-u", n+".service", "-n", strconv.Itoa(lines), "--no-pager")
	case InitOpenRC:
		return m.run(10*time.Second, "tail", "-n", strconv.Itoa(lines), "--", ServiceLogPath(n))
	default:
		return nil, errors.New("当前 init 没有已配置的受管日志")
	}
}

func ServicePIDPath(name string) string { return path.Join("/run/qingnode", name+".supervise.pid") }
func ServiceLogPath(name string) string { return path.Join("/var/log/qingnode", name+".log") }

// readSmall is used by stop proofs; neither symlinks nor unbounded data qualify.
func readSmall(path string, limit int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("状态文件不是普通文件")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	out, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(out)) > limit {
		return nil, errors.New("状态文件读取失败或超限")
	}
	return out, nil
}
