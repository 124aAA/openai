package node

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"qingnode/internal/platform"
)

type auxiliaryNativeState struct {
	Member    string   `json:"member"`
	Active    bool     `json:"active"`
	Enabled   string   `json:"enabled"`
	Runlevels []string `json:"runlevels,omitempty"`
}

var errAuxiliaryTransition = errors.New("附属服务正在转换状态")
var errAuxiliaryFailed = errors.New("附属服务处于已核对来源的失败状态")

func auxiliaryRun(manager platform.Manager, timeout time.Duration, command string, args ...string) ([]byte, error) {
	if manager.Execute != nil {
		return manager.Execute(timeout, command, args...)
	}
	return Run(timeout, command, args...)
}

func auxiliaryNative(manager platform.Manager, member string, present bool) (auxiliaryNativeState, error) {
	r := auxiliaryNativeState{Member: member, Enabled: "absent"}
	base := strings.TrimSuffix(strings.TrimSuffix(member, ".service"), ".timer")
	if !auxiliaryName(base) {
		return r, errors.New("未知附属服务状态目标")
	}
	if manager.ResolvedKind() == platform.InitSystemd {
		properties := "LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths"
		serviceUnit := strings.HasSuffix(member, ".service")
		if serviceUnit {
			properties += ",MainPID"
		}
		out, commandErr := auxiliaryRun(manager, 10*time.Second, "systemctl", "show", member, "--no-pager", "--property="+properties)
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return r, errors.New("附属服务native状态无法解析；未猜测停止状态")
			}
			if _, exists := values[key]; exists {
				return r, errors.New("附属服务native状态字段重复")
			}
			values[key] = value
		}
		expectedFields, pid := 6, 0
		if serviceUnit {
			expectedFields = 7
			var err error
			pid, err = strconv.Atoi(values["MainPID"])
			if err != nil || pid < 0 {
				return r, errors.New("附属服务PID未知")
			}
		}
		if len(values) != expectedFields || values["DropInPaths"] != "" {
			return r, errors.New("附属服务native状态缺项或存在外部drop-in")
		}
		if !present {
			if values["LoadState"] != "not-found" || values["ActiveState"] != "inactive" || values["FragmentPath"] != "" || values["UnitFileState"] != "" && values["UnitFileState"] != "not-found" || pid != 0 {
				return r, errors.New("磁盘定义缺失但native状态不明确或存在其它来源；拒绝接管")
			}
			return r, nil // structured not-found proof, independent of exit status
		}
		if commandErr != nil {
			return r, errors.New("无法读取当前init的附属服务状态")
		}
		if values["LoadState"] != "loaded" || values["FragmentPath"] != auxiliaryDefinitionPath(manager, member) {
			return r, errors.New("附属服务加载来源不是本项目的目标文件")
		}
		switch values["ActiveState"] {
		case "active":
			r.Active = true
		case "inactive":
		case "activating", "deactivating", "reloading":
			return r, errAuxiliaryTransition
		case "failed":
			return r, errAuxiliaryFailed
		default:
			return r, errors.New("附属服务正在变化、失败或状态未知；待其稳定后再操作")
		}
		if values["SubState"] == "" || !r.Active && pid != 0 {
			return r, errors.New("附属服务运行证据不完整")
		}
		switch values["UnitFileState"] {
		case "enabled", "disabled", "static":
			r.Enabled = values["UnitFileState"]
		default:
			return r, errors.New("附属服务自启动状态未知或不支持恢复")
		}
		if strings.HasSuffix(member, ".timer") && pid != 0 {
			return r, errors.New("timer意外包含工作进程")
		}
		return r, nil
	}
	if manager.ResolvedKind() != platform.InitOpenRC {
		return r, errors.New("当前init不提供可验证的附属服务控制")
	}
	if !present {
		levels, err := manager.Runlevels(base)
		if err != nil || len(levels) > 0 {
			return r, errors.New("缺失OpenRC定义但存在自启项或无法完整核对")
		}
		// An absent script is not by itself proof that OpenRC never started it.
		// Refuse adoption if OpenRC retains any native lifecycle marker.
		runtime := "/run/openrc"
		if manager.RuntimeRoot != "" {
			runtime = filepath.Join(manager.RuntimeRoot, "openrc")
		}
		for _, phase := range []string{"started", "starting", "stopping", "inactive", "failed", "scheduled"} {
			if _, err := os.Lstat(filepath.Join(runtime, phase, base)); !errors.Is(err, os.ErrNotExist) {
				return r, errors.New("缺失OpenRC定义但仍有native生命周期记录，未猜测停止")
			}
		}
		return r, nil
	}
	state, err := manager.State(base)
	if err != nil || state.Active == nil || state.Enabled == nil {
		return r, errors.New("OpenRC附属服务运行或自启状态未知")
	}
	r.Active, r.Enabled = *state.Active, "disabled"
	if *state.Enabled {
		r.Enabled = "enabled"
	}
	r.Runlevels, err = manager.Runlevels(base)
	return r, err
}

func auxiliaryMembers(manager platform.Manager, name string) []string {
	if manager.ResolvedKind() == platform.InitSystemd {
		if name == "qingnode-monitor" {
			return []string{name + ".timer", name + ".service"}
		}
		return []string{name + ".service"}
	}
	return []string{name}
}

func auxiliaryCommand(manager platform.Manager, verb, member string) error {
	if verb != "start" && verb != "stop" && verb != "enable" && verb != "disable" && verb != "reset-failed" {
		return errors.New("不支持的附属native操作")
	}
	base := strings.TrimSuffix(strings.TrimSuffix(member, ".service"), ".timer")
	if !auxiliaryName(base) || strings.HasSuffix(member, ".timer") && base != "qingnode-monitor" {
		return errors.New("拒绝控制未知native单元")
	}
	var err error
	if manager.ResolvedKind() == platform.InitSystemd {
		_, err = auxiliaryRun(manager, 190*time.Second, "systemctl", verb, member)
	} else if manager.ResolvedKind() == platform.InitOpenRC {
		if verb == "reset-failed" {
			return errors.New("OpenRC不接受systemd失败状态复位操作")
		}
		_, err = manager.Command(verb, base)
	} else {
		return errors.New("当前init不可用")
	}
	if err != nil {
		return fmt.Errorf("附属服务%s %s失败：%w", member, verb, err)
	}
	return nil
}

// During a transaction a file can be absent while init still has the previous
// owned definition cached. Reload it before observations when that is possible;
// never treat an unparseable state as inactive.
func auxiliaryCurrent(manager platform.Manager, member string) (auxiliaryNativeState, error) {
	_, err := os.Lstat(auxiliaryDefinitionPath(manager, member))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return auxiliaryNativeState{}, err
	}
	return auxiliaryNative(manager, member, err == nil)
}

func auxiliaryStopCurrent(manager platform.Manager, name string) error {
	for _, member := range auxiliaryMembers(manager, name) {
		state, err := auxiliaryCurrent(manager, member)
		if errors.Is(err, errAuxiliaryTransition) || errors.Is(err, errAuxiliaryFailed) {
			failed := errors.Is(err, errAuxiliaryFailed)
			if err := auxiliaryVerifyNativeSource(manager, member); err != nil {
				return err
			}
			if err := auxiliaryCommand(manager, "stop", member); err != nil {
				return err
			}
			if failed {
				if err := auxiliaryCommand(manager, "reset-failed", member); err != nil {
					return err
				}
			}
			state, err = auxiliaryCurrent(manager, member)
		}
		if err != nil {
			return err
		}
		if state.Active {
			if err := auxiliaryCommand(manager, "stop", member); err != nil {
				return err
			}
		}
	}
	return nil
}

func auxiliaryVerifyNativeSource(manager platform.Manager, member string) error {
	if err := auxiliaryCheckOverrides(manager, member); err != nil {
		return err
	}
	if manager.ResolvedKind() != platform.InitSystemd {
		return nil
	}
	out, _ := auxiliaryRun(manager, 10*time.Second, "systemctl", "show", member, "--property=FragmentPath,DropInPaths")
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("恢复前无法核对native来源")
		}
		if _, exists := values[key]; exists {
			return errors.New("恢复来源字段重复")
		}
		values[key] = value
	}
	if len(values) != 2 || values["DropInPaths"] != "" || values["FragmentPath"] != "" && values["FragmentPath"] != auxiliaryDefinitionPath(manager, member) {
		return errors.New("恢复前发现其它服务来源或附加配置，拒绝接管")
	}
	return nil
}

func auxiliaryWaitStable(manager platform.Manager, name string) error {
	deadline := time.Now().Add(190 * time.Second)
	for {
		busy := false
		for _, member := range auxiliaryMembers(manager, name) {
			_, err := auxiliaryCurrent(manager, member)
			if errors.Is(err, errAuxiliaryTransition) {
				busy = true
				continue
			}
			if err != nil {
				return err
			}
		}
		if !busy {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("附属服务未在有界等待内稳定，不能宣称恢复成功")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func auxiliaryDisableCurrent(manager platform.Manager, name string) error {
	for _, member := range auxiliaryMembers(manager, name) {
		state, err := auxiliaryCurrent(manager, member)
		if err != nil {
			return err
		}
		if state.Enabled == "enabled" || len(state.Runlevels) > 0 {
			if err := auxiliaryCommand(manager, "disable", member); err != nil {
				return err
			}
		}
	}
	return nil
}

func auxiliaryRestoreNative(manager platform.Manager, name string, previous []auxiliaryNativeState, preserve bool) error {
	for _, member := range auxiliaryMembers(manager, name) {
		var wanted auxiliaryNativeState
		for _, state := range previous {
			if state.Member == member {
				wanted = state
			}
		}
		current, err := auxiliaryCurrent(manager, member)
		if err != nil {
			return err
		}
		if current.Enabled == "absent" {
			continue
		}
		if preserve && (wanted.Enabled == "enabled" || len(wanted.Runlevels) > 0) {
			if manager.ResolvedKind() == platform.InitOpenRC {
				if err := manager.EnableRunlevels(name, wanted.Runlevels); err != nil {
					return err
				}
			} else if current.Enabled != "enabled" {
				if err := auxiliaryCommand(manager, "enable", member); err != nil {
					return err
				}
			}
		} else if current.Enabled == "enabled" {
			if err := auxiliaryCommand(manager, "disable", member); err != nil {
				return err
			}
		}
	}
	// Start the timer only when it was already running; a fresh installation
	// stays stopped/disabled and never enables a monitoring policy.
	for _, member := range auxiliaryMembers(manager, name) {
		for _, state := range previous {
			if preserve && state.Member == member && state.Active {
				if err := auxiliaryCommand(manager, "start", member); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func auxiliaryVerifyNative(manager platform.Manager, name string, previous []auxiliaryNativeState, preserve, installed bool) error {
	for _, member := range auxiliaryMembers(manager, name) {
		wantActive, wantEnabled := false, false
		var wantLevels []string
		for _, state := range previous {
			if preserve && state.Member == member {
				wantActive, wantEnabled, wantLevels = state.Active, state.Enabled == "enabled", state.Runlevels
			}
		}
		actual, err := auxiliaryNative(manager, member, installed)
		if err != nil {
			return err
		}
		if actual.Active != wantActive || (actual.Enabled == "enabled") != wantEnabled || manager.ResolvedKind() == platform.InitOpenRC && !auxiliaryEqualStrings(actual.Runlevels, wantLevels) {
			return errors.New("附属服务实际运行或自启动状态与事务目标不一致")
		}
	}
	return nil
}
