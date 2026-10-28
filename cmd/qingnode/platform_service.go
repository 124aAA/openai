package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/platform"
)

func serviceKind(value string) (platform.InitKind, error) {
	k := platform.InitKind(value)
	if k != platform.InitSystemd && k != platform.InitOpenRC {
		return k, errors.New("服务管理器仅支持systemd或openrc")
	}
	return k, nil
}

func renderServiceDefinition(args []string) error {
	f := fs("service unit")
	manager := f.String("manager", "systemd", "systemd或openrc；只输出受管服务定义")
	name := f.String("name", "qingnode", "qingnode或qingnode-subscription；附属账户须显式准备")
	publicURL := f.String("public-url", "", "订阅已有HTTPS反向代理的公开URL，不含令牌")
	if e := parse(f, args); e != nil {
		return e
	}
	k, e := serviceKind(*manager)
	if e != nil {
		return e
	}
	if *name == "qingnode-subscription" {
		definition, e := auxiliaryServiceDefinition(k, *name, *publicURL)
		if e == nil {
			fmt.Print(definition)
		}
		return e
	}
	if *name != "qingnode" || *publicURL != "" {
		return errors.New("未知服务或不适用的public-url")
	}
	definition, e := node.ServiceDefinition(k)
	if e == nil {
		fmt.Print(definition)
	}
	return e
}

const monitorSystemdService = node.AuxiliaryMonitorSystemdService
const monitorSystemdTimer = node.AuxiliaryMonitorSystemdTimer

// A name or marker alone cannot attest to a service's command and privileges.
// Controls and material generation use exactly the same local definitions.
func auxiliaryServiceDefinition(kind platform.InitKind, name, publicURL string) (string, error) {
	plan, err := node.NewAuxiliaryServicePlan(platform.NewManager(kind, nil), name, publicURL)
	if err != nil {
		return "", err
	}
	filename := name
	if kind == platform.InitSystemd {
		filename += ".service"
	}
	for _, file := range plan.Definitions {
		if file.Name == filename {
			return string(file.Contents), nil
		}
	}
	return "", errors.New("附属服务规范缺少本机服务定义")
}

// Tests replace only this local factory; the production CLI accepts no
// environment override that can pretend an init controller is running.
var auxiliaryManager = func() platform.Manager { return platform.NewManager("", nil) }

func auxiliaryName(name string) bool {
	return name == "qingnode-monitor" || name == "qingnode-subscription"
}

func (a *app) auxiliaryDeployment(manager platform.Manager, action, name, publicURL string, preview, yes bool) error {
	if !auxiliaryName(name) {
		return errors.New("install/remove/recover仅用于明确指定的qingnode-monitor或qingnode-subscription；核心沿原安装/卸载事务")
	}
	if preview && yes {
		return errors.New("--preview和--yes不能同时使用")
	}
	if !preview && !yes {
		return errors.New("附属服务变更需要--yes；先用--preview查看，安装不会自动启动或启用新服务")
	}
	if a.offline {
		return errors.New("离线模式不部署附属服务")
	}
	if action == "recover" && publicURL != "" {
		return errors.New("recover使用本地受管记录，不接受public-url替换恢复材料")
	}
	// Check the managed root under its read lease, then release State before
	// any native action can start the monitor's own State reader.
	if err := a.store.InspectExisting(func() error {
		_, err := a.store.Load()
		return err
	}); err != nil {
		return err
	}
	plan := node.AuxiliaryServicePlan{Name: name, Manager: manager}
	var err error
	if action == "install" || publicURL != "" {
		plan, err = node.NewAuxiliaryServicePlan(manager, name, publicURL)
		if err != nil {
			return err
		}
	}
	if action == "recover" {
		result, err := node.RecoverAuxiliaryService(a.store.Root, plan, preview)
		if err != nil {
			return err
		}
		return printAuxiliaryPreview(result)
	}
	if preview {
		result, err := node.PreviewAuxiliaryService(a.store.Root, plan, action)
		if err != nil {
			return err
		}
		return printAuxiliaryPreview(result)
	}
	if err = node.ApplyAuxiliaryService(a.store.Root, plan, action); err != nil {
		return err
	}
	a.message("SUCCESS", "附属服务"+name+"的"+action+"事务已完成；代理State未改动")
	return nil
}

func printAuxiliaryPreview(result node.AuxiliaryServicePreview) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err == nil {
		fmt.Println(string(b))
	}
	return err
}

func auxiliaryNative(manager platform.Manager, timeout time.Duration, command string, args ...string) ([]byte, error) {
	if manager.Execute != nil {
		return manager.Execute(timeout, command, args...)
	}
	return platform.RunCommand(timeout, command, args...)
}

// This is a single fixed local timer, not a general unit-name escape hatch.
func monitorTimerCommand(manager platform.Manager, action string) error {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return errors.New("未知监控调度操作")
	}
	_, err := auxiliaryNative(manager, 35*time.Second, "systemctl", action, "qingnode-monitor.timer")
	return err
}

func monitorTimerState(manager platform.Manager) (platform.ServiceState, error) {
	s := platform.ServiceState{Name: "qingnode-monitor.timer", Kind: platform.InitSystemd, State: "unknown"}
	out, err := auxiliaryNative(manager, 8*time.Second, "systemctl", "show", "qingnode-monitor.timer", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState")
	if err != nil {
		return s, errors.New("无法读取监控timer状态，未当作停止或禁用")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return s, errors.New("监控timer状态不完整")
		}
		if _, exists := fields[key]; exists {
			return s, errors.New("监控timer状态字段重复")
		}
		fields[key] = value
	}
	if len(fields) != 4 || fields["LoadState"] != "loaded" || fields["ActiveState"] == "" || fields["SubState"] == "" {
		return s, errors.New("监控timer尚未加载或状态不完整")
	}
	s.State, s.SubState = fields["ActiveState"], fields["SubState"]
	switch s.State {
	case "active", "inactive", "failed":
		active := s.State == "active"
		s.Active = &active
	default:
		return s, errors.New("监控timer处于转换或未知状态")
	}
	switch fields["UnitFileState"] {
	case "enabled", "disabled":
		enabled := fields["UnitFileState"] == "enabled"
		s.Enabled = &enabled
	default:
		return s, errors.New("监控timer自启状态不完整")
	}
	return s, nil
}

func showAuxiliaryService(manager platform.Manager, name string) error {
	s, err := manager.State(name)
	if name != "qingnode-monitor" || manager.ResolvedKind() != platform.InitSystemd {
		fmt.Print(formatServiceState(s))
		return err
	}
	// The oneshot has no Install section. Report its worker state separately
	// from the real scheduler's enablement, rather than calling static disabled.
	timer, timerErr := monitorTimerState(manager)
	s.Enabled = timer.Enabled
	fmt.Print(formatServiceState(s))
	fmt.Printf("WorkerUnit=qingnode-monitor.service\nSchedulerUnit=qingnode-monitor.timer\nSchedulerActiveState=%s\nSchedulerSubState=%s\n", timer.State, timer.SubState)
	if err != nil {
		return err
	}
	return timerErr
}

func (a *app) serviceLogs(manager platform.Manager, name string, lines int) error {
	if name != "qingnode" && !auxiliaryName(name) {
		return errors.New("日志仅支持本项目代理、订阅和监控服务")
	}
	if lines < 1 || lines > 1000 {
		return errors.New("日志行数须在1–1000之间")
	}
	if a.offline {
		return errors.New("离线模式没有宿主服务日志")
	}
	return a.store.InspectExisting(func() error {
		s, err := a.store.Load()
		if err != nil {
			return errors.New("无法安全读取日志脱敏材料，未展示宿主日志")
		}
		out, err := manager.Logs(name, lines)
		if err != nil {
			return errors.New("无法读取所选受管服务日志")
		}
		text := a.safeText(string(out), s)
		if name == "qingnode-monitor" {
			config, err := a.monitorStore().LoadConfig()
			if err != nil && !os.IsNotExist(err) {
				return errors.New("监控秘密配置不可读，未展示可能未经脱敏的日志")
			}
			if err == nil {
				for _, secret := range []string{config.Notifications.Endpoint, config.Notifications.Token, config.Notifications.ChatID} {
					if secret != "" {
						for _, encoded := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
							text = strings.ReplaceAll(text, encoded, "[REDACTED]")
						}
					}
				}
			}
		}
		fmt.Print(node.Redact(text))
		return nil
	})
}

// Starting a systemd oneshot waits for monitor run, which must inspect State.
// Keep ownership preflight under the management lock, then use the separate
// per-service lease while the native controller runs. Status never enters here.
func (a *app) controlAuxiliaryService(manager platform.Manager, action, name string, expected []byte) error {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return errors.New("未知附属服务操作")
	}
	var release func()
	err := a.store.InspectExisting(func() error {
		var err error
		release, err = node.AuxiliaryControlLease(a.store.Root, name)
		if err != nil {
			return err
		}
		pending, err := node.AuxiliaryServicePending(a.store.Root, name)
		if err != nil {
			return err
		}
		if pending {
			return errors.New("附属服务有未完成事务；先service recover --name对应服务 --preview")
		}
		return manager.VerifyOwnership(name, expected)
	})
	if release != nil {
		defer release()
	}
	if err != nil {
		return err
	}
	if err = manager.VerifyOwnership(name, expected); err != nil {
		return err
	}
	if name == "qingnode-monitor" && manager.ResolvedKind() == platform.InitSystemd {
		plan, planErr := node.NewAuxiliaryServicePlan(manager, name, "")
		if planErr != nil {
			return planErr
		}
		if _, err = node.PreviewAuxiliaryService(a.store.Root, plan, "inspect"); err != nil {
			return err
		}
		switch action {
		case "enable", "disable":
			err = monitorTimerCommand(manager, action)
		case "stop":
			if err = monitorTimerCommand(manager, "stop"); err == nil {
				_, err = manager.Command("stop", name)
			}
		case "start", "restart":
			// A timer firing concurrently queues the same systemd oneshot job;
			// monitor's measurement lease remains the second single-run guard.
			if err = monitorTimerCommand(manager, action); err == nil {
				// The oneshot's configured budget is 180 seconds. Keep this
				// narrowly scoped wait beyond that budget; core controls retain
				// the original native timeout.
				_, err = auxiliaryNative(manager, 190*time.Second, "systemctl", "start", "qingnode-monitor.service")
			}
		}
	} else {
		_, err = manager.Command(action, name)
	}
	if err != nil {
		return fmt.Errorf("附属服务 %s %s 失败：%w", name, action, err)
	}
	if err = manager.VerifyOwnership(name, expected); err != nil {
		return fmt.Errorf("附属服务操作后定义或来源已变化：%w", err)
	}
	if name == "qingnode-monitor" && manager.ResolvedKind() == platform.InitSystemd {
		plan, planErr := node.NewAuxiliaryServicePlan(manager, name, "")
		if planErr != nil {
			return planErr
		}
		if _, err = node.PreviewAuxiliaryService(a.store.Root, plan, "inspect"); err != nil {
			return fmt.Errorf("监控调度对象操作后无法核对：%w", err)
		}
	}
	return nil
}

// Service detection can be replaced only by Go tests. Production never accepts
// a caller-provided environment override that could simulate an active init.
var monitorInitKind = platform.DetectServiceManager

func monitorManager(ctx context.Context) platform.Manager {
	return platform.NewManager(monitorInitKind(), func(timeout time.Duration, name string, args ...string) ([]byte, error) {
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return monitorCommand(c, name, args...)
	})
}

func formatServiceState(s platform.ServiceState) string {
	enabled := "unknown"
	if s.Enabled != nil {
		enabled = "disabled"
		if *s.Enabled {
			enabled = "enabled"
		}
	}
	return fmt.Sprintf("Manager=%s\nActiveState=%s\nSubState=%s\nMainPID=%d\nUnitFileState=%s\nReason=%s\n", s.Kind, s.State, s.SubState, s.PID, enabled, strings.TrimSpace(s.Reason))
}
