package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"qingnode/internal/monitor"
	"qingnode/internal/node"
	"qingnode/internal/platform"
)

func (a *app) monitorStore() *monitor.Store {
	return &monitor.Store{Root: filepath.Join(a.store.Root, "monitor")}
}

func monitorJSON(v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e == nil {
		fmt.Println(string(b))
	}
	return e
}

func (a *app) monitor(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：monitor configure|run|watch|status|history|disable|timer|api|traffic|ledger；默认仅观察，周期任务须显式安装")
	}
	action := args[0]
	if action == "api" {
		return a.monitorAPI(args[1:])
	}
	if action == "traffic" {
		return a.monitorTraffic(args[1:])
	}
	if action == "ledger" {
		return a.monitorLedger(args[1:])
	}
	f := fs("monitor " + action)
	input := f.String("file", "", "configure的私有JSON输入；通知凭据不放命令行")
	preview := f.Bool("preview", false, "只读校验和显示影响")
	yes := f.Bool("yes", false, "保存监控计划或停止后续恢复与通知")
	cycles := f.Int("cycles", 1, "运行轮数1–100；使用计划间隔，不追赶错过的轮次")
	applyExpiry := f.Bool("apply-expiry", false, "显式执行已保存的到期计划；可能中断共享核心连接")
	applyQuota := f.Bool("apply-quota", false, "显式执行已达硬上限的流量配额停用；可能中断共享核心连接")
	out := f.String("out", "", "timer输出目录，须已存在且在受管目录外")
	manager := f.String("manager", "systemd", "timer服务管理器systemd或openrc；只生成材料")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	st := a.monitorStore()
	switch action {
	case "configure":
		if e := rejectTopologyFlags(f, "file", "preview", "yes"); e != nil {
			return e
		}
		if *input == "" || (!*preview && !*yes) {
			return errors.New("需要--file和--preview或--yes")
		}
		c, e := monitor.ReadConfigFile(*input)
		if e != nil {
			return e
		}
		e = a.store.InspectExisting(func() error {
			if e := rejectMonitorPending(a.store.Root); e != nil {
				return e
			}
			s, e := a.store.Load()
			if e != nil {
				return e
			}
			return validateMonitorJobs(s, c)
		})
		if e != nil {
			return e
		}
		if e = monitorJSON(monitorConfigPreview(c)); e != nil {
			return e
		}
		fmt.Println("只保存监控计划；不启动代理或定时器。restart策略可能中断共享核心的全部既有连接。")
		if *preview {
			return nil
		}
		return st.SaveConfig(c)
	case "status", "history":
		if e := rejectTopologyFlags(f); e != nil {
			return e
		}
		if action == "status" {
			s, e := st.LoadStatus()
			if e != nil {
				return e
			}
			return monitorJSON(s)
		}
		h, e := st.LoadHistory()
		if e != nil {
			return e
		}
		return monitorJSON(h)
	case "disable":
		if e := rejectTopologyFlags(f, "preview", "yes"); e != nil {
			return e
		}
		if !*yes && !*preview {
			return errors.New("停止监控需要--yes或--preview")
		}
		c, e := st.LoadConfig()
		if e != nil {
			return e
		}
		c.Enabled = false
		c.Recovery.Mode = "observe"
		c.Notifications.Enabled = false
		fmt.Println("停止后续监控、恢复和通知；已在运行的有界检查可完成，代理运行与自启状态不变。")
		if *preview {
			return nil
		}
		return st.SaveConfig(c)
	case "run", "watch":
		allowed := []string{"cycles", "apply-expiry", "apply-quota"}
		if action == "watch" {
			allowed = []string{"apply-expiry", "apply-quota"}
		}
		if e := rejectTopologyFlags(f, allowed...); e != nil {
			return e
		}
		if a.offline {
			return errors.New("--offline不执行监控网络检查或恢复")
		}
		if *cycles < 1 || *cycles > 100 {
			return errors.New("运行轮数必须为1–100")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		for i := 0; action == "watch" || i < *cycles; i++ {
			c, e := st.LoadConfig()
			if e != nil {
				return e
			}
			now := time.Now().UTC()
			if c.Enabled {
				a.monitorSampleAndRefresh(ctx)
			}
			if *applyExpiry && c.Enabled {
				if e = a.monitorExpireDue(now); e != nil {
					return e
				}
			}
			var quotaDisabledEvents []monitor.Event
			if *applyQuota && c.Enabled {
				quotaDisabledEvents, e = a.monitorApplyQuotas(now)
				if e != nil {
					return e
				}
			}
			snapshot, e := a.monitorRoundWithExtras(ctx, c, quotaDisabledEvents)
			if e != nil {
				return e
			}
			if e = monitorJSON(snapshot); e != nil {
				return e
			}
			if action != "watch" && (!c.Enabled || i+1 == *cycles) {
				return nil
			}
			timer := time.NewTimer(time.Duration(c.IntervalSeconds) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		return nil
	case "timer":
		if e := rejectTopologyFlags(f, "out", "manager"); e != nil {
			return e
		}
		kind, e := serviceKind(*manager)
		if e != nil {
			return e
		}
		return a.monitorTimerFor(*out, kind)
	default:
		return errors.New("未知监控操作")
	}
}

func monitorConfigPreview(c monitor.Config) any {
	type job struct {
		ID, NodeID, EgressID, UserID, EndpointID string
		Enabled, HTTPSConfigured, UDPConfigured  bool
		Signals                                  []monitor.SignalKind
	}
	jobs := []job{}
	for _, j := range c.Jobs {
		jobs = append(jobs, job{j.ID, j.NodeID, j.EgressID, j.UserID, j.EndpointID, j.Enabled, j.TargetURL != "", j.UDPAddress != "", j.Signals})
	}
	return struct {
		Version                                 int
		Enabled                                 bool
		IntervalSeconds, TimeoutMS, Concurrency int
		MaxBytes                                int64
		History                                 monitor.HistoryLimits
		Recovery                                monitor.RecoveryPolicy
		NotificationsEnabled                    bool
		NotificationKind                        string
		Jobs                                    []job
	}{c.Version, c.Enabled, c.IntervalSeconds, c.TimeoutMS, c.Concurrency, c.MaxBytes, c.History, c.Recovery, c.Notifications.Enabled, c.Notifications.Kind, jobs}
}

func (a *app) monitorSampleAndRefresh(ctx context.Context) {
	var st node.State
	if err := a.store.InspectExisting(func() error {
		if err := rejectMonitorPending(a.store.Root); err != nil {
			return err
		}
		loaded, err := a.store.Load()
		if err != nil {
			return err
		}
		st = loaded
		return nil
	}); err != nil {
		return
	}
	if _, ok := a.sampleTrafficLedger(ctx, st, false); !ok {
		return
	}
	_ = a.store.InspectExisting(func() error {
		if err := rejectMonitorPending(a.store.Root); err != nil {
			return err
		}
		latest, err := a.store.Load()
		if err != nil {
			return err
		}
		return a.refreshPublished(latest)
	})
}

func (a *app) monitorApplyQuotas(now time.Time) ([]monitor.Event, error) {
	previous, e := a.monitorStore().LoadStatus()
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if !previous.FinishedAt.IsZero() && now.Before(previous.FinishedAt) {
		return nil, errors.New("时钟早于上次监控记录；未执行流量配额停用")
	}
	var events []monitor.Event
	err := a.store.InspectExisting(func() error {
		if e := rejectMonitorPending(a.store.Root); e != nil {
			return e
		}
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		lookup, gap, e := a.loadUsageLookup()
		if e != nil {
			return e
		}
		candidate, plan, e := node.ApplyDueTrafficQuotasSince(s, lookup, gap, now, previous.FinishedAt)
		if e != nil {
			return e
		}
		if plan.Ready == 0 {
			return nil
		}
		if e = a.store.Apply(candidate); e != nil {
			return e
		}
		for _, d := range plan.Items {
			if !d.Due || d.Status != "due" {
				continue
			}
			targetName, targetID := resolveQuotaTarget(s, d.TrafficQuota)
			events = append(events, monitor.Event{
				At:         now,
				JobID:      "quota-" + d.ID,
				From:       monitor.Healthy,
				To:         monitor.Disabled,
				Kind:       "quota-disabled",
				TargetName: targetName,
				TargetID:   targetID,
				Reason:     fmt.Sprintf("已达硬配额上限 %d/%d 字节（周期 %s），凭据已停用", d.UsedBytes, d.HardBytes, d.Period),
				DedupeKey:  "quota-disabled:" + d.ID + ":" + d.Period,
			})
		}
		return nil
	})
	return events, err
}

func resolveQuotaTarget(s node.State, q node.TrafficQuota) (string, string) {
	if q.NodeID != "" {
		if n, err := s.Find(q.NodeID); err == nil && n.ID == q.NodeID {
			return n.Name, n.ID
		}
		return q.NodeID, q.NodeID
	}
	for _, d := range s.Devices {
		if d.ID == q.DeviceID {
			return d.Name, d.ID
		}
	}
	return q.DeviceID, q.DeviceID
}

func (a *app) monitorExpireDue(now time.Time) error {
	previous, e := a.monitorStore().LoadStatus()
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if !previous.FinishedAt.IsZero() && now.Before(previous.FinishedAt) {
		return errors.New("时钟早于上次监控记录；未执行到期停用")
	}
	return a.store.InspectExisting(func() error {
		if e := rejectMonitorPending(a.store.Root); e != nil {
			return e
		}
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		candidate, plan, e := node.ApplyDueExpirationsSince(s, now, previous.FinishedAt)
		if e != nil {
			return e
		}
		if plan.Ready == 0 {
			return nil
		}
		// The already-held management lock serializes Apply with manual edits. It
		// does not enter WithLock's automatic recovery path.
		return a.store.Apply(candidate)
	})
}

func rejectMonitorPending(root string) error {
	if e := rejectPending(root); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(root, node.MigrationJournalName)); e == nil {
		return errors.New("存在迁移恢复事务；监控不自动修复，请先显式处理恢复")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}

func validateMonitorJobs(s node.State, c monitor.Config) error {
	if e := s.Validate(); e != nil {
		return e
	}
	for _, j := range c.Jobs {
		if j.NodeID != "" {
			n, e := s.Find(j.NodeID)
			if e != nil || n.ID != j.NodeID {
				return errors.New("监控引用不存在的节点稳定ID")
			}
			if j.UserID != "" {
				u, e := node.SelectUser(*n, j.UserID)
				if e != nil || u.ID != j.UserID {
					return errors.New("监控引用不存在的用户稳定ID")
				}
			}
			if j.TargetURL != "" && j.UserID == "" {
				return errors.New("代理检查必须明确user_id，不能默认选第一条凭据")
			}
			endpoint := j.EndpointID
			if endpoint == "" {
				endpoint = "default"
			}
			if _, e := node.WithEndpoint(*n, endpoint); e != nil {
				return e
			}
		} else {
			if _, e := makeEgressGraph(s, j.EgressID); e != nil {
				return e
			}
		}
	}
	return nil
}

func (a *app) monitorRound(ctx context.Context, c monitor.Config) (monitor.Snapshot, error) {
	return a.monitorRoundWithExtras(ctx, c, nil)
}

func (a *app) monitorRoundWithExtras(ctx context.Context, c monitor.Config, initialExtras []monitor.Event) (monitor.Snapshot, error) {
	var s node.State
	var release func()
	e := a.store.InspectExisting(func() error {
		if e := rejectMonitorPending(a.store.Root); e != nil {
			return e
		}
		var e error
		s, e = a.store.Load()
		if e != nil {
			return e
		}
		if e = validateMonitorJobs(s, c); e != nil {
			return e
		}
		release, e = node.MeasurementLease(a.store.Root)
		return e
	})
	if e != nil {
		return monitor.Snapshot{}, e
	}
	defer release()
	adapter := &monitorAdapter{app: a, state: s}
	engine := a.newMonitorEngine(s, initialExtras)
	return engine.RunOnce(ctx, c, adapter, adapter)
}

func (a *app) newMonitorEngine(s node.State, initialExtras []monitor.Event) monitor.Engine {
	return monitor.Engine{
		Store:    a.monitorStore(),
		Redactor: func(raw string) string { return node.Redact(raw, s) },
		TargetResolver: func(j monitor.Job) (string, string, *int) {
			if j.NodeID != "" {
				if n, err := s.Find(j.NodeID); err == nil && n.ID == j.NodeID {
					var certDays *int
					if n.CertificateID != "" {
						if r, err := s.FindCertificate(n.CertificateID); err == nil {
							if cs, err := node.InspectCertificateResource(*r, a.store.Root, time.Now().UTC()); err == nil && cs.NotAfter != nil && cs.DaysRemaining != nil && *cs.DaysRemaining < 14 {
								d := *cs.DaysRemaining
								certDays = &d
							}
						}
					}
					return n.Name, n.ID, certDays
				}
				return "", j.NodeID, nil
			}
			for _, eg := range s.Egresses {
				if eg.ID == j.EgressID {
					return eg.Name, eg.ID, nil
				}
			}
			return "", j.EgressID, nil
		},
		ExtraEvents: func(now time.Time, _ monitor.Config) []monitor.Event {
			out := append([]monitor.Event(nil), initialExtras...)
			for _, r := range s.Certificates {
				cs, err := node.InspectCertificateResource(r, a.store.Root, now)
				if err != nil || cs.NotAfter == nil || !now.Before(*cs.NotAfter) || cs.NotAfter.Sub(now) >= 14*24*time.Hour {
					continue
				}
				days := int(cs.NotAfter.Sub(now).Hours() / 24)
				targetName := r.Name
				targetID := r.ID
				for _, n := range s.Nodes {
					if n.Enabled && n.CertificateID == r.ID {
						targetName = n.Name
						targetID = n.ID
						break
					}
				}
				out = append(out, monitor.Event{
					At:           now,
					JobID:        "cert-" + r.ID,
					From:         monitor.Healthy,
					To:           monitor.Degraded,
					Kind:         "cert-expiring",
					TargetName:   targetName,
					TargetID:     targetID,
					Signals:      []string{fmt.Sprintf("certificate=degraded(days_left_%d)", days)},
					Reason:       fmt.Sprintf("证书 %s 剩余 %d 天到期（< 14 天）", r.Name, days),
					CertDaysLeft: &days,
					DedupeKey:    "cert-expiring:" + r.ID + ":" + cs.NotAfter.UTC().Format(time.RFC3339),
				})
			}
			if len(s.TrafficQuotas) > 0 {
				lookup, gap, err := a.loadUsageLookup()
				if err == nil {
					if plan, err := node.PlanTrafficQuotas(s, lookup, gap, now); err == nil {
						for _, d := range plan.Items {
							if !d.Warned || d.DisabledAt != "" {
								continue
							}
							targetName, targetID := resolveQuotaTarget(s, d.TrafficQuota)
							out = append(out, monitor.Event{
								At:         now,
								JobID:      "quota-" + d.ID,
								From:       monitor.Healthy,
								To:         monitor.Degraded,
								Kind:       "quota-warning",
								TargetName: targetName,
								TargetID:   targetID,
								Reason:     fmt.Sprintf("流量已达软告警阈值 %d/%d 字节（周期 %s）", d.UsedBytes, d.WarnBytes, d.Period),
								DedupeKey:  "quota-warning:" + d.ID + ":" + d.Period,
							})
						}
					}
				}
			}
			return out
		},
	}
}

// This exports instructions only. Nothing is installed, enabled or started.
func (a *app) monitorTimer(directory string) error {
	return a.monitorTimerFor(directory, platform.InitSystemd)
}

func (a *app) monitorTimerFor(directory string, manager platform.InitKind) error {
	if directory == "" {
		return errors.New("timer需要--out已有目录；只生成文件，不安装服务")
	}
	root, e := filepath.Abs(directory)
	if e != nil {
		return e
	}
	i, e := os.Lstat(root)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("输出须为已有普通目录")
	}
	plan, e := node.NewAuxiliaryServicePlan(platform.NewManager(manager, nil), "qingnode-monitor", "")
	if e != nil {
		return e
	}
	for _, file := range plan.Definitions {
		dest := filepath.Join(root, file.Name)
		if e = a.probeOutput(dest); e != nil {
			return e
		}
	}
	for _, file := range plan.Definitions {
		if e = writeOutput(filepath.Join(root, file.Name), file.Contents); e != nil {
			return e
		}
	}
	if manager == platform.InitOpenRC {
		fmt.Println("已生成可选OpenRC监控服务；审查后以0755安装到/etc/init.d/qingnode-monitor，再显式rc-update add qingnode-monitor default及rc-service qingnode-monitor start。独立watch按计划间隔串行运行，不修改全局cron；监控需管理权限，代理与订阅仍为非root。停止：rc-service qingnode-monitor stop，然后qingnode monitor disable --yes。")
		return nil
	}
	fmt.Println("已生成service/timer；先审查并复制到/etc/systemd/system，再显式enable --now qingnode-monitor.timer。停止：systemctl disable --now qingnode-monitor.timer，然后qingnode monitor disable --yes。timer固定约60秒；自定义间隔可审查后修改文件。")
	return nil
}
