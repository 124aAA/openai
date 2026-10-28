package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/probe"
)

type egressHealthHistory struct {
	Version  int                                 `json:"version"`
	Policies map[string]node.FailoverObservation `json:"policies"`
}

type egressPathResult struct {
	EgressID string        `json:"egress_id"`
	Scope    string        `json:"scope"`
	Health   string        `json:"health"`
	Category string        `json:"error_category,omitempty"`
	Report   *probe.Report `json:"report,omitempty"`
}

type egressHealthRound struct {
	StartedAt time.Time              `json:"started_at"`
	Paths     []egressPathResult     `json:"paths"`
	Decision  *node.FailoverDecision `json:"decision,omitempty"`
	Applied   *bool                  `json:"selection_applied"`
	ApplyMS   int64                  `json:"apply_elapsed_ms"`
}

type egressHealthReport struct {
	Version     int                 `json:"version"`
	Source      string              `json:"source"`
	Initiator   string              `json:"initiator"`
	StartedAt   time.Time           `json:"started_at"`
	FinishedAt  time.Time           `json:"finished_at"`
	Status      string              `json:"status"`
	BudgetMS    int64               `json:"measurement_budget_ms"`
	MaxRounds   int                 `json:"max_rounds"`
	MaxPaths    int                 `json:"max_paths_per_round"`
	PathBytes   int64               `json:"max_payload_bytes_per_path"`
	Concurrency int                 `json:"concurrency"`
	Rounds      []egressHealthRound `json:"rounds"`
	Limitations []string            `json:"limitations"`
}

func readEgressHealthHistory(root string) (egressHealthHistory, error) {
	h := egressHealthHistory{Version: 1, Policies: map[string]node.FailoverObservation{}}
	path := filepath.Join(root, "egress-health.json")
	i, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return h, nil
	}
	if err != nil {
		return h, err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > 256<<10 {
		return h, errors.New("主备观测须为私有普通文件且不超过256KiB")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return h, err
	}
	if checkTopologyJSON(json.NewDecoder(bytes.NewReader(b))) != nil {
		return h, errors.New("主备观测含null、重复或非小写字段，保留原件")
	}
	if err = probe.StrictJSON(b, &h); err != nil || h.Version != 1 || len(h.Policies) > 128 {
		return h, errors.New("主备观测格式或版本无效，保留原件并拒绝覆盖")
	}
	var shape map[string]json.RawMessage
	if err = json.Unmarshal(b, &shape); err != nil {
		return h, err
	}
	for key := range shape {
		if key != "version" && key != "policies" {
			return h, errors.New("主备观测字段名或版本无效，保留原件")
		}
	}
	var policies map[string]map[string]json.RawMessage
	if err = json.Unmarshal(shape["policies"], &policies); err != nil {
		return h, errors.New("主备观测对象无效")
	}
	allowed := map[string]bool{"version": true, "config_sha256": true, "selected": true, "consecutive_failures": true, "consecutive_recoveries": true, "last_observed": true, "last_switch": true}
	for id, fields := range policies {
		if len(id) != 16 {
			return h, errors.New("主备观测ID无效")
		}
		for _, char := range id {
			if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
				return h, errors.New("主备观测ID无效")
			}
		}
		for key := range fields {
			if !allowed[key] {
				return h, errors.New("主备观测含未支持字段，保留原件")
			}
		}
	}
	for _, o := range h.Policies {
		if err = o.Validate(); err != nil {
			return h, err
		}
	}
	if h.Policies == nil {
		h.Policies = map[string]node.FailoverObservation{}
	}
	return h, nil
}

func selectedPolicyMember(p node.EgressPolicy) string {
	if p.Selected == "backup" {
		return "backup"
	}
	return "primary"
}

// An exact egress ID wins even when a policy's display name happens to be that
// ID. Only after checking stable IDs may the UI accept a name as shorthand.
func healthPolicy(st *node.State, id string) (*node.EgressPolicy, error) {
	for _, e := range st.Egresses {
		if e.ID == id {
			return nil, errors.New("所选稳定ID是远程出口")
		}
	}
	return st.FindEgressPolicy(id)
}

// Probes run outside the State lock. Applying rechecks the complete measured
// policy/path binding under the ordinary transaction lock before choosing.
func (a *app) commitHealthDecision(ctx context.Context, snapshot node.State, policy node.EgressPolicy, primary, backup string, at time.Time) (decision node.FailoverDecision, applied *bool, err error) {
	applied = new(bool)
	if err = ctx.Err(); err != nil {
		return
	}
	binding, err := node.PolicyHealthDigest(snapshot, policy)
	if err != nil {
		return decision, applied, err
	}
	err = a.store.WithLock(func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		current, e := a.store.Load()
		if e != nil {
			return e
		}
		p, e := current.FindEgressPolicy(policy.ID)
		if e != nil {
			return e
		}
		nowBinding, e := node.PolicyHealthDigest(current, *p)
		if e != nil || nowBinding != binding || selectedPolicyMember(*p) != selectedPolicyMember(policy) {
			return errors.New("探测期间出口路径或策略已改变，拒绝应用过期结果")
		}
		h, e := readEgressHealthHistory(a.store.Root)
		if e != nil {
			return e
		}
		decision, e = node.EvaluateFailover(*p, h.Policies[p.ID], binding, primary, backup, at)
		if e != nil {
			return e
		}
		// Cancellation before starting a transaction cannot change the selection.
		// Once Apply starts, it must finish or recover under the existing lock.
		if e = ctx.Err(); e != nil {
			return e
		}
		if decision.Changed {
			p.Selected = decision.To
			applied = nil // A late journal/fsync error may follow a committed choice.
			if e = a.store.Apply(current); e != nil {
				return e // Keep the observation; inspect/recover to resolve unknown outcome.
			}
			applied = new(bool)
			*applied = true
		}
		for id := range h.Policies {
			found := false
			for _, present := range current.EgressPolicies {
				found = found || present.ID == id
			}
			if !found {
				delete(h.Policies, id)
			}
		}
		h.Policies[p.ID] = decision.Observation
		data, e := json.MarshalIndent(h, "", "  ")
		if e != nil {
			return e
		}
		if e = node.AtomicWrite(filepath.Join(a.store.Root, "egress-health.json"), append(data, '\n'), 0600); e != nil {
			return fmt.Errorf("主备观测未保存；选择是否已应用见selection_applied，下次保守重建冷却窗口：%w", e)
		}
		return nil
	})
	return decision, applied, err
}

func makeEgressGraph(st node.State, id string) (probe.GraphProfile, error) {
	outs, endpoints, tag, err := node.BuildEgressGraph(st, id)
	if err != nil {
		return probe.GraphProfile{}, err
	}
	convert := func(items []node.M) []json.RawMessage {
		var out []json.RawMessage
		for _, item := range items {
			b, _ := json.Marshal(item)
			out = append(out, b)
		}
		return out
	}
	p, err := probe.NewGraphProfile(id, st.CoreVersion, tag, convert(outs), convert(endpoints))
	if err != nil {
		return p, err
	}
	if st.DNS != nil && st.DNS.Type == "udp" {
		port := 53
		if st.DNS.Port != nil {
			port = *st.DNS.Port
		}
		return probe.SetGraphResolver(p, "udp", st.DNS.Server, port)
	}
	return probe.SetGraphResolver(p, "system", "", 0)
}

func measureEgressGraph(ctx context.Context, p probe.GraphProfile, opts probe.SandboxOptions, target, udp string, timeout time.Duration) (result egressPathResult) {
	result = egressPathResult{EgressID: p.NodeID, Scope: "egress_and_its_declared_upstreams_from_this_initiator", Health: "unknown"}
	if udp != "" && !p.SupportsNetwork("udp") {
		result.Category = "udp_not_supported"
		return result
	}
	o := probe.Options{Path: "client-proxy", Mode: "light", TargetURL: target, UDPAddress: udp, Timeout: timeout, Samples: 1, MaxBytes: 16 << 10, Concurrency: 1, UDPTimeout: time.Second, Initiator: "qingnode-server-egress", NodeID: p.NodeID, ConfigSHA256: p.ConfigSHA256, CoreVersion: p.CoreVersion}
	if _, err := probe.NormalizeOptions(o); err != nil {
		result.Category = "invalid_probe_options"
		return result
	}
	sandbox, err := probe.StartGraphSandbox(ctx, p, opts)
	if err != nil {
		result.Category = "local_core_config_or_permission"
		return result
	}
	defer func() {
		if sandbox.Close() != nil {
			result.Health, result.Category = "unknown", "local_cleanup_failed"
		}
	}()
	transport := sandbox.Transport()
	defer transport.CloseIdleConnections()
	o.ClientVersion, o.UDPProxyAddress = sandbox.Version, sandbox.Address
	o.UDPProxyUsername, o.UDPProxyPassword = sandbox.Username, sandbox.Password
	r, err := probe.Run(ctx, o, probe.Dependencies{Transport: transport, MetricsPID: sandbox.PID})
	result.Report = &r
	if err != nil || ctx.Err() != nil || r.Status == "canceled" {
		result.Category = "canceled_or_incomplete"
		return result
	}
	select {
	case <-sandbox.Done():
		result.Category = "local_core_exited"
		return result
	default:
	}
	result.Health = classifyEgressProbe(r, udp != "")
	return result
}

func classifyEgressProbe(r probe.Report, requireUDP bool) string {
	if r.Status == "canceled" || r.Status == "" {
		return "unknown"
	}
	if r.Status != "completed" || len(r.Errors) != 0 || len(r.Samples) == 0 {
		return "unhealthy"
	}
	for _, sample := range r.Samples {
		if sample.Status != "success" {
			return "unhealthy"
		}
	}
	if requireUDP && (r.UDP == nil || r.UDP.Status != "passed" || r.UDP.Received != 1 || r.UDP.Lost != 0 || r.UDP.Unfinished != 0) {
		return "unhealthy"
	}
	return "healthy"
}

func (a *app) egressHealth(args []string) error {
	f := fs("egress health")
	id := f.String("id", "", "远程出口或主备策略ID；测试由当前服务器发起")
	target := f.String("target", "", "明确的受控HTTPS目标；策略可采用已保存目标")
	udp := f.String("udp-target", "", "受控序号UDP响应端点；TCP通过不替代UDP")
	apply := f.Bool("apply", false, "明确授权累计观测并按策略阈值统一应用选择，可能重启共享核心")
	watch := f.Bool("watch", false, "在总预算内重复；必须同时--apply，不安装后台服务")
	rounds := f.Int("rounds", 1, "1–16轮，每轮每条路径轻量探测一次")
	interval := f.Duration("interval", 5*time.Second, "重复轮之间等待1–60秒")
	budget := f.Duration("budget", 60*time.Second, "探测及等待预算1–120秒；已开始的事务须完成或恢复，另记耗时")
	core := f.String("core", "", "明确的官方核心绝对路径；须同时给摘要")
	digest := f.String("core-sha256", "", "上述受信核心的SHA-256")
	out := f.String("out", "", "不含凭据的新JSON结果文件")
	jsonOutput := f.Bool("json", false, "在标准输出显示完整版本化JSON；默认简洁文本")
	if err := parse(f, args); err != nil {
		return err
	}
	if a.offline || *id == "" || *rounds < 1 || *rounds > 16 || *interval < time.Second || *interval > time.Minute || *budget < time.Second || *budget > 120*time.Second || (*watch && !*apply) || (!*watch && *rounds != 1) || ((*core == "") != (*digest == "")) {
		return errors.New("需在线测试、明确--id和有效预算；重复需--watch --apply，单次最多16轮/120秒，核心路径与摘要成对")
	}
	release, e := a.measurementLeaseIfManaged()
	if e != nil {
		return e
	}
	defer release()
	var output *pinnedOutput
	if *out != "" {
		if err := a.probeOutput(*out); err != nil {
			return err
		}
		var err error
		output, err = pinNewOutput(*out)
		if err != nil {
			return err
		}
		defer output.root.Close()
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *budget)
	defer cancel()
	report := egressHealthReport{Version: 1, Source: "qingnode-egress-health", Initiator: "this-server-cli", StartedAt: time.Now().UTC(), Status: "completed", BudgetMS: budget.Milliseconds(), MaxRounds: *rounds, MaxPaths: 64, PathBytes: 16 << 10, Concurrency: 1, Limitations: []string{"逐段记录各出口及其声明的上游路径，不将重叠路径耗时相减推算单段握手。", "当前服务器发起，不代表用户运营商；入口端到端请从真实客户端使用probe/qingprobe。", "每路径每轮1个HTTPS样本及可选1个序号UDP样本，应用有效载荷最多16384字节；最多16轮、每轮64路径、单并发，合计上限16MiB，协议封装流量未知。", "主备只在显式--apply时累计和应用；不是永久后台监控。共享核心应用可能中断全部已有连接，不会迁移TCP会话。", "仅TCP承载的上游段按TCP单独测试；UDP结果须看声明支持UDP的完整出口路径。"}}
	var runErr error
	for round := 0; round < *rounds; round++ {
		if round > 0 {
			timer := time.NewTimer(*interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				runErr = ctx.Err()
			case <-timer.C:
			}
			if runErr != nil {
				break
			}
		}
		var state node.State
		var policy *node.EgressPolicy
		var ids []string
		var timeout = 10 * time.Second
		err := a.store.InspectExisting(func() error {
			if e := rejectPending(a.store.Root); e != nil {
				return e
			}
			var e error
			state, e = a.store.Load()
			if e != nil {
				return e
			}
			if e = state.Validate(); e != nil {
				return e
			}
			if p, pe := healthPolicy(&state, *id); pe == nil {
				copy := *p
				policy = &copy
				ids = []string{p.Primary}
				if p.Mode == "failover" {
					ids = append(ids, p.Backup)
					timeout = time.Duration(p.Health.TimeoutSeconds) * time.Second
					if *apply && (flagSet(f, "target") || flagSet(f, "udp-target")) {
						return errors.New("应用必须使用策略已保存的健康目标，不能用临时目标累计阈值")
					}
					if !flagSet(f, "target") {
						*target = p.Health.URL
					}
					if !flagSet(f, "udp-target") {
						*udp = p.Health.UDPAddress
					}
					if _, e = readEgressHealthHistory(a.store.Root); e != nil {
						return e
					}
				}
			} else {
				egress, e := state.FindEgress(*id)
				if e != nil {
					return e
				}
				ids = []string{egress.ID}
			}
			if *apply && (policy == nil || policy.Mode != "failover") {
				return errors.New("--apply仅用于已保存的显式主备策略")
			}
			if *target == "" {
				return errors.New("需明确--target HTTPS目标，或在主备策略中保存目标")
			}
			if *udp != "" {
				for _, id := range ids {
					e, egressErr := state.FindEgress(id)
					if egressErr != nil || !e.UDP {
						return errors.New("明确请求UDP测试，但所选出口声明仅TCP；未执行或累计健康结果")
					}
				}
			}
			return nil
		})
		if err != nil {
			runErr = err
			break
		}
		options := probe.SandboxOptions{CoreBinary: *core, SHA256: *digest}
		if *core == "" {
			options, err = a.probeDefaultCore(probe.Profile{CoreVersion: state.CoreVersion})
			if err != nil {
				runErr = err
				break
			}
		}
		currentRound := egressHealthRound{StartedAt: time.Now().UTC(), Applied: new(bool)}
		requested, seen := map[string]bool{}, map[string]bool{}
		for _, id := range ids {
			requested[id], seen[id] = true, true
		}
		for index := 0; index < len(ids); index++ {
			e, _ := state.FindEgress(ids[index])
			if e != nil && e.Detour != "" && !seen[e.Detour] {
				seen[e.Detour] = true
				ids = append(ids, e.Detour)
			}
		}
		if len(ids) > report.MaxPaths {
			runErr = errors.New("本次路径数量超过64上限，未执行超限测试")
			break
		}
		for _, id := range ids {
			p, e := makeEgressGraph(state, id)
			if e != nil {
				runErr = e
				break
			}
			pathUDP := *udp
			if !requested[id] && !p.SupportsNetwork("udp") {
				pathUDP = ""
			}
			currentRound.Paths = append(currentRound.Paths, measureEgressGraph(ctx, p, options, *target, pathUDP, timeout))
			if ctx.Err() != nil {
				runErr = ctx.Err()
				break
			}
		}
		if runErr == nil {
			runErr = ctx.Err()
		}
		if runErr == nil && *apply {
			values := map[string]string{}
			for _, p := range currentRound.Paths {
				values[p.EgressID] = p.Health
			}
			applyStarted := time.Now()
			d, applied, e := a.commitHealthDecision(ctx, state, *policy, values[policy.Primary], values[policy.Backup], time.Now().UTC())
			currentRound.ApplyMS = time.Since(applyStarted).Milliseconds()
			currentRound.Decision, currentRound.Applied = &d, applied
			if e != nil {
				runErr = e
			}
		}
		report.Rounds = append(report.Rounds, currentRound)
		if runErr != nil {
			break
		}
	}
	if runErr == nil {
		runErr = ctx.Err()
	}
	if runErr != nil {
		report.Limitations = append(report.Limitations, node.Redact(runErr.Error()))
	}
	pathFailure := false
	for _, round := range report.Rounds {
		for _, p := range round.Paths {
			pathFailure = pathFailure || p.Health != "healthy"
		}
	}
	report.Status = egressHealthStatus(runErr, pathFailure)
	report.FinishedAt = time.Now().UTC()
	outputErr := emitEgressHealthReport(report, output, *out, *jsonOutput)
	if outputErr != nil {
		return errors.Join(runErr, outputErr)
	}
	if runErr != nil {
		return runErr
	}
	if pathFailure {
		return errors.New("出口测试有失败或未知项，报告已保留；未自动回落direct")
	}
	return nil
}

// The command budget and user cancellation have different meanings. Neither
// means the last transaction necessarily remained unchanged.
func egressHealthStatus(err error, pathFailure bool) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if err != nil || pathFailure {
		return "failed"
	}
	return "completed"
}

// Always expose the observed application outcome even if the requested result
// file cannot be saved after a successful selection transaction.
func emitEgressHealthReport(report egressHealthReport, output *pinnedOutput, path string, jsonOutput bool) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	var saveErr error
	if output != nil {
		saveErr = output.write(append(data, '\n'))
		if saveErr != nil {
			report.Limitations = append(report.Limitations, "结果文件保存失败，实际选择见本报告；文件错误不表示配置未改变。")
			data, err = json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
		}
		if !jsonOutput && saveErr == nil {
			fmt.Printf("已保存链路报告：%s\n", path)
		}
	}
	if jsonOutput {
		if err = writeOutput("", data); err != nil {
			return errors.Join(saveErr, fmt.Errorf("报告标准输出失败；用egress policy list / doctor核对实际选择，不能视为配置未改变：%w", err))
		}
	} else {
		fmt.Printf("链路测试：%s；发起端：当前服务器；%d轮；探测及等待预算%dms\n", report.Status, len(report.Rounds), report.BudgetMS)
		for index, round := range report.Rounds {
			for _, path := range round.Paths {
				fmt.Printf("  第%d轮 %s：%s %s\n", index+1, path.EgressID, path.Health, path.Category)
			}
			if round.Decision != nil {
				applied := "未知，先运行egress policy list / doctor，再按需显式recover"
				if round.Applied != nil {
					applied = fmt.Sprint(*round.Applied)
				}
				fmt.Printf("  选择%s→%s；实际应用:%s；应用耗时%dms；%s\n", round.Decision.From, round.Decision.To, applied, round.ApplyMS, round.Decision.Reason)
			}
		}
		fmt.Println("分段包含各自上游，不能相减当独立握手；入口端到端仍需真实客户端测试。")
	}

	if saveErr != nil {
		return fmt.Errorf("结果文件未保存；实际出口选择已在标准输出报告，不能视为配置未变：%w", saveErr)
	}
	return nil
}
