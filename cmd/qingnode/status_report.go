package main

// Status reports contain observations, never State or exported authentication.
// In particular, a running server is not evidence of public client access.
import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

type statusIssue struct {
	Category    string `json:"category"`
	Message     string `json:"message"`
	NextCommand string `json:"next_command"`
}
type statusVerification struct {
	TCP      string     `json:"tcp"`
	UDP      string     `json:"udp"`
	Source   string     `json:"source"`
	At       *time.Time `json:"at"`
	Validity string     `json:"validity"`
	Method   string     `json:"method"`
}
type statusEndpoint struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}
type statusNode struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	Protocol           string             `json:"protocol"`
	Enabled            bool               `json:"enabled"`
	Listen             string             `json:"listen"`
	Endpoints          []statusEndpoint   `json:"endpoints"`
	CredentialCount    int                `json:"credential_count"`
	Certificate        string             `json:"certificate"`
	ClientVerification statusVerification `json:"client_verification"`
}
type statusReport struct {
	Version             int       `json:"version"`
	Source              string    `json:"source"`
	ObservedAt          time.Time `json:"observed_at"`
	ObservationLocation string    `json:"observation_location"`
	Offline             bool      `json:"offline"`
	ManagerVersion      string    `json:"manager_version"`
	Revision            string    `json:"revision"`
	Configured          *bool     `json:"configured"`
	CoreVersion         string    `json:"core_version"`
	CoreInstalled       *bool     `json:"core_installed"`
	CoreVerified        *bool     `json:"core_verified"`
	LastDiagnostic      *struct {
		At                  time.Time `json:"at"`
		Errors              int       `json:"errors"`
		Warnings            int       `json:"warnings"`
		ObservationLocation string    `json:"observation_location"`
		Validity            string    `json:"validity"`
	} `json:"last_diagnostic"`
	Service struct {
		State          string   `json:"state"`
		Substate       string   `json:"substate"`
		Autostart      *bool    `json:"autostart"`
		RuntimeSeconds *float64 `json:"runtime_seconds"`
		Restarts       *uint64  `json:"restarts"`
	} `json:"service"`
	Configuration struct {
		Nodes        int `json:"nodes"`
		Enabled      int `json:"enabled_nodes"`
		Devices      int `json:"devices"`
		Certificates int `json:"certificates"`
		Egresses     int `json:"egresses"`
	} `json:"configuration"`
	Resources struct {
		CPUs            int      `json:"cpus"`
		LoadOne         *float64 `json:"load_one"`
		MemoryTotal     *uint64  `json:"memory_total_bytes"`
		MemoryAvailable *uint64  `json:"memory_available_bytes"`
		DiskTotal       *uint64  `json:"disk_total_bytes"`
		DiskAvailable   *uint64  `json:"disk_available_bytes"`
	} `json:"resources"`
	Nodes    []statusNode  `json:"nodes"`
	Pending  []string      `json:"pending_transactions"`
	Issues   []statusIssue `json:"issues"`
	Untested []string      `json:"untested"`
}

func (a *app) statusJSON(w io.Writer) error {
	r := statusReport{Version: 1, Source: "qingnode-local-status", ObservedAt: time.Now().UTC(),
		ObservationLocation: "server-local", Offline: a.offline, ManagerVersion: version, Revision: revision,
		Nodes: []statusNode{}, Pending: []string{}, Issues: []statusIssue{},
		Untested: []string{"public-ingress", "client-authentication", "udp-forwarding", "mobile-or-GUI-import"}}
	var s node.State
	var h dashboardHistory
	var stateErr, historyErr error
	err := a.store.Inspect(func() error {
		var e error
		s, e = a.store.Load()
		if e != nil {
			return e
		}
		if e = s.Validate(); e != nil {
			return e
		}
		h, historyErr = readDashboardHistory(a.store.Root)
		return nil
	})
	stateErr = err
	text := func(v string) string { return ui.SanitizeText(node.Redact(v, s)) }
	issue := func(category, message, next string) {
		if a.offline && strings.HasPrefix(next, "qingnode ") {
			quoted := "'" + strings.ReplaceAll(a.store.Root, "'", "'\"'\"'") + "'"
			next = "qingnode --offline --root " + quoted + strings.TrimPrefix(next, "qingnode")
		}
		r.Issues = append(r.Issues, statusIssue{category, text(message), next})
	}
	if stateErr != nil {
		issue("configuration", stateErr.Error(), "qingnode doctor")
	} else {
		configured := len(s.Nodes) > 0 || len(s.Forwards) > 0
		r.Configured = &configured
		r.CoreVersion = s.CoreVersion
		r.Configuration.Nodes, r.Configuration.Devices, r.Configuration.Certificates, r.Configuration.Egresses = len(s.Nodes), len(s.Devices), len(s.Certificates), len(s.Egresses)
		corePath := node.CorePath(a.store.Root, s.CoreVersion)
		_, coreErr := os.Lstat(corePath)
		if coreErr == nil || errors.Is(coreErr, os.ErrNotExist) {
			installed := coreErr == nil
			r.CoreInstalled = &installed
			if installed {
				verified := node.VerifyCore(a.store.Root, s.CoreVersion) == nil
				r.CoreVerified = &verified
				if !verified {
					issue("core-integrity", "已安装核心未通过本地摘要校验", "qingnode core check")
				}
			} else if configured && !a.offline {
				issue("core-missing", "已保存配置但核心尚未安装", "qingnode core install")
			}
		} else {
			issue("core-unavailable", "无法安全读取核心安装状态", "qingnode doctor")
		}
		for _, n := range s.Nodes {
			if n.Enabled {
				r.Configuration.Enabled++
			}
			v := statusVerification{TCP: "unknown", UDP: "unknown", Source: "unknown", Validity: "not-tested", Method: "administrator-record; not an automatic probe"}
			if record, ok := h.Public[n.ID]; ok && historyErr == nil {
				if record.At.IsZero() || record.At.After(r.ObservedAt.Add(time.Minute)) || !validSource(record.Source) || !validProbeResult(record.TCP) || !validProbeResult(record.UDP) {
					v.Validity = "invalid-record"
				} else {
					at := record.At.UTC()
					v.At, v.Source = &at, text(record.Source)
					switch {
					case record.Fingerprint != publicFingerprint(s, n):
						v.Validity = "configuration-changed"
					case r.ObservedAt.Sub(record.At) > 24*time.Hour:
						v.Validity = "stale"
					default:
						v.TCP, v.UDP, v.Validity = record.TCP, record.UDP, "historical-record"
					}
				}
			}
			entry := statusNode{ID: n.ID, Name: text(n.Name), Protocol: n.Protocol, Enabled: n.Enabled,
				Listen: net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)), Endpoints: []statusEndpoint{}, CredentialCount: len(n.Users),
				Certificate: text(certificateLabel(n, r.ObservedAt)), ClientVerification: v}
			for _, ep := range node.EffectiveEndpoints(n) {
				entry.Endpoints = append(entry.Endpoints, statusEndpoint{ep.ID, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))})
			}
			r.Nodes = append(r.Nodes, entry)
		}
	}
	if historyErr != nil {
		issue("history", historyErr.Error(), "qingnode doctor")
	}
	if stateErr == nil && historyErr == nil && h.Diagnostic != nil {
		d := h.Diagnostic
		if d.At.IsZero() || d.At.After(r.ObservedAt.Add(time.Minute)) {
			issue("diagnostic-record", "服务器自检记录的时间无效", "qingnode doctor")
		} else {
			r.LastDiagnostic = &struct {
				At                  time.Time `json:"at"`
				Errors              int       `json:"errors"`
				Warnings            int       `json:"warnings"`
				ObservationLocation string    `json:"observation_location"`
				Validity            string    `json:"validity"`
			}{d.At.UTC(), d.Errors, d.Warnings, "server-local", "historical-record"}
			if d.Fingerprint != stateFingerprint(s) {
				r.LastDiagnostic.Validity = "configuration-changed"
			} else if r.ObservedAt.Sub(d.At) > 24*time.Hour {
				r.LastDiagnostic.Validity = "stale"
			}
			if d.Errors > 0 {
				issue("last-diagnostic-failed", "最近一次服务器自检记录有错误；原因及客户端可达性仍需分层核对", "qingnode doctor")
			}
		}
	}
	for _, name := range []string{"transaction.json", "uninstall.json", node.MigrationJournalName, ".auxiliary-qingnode-monitor.journal.json", ".auxiliary-qingnode-subscription.journal.json", ".auxiliary-qingnode-monitor.conflict.json", ".auxiliary-qingnode-subscription.conflict.json"} {
		if _, e := os.Lstat(filepath.Join(a.store.Root, name)); e == nil {
			r.Pending = append(r.Pending, name)
			next := "qingnode recover"
			if strings.HasPrefix(name, ".auxiliary-") {
				next = "qingnode service recover --name " + strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(name, ".auxiliary-"), ".journal.json"), ".conflict.json") + " --preview"
				if a.offline {
					issue("pending-transaction", "发现附属服务恢复材料；离线模式不能核对或恢复真实宿主服务。先查看参数，在原宿主或完成环境映射后预览恢复", strings.TrimSuffix(next, " --preview")+" --help")
					continue
				}
			}
			if name == node.MigrationJournalName {
				next = "qingnode restore --recover-migration --yes"
			}
			issue("pending-transaction", "发现尚未完成或有冲突的恢复材料；查询未恢复或重启服务", next)
		} else if !errors.Is(e, os.ErrNotExist) {
			issue("pending-unknown", "无法核对恢复材料", "qingnode doctor")
		}
	}
	r.Service.State, r.Service.Substate = "unknown", "unknown"
	if a.offline {
		r.Service.State = "not-observed-offline"
	} else {
		svc := node.OverviewService(a.serviceRunner)
		if svc.ActiveState != "" {
			r.Service.State = svc.ActiveState
		}
		if svc.SubState != "" {
			r.Service.Substate = svc.SubState
		}
		if svc.UnitFileState == "enabled" || svc.UnitFileState == "disabled" {
			enabled := svc.UnitFileState == "enabled"
			r.Service.Autostart = &enabled
		}
		if svc.Runtime != nil {
			seconds := svc.Runtime.Seconds()
			r.Service.RuntimeSeconds = &seconds
		}
		r.Service.Restarts = svc.AutoRestarts
		if svc.ActiveState == "failed" {
			issue("service-failed", "服务报告启动失败；这不证明客户端或目标站的故障原因", "qingnode logs")
		}
		if svc.ActiveState == "" {
			issue("service-unknown", "未能确认本机服务控制器状态；没有将工具存在当作运行成功", "qingnode capabilities --json --skip-loopback")
		}
	}
	resources := node.OverviewResources(a.store.Root)
	r.Resources.CPUs, r.Resources.LoadOne, r.Resources.MemoryTotal, r.Resources.MemoryAvailable, r.Resources.DiskTotal, r.Resources.DiskAvailable = resources.CPUs, resources.Load1, resources.MemoryTotal, resources.MemoryAvailable, resources.DiskTotal, resources.DiskAvailable
	if e := json.NewEncoder(w).Encode(r); e != nil {
		return e
	}
	return stateErr
}

func (a *app) overviewCommand(args []string) error {
	f := fs("overview")
	machine := f.Bool("json", false, "版本1脱敏本机状态；不联网、不恢复事务")
	if err := parse(f, args); err != nil {
		return err
	}
	if *machine {
		return a.statusJSON(os.Stdout)
	}
	return a.overview(os.Stdout)
}

func (a *app) nodeStatusJSON(w io.Writer, id string) error {
	return a.store.InspectExisting(func() error {
		s, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = s.Validate(); err != nil {
			return err
		}
		nodes := s.Nodes
		if id != "" {
			n, err := s.Find(id)
			if err != nil {
				return err
			}
			nodes = []node.Node{*n}
		}
		views := []statusNode{}
		for _, n := range nodes {
			entry := statusNode{ID: n.ID, Name: ui.SanitizeText(node.Redact(n.Name, s)), Protocol: n.Protocol, Enabled: n.Enabled,
				Listen: net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)), Endpoints: []statusEndpoint{}, CredentialCount: len(n.Users),
				Certificate: certificateLabel(n, time.Now()), ClientVerification: statusVerification{TCP: "unknown", UDP: "unknown", Source: "unknown", Validity: "not-tested", Method: "not measured by info"}}
			for _, ep := range node.EffectiveEndpoints(n) {
				entry.Endpoints = append(entry.Endpoints, statusEndpoint{ep.ID, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))})
			}
			views = append(views, entry)
		}
		return json.NewEncoder(w).Encode(struct {
			Version int          `json:"version"`
			Source  string       `json:"source"`
			Nodes   []statusNode `json:"nodes"`
		}{1, "qingnode-public-node-info", views})
	})
}

func printMachineHelp() error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		Version       int               `json:"version"`
		Usage         string            `json:"usage"`
		ExitCodes     map[string]string `json:"exit_codes"`
		JSONCommands  []string          `json:"json_commands"`
		ResultReceipt map[string]string `json:"execution_receipt"`
		Notes         []string          `json:"notes"`
	}{1, "qingnode [--offline --root DIR] COMMAND [OPTIONS]", map[string]string{"0": "success-or-help", "1": "error", "130": "interrupted-secret-input", "143": "terminated-secret-input"},
		[]string{"help --json", "version --json", "overview --json", "status --json", "info --json", "list --json", "edit --preview --json", "batch --preview --json", "capabilities --json", "network status --json", "egress health --json", "protocols list", "doctor --json", "diagnose --json", "ports --json", "dns show --json", "dns diagnose --json", "hy2 show --json", "hy2 plan --json", "endpoint list --json", "egress list --json", "egress show --json", "egress policy list --json", "forward list --json", "device list --json", "device show --json", "expiration list --json", "subscription status --json"},
		map[string]string{"global_option": "--result-dir NEW_PRIVATE_DIRECTORY", "format": "version 1; started.json and atomically published result.json", "scope": "typed execution and observed Apply finalization; never captured stdout or arguments", "incomplete": "missing result.json, canceled, interrupted, help, failed, or running are not completed", "side_effects": "errors may follow committed configuration or host changes; inspect before retrying", "command_data": "use each command's JSON report or explicit private output separately"},
		[]string{"Global options precede the command. Use COMMAND --help for its exact parameters.", "JSON diagnostics never contain State or authentication; export is the explicit private credential output.", "Input files are command-specific, bounded and validated. No implicit stdin JSON or shell execution.", "A completed local query is not a public connectivity or GUI acceptance result."}})
}

func printVersion(args []string) error {
	f := fs("version")
	machine := f.Bool("json", false, "版本1管理器版本信息")
	if err := parse(f, args); err != nil {
		return err
	}
	if *machine {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "manager_version": version, "revision": revision})
	}
	fmt.Printf("QingNode %s (%s)\n", version, revision)
	return nil
}
