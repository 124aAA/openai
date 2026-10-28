package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
	"qingnode/internal/node"
	"qingnode/internal/platform"
	"qingnode/internal/ui"
)

func (a *app) message(level, text string) {
	if level == "DEBUG" && !a.debug {
		return
	}
	color := ""
	if term.IsTerminal(int(os.Stderr.Fd())) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		color = map[string]string{"INFO": "\x1b[36m", "SUCCESS": "\x1b[32m", "WARN": "\x1b[33m", "ERROR": "\x1b[31m", "DEBUG": "\x1b[36m"}[level]
	}
	end := ""
	if color != "" {
		end = "\x1b[0m"
	}
	fmt.Fprintf(os.Stderr, "%s%s%s\n", color, ui.WrapText("["+level+"] "+text, ui.Width(os.Stderr)), end)
}
func (a *app) safeText(text string, s node.State) string {
	states := []node.State{s}
	paths, _ := filepath.Glob(filepath.Join(a.store.Root, "generations", "g-*", "state.json"))
	for _, p := range paths {
		if old, e := node.ReadState(p); e == nil {
			states = append(states, old)
		}
	}
	return node.Redact(text, states...)
}
func redact(text string, s node.State) string { return node.Redact(text, s) }
func (a *app) recentLogs(s node.State) {
	_ = a.recentLogsTo(os.Stdout, s)
}
func (a *app) recentLogsTo(w io.Writer, s node.State) error {
	if a.offline {
		return nil
	}
	b, e := platform.NewManager("", nil).Logs("qingnode", 40)
	if e != nil {
		a.message("WARN", "无法读取当前服务管理器日志；请先运行 qingnode capabilities 核查控制器")
		return nil
	}
	_, e = fmt.Fprint(w, a.safeText(string(b), s))
	return e
}
func (a *app) status(s node.State) (err error) {
	w := newStateTextWriter(os.Stdout, s)
	defer func() { err = errors.Join(err, w.Flush()) }()
	fmt.Fprintf(w, "管理器：%s；配置核心：%s\n配置文件：%s\n", version, s.CoreVersion, filepath.Join(a.store.Root, "current", "server.json"))
	if a.offline {
		fmt.Fprintln(w, "离线模式：未查询系统服务。")
		return nil
	}
	serviceState, e := platform.NewManager("", nil).State("qingnode")
	if e != nil {
		fmt.Fprint(w, formatServiceState(serviceState))
		return fmt.Errorf("服务控制器查询失败：%w", e)
	}
	b := []byte(formatServiceState(serviceState))
	fmt.Fprint(w, a.safeText(string(b), s))
	pid := (node.SystemBackend{Root: a.store.Root}).PID()
	if pid > 0 {
		if elapsed, e := node.Run(5*time.Second, "ps", "-p", fmt.Sprint(pid), "-o", "etime="); e == nil {
			fmt.Fprintln(w, "运行时长："+strings.TrimSpace(string(elapsed)))
		}
	}
	for _, n := range s.Nodes {
		fmt.Fprintf(w, "%s：%s，启用=%t\n", n.Name, node.PortLabel(n), n.Enabled)
	}
	for _, v := range s.Forwards {
		fmt.Fprint(w, node.Redact(fmt.Sprintf("中转%s：%s/%s，出口=%s，启用=%t\n", v.Name, net.JoinHostPort(v.Listen, strconv.Itoa(v.Port)), v.Network, displayEgress(v.EgressID), v.Enabled), s))
	}
	for _, e := range s.Egresses {
		if e.WireGuard != nil && e.WireGuard.ListenPort > 0 {
			fmt.Fprintf(w, "用户态WireGuard %s：UDP %d（这是本机声明；端到端流量需另测）\n", e.ID, e.WireGuard.ListenPort)
		}
	}
	if strings.Contains(string(b), "ActiveState=failed") {
		return errors.Join(errors.New("服务启动失败；运行 qingnode diagnose 获取建议"), a.recentLogsTo(w, s))
	}
	return nil
}
func (a *app) service(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：service start|stop|restart|status|enable|disable|logs；附属服务另有install|remove|recover --name qingnode-subscription|qingnode-monitor --preview或--yes")
	}
	cmd := args[0]
	f := fs("service " + cmd)
	name := f.String("name", "qingnode", "本项目服务名称")
	publicURL := f.String("public-url", "", "订阅服务定义中的HTTPS公开URL；用于精确核对，不含令牌")
	preview := f.Bool("preview", false, "只读预览附属服务安装、删除或恢复，不创建事务")
	yes := f.Bool("yes", false, "明确提交附属服务安装、删除或恢复；不自动启用新服务")
	lines := f.Int("lines", 40, "日志行数1–1000；仅logs")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	if cmd == "install" || cmd == "remove" || cmd == "recover" {
		if e := rejectTopologyFlags(f, "name", "public-url", "preview", "yes"); e != nil {
			return e
		}
		return a.auxiliaryDeployment(auxiliaryManager(), cmd, *name, *publicURL, *preview, *yes)
	}
	if cmd == "logs" {
		if e := rejectTopologyFlags(f, "name", "lines"); e != nil {
			return e
		}
		return a.serviceLogs(auxiliaryManager(), *name, *lines)
	}
	if e := rejectTopologyFlags(f, "name", "public-url"); e != nil {
		return e
	}
	if *name != "qingnode" {
		if *name != "qingnode-subscription" && *name != "qingnode-monitor" {
			return errors.New("只操作本项目代理、订阅或监控服务")
		}
		if a.offline {
			return errors.New("离线模式不操作附属服务")
		}
		switch cmd {
		case "start", "stop", "restart", "status", "enable", "disable":
		default:
			return errors.New("未知附属服务操作")
		}
		manager := auxiliaryManager()
		if cmd == "status" {
			return showAuxiliaryService(manager, *name)
		}
		expected, e := auxiliaryServiceDefinition(manager.ResolvedKind(), *name, *publicURL)
		if e != nil {
			return e
		}
		return a.controlAuxiliaryService(manager, cmd, *name, []byte(expected))
	}
	if *publicURL != "" {
		return errors.New("public-url仅适用于订阅附属服务")
	}
	if cmd != "enable" && cmd != "disable" {
		switch cmd {
		case "start", "stop", "restart", "status":
			return a.operation(cmd, nil)
		}
		return errors.New("未知服务操作")
	}
	if a.offline {
		return errors.New("离线模式不修改系统自启")
	}
	return a.store.WithLock(func() error {
		_, e := platform.NewManager("", nil).Command(cmd, "qingnode")
		if e == nil {
			a.message("SUCCESS", "已修改开机自启设置；当前进程运行状态不变")
		}
		return e
	})
}
func (a *app) ports(args []string) error {
	return a.portsWithRunner(args, nil)
}
func (a *app) portsWithRunner(args []string, run diagnosticRunner) error {
	f := fs("ports")
	machine := f.Bool("json", false, "版本1本机监听观察；不代表认证、公网或UDP业务通过")
	if e := parse(f, args); e != nil {
		return e
	}
	if run == nil {
		run = node.Run
		if *machine {
			run = runBoundedDiagnostic
		}
	}
	if *machine {
		report, err := observeListeners(run)
		return errors.Join(err, json.NewEncoder(os.Stdout).Encode(report))
	}
	b, e := run(8*time.Second, "ss", "-H", "-lntup")
	if e != nil {
		return fmt.Errorf("无法读取监听端口，请安装 iproute2：%w", e)
	}
	fmt.Print(node.Redact(string(b)))
	return nil
}
func (a *app) info(args []string) error {
	f := fs("info")
	id := f.String("id", "", "节点名称或 ID")
	machine := f.Bool("json", false, "版本1脱敏本地节点视图，不包含认证材料")
	secrets := f.Bool("show-secrets", false, "显示连接凭据和完整链接")
	private := f.Bool("show-private", false, "显示 REALITY 私钥；不要截图分享")
	if e := parse(f, args); e != nil {
		return e
	}
	if *machine {
		if *secrets || *private {
			return errors.New("info --json不输出认证材料；请用显式export导出私有配置")
		}
		return a.nodeStatusJSON(os.Stdout, *id)
	}
	return a.inspectState(func(s *node.State) error {
		if e := s.Validate(); e != nil {
			return e
		}
		nodes := s.Nodes
		if *id != "" {
			n, e := s.Find(*id)
			if e != nil {
				return e
			}
			nodes = []node.Node{*n}
		}
		w := newStateTextWriter(os.Stdout, *s)
		for _, n := range nodes {
			fmt.Fprintf(w, "\n节点：%s\nID：%s\n协议：%s\n服务器：%s\n监听：%s (%s)\n启用：%t\n", n.Name, n.ID, n.Protocol, n.Host, net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)), strings.Join(node.Networks(n), "+"), n.Enabled)
			fmt.Fprintf(w, "出口：%s；最终客户端仅使用此入口地址与入口凭据，内部出口凭据不会加入分享。\n", displayEgress(n.EgressID))
			fmt.Fprintf(w, "客户端端口：%d\n传输协议：%s\n", node.EffectiveConnectPort(n), strings.Join(node.Networks(n), "+"))
			fmt.Fprintln(w, "本地监听用于端口检查与防火墙；连接端点用于客户端，NAT/云安全组与公网入站尚需独立验证。")
			for _, ep := range node.EffectiveEndpoints(n) {
				fmt.Fprintf(w, "连接端点 %s：%s\n", ep.ID, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)))
			}
			if c := n.Certificate; c != nil {
				fmt.Fprintf(w, "TLS：启用，校验证书\nSNI：%s\n证书方式：%s\n", c.ServerName, c.Mode)
			}
			if r := n.Reality; r != nil {
				fmt.Fprintf(w, "Reality Public Key：%s\nSNI：%s\n握手目标：%s\nFlow：xtls-rprx-vision\nFingerprint：%s\n", r.PublicKey, r.ServerName, r.Target, node.Fingerprint(r))
				if *secrets {
					w.Raw(fmt.Sprintf("Short ID：%s\n", r.ShortID))
				} else {
					fmt.Fprintln(w, "Short ID：已隐藏；请用显式export导出客户端配置")
				}
				if *private {
					w.Raw(fmt.Sprintf("Reality Private Key：%s\n", r.PrivateKey))
				}
			}
			fmt.Fprintf(w, "创建时间：%s\n更新时间：%s\n", n.CreatedAt, n.UpdatedAt)
			for _, u := range n.Users {
				fmt.Fprintf(w, "凭据：%s (%s)\n", u.Name, u.ID)
				if len(node.ProtocolExportWarnings(n, "uri")) == 0 {
					fmt.Fprintf(w, "导出链接：qingnode export --id %s --format uri --user %s\n", n.ID, u.ID)
				} else {
					fmt.Fprintln(w, "当前协议或高级设置需使用完整配置，不能等价表达为分享链接。")
				}
				version := lockedExportClientVersion(n.Protocol, "sing-box")
				if version != "" {
					fmt.Fprintf(w, "导出配置：qingnode export --id %s --format sing-box --user %s --client-version %s --out client.json\n", n.ID, u.ID, version)
				} else {
					fmt.Fprintf(w, "导出配置：qingnode export --id %s --format sing-box --user %s --out client.json\n", n.ID, u.ID)
				}
				if *secrets {
					if u.UUID != "" {
						w.Raw(fmt.Sprintf("UUID：%s\n", u.UUID))
						if n.Protocol == "tuic" {
							w.Raw(fmt.Sprintf("Password：%s\n", u.Password))
						}
					} else {
						if n.Shadowsocks != nil {
							w.Raw(fmt.Sprintf("加密方法：%s\nPassword：%s\n", n.Shadowsocks.Method, node.SSPassword(n, u)))
						} else {
							w.Raw(fmt.Sprintf("Password：%s\n", u.Password))
						}
					}
					if len(node.ProtocolExportWarnings(n, "uri")) == 0 {
						w.Raw(fmt.Sprintf("分享链接：\n%s\n", node.URI(n, u)))
					}
				}
			}
		}
		return w.Flush()
	})
}

// Findings carry actions, not raw command errors or entire firewall rulesets.
func (a *app) doctor(s node.State, loadErr error) error {
	return a.doctorWithReport(s, loadErr, nil)
}
func (a *app) doctorWithReport(s node.State, loadErr error, report *diagnosticReport) error {
	errorsFound := 0
	warnings := 0
	check := func(id, scope, label string, e error, warning bool, advice string) {
		if report != nil {
			status, message := "healthy", ""
			if e != nil {
				message = a.safeText(e.Error(), s)
				if warning {
					status = "degraded"
					warnings++
				} else {
					status = "failed"
					errorsFound++
				}
			}
			report.add(s, id, scope, label, status, message, advice)
			return
		}
		if e == nil {
			a.message("SUCCESS", "✓ "+label)
			return
		}
		level := "ERROR"
		sign := "✗"
		if warning {
			warnings++
			level = "WARN"
			sign = "⚠"
		} else {
			errorsFound++
		}
		a.message(level, sign+" "+label+"："+a.safeText(e.Error(), s))
		if advice != "" {
			fmt.Fprintln(os.Stderr, "  建议："+advice)
		}
	}
	if loadErr == nil {
		loadErr = s.Validate()
	}
	check("state", "local", "节点配置与身份", loadErr, false, "保留现场和历史代；配置损坏时先找回有效 state.json，不要直接重新生成密钥")
	check("core", "local", "sing-box "+s.CoreVersion+" 及摘要", node.VerifyCore(a.store.Root, s.CoreVersion), false, "运行 qingnode core install；GitHub 不通时使用 --archive 官方归档")
	config := filepath.Join(a.store.Root, "current", "server.json")
	_, e := os.Stat(config)
	check("config-file", "local", "配置文件存在", e, false, "完成安装或从备份恢复")
	if e == nil && !a.offline {
		check("core-config", "local", "sing-box check 和端口预检", a.store.Backend.Check(s, config), false, "运行 qingnode ports；更换冲突端口或修复证书后重试")
	} else if report != nil && !a.offline {
		report.add(s, "core-config", "local", "核心配置与端口预检", "unknown", "派生配置缺失，未调用核心进行校验", "qingnode apply")
	}
	check("certificates", "local", "启用节点证书有效期", node.ValidateCertificateDates(s), false, "使用 edit --cert/--key 导入续期证书，或先 disable 对应节点")
	for _, journal := range []string{"transaction.json", "uninstall.json"} {
		_, err := os.Lstat(filepath.Join(a.store.Root, journal))
		if err == nil {
			check("pending/"+journal, "local", "未完成事务："+journal, errors.New("发现中断记录"), true, "运行 qingnode recover；诊断不会自动重启或回退")
		} else if !errors.Is(err, os.ErrNotExist) {
			if report != nil {
				report.add(s, "pending/"+journal, "local", "中断事务检查", "unknown", "无法读取事务记录状态", "")
			} else {
				a.message("WARN", "无法确认中断事务状态；请保留现有文件并检查读取权限")
			}
		} else if report != nil {
			report.add(s, "pending/"+journal, "local", "中断事务检查", "healthy", "未发现此类中断记录", "")
		}
	}
	check("pending-migration", "local", "完整迁移事务", node.MigrationPending(a.store.Root), true, "完整迁移中断时使用 qingnode restore --recover-migration --yes；先保留现场")
	if !a.offline {
		be := node.SystemBackend{Root: a.store.Root}
		active, activeErr := be.ActiveState()
		if activeErr == nil && !active {
			activeErr = errors.New("当前未运行")
		}
		check("service", "local", "受管服务运行状态", activeErr, true, "先确认本机服务控制器可用；需要运行时执行 qingnode start，并查看 qingnode logs")
		sockets := be.Sockets()
		for _, n := range s.Nodes {
			if n.Enabled {
				one := node.NewState()
				one.Nodes = []node.Node{n}
				var err error
				if !node.SocketsReady(one, sockets) {
					err = errors.New("未发现该服务进程的预期监听")
				}
				check("listen/"+n.ID, "local", n.Name+" "+node.PortLabel(n), err, false, "先检查服务日志及端口冲突，再核对本机防火墙与云安全组")
			}
		}
		if len(s.Forwards) > 0 || len(s.Egresses) > 0 {
			var err error
			if !node.SocketsReady(s, sockets) {
				err = errors.New("未发现该服务进程的全部预期节点、中转或用户态WireGuard监听")
			}
			check("topology-listen", "local", "拓扑本地监听就绪（不是链路可用证明）", err, false, "核对forward/egress声明、服务日志、端口冲突；链路请另运行egress health或经入口probe")
		}
		b, e := node.Run(5*time.Second, "timedatectl", "show", "--property=NTPSynchronized", "--value")
		if e == nil && strings.TrimSpace(string(b)) != "yes" {
			e = errors.New("系统未报告时间已同步")
		}
		check("clock", "local", "系统时间同步", e, true, "检查 timedatectl status 或已安装的 chrony；证书及协议认证依赖正确时间")
		found := false
		for _, tool := range []string{"ufw", "firewall-cmd", "nft", "iptables"} {
			if _, e := exec.LookPath(tool); e == nil {
				if report != nil {
					report.add(s, "firewall-tool/"+tool, "local-capability", "防火墙工具："+tool, "healthy", "仅证明命令存在，未证明规则或公网端口可达", "")
				} else {
					fmt.Fprintln(os.Stderr, "[INFO] 已检测到防火墙工具："+tool)
				}
				found = true
			}
		}
		if !found {
			check("firewall-detection", "local-capability", "本机防火墙识别", errors.New("未检测到支持的工具"), true, "手动检查云安全组；工具不存在不代表端口已经开放")
		}
	}
	if a.offline {
		if report != nil {
			for _, item := range []struct{ id, label string }{{"core-config", "核心配置与端口预检"}, {"service", "宿主服务与监听"}, {"public-egress", "服务器出站地址"}, {"dns", "网络DNS检查"}, {"reality-targets", "REALITY握手目标"}} {
				report.add(s, item.id, "not-measured", item.label, "unknown", "离线模式未执行宿主或网络探测", "")
			}
		} else {
			a.message("INFO", "离线模式未执行宿主服务、DNS、公网出站或REALITY目标探测；这些结果保持未测。")
		}
	} else {
		var v4, v6 string
		var e4, e6 error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); v4, e4 = node.PublicIP("4") }()
		go func() { defer wg.Done(); v6, e6 = node.PublicIP("6") }()
		wg.Wait()
		check("public-egress-v4", "server-outbound", "公网 IPv4 "+v4, e4, true, "IPv6-only VPS 可使用 IPv6；否则检查 DNS、默认路由和 HTTPS 出站")
		check("public-egress-v6", "server-outbound", "公网 IPv6 "+v6, e6, true, "纯 IPv4 VPS 可忽略；仅在使用 IPv6/AAAA 时处理")
		_, e = node.Lookup("github.com")
		check("github-dns", "server-outbound", "GitHub DNS", e, false, "检查 /etc/resolv.conf 和 DNS 服务；不会自动覆盖系统 DNS")
		for _, n := range s.Nodes {
			if !n.Enabled {
				continue
			}
			for _, endpoint := range node.EffectiveEndpoints(n) {
				if net.ParseIP(endpoint.Host) == nil {
					_, e := node.Lookup(endpoint.Host)
					check("endpoint-dns/"+n.ID+"/"+endpoint.ID, "server-outbound", n.Name+"/"+endpoint.ID+" 连接域名解析", e, false, "检查A/AAAA；解析成功和IPv4回落成功均不证明IPv6或入站可达")
				}
			}
			if n.Reality != nil {
				check("reality-target/"+n.ID, "server-outbound", n.Name+" REALITY TLS1.3/HTTP2", node.CheckReality(n.Reality), false, "检查 SNI 与握手目标；用 edit 修改目标，现有密钥会保留")
			}
		}
	}
	if report == nil && (errorsFound > 0 || a.debug) {
		a.recentLogs(s)
	}
	if report == nil {
		fmt.Fprintf(os.Stderr, "诊断结果：%d 项错误，%d 项警告。公网客户端握手与 UDP 传输需另行实测。\n", errorsFound, warnings)
	}
	if e := a.noteHistory(func(h *dashboardHistory) {
		h.Diagnostic = &checkRecord{At: time.Now().UTC(), Fingerprint: stateFingerprint(s), Errors: errorsFound, Warnings: warnings, Offline: a.offline}
	}); e != nil {
		if report != nil {
			report.Issues = append(report.Issues, "检查已完成，结果历史未能保存；节点配置不变")
		} else {
			a.message("WARN", "检查已完成，但首页记录保存失败："+node.Redact(e.Error()))
		}
	}
	if errorsFound > 0 {
		if report != nil {
			return fmt.Errorf("诊断有 %d 项失败；原因与下一步见JSON checks字段", errorsFound)
		}
		return fmt.Errorf("发现 %d 项错误，请按上方建议处理", errorsFound)
	}
	return nil
}
