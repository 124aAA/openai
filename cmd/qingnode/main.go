package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/term"
	"qingnode/internal/node"
	"qingnode/internal/ui"
)

var version = "0.3.0"
var revision = "source"

const defaultRoot = "/var/lib/qingnode"

type app struct {
	store           *node.Store
	serviceRunner   node.Runner                                // explicit observation fixture; nil uses actual host init
	installCoreFn   func(string, string, string, string) error // nil uses the official installer
	wizardCollect   func([]string) error                       // bootstrap-only validated fields, without State or credentials
	offline         bool
	debug           bool
	in              *bufio.Reader
	menuPreview     bool // show the actual candidate impact only for interactive tasks
	menuPreviewDone bool
}

func main() {
	e := run(os.Args[1:])
	if errors.Is(e, errMenuCanceled) {
		fmt.Fprintln(os.Stderr, "已取消；本次表单未应用。")
		return
	}
	if e != nil && !errors.Is(e, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, ui.WrapText("[ERROR] "+safeCLIError(e.Error()), ui.Width(os.Stderr)))
		os.Exit(commandExitCode(e))
	}
}
func run(args []string) (result error) {
	f := flag.NewFlagSet("qingnode", flag.ContinueOnError)
	f.SetOutput(cliErrorWriter{os.Stderr})
	debug := f.Bool("debug", false, "详细诊断，敏感内容仍脱敏")
	root := f.String("root", defaultRoot, "状态目录；自定义目录须搭配 --offline")
	offline := f.Bool("offline", false, "离线生成，不操作服务管理器，也不代表节点可连接")
	reportDir := f.String("result-dir", "", "新私有目录：started.json与原子发布的版本1执行回执；不记录参数或秘密")
	parseErr := f.Parse(args)
	var report *executionReporter
	if *reportDir != "" {
		var err error
		report, err = beginExecutionReport(*reportDir, *root, f.Args())
		if err != nil {
			return fmt.Errorf("未开始执行；无法准备新结果回执目录：%w", err)
		}
		defer func() {
			if err := report.finish(result); err != nil {
				if errors.Is(result, flag.ErrHelp) || errors.Is(result, errMenuCanceled) {
					result = nil
				}
				result = errors.Join(result, err)
			}
		}()
	}
	if e := parseErr; e != nil {
		if errors.Is(e, flag.ErrHelp) {
			help()
			return nil
		}
		return e
	}
	args = f.Args()
	if report != nil && len(args) == 0 {
		return errors.New("执行回执模式需要明确命令；不自动进入交互菜单")
	}
	if len(args) == 3 && args[0] == "validate-state" && args[1] == "--file" {
		s, e := node.ReadState(args[2])
		if e != nil {
			return e
		}
		return s.Validate()
	}
	if len(args) >= 2 && args[0] == "service" && args[1] == "unit" {
		return renderServiceDefinition(args[2:])
	}
	if len(args) == 1 && args[0] == "redact-log" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
		if e != nil {
			return e
		}
		fmt.Print(node.Redact(string(b)))
		return nil
	}
	// This help path must also work before the service account or a complete
	// bootstrap bundle exists; it never installs or queries the host.
	if len(args) == 2 && args[0] == "install" && (args[1] == "--help" || args[1] == "-h") {
		fmt.Fprintln(os.Stdout, "已安装：qingnode install 接受 init 参数；查看 qingnode init --help。")
		fmt.Fprintln(os.Stdout, "首次安装：在完整安装包中运行 bash install.sh --help；支持 --repo、--version 和 --core-archive。")
		return nil
	}
	if len(args) > 0 && args[0] == "validate-install" {
		a := app{}
		return a.add("validate-install", args[1:])
	}
	if len(args) > 0 && args[0] == "collect-install" {
		return collectInstall(args[1:])
	}
	if len(args) > 0 && args[0] == "version" {
		return printVersion(args[1:])
	}
	if len(args) > 0 && args[0] == "capabilities" {
		a := app{store: &node.Store{Root: *root}, offline: *offline, debug: *debug}
		return a.capabilities(args[1:])
	}
	if len(args) > 0 && args[0] == "reality-targets" {
		if *offline {
			return errors.New("目标测速需要联网，请移除 --offline")
		}
		return realityTargets(args[1:])
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help") {
		if len(args) == 2 && args[1] == "--json" {
			return printMachineHelp()
		}
		if len(args) != 1 {
			return errors.New("help 仅接受 --json")
		}
		help()
		return nil
	}
	if len(args) > 0 && args[0] == "serve" {
		if *offline || *root != defaultRoot {
			return errors.New("serve 仅供已安装的受管服务使用")
		}
		return serve(*root)
	}
	// The optional download server runs as a separate unprivileged process.
	// It never opens State or requires the proxy management group/account.
	if len(args) >= 2 && args[0] == "subscription" && args[1] == "serve" {
		return subscriptionServe(args[2:])
	}
	if !*offline && *root != defaultRoot {
		return errors.New("自定义目录仅可用于 --offline 离线生成")
	}
	if *offline && filepath.Clean(*root) == defaultRoot {
		return errors.New("离线模式请用 --root 指定独立目录，避免修改已安装服务的状态")
	}
	var backend node.Backend = node.OfflineBackend{}
	gid := -1
	if !*offline {
		if os.Geteuid() != 0 {
			return errors.New("系统管理需要 root，请使用 sudo；仅生成配置可用 --offline --root")
		}
		g, e := user.LookupGroup("qingnode")
		if e != nil {
			if len(args) == 0 || args[0] == "install" {
				return bootstrap(args)
			}
			if len(args) == 0 || (args[0] != "doctor" && args[0] != "diagnose" && args[0] != "status") {
				return errors.New("请先运行安装包中的 install.sh")
			}
		} else {
			gid, e = strconv.Atoi(g.Gid)
			if e != nil {
				return errors.New("专用组 ID 无效")
			}
		}
		backend = node.SystemBackend{Root: *root}
	}
	a := app{store: &node.Store{Root: *root, Backend: backend, GID: gid}, offline: *offline, debug: *debug, in: bufio.NewReader(os.Stdin)}
	a.store.AfterCommit = a.refreshPublished
	a.store.BeforeCommit = a.revokeRemovedPublishedDevices
	if report != nil {
		report.wrapApplyHook(a.store)
	}
	if len(args) == 0 {
		return a.menu()
	}
	return a.command(args)
}
func help() {
	fmt.Print(`QingNode 青节点 — 个人 VPS 节点管理工具

用法：qingnode [--offline --root 目录] 命令 [参数]
不带命令进入中文菜单。离线模式只生成配置，不部署服务。
脚本可在命令前加 --result-dir 新目录，保存不含参数/秘密的版本1执行回执；领域数据用各自JSON或私有导出。
result.json缺失或status非completed不能当通过；返回错误仍可能已经提交配置，禁止据此盲目重试。

 init         初始化节点；--auto 自动探测地址/目标/端口，重复执行保留原节点
 add          添加 reality / ss2022 / hysteria2 / anytls / trojan / ss-aead / tuic 节点
 protocols    list查看分层能力；options以私有JSON预览/应用协议高级设置
 list / info  查看节点概要（凭据脱敏）
 edit         修改名称、地址、端口、证书或目标；--preview 只读查看影响
 batch        --file JSON 批量编辑并统一应用；--preview 只读查看影响
 hy2          show / plan / apply / revert / compare，隔离管理HY2性能选择
 enable       启用节点
 disable      停用节点
 delete       删除指定节点，须 --yes
 user-add     添加一个独立凭据
 user-delete  删除指定凭据，须 --yes
 rotate       更换凭据、REALITY 密钥/short ID、SS2022 服务密钥
 endpoint     list / add / edit / remove / material；连接端点与外部待验证材料
 egress       list / show / add / edit / remove / policy / health；远程出口凭据独立保存
 route        set --id 入口节点 --egress direct或出口/策略ID
 forward      list / add / edit / remove；固定目标的TCP/UDP端口中转
 topology     batch --file 严格JSON [--preview]，统一修改出口、策略、中转与引用
 wireguard    pair；为两台自有服务器生成用户态落地配对，分端执行与撤回
 capabilities  本机运行能力探测；不表示外部链路已通过
 wizard       --nat 显式填写NAT本地监听与外部连接端口
 export       导出 uri / qr / base64 / mihomo / provider / sing-box；--endpoint选择入口
 device       list/show/create/apply/remove/disable/tags；明确绑定设备的节点与凭据
 certificate  list/status/import/update/bind/unbind/remove；稳定证书资源，私有输入与影响预览
 monitor      configure/run/status/history/disable/timer/api/traffic；可选有界监控，默认只观察
 expiration   list/set/remove/apply；明确代理凭据到期，与下载令牌独立
 subscription init/configure/publish/status/issue/rotate/revoke/qr/check/serve；可选只读设备订阅
 render       导出服务器配置；包含私钥，仅保存于安全路径
 check        调用锁定的官方核心检查配置
 apply        检查并统一应用当前配置；重复应用免重启
 rollback     回退到上一代节点和核心版本
 core         install / update / check / versions，默认 sing-box 1.14.0
 install      安装核心并初始化首个节点
 update       更新官方核心；旧版本和配置代保留
 self-update  更新管理器，使用 --bundle 或 --repo/--version
 status       本机服务状态
 overview     首页状态总览，只读本机，不联网
 check-updates  主动联网查询管理器及适配核心更新，保存查询结果
 public-check  登记已完成的客户端实测（管理员记录，非自动公网检测）
 probe        local / profile / run / compare / udp-echo，受限的隔离网络测试
 dns          show / diagnose / set / reset，解析耗时、预期地址核对及项目内解析器
 doctor       检查配置、DNS、证书、监听和防火墙
 logs         查看脱敏日志；--name qingnode-subscription|qingnode-monitor选择附属服务
 backup       配置备份；--full完整加密迁移，--preview预检，--prune受管保留
 restore      预检/恢复加密备份；提交须--yes，运行资产短停须--quiesce
 service      start/stop/restart/status/enable/disable/logs；附属install/remove/recover须--preview或--yes
 ports        查看监听端口及进程
 reality-targets  筛选并显示延迟最低的 REALITY 目标，默认前三名；不修改节点
 firewall     status / enable / disable / sync（已启用的 UFW）
 network      status / plan / apply / restore / bbr（仅现有内核能力）
 recover      恢复中断的配置或卸载事务
 uninstall    --yes 只移除核心；--purge --yes 清除自身数据
 version

带参数的命令可追加 --help；recover 等无参数命令请查看本帮助。导出完整配置优先使用 --out 文件。
远程出口失效不会自动回落direct。显式主备须主动运行egress health --apply或有预算的--watch。
拓扑运行配置统一由共享核心承载，应用或切换可能打断已有连接；不会无损迁移TCP会话。
设备批量导出用export --device ID --format 格式 --client-version 固定版本 --out 私有文件。
订阅令牌撤销仅禁止下载；停用已下载代理认证须device disable --disable-credentials。
公开订阅须验证HTTPS；HTTP仅允许明确的本机反向代理入口。没有Web面板。
`)
}
func (a *app) prompt(q, def string) (string, error) {
	label := q
	if def != "" {
		label += " [" + def + "]"
	}
	fmt.Fprint(os.Stderr, ui.WrapText(label+": ", ui.Width(os.Stderr)))
	line, e := a.in.ReadSlice('\n')
	if e != nil {
		if errors.Is(e, bufio.ErrBufferFull) {
			return "", errors.New("单行输入最多4095字节；本次未应用，取消可输入 :cancel")
		}
		return "", e
	}
	s := strings.TrimSpace(string(line))
	for _, r := range s {
		if unicode.IsControl(r) || r == '\ufffd' || r == '\u202a' || r == '\u202b' || r == '\u202c' || r == '\u202d' || r == '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return "", errors.New("输入包含控制字符或无效编码；本次未应用")
		}
	}
	if s == "" {
		s = def
	}
	if s == ":cancel" {
		return "", errMenuCanceled
	}
	return s, nil
}
func (a *app) locked(fn func(*node.State) error) error {
	return a.store.WithLock(func() error {
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		return fn(&s)
	})
}

// Queries share the management lock, but never recover transactions or services.
func (a *app) inspectState(fn func(*node.State) error) error {
	return a.store.Inspect(func() error {
		for _, journal := range []string{"transaction.json", "uninstall.json"} {
			if _, e := os.Lstat(filepath.Join(a.store.Root, journal)); e == nil {
				a.message("WARN", "发现中断操作；当前配置尚未确认提交。查询不会恢复或重启服务，请先核查 qingnode doctor，再用 qingnode recover 恢复。")
				break
			}
		}
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		return fn(&s)
	})
}
func (a *app) mutate(fn func(*node.State) error) error {
	return a.locked(func(s *node.State) error {
		if e := s.Validate(); e != nil {
			return e
		}
		if e := fn(s); e != nil {
			return e
		}
		if a.menuPreview {
			if e := a.previewMenuMutation(*s); e != nil {
				return e
			}
		}
		if e := a.store.Apply(*s); e != nil {
			return e
		}
		if a.offline {
			fmt.Fprintln(os.Stderr, "已保存离线配置；未启动服务，也未验证公网连通。")
		} else {
			fmt.Fprintln(os.Stderr, "配置已应用；请用客户端验证实际连接。")
		}
		return nil
	})
}

// install builds one candidate in a read-only snapshot, then takes a lock that
// never recovers journals and verifies that the source State has not changed.
func (a *app) mutateInstall(fn func(*node.State) error) error {
	var before, candidate node.State
	if err := a.store.Inspect(func() error {
		if err := rejectPending(a.store.Root); err != nil {
			return err
		}
		if err := node.MigrationPending(a.store.Root); err != nil {
			return err
		}
		state, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = state.Validate(); err != nil {
			return err
		}
		before = state.Clone()
		if err = fn(&state); err != nil {
			return err
		}
		candidate = state.Clone()
		return nil
	}); err != nil {
		return err
	}
	return a.commitInstall(before, candidate)
}

// commitInstall rejects stale candidates before installing the core.
func (a *app) commitInstall(before, candidate node.State) error {
	return a.store.WithLockNoRecovery(func() error {
		if err := rejectPending(a.store.Root); err != nil {
			return err
		}
		if err := node.MigrationPending(a.store.Root); err != nil {
			return err
		}
		current, err := a.store.Load()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before.Clone(), current.Clone()) {
			return errors.New("预检期间配置发生变化；未安装核心，请重试")
		}
		if err := a.installCore(candidate.CoreVersion, candidate.CoreArchiveSHA256); err != nil {
			return err
		}
		if err := a.store.Apply(candidate); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "配置已应用；请用客户端验证实际连接。")
		return nil
	})
}

func fs(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(cliErrorWriter{os.Stderr})
	return f
}
func portFlag(f *flag.FlagSet, defaultValue int) *int {
	return namedPortFlag(f, "port", defaultValue, "监听端口（十进制，1–65535）")
}
func namedPortFlag(f *flag.FlagSet, name string, defaultValue int, description string) *int {
	value := defaultValue
	f.Func(name, description, func(raw string) error {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("端口须为十进制 1–65535")
		}
		value = n
		return nil
	})
	f.Lookup(name).DefValue = strconv.Itoa(defaultValue)
	return &value
}
func parse(f *flag.FlagSet, args []string) error {
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("无法识别参数：%s", strings.Join(f.Args(), " "))
	}
	return nil
}
func (a *app) command(args []string) error {
	if len(args) == 0 {
		return nil
	}
	cmd, rest := args[0], args[1:]
	if cmd == "overview" {
		return a.overviewCommand(rest)
	}
	if cmd == "check-updates" {
		if len(rest) != 0 {
			return errors.New("该命令不接受参数")
		}
		return a.checkUpdates()
	}
	if cmd == "public-check" {
		return a.publicCheck(rest)
	}
	if cmd == "probe" {
		return a.probe(rest)
	}
	if cmd == "endpoint" {
		return a.endpoint(rest)
	}
	if cmd == "capabilities" {
		return a.capabilities(rest)
	}
	if cmd == "dns" {
		return a.dns(rest)
	}
	if cmd == "diagnose" {
		cmd = "doctor"
	}
	if cmd == "wizard" {
		f := fs(cmd)
		protocol := f.String("protocol", "", "已选择的协议；留空显示选择菜单")
		quiet := f.Bool("quiet", false, "由安装器统一显示完成结果")
		nat := f.Bool("nat", false, "显式填写本地监听及外部NAT映射，不探测或修改云NAT")
		fieldsFile := f.String("fields-file", "", "安装器的私有版本化参数文件；不执行文件内容")
		if e := parse(f, rest); e != nil {
			return e
		}
		if *fieldsFile != "" {
			if *nat {
				return errors.New("参数文件不能与NAT表单混用")
			}
			return a.applyCollectedInstall(*fieldsFile, *protocol)
		}
		return a.installWizardOptions(true, *protocol, *quiet, *nat)
	}
	if cmd == "update" {
		return a.core(append([]string{"update"}, rest...))
	}
	if cmd == "service" {
		return a.service(rest)
	}
	if cmd == "network" {
		return a.network(rest)
	}
	if cmd == "firewall" {
		return a.firewall(rest)
	}
	if cmd == "self-update" {
		return a.selfUpdate(rest)
	}
	if cmd == "ports" {
		return a.ports(rest)
	}
	if cmd == "recover" {
		if len(rest) != 0 {
			return errors.New("recover 不接受参数")
		}
		return a.store.WithLock(func() error {
			st, err := a.store.Load()
			if err != nil {
				return err
			}
			if err = a.refreshPublished(st); err != nil {
				return fmt.Errorf("配置事务已恢复；订阅发布未完成：%w", err)
			}
			a.message("SUCCESS", "事务恢复完成")
			return nil
		})
	}
	var e error
	switch cmd {
	case "init", "add", "install":
		e = a.add(cmd, rest)
	case "list":
		e = a.list(rest)
	case "info":
		e = a.info(rest)
	case "edit":
		e = a.edit(rest)
	case "batch":
		e = a.batch(rest)
	case "hy2":
		e = a.hy2(rest)
	case "egress":
		e = a.egress(rest)
	case "route":
		e = a.route(rest)
	case "forward":
		e = a.forward(rest)
	case "topology":
		e = a.topology(rest)
	case "wireguard":
		e = a.wireguardPair(rest)
	case "device":
		e = a.device(rest)
	case "certificate":
		e = a.certificates(rest)
	case "protocols":
		e = a.protocols(rest)
	case "monitor":
		e = a.monitor(rest)
	case "expiration":
		e = a.expiration(rest)
	case "subscription":
		e = a.subscription(rest)
	case "enable", "disable", "delete":
		e = a.toggle(cmd, rest)
	case "user-add", "user-delete", "rotate":
		e = a.users(cmd, rest)
	case "export", "render":
		e = a.export(cmd, rest)
	case "core":
		e = a.core(rest)
	case "backup", "restore":
		e = a.backup(cmd, rest)
	case "check", "apply", "rollback", "start", "stop", "restart", "status", "doctor", "logs":
		e = a.operation(cmd, rest)
	case "uninstall":
		e = a.uninstall(rest)
	default:
		e = fmt.Errorf("未知命令 %q，运行 qingnode help 查看帮助", cmd)
	}
	if errors.Is(e, flag.ErrHelp) {
		return nil
	}
	return e
}
func writeOutput(out string, b []byte) error {
	if out == "" {
		_, e := os.Stdout.Write(append(b, '\n'))
		return e
	}
	f, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
func (a *app) export(cmd string, args []string) error {
	f := fs(cmd)
	id := f.String("id", "", "节点 ID 或名称")
	uid := f.String("user", "", "凭据 ID 或名称")
	endpoint := f.String("endpoint", "default", "连接端点ID；默认default")
	format := f.String("format", "uri", "uri/qr/base64/mihomo/provider/sing-box；设备另支持sing-box-outbounds")
	out := f.String("out", "", "输出文件（拒绝覆盖已有文件）")
	clientVersion := f.String("client-version", "", "目标客户端版本；新协议单节点及设备导出sing-box须1.14.0/1.14.3，Mihomo须1.19.30")
	allowLossy := f.Bool("allow-lossy", false, "明确允许目标格式缺失设置；会逐项警告")
	device := f.String("device", "", "多节点设备Profile稳定ID或名称；必须--out")
	profileFile := f.String("profile-file", "", "只读临时设备输入，version:1且profiles一项")
	if e := parse(f, args); e != nil {
		return e
	}
	if *device != "" || *profileFile != "" {
		if cmd != "export" || flagSet(f, "id") || flagSet(f, "user") || flagSet(f, "endpoint") {
			return errors.New("设备导出不能混用单节点id/user/endpoint或render")
		}
		return a.exportDevice(*device, *profileFile, *format, *clientVersion, *out, *allowLossy)
	}
	if cmd == "render" && flagSet(f, "endpoint") {
		return errors.New("render生成本地服务端配置，不接受客户端--endpoint")
	}
	return a.inspectState(func(s *node.State) error {
		if e := s.Validate(); e != nil {
			return e
		}
		var b []byte
		var e error
		if cmd == "render" {
			b, e = node.Server(*s, a.store.Root)
		} else {
			n, err := s.Find(*id)
			if err != nil {
				return err
			}
			u, err := node.SelectUser(*n, *uid)
			if err != nil {
				return err
			}
			selected, err := node.WithEndpoint(*n, *endpoint)
			if err != nil {
				return err
			}
			result, err := node.ExportWithCapabilities(selected, u, *format, *clientVersion, nil, *allowLossy)
			if err != nil {
				return err
			}
			b = result.Data
			for _, warning := range result.Warnings {
				a.message("WARN", warning)
			}
		}
		if e != nil {
			return e
		}
		return writeOutput(*out, b)
	})
}
func (a *app) core(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：core install|update|check [--version 1.14.x] [--sha256 摘要] [--archive 本地归档]")
	}
	cmd := args[0]
	if cmd == "versions" {
		if len(args) != 1 {
			return errors.New("versions 不接受参数")
		}
		return a.coreVersions()
	}
	f := fs("core " + cmd)
	v := f.String("version", node.DefaultCore, "核心版本")
	sum := f.String("sha256", "", "非默认版本：官方归档 SHA-256")
	downgrade := f.Bool("allow-downgrade", false, "明确允许降低核心版本")
	archive := f.String("archive", "", "离线安装官方 tar.gz")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	explicitVersion := false
	f.Visit(func(x *flag.Flag) {
		if x.Name == "version" {
			explicitVersion = true
		}
	})
	if cmd == "check" {
		return a.inspectState(func(s *node.State) error { return node.VerifyCore(a.store.Root, s.CoreVersion) })
	}
	if cmd != "install" && cmd != "update" {
		return errors.New("未知 core 子命令")
	}
	return a.locked(func(s *node.State) error {
		if cmd == "install" && !explicitVersion {
			*v = s.CoreVersion
		}
		if cmd == "update" && !explicitVersion {
			r, e := node.LatestStable("SagerNet/sing-box")
			if e != nil {
				return e
			}
			*v = strings.TrimPrefix(r.Tag, "v")
			if !node.SupportedVersion(*v) {
				return fmt.Errorf("当前 %s；官方最新 %s 尚未适配，保持原版本", s.CoreVersion, *v)
			}
			if *sum == "" && *v != node.DefaultCore {
				*sum = r.CoreDigest()
			}
		}
		if *sum == "" && *v == s.CoreVersion {
			*sum = s.CoreArchiveSHA256
		}
		if node.CompareVersion(*v, s.CoreVersion) < 0 && !*downgrade {
			return errors.New("目标版本低于当前版本；如确需降级，增加 --allow-downgrade")
		}
		fmt.Fprintf(os.Stderr, "当前 sing-box %s → 目标 %s；旧核心与配置代会保留。\n", s.CoreVersion, *v)
		if e := node.InstallCore(a.store.Root, *v, *sum, *archive); e != nil {
			return e
		}
		if s.CoreVersion != *v {
			s.CoreVersion = *v
			s.CoreArchiveSHA256 = *sum
			return a.store.Apply(*s)
		}
		fmt.Fprintln(os.Stderr, "核心已校验并就绪。")
		return nil
	})
}
func password(path string, confirm bool) (string, error) {
	if path != "" {
		i, e := os.Lstat(path)
		if e != nil {
			return "", e
		}
		if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
			return "", errors.New("口令文件必须是权限 600 的普通文件")
		}
		b, e := readLimited(path, 4096)
		return strings.TrimRight(string(b), "\r\n"), e
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("非交互运行请提供 --password-file；不接受命令行明文口令")
	}
	fmt.Fprint(os.Stderr, "备份口令（至少 12 字节，不回显）：")
	b, e := readTerminalPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return "", e
	}
	if confirm {
		fmt.Fprint(os.Stderr, "再次输入：")
		c, e := readTerminalPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if e != nil {
			return "", e
		}
		if string(c) != string(b) {
			return "", errors.New("两次口令不一致")
		}
	}
	return string(b), nil
}
func flagSet(f *flag.FlagSet, name string) bool {
	found := false
	f.Visit(func(x *flag.Flag) {
		if x.Name == name {
			found = true
		}
	})
	return found
}
