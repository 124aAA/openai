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
	"strconv"
	"strings"

	"golang.org/x/term"
	"qingnode/internal/node"
)

var version = "0.2.6"
var revision = "source"

const defaultRoot = "/var/lib/qingnode"

type app struct {
	store   *node.Store
	offline bool
	debug   bool
	in      *bufio.Reader
}

func main() {
	if e := run(os.Args[1:]); e != nil && !errors.Is(e, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "[ERROR]", node.Redact(e.Error()))
		os.Exit(1)
	}
}
func run(args []string) error {
	f := flag.NewFlagSet("qingnode", flag.ContinueOnError)
	debug := f.Bool("debug", false, "详细诊断，敏感内容仍脱敏")
	root := f.String("root", defaultRoot, "状态目录；自定义目录须搭配 --offline")
	offline := f.Bool("offline", false, "离线生成，不操作 systemd，也不代表节点可连接")
	if e := f.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			help()
			return nil
		}
		return e
	}
	args = f.Args()
	if len(args) == 3 && args[0] == "validate-state" && args[1] == "--file" {
		s, e := node.ReadState(args[2])
		if e != nil {
			return e
		}
		return s.Validate()
	}
	if len(args) == 2 && args[0] == "service" && args[1] == "unit" {
		fmt.Print(node.ServiceUnit)
		return nil
	}
	if len(args) == 1 && args[0] == "redact-log" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
		if e != nil {
			return e
		}
		fmt.Print(node.Redact(string(b)))
		return nil
	}
	if len(args) > 0 && args[0] == "version" {
		fmt.Printf("QingNode %s (%s)\n", version, revision)
		return nil
	}
	if len(args) > 0 && args[0] == "reality-targets" {
		if *offline {
			return errors.New("目标测速需要联网，请移除 --offline")
		}
		return realityTargets(args[1:])
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help") {
		help()
		return nil
	}
	if len(args) > 0 && args[0] == "serve" {
		if *offline || *root != defaultRoot {
			return errors.New("serve 仅供已安装的 systemd 服务使用")
		}
		return serve(*root)
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
	if len(args) == 0 {
		return a.menu()
	}
	return a.command(args)
}
func help() {
	fmt.Print(`QingNode 青节点 — 个人 VPS 节点管理工具

用法：qingnode [--offline --root 目录] 命令 [参数]
不带命令进入中文菜单。离线模式只生成配置，不部署服务。

 init         初始化节点；--auto 自动探测地址/目标/端口，重复执行保留原节点
 add          添加 reality / ss2022 / hysteria2 节点
 list / info  查看节点概要（凭据脱敏）
 edit         修改名称、地址、端口、证书或目标
 enable       启用节点
 disable      停用节点
 delete       删除指定节点，须 --yes
 user-add     添加一个独立凭据
 user-delete  删除指定凭据，须 --yes
 rotate       更换凭据、REALITY 密钥/short ID、SS2022 服务密钥
 export       导出 uri / qr / base64 / mihomo / provider / sing-box
 render       导出服务器配置；包含私钥，仅保存于安全路径
 check        调用锁定的官方核心检查配置
 apply        检查并重启当前服务
 rollback     回退到上一代节点和核心版本
 core         install / update / check / versions，默认 sing-box 1.14.0
 install      安装核心并初始化首个节点
 update       更新官方核心；旧版本和配置代保留
 self-update  更新管理器，使用 --bundle 或 --repo/--version
 status       本机服务状态
 overview     首页状态总览，只读本机，不联网
 check-updates  主动联网查询管理器及适配核心更新，保存查询结果
 public-check  登记已完成的客户端实测（管理员记录，非自动公网检测）
 doctor       检查配置、DNS、证书、监听和防火墙
 logs         查看脱敏后的最近日志
 backup       导出 AES-GCM 加密配置快照
 restore      恢复加密备份，须 --yes
 service      start / stop / restart / status / enable / disable
 ports        查看监听端口及进程
 reality-targets  筛选并显示延迟最低的 REALITY 目标，默认前三名；不修改节点
 firewall     status / enable / disable / sync（已启用的 UFW）
 network      status / bbr（仅系统内核）
 recover      恢复中断的配置或卸载事务
 uninstall    --yes 只移除核心；--purge --yes 清除自身数据
 version

各命令追加 --help 查看参数。导出完整配置优先使用 --out 文件。
首版在线订阅、自动链式出站及 Web 面板尚未提供。
`)
}
func (a *app) prompt(q, def string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s", q)
	if def != "" {
		fmt.Fprintf(os.Stderr, " [%s]", def)
	}
	fmt.Fprint(os.Stderr, ": ")
	s, e := a.in.ReadString('\n')
	if e != nil && len(s) == 0 {
		return "", e
	}
	s = strings.TrimSpace(s)
	if s == "" {
		s = def
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
func (a *app) mutate(fn func(*node.State) error) error {
	return a.locked(func(s *node.State) error {
		if e := s.Validate(); e != nil {
			return e
		}
		if e := fn(s); e != nil {
			return e
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
func fs(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }
func portFlag(f *flag.FlagSet, defaultValue int) *int {
	value := defaultValue
	f.Func("port", "监听端口（十进制，1–65535）", func(raw string) error {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("端口须为十进制 1–65535")
		}
		value = n
		return nil
	})
	f.Lookup("port").DefValue = strconv.Itoa(defaultValue)
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
	if cmd == "overview" || cmd == "check-updates" {
		if len(rest) != 0 {
			return errors.New("该命令不接受参数")
		}
		if cmd == "overview" {
			return a.overview(os.Stdout)
		}
		return a.checkUpdates()
	}
	if cmd == "public-check" {
		return a.publicCheck(rest)
	}
	if cmd == "diagnose" {
		cmd = "doctor"
	}
	if cmd == "install" {
		if e := a.core([]string{"install"}); e != nil {
			return e
		}
		cmd = "init"
	}
	if cmd == "wizard" {
		f := fs(cmd)
		protocol := f.String("protocol", "", "已选择的协议；留空显示选择菜单")
		quiet := f.Bool("quiet", false, "由安装器统一显示完成结果")
		if e := parse(f, rest); e != nil {
			return e
		}
		return a.installWizard(true, *protocol, *quiet)
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
		return a.store.WithLock(func() error { a.message("SUCCESS", "事务恢复完成"); return nil })
	}
	var e error
	switch cmd {
	case "init", "add":
		e = a.add(cmd, rest)
	case "list":
		e = a.list(rest)
	case "info":
		e = a.info(rest)
	case "edit":
		e = a.edit(rest)
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
	format := f.String("format", "uri", "uri/qr/base64/mihomo/provider/sing-box")
	out := f.String("out", "", "输出文件（拒绝覆盖已有文件）")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.locked(func(s *node.State) error {
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
			b, e = node.Export(*n, u, *format)
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
	return a.locked(func(s *node.State) error {
		if cmd == "check" {
			return node.VerifyCore(a.store.Root, s.CoreVersion)
		}
		if cmd != "install" && cmd != "update" {
			return errors.New("未知 core 子命令")
		}
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
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return "", e
	}
	if confirm {
		fmt.Fprint(os.Stderr, "再次输入：")
		c, e := term.ReadPassword(int(os.Stdin.Fd()))
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
