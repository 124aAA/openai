package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
	"qingnode/internal/node"
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
	fmt.Fprintf(os.Stderr, "%s[%s] %s%s\n", color, level, text, end)
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
	if a.offline {
		return
	}
	b, e := node.Run(8*time.Second, "journalctl", "-u", "qingnode.service", "--no-pager", "-n", "40", "-o", "short-iso")
	if e != nil {
		a.message("WARN", "无法读取服务日志：请运行 journalctl -u qingnode.service")
		return
	}
	fmt.Print(a.safeText(string(b), s))
}
func (a *app) status(s node.State) error {
	fmt.Printf("管理器：%s；配置核心：%s\n配置文件：%s\n", version, s.CoreVersion, filepath.Join(a.store.Root, "current", "server.json"))
	if a.offline {
		fmt.Println("离线模式：未查询系统服务。")
		return nil
	}
	b, e := node.Run(8*time.Second, "systemctl", "show", "qingnode.service", "--property=ActiveState,SubState,MainPID,ActiveEnterTimestamp,ExecMainStartTimestamp,UnitFileState,Result")
	if e != nil {
		return fmt.Errorf("systemd 查询失败：%w", e)
	}
	fmt.Print(a.safeText(string(b), s))
	pid := (node.SystemBackend{Root: a.store.Root}).PID()
	if pid > 0 {
		if elapsed, e := node.Run(5*time.Second, "ps", "-p", fmt.Sprint(pid), "-o", "etime="); e == nil {
			fmt.Println("运行时长：" + strings.TrimSpace(string(elapsed)))
		}
	}
	for _, n := range s.Nodes {
		fmt.Printf("%s：%s，启用=%t\n", n.Name, node.PortLabel(n), n.Enabled)
	}
	if strings.Contains(string(b), "ActiveState=failed") {
		a.recentLogs(s)
		return errors.New("服务启动失败；运行 qingnode diagnose 获取建议")
	}
	return nil
}
func (a *app) service(args []string) error {
	if len(args) != 1 {
		return errors.New("用法：service start|stop|restart|status|enable|disable")
	}
	cmd := args[0]
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
		_, e := node.Run(12*time.Second, "systemctl", cmd, "qingnode.service")
		if e == nil {
			a.message("SUCCESS", "已修改开机自启设置；当前进程运行状态不变")
		}
		return e
	})
}
func (a *app) ports(args []string) error {
	f := fs("ports")
	if e := parse(f, args); e != nil {
		return e
	}
	b, e := node.Run(8*time.Second, "ss", "-H", "-lntup")
	if e != nil {
		return fmt.Errorf("无法读取监听端口，请安装 iproute2：%w", e)
	}
	fmt.Print(node.Redact(string(b)))
	return nil
}
func (a *app) info(args []string) error {
	f := fs("info")
	id := f.String("id", "", "节点名称或 ID")
	secrets := f.Bool("show-secrets", false, "显示连接凭据和完整链接")
	private := f.Bool("show-private", false, "显示 REALITY 私钥；不要截图分享")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.locked(func(s *node.State) error {
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
		for _, n := range nodes {
			fmt.Printf("\n节点：%s\nID：%s\n协议：%s\n服务器：%s\n监听：%s:%d (%s)\n启用：%t\n", n.Name, n.ID, n.Protocol, n.Host, n.Listen, n.Port, strings.Join(node.Networks(n), "+"), n.Enabled)
			fmt.Printf("导出链接：qingnode export --id %s --format uri\n", n.ID)
			if r := n.Reality; r != nil {
				fmt.Printf("Reality Public Key：%s\nShort ID：%s\nSNI：%s\n握手目标：%s\nFlow：xtls-rprx-vision\nFingerprint：%s\n", r.PublicKey, r.ShortID, r.ServerName, r.Target, node.Fingerprint(r))
				if *private {
					fmt.Printf("Reality Private Key：%s\n", r.PrivateKey)
				}
			}
			fmt.Printf("创建时间：%s\n更新时间：%s\n", n.CreatedAt, n.UpdatedAt)
			for _, u := range n.Users {
				fmt.Printf("凭据：%s (%s)\n", u.Name, u.ID)
				if *secrets {
					if u.UUID != "" {
						fmt.Printf("UUID：%s\n", u.UUID)
					} else {
						if n.Shadowsocks != nil {
							fmt.Printf("加密方法：%s\nPassword：%s\n", n.Shadowsocks.Method, node.SSPassword(n, u))
						} else {
							fmt.Printf("Password：%s\n", u.Password)
						}
					}
					fmt.Println(node.URI(n, u))
				}
			}
		}
		return nil
	})
}

// Findings carry actions, not raw command errors or entire firewall rulesets.
func (a *app) doctor(s node.State, loadErr error) error {
	errorsFound := 0
	warnings := 0
	check := func(label string, e error, warning bool, advice string) {
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
	check("节点数据库与 UUID/key/short ID", loadErr, false, "保留现场和历史代；数据库损坏时先找回有效 state.json，不要直接重新生成密钥")
	check("sing-box "+s.CoreVersion+" 及摘要", node.VerifyCore(a.store.Root, s.CoreVersion), false, "运行 qingnode core install；GitHub 不通时使用 --archive 官方归档")
	config := filepath.Join(a.store.Root, "current", "server.json")
	_, e := os.Stat(config)
	check("配置文件存在", e, false, "完成安装或从备份恢复")
	if e == nil && !a.offline {
		check("sing-box check 和端口预检", a.store.Backend.Check(s, config), false, "运行 qingnode ports；更换冲突端口或修复证书后重试")
	}
	check("启用节点证书有效期", node.ValidateCertificateDates(s), false, "使用 edit --cert/--key 导入续期证书，或先 disable 对应节点")
	if _, e := os.Stat(filepath.Join(a.store.Root, "transaction.json")); e == nil {
		check("未完成的配置事务", errors.New("发现中断记录"), true, "运行 qingnode recover；诊断不会自动重启或回退")
	}
	if !a.offline {
		be := node.SystemBackend{Root: a.store.Root}
		var activeErr error
		if !be.Active() {
			activeErr = errors.New("当前未运行")
		}
		check("systemd 运行状态", activeErr, true, "需要运行时执行 qingnode start；先查看 qingnode logs")
		sockets := be.Sockets()
		for _, n := range s.Nodes {
			if n.Enabled {
				one := node.NewState()
				one.Nodes = []node.Node{n}
				var err error
				if !node.SocketsReady(one, sockets) {
					err = errors.New("未发现该服务进程的预期监听")
				}
				check(n.Name+" "+node.PortLabel(n), err, false, "先检查服务日志及端口冲突，再核对本机防火墙与云安全组")
			}
		}
		b, e := node.Run(5*time.Second, "timedatectl", "show", "--property=NTPSynchronized", "--value")
		if e == nil && strings.TrimSpace(string(b)) != "yes" {
			e = errors.New("系统未报告时间已同步")
		}
		check("系统时间同步", e, true, "检查 timedatectl status 或已安装的 chrony；证书及协议认证依赖正确时间")
		found := false
		for _, tool := range []string{"ufw", "firewall-cmd", "nft", "iptables"} {
			if _, e := exec.LookPath(tool); e == nil {
				fmt.Fprintln(os.Stderr, "[INFO] 已检测到防火墙工具："+tool)
				found = true
			}
		}
		if !found {
			check("本机防火墙识别", errors.New("未检测到支持的工具"), true, "手动检查云安全组；工具不存在不代表端口已经开放")
		}
	}
	var v4, v6 string
	var e4, e6 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); v4, e4 = node.PublicIP("4") }()
	go func() { defer wg.Done(); v6, e6 = node.PublicIP("6") }()
	wg.Wait()
	check("公网 IPv4 "+v4, e4, true, "IPv6-only VPS 可使用 IPv6；否则检查 DNS、默认路由和 HTTPS 出站")
	check("公网 IPv6 "+v6, e6, true, "纯 IPv4 VPS 可忽略；仅在使用 IPv6/AAAA 时处理")
	_, e = node.Lookup("github.com")
	check("GitHub DNS", e, false, "检查 /etc/resolv.conf 和 DNS 服务；不会自动覆盖系统 DNS")
	for _, n := range s.Nodes {
		if !n.Enabled {
			continue
		}
		if net.ParseIP(n.Host) == nil {
			_, e := node.Lookup(n.Host)
			check(n.Name+" 连接域名解析", e, false, "检查域名的 A/AAAA 记录")
		}
		if n.Reality != nil {
			check(n.Name+" REALITY TLS1.3/HTTP2", node.CheckReality(n.Reality), false, "检查 SNI 与握手目标；用 edit 修改目标，现有密钥会保留")
		}
	}
	if errorsFound > 0 || a.debug {
		a.recentLogs(s)
	}
	fmt.Fprintf(os.Stderr, "诊断结果：%d 项错误，%d 项警告。公网客户端握手与 UDP 传输需另行实测。\n", errorsFound, warnings)
	if errorsFound > 0 {
		return fmt.Errorf("发现 %d 项错误，请按上方建议处理", errorsFound)
	}
	return nil
}
