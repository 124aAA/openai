package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
	"qingnode/internal/node"
	"qingnode/internal/ui"
)

func (a *app) menuChoice(key string) (string, error) {
	fmt.Fprintln(os.Stderr, "\n"+ui.Text(key))
	return a.prompt(ui.Text("exit_choice"), "")
}
func (a *app) executeMenu(args ...string) {
	if e := a.command(args); e != nil {
		a.message("ERROR", node.Redact(e.Error()))
	}
}
func (a *app) confirm(key string) bool {
	s, e := a.prompt(ui.Text(key), "")
	return e == nil && s == "yes"
}
func (a *app) menu() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("菜单需要交互终端；自动化请使用 CLI 命令，例如 qingnode status")
	}
	var empty bool
	if e := a.store.Inspect(func() error { s, e := a.store.Load(); empty = len(s.Nodes) == 0; return e }); e != nil {
		a.message("ERROR", node.Redact(e.Error()))
	} else if empty {
		a.message("INFO", "尚无节点，进入首次安装向导")
		if e := a.installWizard(true); e != nil {
			a.message("WARN", e.Error())
		}
	}
	for {
		choice, e := a.menuChoice("main")
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return e
		}
		switch choice {
		case "0":
			return nil
		case "1":
			e = a.nodeMenu()
		case "2":
			e = a.exportWizard()
		case "3":
			e = a.serviceMenu()
		case "4":
			e = a.maintenanceMenu()
		case "5":
			e = a.systemMenu()
		default:
			a.message("WARN", "请选择菜单中的数字")
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			a.message("ERROR", node.Redact(e.Error()))
		}
	}
}
func (a *app) selectNode() (node.Node, error) {
	var nodes []node.Node
	if e := a.store.Inspect(func() error { s, e := a.store.Load(); nodes = s.Nodes; return e }); e != nil {
		return node.Node{}, e
	}
	if len(nodes) == 0 {
		return node.Node{}, errors.New("尚无节点，请先添加")
	}
	for i, n := range nodes {
		fmt.Fprintf(os.Stderr, "%d. %s  %s  %s  启用=%t\n", i+1, n.Name, n.Protocol, node.PortLabel(n), n.Enabled)
	}
	answer, e := a.prompt("节点序号，0 返回", "")
	if e != nil {
		return node.Node{}, e
	}
	if answer == "0" {
		return node.Node{}, errors.New("已取消")
	}
	i, e := strconv.Atoi(answer)
	if e != nil || i < 1 || i > len(nodes) {
		return node.Node{}, errors.New("节点序号无效")
	}
	return nodes[i-1], nil
}
func (a *app) selectUser(n node.Node) (string, error) {
	if len(n.Users) == 1 {
		return n.Users[0].ID, nil
	}
	for i, u := range n.Users {
		fmt.Fprintf(os.Stderr, "%d. %s\n", i+1, u.Name)
	}
	value, e := a.prompt("凭据序号", "")
	if e != nil {
		return "", e
	}
	i, e := strconv.Atoi(value)
	if e != nil || i < 1 || i > len(n.Users) {
		return "", errors.New("凭据序号无效")
	}
	return n.Users[i-1].ID, nil
}
func (a *app) installWizard(first bool) error {
	protocol, e := a.prompt("协议 "+strings.Join(node.Protocols(), " / "), "reality")
	if e != nil {
		return e
	}
	name, e := a.prompt("节点名称", "main")
	if e != nil {
		return e
	}
	detected := ""
	if !a.offline {
		a.message("INFO", "查询公网 IPv4，失败时尝试 IPv6…")
		detected, _ = node.PublicIP("4")
		if detected == "" {
			detected, _ = node.PublicIP("6")
		}
	}
	host, e := a.prompt("客户端连接的公网 IP 或域名", detected)
	if e != nil {
		return e
	}
	port, e := a.prompt("端口（r 随机）", "443")
	if e != nil {
		return e
	}
	cmd := "add"
	if first {
		cmd = "init"
	}
	args := []string{cmd, "--name", name, "--protocol", protocol, "--server", host}
	if port == "r" {
		args = append(args, "--random-port")
	} else {
		args = append(args, "--port", port)
	}
	if protocol != "ss2022" {
		sni, e := a.prompt("REALITY 目标域名 / 证书域名", "")
		if e != nil {
			return e
		}
		args = append(args, "--sni", sni)
	}
	if protocol == "hysteria2" {
		mode, e := a.prompt("证书方式：acme 自动签发 / pem 导入", "acme")
		if e != nil {
			return e
		}
		if mode == "acme" {
			email, e := a.prompt("ACME 邮箱（域名指向本机，TCP 80 可达）", "")
			if e != nil {
				return e
			}
			args = append(args, "--acme-email", email)
		} else if mode == "pem" {
			cert, e := a.prompt("完整证书链 PEM 路径", "")
			if e != nil {
				return e
			}
			key, e := a.prompt("私钥 PEM 路径", "")
			if e != nil {
				return e
			}
			args = append(args, "--cert", cert, "--key", key)
		} else {
			return errors.New("证书方式无效")
		}
	}
	if !a.offline {
		if e := a.core([]string{"install"}); e != nil {
			return e
		}
	}
	return a.command(args)
}
func (a *app) nodeMenu() error {
	for {
		choice, e := a.menuChoice("nodes")
		if e != nil {
			return e
		}
		if choice == "0" {
			return nil
		}
		if choice == "1" {
			a.executeMenu("info")
			continue
		}
		if choice == "2" {
			if e = a.installWizard(false); e != nil {
				a.message("ERROR", e.Error())
			}
			continue
		}
		n, e := a.selectNode()
		if e != nil {
			a.message("WARN", e.Error())
			continue
		}
		args := []string{}
		switch choice {
		case "3":
			name, e := a.prompt("新名称", n.Name)
			if e != nil {
				return e
			}
			host, e := a.prompt("新公网 IP/域名", n.Host)
			if e != nil {
				return e
			}
			args = []string{"edit", "--id", n.ID, "--name", name, "--server", host}
		case "4":
			p, e := a.prompt("新端口（r 随机）", strconv.Itoa(n.Port))
			if e != nil {
				return e
			}
			args = []string{"edit", "--id", n.ID}
			if p == "r" {
				args = append(args, "--random-port")
			} else {
				args = append(args, "--port", p)
			}
		case "5":
			args = []string{"enable", "--id", n.ID}
		case "6":
			args = []string{"disable", "--id", n.ID}
		case "7":
			if !a.confirm("delete_warning") {
				continue
			}
			args = []string{"delete", "--id", n.ID, "--yes"}
		case "8":
			if e = a.userMenu(n); e != nil {
				a.message("ERROR", e.Error())
			}
			continue
		case "9":
			if e = a.realityMenu(n); e != nil {
				a.message("ERROR", e.Error())
			}
			continue
		default:
			a.message("WARN", "请选择菜单中的数字")
			continue
		}
		a.executeMenu(args...)
	}
}
func (a *app) userMenu(n node.Node) error {
	choice, e := a.menuChoice("users")
	if e != nil {
		return e
	}
	if choice == "0" {
		return nil
	}
	if choice == "1" {
		name, e := a.prompt("设备凭据名称", "")
		if e != nil {
			return e
		}
		return a.command([]string{"user-add", "--id", n.ID, "--name", name})
	}
	if choice == "4" {
		if n.Shadowsocks == nil {
			return errors.New("仅用于 SS2022")
		}
		if !a.confirm("rotate_warning") {
			return nil
		}
		return a.command([]string{"rotate", "--id", n.ID, "--server-key", "--yes"})
	}
	if choice != "2" && choice != "3" {
		return errors.New("无效选择")
	}
	user, e := a.selectUser(n)
	if e != nil {
		return e
	}
	key := "delete_warning"
	cmd := "user-delete"
	if choice == "3" {
		key = "rotate_warning"
		cmd = "rotate"
	}
	if !a.confirm(key) {
		return nil
	}
	return a.command([]string{cmd, "--id", n.ID, "--user", user, "--yes"})
}
func (a *app) realityMenu(n node.Node) error {
	choice, e := a.menuChoice("reality")
	if e != nil {
		return e
	}
	if choice == "0" {
		return nil
	}
	if choice == "1" {
		return a.info([]string{"--id", n.ID, "--show-secrets"})
	}
	if choice == "7" {
		if n.Certificate == nil {
			return errors.New("当前协议不使用 PEM 证书")
		}
		cert, e := a.prompt("新证书链路径", "")
		if e != nil {
			return e
		}
		key, e := a.prompt("新私钥路径", "")
		if e != nil {
			return e
		}
		return a.command([]string{"edit", "--id", n.ID, "--cert", cert, "--key", key})
	}
	if n.Reality == nil {
		return errors.New("当前节点不是 REALITY")
	}
	switch choice {
	case "2":
		return a.info([]string{"--id", n.ID, "--show-private"})
	case "3":
		sni, e := a.prompt("SNI", n.Reality.ServerName)
		if e != nil {
			return e
		}
		target, e := a.prompt("握手目标 主机:端口（可与 SNI 不同）", n.Reality.Target)
		if e != nil {
			return e
		}
		return a.command([]string{"edit", "--id", n.ID, "--sni", sni, "--target", target})
	case "4":
		fp, e := a.prompt("chrome/firefox/safari/ios/edge", node.Fingerprint(n.Reality))
		if e != nil {
			return e
		}
		return a.command([]string{"edit", "--id", n.ID, "--fingerprint", fp})
	case "5", "6":
		if !a.confirm("rotate_warning") {
			return nil
		}
		flag := "--keys"
		if choice == "6" {
			flag = "--short-id"
		}
		return a.command([]string{"rotate", "--id", n.ID, flag, "--yes"})
	}
	return errors.New("无效选择")
}
func (a *app) exportWizard() error {
	n, e := a.selectNode()
	if e != nil {
		return e
	}
	u, e := a.selectUser(n)
	if e != nil {
		return e
	}
	f, e := a.prompt("uri 链接 / qr 二维码 / mihomo / provider / sing-box / base64", "uri")
	if e != nil {
		return e
	}
	out, e := a.prompt("保存路径（留空显示终端；拒绝覆盖已有文件）", "")
	if e != nil {
		return e
	}
	return a.command([]string{"export", "--id", n.ID, "--user", u, "--format", f, "--out", out})
}
func (a *app) serviceMenu() error {
	for {
		choice, e := a.menuChoice("service")
		if e != nil {
			return e
		}
		if choice == "0" {
			return nil
		}
		commands := map[string][]string{"1": {"status"}, "2": {"start"}, "3": {"stop"}, "4": {"restart"}, "5": {"service", "enable"}, "6": {"service", "disable"}, "7": {"logs"}}
		if args, ok := commands[choice]; ok {
			a.executeMenu(args...)
		} else {
			a.message("WARN", "无效选择")
		}
	}
}
func (a *app) maintenanceMenu() error {
	for {
		choice, e := a.menuChoice("maintenance")
		if e != nil {
			return e
		}
		if choice == "0" {
			return nil
		}
		switch choice {
		case "1":
			file, e := a.prompt("备份路径（留空按时间命名）", "")
			if e != nil {
				return e
			}
			a.executeMenu("backup", "--file", file)
		case "2":
			file, e := a.prompt("备份路径（.qnbak 加密 / .json 卸载快照）", "")
			if e != nil {
				return e
			}
			if a.confirm("restore_warning") {
				args := []string{"restore", "--file", file, "--yes"}
				if strings.HasSuffix(file, ".json") {
					args = append(args, "--snapshot")
				}
				a.executeMenu(args...)
			}
		case "3":
			if e = a.coreVersions(); e != nil {
				a.message("ERROR", e.Error())
				continue
			}
			v, e := a.prompt("目标版本（输入数字版本；留空返回）", "")
			if e != nil {
				return e
			}
			if v == "" {
				continue
			}
			sum, e := a.prompt("官方归档 SHA-256（默认锁定版本可留空）", "")
			if e != nil {
				return e
			}
			a.executeMenu("core", "update", "--version", strings.TrimPrefix(v, "v"), "--sha256", sum)
		case "4":
			bundle, e := a.prompt("新版已解压发行包目录", "")
			if e != nil {
				return e
			}
			a.executeMenu("self-update", "--bundle", bundle)
			return nil
		case "5":
			if a.confirm("回退将恢复上一代节点/核心，相关链接可能变化。输入 yes 继续") {
				a.executeMenu("rollback")
			}
		case "6":
			a.executeMenu("recover")
		case "7":
			mode, e := a.menuChoice("uninstall")
			if e != nil {
				return e
			}
			if mode == "0" {
				continue
			}
			if mode != "1" && mode != "2" {
				continue
			}
			if !a.confirm("确认停止服务并卸载选定内容？输入 yes 继续") {
				continue
			}
			args := []string{"uninstall", "--yes"}
			if mode == "2" {
				args = append(args, "--purge")
			}
			if e = a.command(args); e != nil {
				a.message("ERROR", e.Error())
			} else {
				return io.EOF
			}
		default:
			a.message("WARN", "无效选择")
		}
	}
}
func (a *app) systemMenu() error {
	for {
		choice, e := a.menuChoice("system")
		if e != nil {
			return e
		}
		if choice == "0" {
			return nil
		}
		switch choice {
		case "1":
			a.executeMenu("diagnose")
		case "2":
			a.executeMenu("ports")
		case "5":
			a.executeMenu("logs")
		case "3":
			c, e := a.menuChoice("firewall")
			if e != nil {
				return e
			}
			cmd := map[string]string{"1": "status", "2": "enable", "3": "disable", "4": "sync"}[c]
			if cmd != "" {
				a.executeMenu("firewall", cmd)
			}
		case "4":
			c, e := a.menuChoice("network")
			if e != nil {
				return e
			}
			cmd := map[string]string{"1": "status", "2": "bbr"}[c]
			if cmd != "" {
				a.executeMenu("network", cmd)
			}
		default:
			a.message("WARN", "无效选择")
		}
	}
}
