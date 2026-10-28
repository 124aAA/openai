package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
	"qingnode/internal/node"
	"qingnode/internal/ui"
)

var errMenuCanceled = errors.New("已取消")

func (a *app) wizardPrompt(q, def string) (string, error) {
	value, e := a.prompt(q, def)
	if e == nil && value == ":cancel" {
		return "", errMenuCanceled
	}
	if e == nil && (!utf8.ValidString(value) || len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0) {
		return "", errors.New("输入包含控制字符、无效文字或超过4096字节；尚未提交本次表单")
	}
	return value, e
}

func (a *app) menuChoice(key string) (string, error) {
	fmt.Fprintln(ui.HumanWriter(os.Stderr), "\n"+ui.Text(key))
	return a.wizardPrompt(ui.Text("exit_choice"), "")
}
func (a *app) executeMenu(args ...string) {
	if e := a.menuCommand(args); e != nil {
		a.message("ERROR", node.Redact(e.Error()))
	}
}
func (a *app) confirm(key string) bool {
	s, e := a.wizardPrompt(ui.Text(key), "")
	return e == nil && s == "yes"
}
func (a *app) menu() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("菜单需要交互终端；自动化请使用 CLI 命令，例如 qingnode status")
	}
	for {
		if e := a.overview(os.Stderr); e != nil {
			a.message("WARN", e.Error())
		}
		choice, e := a.menuChoice("main")
		if errors.Is(e, io.EOF) || errors.Is(e, errMenuCanceled) {
			return nil
		}
		if e != nil {
			return e
		}
		switch choice {
		case "0":
			return nil
		case "1":
			e = a.quickMenu()
		case "2":
			e = a.nodeMenu()
		case "3":
			e = a.exportTaskMenu()
		case "4":
			e = a.diagnosticTaskMenu()
		case "5":
			e = a.certificateTaskMenu()
		case "6":
			e = a.advancedTaskMenu()
		case "7":
			e = a.maintenanceTaskMenu()
		case "8":
			continue
		case "9":
			e = a.checkUpdates()
		default:
			a.message("WARN", "请选择菜单中的数字")
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
		if errors.Is(e, errMenuCanceled) {
			continue
		}
		if e != nil {
			a.message("ERROR", node.Redact(e.Error()))
		}
	}
}
func (a *app) selectNode() (node.Node, error) {
	var nodes []node.Node
	if e := a.inspectState(func(s *node.State) error { nodes = s.Nodes; return s.Validate() }); e != nil {
		return node.Node{}, e
	}
	if len(nodes) == 0 {
		return node.Node{}, errors.New("尚无节点，请先添加")
	}
	for i, n := range nodes {
		status := "停用"
		if n.Enabled {
			status = "启用"
		}
		fmt.Fprintf(ui.HumanWriter(os.Stderr), "%d. %s [%s / %s]\n   ID: %s  %s\n", i+1, n.Name, n.Protocol, status, n.ID, node.PortLabel(n))
	}
	for {
		answer, e := a.wizardPrompt("节点序号，0 返回", "")
		if e != nil {
			return node.Node{}, e
		}
		if answer == "0" {
			return node.Node{}, errMenuCanceled
		}
		i, e := strconv.Atoi(answer)
		if e == nil && i >= 1 && i <= len(nodes) {
			return nodes[i-1], nil
		}
		a.message("WARN", "请输入列表中的节点序号，或输入 0 返回")
	}
}
func (a *app) selectUser(n node.Node) (string, error) {
	if len(n.Users) == 1 {
		return n.Users[0].ID, nil
	}
	for i, u := range n.Users {
		fmt.Fprintf(ui.HumanWriter(os.Stderr), "%d. %s\n", i+1, u.Name)
	}
	for {
		value, e := a.wizardPrompt("凭据序号，0 返回", "")
		if e != nil {
			return "", e
		}
		if value == "0" {
			return "", errMenuCanceled
		}
		i, e := strconv.Atoi(value)
		if e == nil && i >= 1 && i <= len(n.Users) {
			return n.Users[i-1].ID, nil
		}
		a.message("WARN", "请输入列表中的凭据序号，或输入 0 返回")
	}
}

type protocolMenuCore struct {
	version   string
	offline   bool
	installed bool
	verified  bool
	tags      []string
	checkErr  error
}

// A version string in State cannot attest to a custom binary's build tags.
// The menu only reads the installed artifact; Apply performs its own check.
func (a *app) inspectProtocolMenuCore() (protocolMenuCore, error) {
	status := protocolMenuCore{offline: a.offline}
	if err := a.inspectState(func(st *node.State) error {
		if err := st.Validate(); err != nil {
			return err
		}
		status.version = st.CoreVersion
		path := node.CorePath(a.store.Root, status.version)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			status.checkErr = err
			return nil
		}
		status.installed = true
		if err := node.VerifyCore(a.store.Root, status.version); err != nil {
			status.checkErr = err
			return nil
		}
		output, err := node.Run(10*time.Second, path, "version")
		if err != nil {
			status.checkErr = fmt.Errorf("无法读取已安装核心构建标签：%w", err)
			return nil
		}
		if !strings.Contains(string(output), "sing-box version "+status.version+"\n") {
			status.checkErr = errors.New("再次读取核心时版本与 State 不一致")
			return nil
		}
		status.tags = node.CoreBuildTags(string(output))
		status.verified = true
		return nil
	}); err != nil {
		return status, err
	}
	return status, nil
}

func (status protocolMenuCore) unavailableReason(protocol string) string {
	if status.offline || !status.installed && status.checkErr == nil {
		return ""
	}
	if status.checkErr != nil {
		return "已安装核心未通过校验：" + status.checkErr.Error()
	}
	if !status.verified {
		return "已安装核心的摘要、版本和构建标签尚未核实"
	}
	capability, ok := node.ProtocolCapabilities(protocol)
	if !ok {
		return "不支持该协议"
	}
	if node.CompareVersion(status.version, capability.MinimumManagedCore) < 0 {
		return "核心版本低于" + capability.MinimumManagedCore
	}
	if err := node.ValidateProtocolCapabilities(node.State{Nodes: []node.Node{{Protocol: protocol}}}, status.tags); err != nil {
		return err.Error()
	}
	return ""
}

func (status protocolMenuCore) label(protocol string) string {
	if status.offline {
		return "离线配置可生成；运行能力未验证"
	}
	if reason := status.unavailableReason(protocol); reason != "" {
		return "当前不可用：" + reason + "；先运行 qingnode core install/check"
	}
	if !status.installed {
		return "核心尚未安装；向导完成参数后安装并校验"
	}
	return "已校验当前核心 " + status.version + " 及所需构建标签"
}

var protocolMenuChoices = []struct{ number, protocol, description string }{
	{"1", "reality", "VLESS REALITY / Vision（无需自己的域名）"},
	{"2", "ss2022", "Shadowsocks 2022（客户端需支持 SS2022）"},
	{"3", "hysteria2", "Hysteria2（UDP，需要域名及证书）"},
	{"4", "anytls", "AnyTLS（TCP监听，需要证书；UDP业务封装）"},
	{"5", "trojan", "Trojan（标准TLS，需要证书）"},
	{"6", "ss-aead", "传统 SS AEAD（默认AES-256-GCM，不使用2022组合密钥）"},
	{"7", "tuic", "TUIC v5（UDP/QUIC，需要证书；0-RTT关闭）"},
}

func protocolMenuClientLabel(protocol string) string {
	switch protocol {
	case "anytls":
		return "客户端完整配置已核对：sing-box 1.14.0/1.14.3、Mihomo 1.19.30；连接池设置不能用URI表达"
	case "trojan", "ss-aead":
		return "客户端完整配置已核对：sing-box 1.14.0/1.14.3、Mihomo 1.19.30"
	case "tuic":
		return "客户端完整配置已核对：sing-box 1.14.0/1.14.3、Mihomo 1.19.30；分享URI未核验"
	default:
		return "客户端导出仍须按目标格式实际验证"
	}
}

func (a *app) selectProtocol() (string, error) {
	selected, err := a.selectProtocolOptions()
	return selected.Protocol, err
}
func (a *app) selectProtocolOptions() (protocolSelection, error) {
	status, err := a.inspectProtocolMenuCore()
	if err != nil {
		return protocolSelection{}, err
	}
	fmt.Fprintln(os.Stderr, "\n请选择要搭建的节点")
	for _, choice := range protocolMenuChoices {
		fmt.Fprintf(os.Stderr, "%s. %s\n   %s；%s\n", choice.number, choice.description, status.label(choice.protocol), protocolMenuClientLabel(choice.protocol))
	}
	fmt.Fprintln(os.Stderr, "h. 根据客户端、证书、UDP和NAT条件帮我选\n0. 返回，不创建")
	for {
		choice, e := a.wizardPrompt("选择1至7、h帮我选，或0", "")
		if e != nil {
			return protocolSelection{}, e
		}
		if choice == "0" {
			return protocolSelection{}, nil
		}
		if choice == "h" {
			return a.guidedProtocol()
		}
		recognized := false
		for _, candidate := range protocolMenuChoices {
			if choice == candidate.number || choice == candidate.protocol {
				recognized = true
				if reason := status.unavailableReason(candidate.protocol); reason != "" {
					a.message("WARN", reason+"；先运行 qingnode core install/check")
					break
				}
				return protocolSelection{Protocol: candidate.protocol}, nil
			}
		}
		if !recognized {
			a.message("WARN", "请输入 1 至 7、协议名称或 0；尚未创建节点")
		}
	}
}
func (a *app) installWizard(first bool, protocol string, quiet bool) error {
	return a.installWizardOptions(first, protocol, quiet, false)
}
func (a *app) installWizardOptions(first bool, protocol string, quiet, nat bool) error {
	if protocol == "" {
		selection, e := a.selectProtocolOptions()
		protocol, nat = selection.Protocol, nat || selection.NAT
		if e != nil || protocol == "" {
			return e
		}
	}
	if _, ok := node.Protocol(protocol); !ok {
		return errors.New("不支持该协议；可用 reality、ss2022、hysteria2、anytls、trojan、ss-aead、tuic")
	}
	if a.wizardCollect == nil {
		status, e := a.inspectProtocolMenuCore()
		if e != nil {
			return e
		}
		if reason := status.unavailableReason(protocol); reason != "" {
			return fmt.Errorf("%s；先运行 qingnode core install/check", reason)
		}
	}
	fmt.Fprintln(os.Stderr, "安装输入中可随时输入 :cancel 返回；填写完这些参数后才创建节点。")
	defaultName := "main"
	if a.wizardCollect == nil {
		if e := a.store.Inspect(func() error {
			s, e := a.store.Load()
			if e != nil {
				return e
			}
			for i := 2; ; i++ {
				if _, e := s.Find(defaultName); e != nil {
					return nil
				}
				defaultName = fmt.Sprintf("main-%d", i)
			}
		}); e != nil {
			return e
		}
	}
	name, e := a.wizardPrompt("节点名称", defaultName)
	if e != nil {
		return e
	}
	detected := ""
	if !a.offline && !nat && a.wizardCollect == nil {
		a.message("INFO", "查询公网 IPv4，失败时尝试 IPv6…")
		detected, _ = node.PublicIP("4")
		if detected == "" {
			detected, _ = node.PublicIP("6")
		}
	}
	host, e := a.wizardPrompt("客户端连接的公网 IP 或域名", detected)
	if e != nil {
		return e
	}
	host, e = node.NormalizeEndpointHost(host)
	if e != nil {
		return e
	}
	listen, connectPort := "", ""
	if nat {
		fmt.Fprintln(os.Stderr, "NAT声明不会修改云厂商映射；出口IP不证明入站可达。TCP/UDP须分别设置，TLS名称独立。")
		listen, e = a.wizardPrompt("本地监听IP（::是否兼容IPv4需实际绑定验证；不保证双栈）", "0.0.0.0")
		if e != nil {
			return e
		}
		if net.ParseIP(listen) == nil {
			return errors.New("本地监听须为IP字面量")
		}
	}
	defaultPort := "443"
	if !a.offline && !nat {
		defaultPort = "auto"
	}
	portLabel := "端口（auto 优先443并避开冲突 / r 随机 / 指定数字）"
	if nat {
		portLabel = "本地监听端口（1–65535数字）"
	}
	port, e := a.wizardPrompt(portLabel, defaultPort)
	if e != nil {
		return e
	}
	if nat {
		if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
			return errors.New("NAT向导本地端口须为1–65535数字")
		}
		connectPort, e = a.wizardPrompt("客户端连接的外部映射端口", port)
		if e != nil {
			return e
		}
		if value, err := strconv.Atoi(connectPort); err != nil || value < 1 || value > 65535 {
			return errors.New("外部连接端口须为1–65535数字")
		}
	}
	cmd := "add"
	if first {
		cmd = "init"
	}
	args := []string{cmd, "--name", name, "--protocol", protocol, "--server", host}
	if nat {
		args = append(args, "--listen", listen, "--connect-port", connectPort)
	}
	if quiet {
		args = append(args, "--quiet")
	}
	if !a.offline {
		args = append(args, "--auto")
	}
	if port == "r" {
		args = append(args, "--random-port")
	} else if port != "auto" || a.offline {
		args = append(args, "--port", port)
	}
	if protocol != "ss2022" && protocol != "ss-aead" {
		label, def := "TLS证书名称（独立于连接地址；复用已有证书资源可留空）", ""
		if protocol == "reality" {
			label = "REALITY 伪装目标域名"
			if !a.offline {
				label, def = label+"（auto 自动筛选并测速）", "auto"
			}
		}
		sni, e := a.wizardPrompt(label, def)
		if e != nil {
			return e
		}
		if protocol != "reality" || sni != "auto" || a.offline {
			args = append(args, "--sni", sni)
		}
	}
	if node.ProtocolRequiresCertificate(protocol) {
		mode, e := a.wizardPrompt("证书方式：acme HTTP01 / pem 导入 / resource 已有证书资源", "acme")
		if e != nil {
			return e
		}
		if mode == "acme" {
			email, e := a.wizardPrompt("ACME 邮箱（域名指向本机，TCP 80 可达）", "")
			if e != nil {
				return e
			}
			args = append(args, "--acme-email", email)
		} else if mode == "pem" {
			cert, e := a.wizardPrompt("完整证书链 PEM 路径", "")
			if e != nil {
				return e
			}
			key, e := a.wizardPrompt("私钥 PEM 路径", "")
			if e != nil {
				return e
			}
			args = append(args, "--cert", cert, "--key", key)
		} else if mode == "resource" {
			id, e := a.menuRequired("已有证书资源稳定ID（DNS01先从私有文件导入资源）")
			if e != nil {
				return e
			}
			// This wizard's last pair is the independent TLS name. A resource
			// owns that name, so never pass a conflicting --sni to add.
			args = append(args[:len(args)-2], "--certificate-id", id)
		} else {
			return errors.New("证书方式无效")
		}
	}
	if a.wizardCollect != nil {
		return a.wizardCollect(args[1:])
	}
	return a.menuCommand(args)
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
			if e = a.installWizard(false, "", false); e != nil {
				if errors.Is(e, io.EOF) {
					return e
				}
				if !errors.Is(e, errMenuCanceled) {
					a.message("ERROR", e.Error())
				}
			}
			continue
		}
		if choice < "3" || choice > "9" || len(choice) != 1 {
			a.message("WARN", "请选择菜单中的数字")
			continue
		}
		n, e := a.selectNode()
		if e != nil {
			if errors.Is(e, io.EOF) {
				return e
			}
			if !errors.Is(e, errMenuCanceled) {
				a.message("WARN", e.Error())
			}
			continue
		}
		args := []string{}
		switch choice {
		case "3":
			a.message("INFO", "修改连接地址后需重新导出并导入客户端；仅改名称只影响标签。现有凭据会保留。")
			name, e := a.wizardPrompt("新名称", n.Name)
			if e != nil {
				return e
			}
			host, e := a.wizardPrompt("新公网 IP/域名", n.Host)
			if e != nil {
				return e
			}
			args = []string{"edit", "--id", n.ID, "--name", name, "--server", host}
		case "4":
			a.message("INFO", "修改本地监听端口；客户端连接端口独立保留。请同步检查NAT映射；现有凭据会保留。")
			p, e := a.wizardPrompt("新端口（r 随机）", strconv.Itoa(n.Port))
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
				if errors.Is(e, io.EOF) {
					return e
				}
				if !errors.Is(e, errMenuCanceled) {
					a.message("ERROR", e.Error())
				}
			}
			continue
		case "9":
			if e = a.realityMenu(n); e != nil {
				if errors.Is(e, io.EOF) {
					return e
				}
				if !errors.Is(e, errMenuCanceled) {
					a.message("ERROR", e.Error())
				}
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
	menu := "users-basic"
	if n.Protocol == "ss2022" {
		menu = "users"
	}
	choice, e := a.menuChoice(menu)
	if e != nil {
		return e
	}
	if choice == "0" {
		return nil
	}
	if choice == "1" {
		name, e := a.wizardPrompt("设备凭据名称", "")
		if e != nil {
			return e
		}
		return a.menuCommand([]string{"user-add", "--id", n.ID, "--name", name})
	}
	if choice == "4" {
		if n.Protocol != "ss2022" {
			return errors.New("仅用于 SS2022")
		}
		if !a.confirm("rotate_warning") {
			return nil
		}
		return a.menuCommand([]string{"rotate", "--id", n.ID, "--server-key", "--yes"})
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
	return a.menuCommand([]string{cmd, "--id", n.ID, "--user", user, "--yes"})
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
		return a.info([]string{"--id", n.ID})
	}
	if choice == "7" {
		if n.Certificate == nil {
			return errors.New("当前协议不使用 PEM 证书")
		}
		cert, e := a.wizardPrompt("新证书链路径", "")
		if e != nil {
			return e
		}
		key, e := a.wizardPrompt("新私钥路径", "")
		if e != nil {
			return e
		}
		return a.menuCommand([]string{"edit", "--id", n.ID, "--cert", cert, "--key", key})
	}
	if n.Reality == nil {
		return errors.New("当前节点不是 REALITY")
	}
	switch choice {
	case "2":
		return a.info([]string{"--id", n.ID, "--show-private"})
	case "3":
		a.message("INFO", "修改 SNI 后所有设备需重新导入；密钥、UUID 和 short ID 会保留。")
		sni, e := a.wizardPrompt("SNI", n.Reality.ServerName)
		if e != nil {
			return e
		}
		target, e := a.wizardPrompt("握手目标 主机:端口（可与 SNI 不同）", n.Reality.Target)
		if e != nil {
			return e
		}
		return a.menuCommand([]string{"edit", "--id", n.ID, "--sni", sni, "--target", target})
	case "4":
		a.message("INFO", "修改客户端指纹后请重新导入客户端配置；服务端凭据会保留。")
		fp, e := a.wizardPrompt("chrome/firefox/safari/ios/edge", node.Fingerprint(n.Reality))
		if e != nil {
			return e
		}
		return a.menuCommand([]string{"edit", "--id", n.ID, "--fingerprint", fp})
	case "5", "6":
		if !a.confirm("rotate_warning") {
			return nil
		}
		flag := "--keys"
		if choice == "6" {
			flag = "--short-id"
		}
		return a.menuCommand([]string{"rotate", "--id", n.ID, flag, "--yes"})
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
	uriWarning := node.ProtocolExportWarnings(n, "uri")
	if len(uriWarning) > 0 {
		fmt.Fprintln(os.Stderr, "分享链接/二维码/Base64 当前节点不可用："+strings.Join(uriWarning, "；"))
	}
	fmt.Fprintln(os.Stderr, "1 分享链接（手机客户端优先）\n2 终端二维码（终端需支持方块字符）\n3 Mihomo 完整配置\n4 sing-box 完整配置\n5 Mihomo provider（供已有配置引用）\n6 Base64 链接文本（不是在线订阅）\n0 返回；也可输入原格式名称")
	formats := map[string]string{"1": "uri", "2": "qr", "3": "mihomo", "4": "sing-box", "5": "provider", "6": "base64"}
	var f string
	for {
		value, err := a.wizardPrompt("导出方式", "1")
		if err != nil {
			return err
		}
		if value == "0" {
			return errMenuCanceled
		}
		f = formats[value]
		if f == "" {
			for _, format := range formats {
				if value == format {
					f = format
				}
			}
		}
		if len(uriWarning) > 0 && (f == "uri" || f == "qr" || f == "base64") {
			a.message("WARN", strings.Join(uriWarning, "；"))
			f = ""
			continue
		}
		if f != "" {
			break
		}
		a.message("WARN", "请选择 1–6、格式名称或 0 返回")
	}
	out, e := a.wizardPrompt("保存路径（留空显示终端；拒绝覆盖已有文件）", "")
	if e != nil {
		return e
	}
	args := []string{"export", "--id", n.ID, "--user", u, "--format", f, "--out", out}
	if version := lockedExportClientVersion(n.Protocol, f); version != "" {
		fmt.Fprintf(os.Stderr, "目标客户端版本：%s（已核验固定版本）\n", version)
		args = append(args, "--client-version", version)
	}
	return a.menuCommand(args)
}

// New protocols have only been verified against these fixed client lines.
// Keep legacy exports unchanged; the normal validator still checks the choice.
func lockedExportClientVersion(protocol, format string) string {
	switch protocol {
	case "anytls", "trojan", "ss-aead", "tuic":
		switch format {
		case "sing-box":
			return "1.14.0"
		case "mihomo", "provider":
			return "1.19.30"
		}
	}
	return ""
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
			file, e := a.wizardPrompt("备份路径（留空按时间命名）", "")
			if e != nil {
				return e
			}
			a.executeMenu("backup", "--file", file)
		case "2":
			file, e := a.wizardPrompt("备份路径（.qnbak 加密 / .json 卸载快照）", "")
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
			v, e := a.wizardPrompt("目标版本（输入数字版本；留空返回）", "")
			if e != nil {
				return e
			}
			if v == "" {
				continue
			}
			sum, e := a.wizardPrompt("官方归档 SHA-256（默认锁定版本可留空）", "")
			if e != nil {
				return e
			}
			a.executeMenu("core", "update", "--version", strings.TrimPrefix(v, "v"), "--sha256", sum)
		case "4":
			bundle, e := a.wizardPrompt("新版已解压发行包目录", "")
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
			if e = a.menuCommand(args); e != nil {
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
		case "6":
			e = a.publicCheckWizard()
		case "3":
			c, e := a.menuChoice("firewall")
			if e != nil {
				return e
			}
			cmd := map[string]string{"1": "status", "2": "enable", "3": "disable", "4": "sync"}[c]
			if cmd != "" {
				if cmd != "status" {
					if e := a.menuCommand([]string{"firewall", "status"}); e != nil {
						return e
					}
					if !a.confirm("将修改本项目的宿主防火墙规则，不清空全局规则。输入yes继续") {
						continue
					}
				}
				a.executeMenu("firewall", cmd)
			}
		case "4":
			c, e := a.menuChoice("network")
			if e != nil {
				return e
			}
			cmd := map[string]string{"1": "status", "2": "bbr"}[c]
			if cmd != "" {
				if cmd == "bbr" {
					if e := a.menuCommand([]string{"network", "bbr", "--preview"}); e != nil {
						return e
					}
					if !a.confirm("将应用上面预览的TCP拥塞/队列设置并保存恢复快照；这不控制HY2的QUIC。输入yes继续") {
						continue
					}
				}
				a.executeMenu("network", cmd)
			}
		default:
			a.message("WARN", "无效选择")
		}
	}
}
