package main

import (
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"net"
	"os"
	"qingnode/internal/node"
	"strconv"
	"strings"
	"time"
)

func (a *app) add(cmd string, args []string) error {
	f := fs(cmd)
	name := f.String("name", "main", "节点名称")
	protocol := f.String("protocol", "reality", "reality / ss2022 / hysteria2")
	host := f.String("server", "", "客户端连接的公网 IP 或域名")
	listen := f.String("listen", "", "监听 IP，默认按公网地址选择通配地址")
	port := f.Int("port", 443, "监听端口")
	randomPort := f.Bool("random-port", false, "选择避开已有节点、监听和 SSH 的随机端口")
	fingerprint := f.String("fingerprint", "chrome", "REALITY 客户端指纹")
	sni := f.String("sni", "", "REALITY 目标域名 / Hysteria2 证书名称")
	target := f.String("target", "", "REALITY 目标主机:端口，默认 SNI:443")
	cert := f.String("cert", "", "PEM 完整证书链")
	key := f.String("key", "", "PEM 私钥")
	email := f.String("acme-email", "", "用 ACME HTTP-01 签发及续期证书")
	uname := f.String("user", "default", "首个凭据名称")
	quiet := f.Bool("quiet", false, "成功后不显示凭据，用于安装日志")
	if e := parse(f, args); e != nil {
		return e
	}
	created := ""
	err := a.mutate(func(s *node.State) error {
		if cmd == "init" && len(s.Nodes) > 0 {
			fmt.Fprintln(os.Stderr, "已经初始化，保留所有节点和凭据；新增节点请用 add。")
			return nil
		}
		var e error
		if *host == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("缺少 --server 公网 IP 或域名")
			}
			*host, e = a.prompt("公网 IP 或连接域名", "")
			if e != nil {
				return e
			}
		}
		if *sni == "" && *protocol != "ss2022" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("缺少 --sni")
			}
			*sni, e = a.prompt("目标 SNI 域名（需自行确认适用）", "")
			if e != nil {
				return e
			}
		}
		if *listen == "" {
			*listen = "0.0.0.0"
			if ip := net.ParseIP(*host); ip != nil && ip.To4() == nil {
				*listen = "::"
			}
		}
		n := node.Node{ID: node.Token(8), Name: *name, Protocol: *protocol, Host: *host, Listen: *listen, Port: *port, Enabled: true, Users: []node.User{node.NewUser(*uname, *protocol)}}
		if *protocol == "reality" {
			if *cert != "" || *key != "" || *email != "" {
				return errors.New("REALITY 不使用证书参数")
			}
			n.Reality, e = node.NewReality(*sni, *target)
			if e == nil {
				n.Reality.Fingerprint = *fingerprint
			}
		} else if *protocol == "hysteria2" {
			n.Certificate, e = loadCert(*sni, *cert, *key, *email)
		} else if *protocol == "ss2022" {
			if *sni != "" || *target != "" || *cert != "" || *key != "" || *email != "" || flagSet(f, "fingerprint") {
				return errors.New("SS2022 不使用 SNI、REALITY 或 TLS 参数")
			}
			n.Shadowsocks = node.NewShadowsocks()
		} else {
			return errors.New("不支持该协议")
		}
		if e != nil {
			return e
		}
		if *randomPort {
			if flagSet(f, "port") {
				return errors.New("--port 与 --random-port 不能同时使用")
			}
			n.Port, e = node.RandomPort(*s, n, node.SSHPorts())
			if e != nil {
				return e
			}
		}
		if !a.offline && node.AvailablePort(n) != nil {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("端口 %s 被占用；运行 qingnode ports 查看进程，或使用 --random-port", node.PortLabel(n))
			}
			n.Port, e = a.choosePort(*s, n)
			if e != nil {
				return e
			}
		}
		s.Nodes = append(s.Nodes, n)
		created = n.ID
		return nil
	})
	if err != nil {
		return err
	}
	if created != "" && !*quiet {
		return a.info([]string{"--id", created, "--show-secrets"})
	}
	return nil
}
func loadCert(sni, cert, key, email string) (*node.Certificate, error) {
	c := &node.Certificate{ServerName: sni}
	if email != "" {
		if cert != "" || key != "" {
			return nil, errors.New("ACME 与 PEM 证书参数不能同时使用")
		}
		c.Mode = "acme"
		c.Email = email
		return c, nil
	}
	if cert == "" || key == "" {
		return nil, errors.New("Hysteria2 需要 --cert 和 --key，或 --acme-email")
	}
	b, e := readLimited(cert, 2<<20)
	if e != nil {
		return nil, e
	}
	k, e := readLimited(key, 1<<20)
	if e != nil {
		return nil, e
	}
	c.Mode = "pem"
	c.CertPEM = string(b)
	c.KeyPEM = string(k)
	return c, nil
}
func readLimited(p string, max int64) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e == nil && int64(len(b)) > max {
		return nil, errors.New("输入文件过大")
	}
	return b, e
}
func (a *app) list(args []string) error {
	f := fs("list")
	id := f.String("id", "", "只查看一个节点")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.locked(func(s *node.State) error {
		nodes := s.Nodes
		if *id != "" {
			n, e := s.Find(*id)
			if e != nil {
				return e
			}
			nodes = []node.Node{*n}
		}
		fmt.Printf("核心：sing-box %s；配置格式：%d\n", s.CoreVersion, s.Schema)
		if len(nodes) == 0 {
			fmt.Println("尚无节点，请运行 init。")
		}
		for _, n := range nodes {
			status := "停用"
			if n.Enabled {
				status = "启用"
			}
			fmt.Printf("\n%s  %s  %s\n  ID: %s\n  地址: %s  监听: %s/%s  凭据数: %d\n", n.Name, n.Protocol, status, n.ID, net.JoinHostPort(n.Host, strconv.Itoa(n.Port)), net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)), strings.Join(node.Networks(n), "+"), len(n.Users))
			for _, u := range n.Users {
				fmt.Printf("  凭据: %s (%s)，认证信息已隐藏\n", u.Name, u.ID)
			}
		}
		return nil
	})
}
func (a *app) edit(args []string) error {
	f := fs("edit")
	id := f.String("id", "", "节点 ID 或名称")
	name := f.String("name", "", "新名称")
	host := f.String("server", "", "新公网 IP/域名")
	listen := f.String("listen", "", "新监听 IP")
	port := f.Int("port", 0, "新端口")
	randomPort := f.Bool("random-port", false, "选择随机端口")
	fingerprint := f.String("fingerprint", "", "新 REALITY 客户端指纹")
	sni := f.String("sni", "", "新 SNI")
	target := f.String("target", "", "新 REALITY 目标")
	cert := f.String("cert", "", "替换证书链")
	key := f.String("key", "", "替换私钥")
	email := f.String("acme-email", "", "改用 ACME HTTP-01")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.mutate(func(s *node.State) error {
		n, e := s.Find(*id)
		if e != nil {
			return e
		}
		if *name != "" {
			n.Name = *name
		}
		if *host != "" {
			n.Host = *host
		}
		if *listen != "" {
			n.Listen = *listen
		}
		if flagSet(f, "port") {
			if *port < 1 || *port > 65535 {
				return errors.New("端口须为 1–65535")
			}
			n.Port = *port
		}
		if *randomPort {
			if flagSet(f, "port") {
				return errors.New("--port 与 --random-port 不能同时使用")
			}
			n.Port, e = node.RandomPort(*s, *n, node.SSHPorts())
			if e != nil {
				return e
			}
		}
		if n.Protocol == "reality" {
			if *cert != "" || *key != "" || *email != "" {
				return errors.New("REALITY 不使用证书参数")
			}
			if *sni != "" {
				oldSNI := n.Reality.ServerName
				n.Reality.ServerName = *sni
				if *target == "" && n.Reality.Target == net.JoinHostPort(oldSNI, "443") {
					n.Reality.Target = net.JoinHostPort(*sni, "443")
				}
			}
			if *fingerprint != "" {
				n.Reality.Fingerprint = *fingerprint
			}
			if *target != "" {
				n.Reality.Target = *target
			}
		} else if n.Protocol == "hysteria2" {
			if *target != "" {
				return errors.New("Hysteria2 不使用 REALITY 目标")
			}
			if *sni != "" {
				n.Certificate.ServerName = *sni
			}
			if *cert != "" || *key != "" || *email != "" {
				n.Certificate, e = loadCert(n.Certificate.ServerName, *cert, *key, *email)
			}
		}
		if n.Protocol != "reality" && *fingerprint != "" {
			return errors.New("fingerprint 仅用于 REALITY")
		}
		if n.Protocol == "ss2022" && (*sni != "" || *target != "" || *cert != "" || *key != "" || *email != "") {
			return errors.New("SS2022 不接受 TLS/REALITY 参数")
		}
		return e
	})
}
func (a *app) toggle(cmd string, args []string) error {
	f := fs(cmd)
	id := f.String("id", "", "节点 ID 或名称")
	yes := f.Bool("yes", false, "确认删除")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.mutate(func(s *node.State) error {
		n, e := s.Find(*id)
		if e != nil {
			return e
		}
		if cmd == "delete" {
			if !*yes {
				return errors.New("删除需要 --yes")
			}
			for i := range s.Nodes {
				if s.Nodes[i].ID == n.ID {
					s.Nodes = append(s.Nodes[:i], s.Nodes[i+1:]...)
					break
				}
			}
		} else {
			n.Enabled = cmd == "enable"
		}
		return nil
	})
}
func (a *app) users(cmd string, args []string) error {
	f := fs(cmd)
	id := f.String("id", "", "节点 ID 或名称")
	u := f.String("user", "", "凭据 ID 或名称")
	name := f.String("name", "", "新增凭据名称")
	keys := f.Bool("keys", false, "更换 REALITY 密钥，所有客户端需要重新导入")
	shortID := f.Bool("short-id", false, "仅重新生成 short ID；旧链接将失效")
	serverKey := f.Bool("server-key", false, "轮换 SS2022 服务密钥；所有客户端链接将失效")
	yes := f.Bool("yes", false, "确认删除或轮换")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.mutate(func(s *node.State) error {
		n, e := s.Find(*id)
		if e != nil {
			return e
		}
		if cmd == "user-add" {
			if *name == "" {
				return errors.New("缺少 --name")
			}
			n.Users = append(n.Users, node.NewUser(*name, n.Protocol))
			return nil
		}
		if !*yes {
			return errors.New("删除或轮换认证信息需要 --yes，旧链接将失效")
		}
		if *serverKey {
			if *keys || *shortID || cmd != "rotate" || n.Shadowsocks == nil {
				return errors.New("--server-key 仅单独用于 SS2022 rotate")
			}
			n.Shadowsocks = node.NewShadowsocks()
			return nil
		}
		if *keys && *shortID {
			return errors.New("--keys 与 --short-id 分别操作，避免误轮换")
		}
		if cmd == "rotate" && *shortID {
			if n.Reality == nil {
				return errors.New("short ID 仅用于 REALITY")
			}
			n.Reality.ShortID = node.Token(8)
			return nil
		}
		if cmd == "rotate" && *keys {
			if n.Protocol != "reality" {
				return errors.New("--keys 仅用于 REALITY")
			}
			old := *n.Reality
			n.Reality, e = node.NewReality(old.ServerName, old.Target)
			if e == nil {
				n.Reality.ShortID = old.ShortID
				n.Reality.Fingerprint = old.Fingerprint
			}
			return e
		}
		selected, e := node.SelectUser(*n, *u)
		if e != nil {
			return e
		}
		for i := range n.Users {
			if n.Users[i].ID != selected.ID {
				continue
			}
			if cmd == "user-delete" {
				if len(n.Users) == 1 {
					return errors.New("最后一个凭据请通过删除整个节点移除")
				}
				n.Users = append(n.Users[:i], n.Users[i+1:]...)
			} else {
				nu := node.NewUser(n.Users[i].Name, n.Protocol)
				nu.ID = n.Users[i].ID
				n.Users[i] = nu
			}
			break
		}
		return nil
	})
}
func (a *app) choosePort(s node.State, n node.Node) (int, error) {
	a.message("WARN", "端口 "+node.PortLabel(n)+" 无法绑定，可能被其他服务占用")
	if b, e := node.Run(5*time.Second, "ss", "-H", "-lntup", "sport = :"+strconv.Itoa(n.Port)); e == nil {
		fmt.Fprint(os.Stderr, node.Redact(string(b)))
	}
	for {
		answer, e := a.prompt("新端口，r 随机，0 返回", "r")
		if e != nil {
			return 0, e
		}
		if answer == "0" {
			return 0, errors.New("已取消")
		}
		if answer == "r" {
			return node.RandomPort(s, n, node.SSHPorts())
		}
		p, e := strconv.Atoi(answer)
		if e != nil || p < 1 || p > 65535 {
			a.message("WARN", "请输入有效端口")
			continue
		}
		n.Port = p
		if node.AvailablePort(n) != nil {
			a.message("WARN", "端口不可用")
			continue
		}
		return p, nil
	}
}
