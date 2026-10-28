package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"net"
	"os"
	"qingnode/internal/node"
	"qingnode/internal/ui"
	"strconv"
	"strings"
	"time"
)

func (a *app) add(cmd string, args []string) error {
	return a.addWithProbes(cmd, args, defaultAutoProbes())
}

func (a *app) addWithProbes(cmd string, args []string, probes autoProbes) error {
	f := fs(cmd)
	auto := f.Bool("auto", false, "无交互发现公网地址、验证 REALITY 目标并避开默认端口冲突")
	name := f.String("name", "main", "节点名称")
	protocol := f.String("protocol", "reality", "reality / ss2022 / hysteria2 / anytls / trojan / ss-aead / tuic")
	method := f.String("method", "aes-256-gcm", "仅传统ss-aead：aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305")
	host := f.String("server", "", "客户端连接的公网 IP 或域名")
	listen := f.String("listen", "", "监听 IP，默认按公网地址选择通配地址")
	port := portFlag(f, 443)
	connectPort := namedPortFlag(f, "connect-port", 0, "客户端连接端口（十进制）；省略使用最终本地监听端口，NAT映射须显式填写")
	randomPort := f.Bool("random-port", false, "选择避开已有节点、监听和 SSH 的随机端口")
	fingerprint := f.String("fingerprint", "chrome", "REALITY 客户端指纹")
	sni := f.String("sni", "", "REALITY 目标域名 / TLS 协议证书名称")
	target := f.String("target", "", "REALITY 目标主机:端口，默认 SNI:443")
	cert := f.String("cert", "", "PEM 完整证书链")
	key := f.String("key", "", "PEM 私钥")
	email := f.String("acme-email", "", "用 ACME HTTP-01 签发及续期证书")
	certificateID := f.String("certificate-id", "", "复用现有证书资源稳定ID；不与PEM/ACME输入混用")
	uname := f.String("user", "default", "首个凭据名称")
	egress := f.String("egress", "", "入口的出口/策略稳定ID；省略或direct保持直连")
	quiet := f.Bool("quiet", false, "成功后不显示节点摘要；普通摘要也不含认证信息")
	var existingPreflight *bool
	if cmd == "validate-install" {
		existingPreflight = f.Bool("existing", false, "仅校验明确填写的值；已有资源引用不在此检查")
	}
	if e := parse(f, args); e != nil {
		return e
	}
	if cmd == "install" || cmd == "validate-install" {
		if cmd == "install" && a.offline {
			return errors.New("install 需要在线准备官方核心；离线生成请使用 init")
		}
		if _, ok := node.Protocol(*protocol); !ok {
			return errors.New("不支持该协议")
		}
		if !node.ValidName(*name) || !node.ValidName(*uname) {
			return errors.New("节点或用户名称为空、过长或包含控制字符")
		}
		if *listen != "" && net.ParseIP(*listen) == nil {
			return errors.New("监听地址须为IP字面量")
		}
		if *randomPort && flagSet(f, "port") {
			return errors.New("--port 与 --random-port 不能同时使用")
		}
		if *protocol == "ss-aead" {
			if _, err := node.NewShadowsocksAEAD(*method); err != nil {
				return err
			}
		}
		if (*protocol == "ss2022" || *protocol == "ss-aead") && (*sni != "" || *target != "" || *cert != "" || *key != "" || *email != "" || *certificateID != "" || flagSet(f, "fingerprint")) {
			return fmt.Errorf("%s 不使用 SNI、REALITY 或 TLS 参数", *protocol)
		}
		if *protocol == "reality" && (*cert != "" || *key != "" || *email != "" || *certificateID != "") {
			return errors.New("REALITY 不使用证书参数")
		}
		if node.ProtocolRequiresCertificate(*protocol) && (*target != "" || flagSet(f, "fingerprint")) {
			return errors.New("该TLS协议不使用REALITY目标或指纹")
		}
		if *certificateID != "" && (*sni != "" || *cert != "" || *key != "" || *email != "") {
			return errors.New("--certificate-id不与SNI/PEM/ACME输入混用；证书资源已声明名称")
		}
		if *email != "" && (*cert != "" || *key != "") {
			return errors.New("ACME 与 PEM 证书参数不能同时使用")
		}
		if (*cert == "") != (*key == "") {
			return errors.New("PEM证书与私钥须成对提供")
		}
	}
	if flagSet(f, "method") && *protocol != "ss-aead" {
		return errors.New("--method仅用于传统ss-aead；SS2022原方法和密钥语义保持")
	}
	if *auto && a.offline {
		return errors.New("--auto 需要在线部署；离线生成请移除 --auto 并显式提供 --server 和协议参数")
	}
	if flagSet(f, "connect-port") && (*connectPort < 1 || *connectPort > 65535) {
		return errors.New("连接端口须为1–65535")
	}
	if *host != "" {
		normalized, err := node.NormalizeEndpointHost(*host)
		if err != nil {
			return err
		}
		*host = normalized
	}
	if cmd == "validate-install" {
		if !*existingPreflight && !*auto && *host == "" {
			return errors.New("缺少 --server 公网 IP 或域名")
		}
		if !*existingPreflight && *protocol == "reality" && !*auto && *sni == "" {
			return errors.New("缺少 --sni")
		}
		if !*existingPreflight && node.ProtocolRequiresCertificate(*protocol) && *certificateID == "" && (*sni == "" || (*email == "" && (*cert == "" || *key == ""))) {
			return errors.New("TLS协议需要 --sni 和 --cert/--key、--acme-email，或已有 --certificate-id")
		}
		// Stateless bootstrap preflight: only check explicitly supplied fields.
		// Auto discovery, external reachability and referenced resources remain
		// unknown and are checked again during the real installation.
		if *sni != "" && (!node.ValidHost(*sni) || (*protocol == "reality" && net.ParseIP(*sni) != nil)) {
			return errors.New("SNI 须为有效域名")
		}
		if *protocol == "reality" && (flagSet(f, "sni") || flagSet(f, "target") || flagSet(f, "fingerprint")) {
			if *sni == "" && *target != "" {
				return errors.New("REALITY目标需要SNI域名")
			}
			if *sni != "" {
				targetValue := *target
				if targetValue == "" {
					targetValue = net.JoinHostPort(*sni, "443")
				}
				if err := node.RealityTargetPolicy(&node.Reality{ServerName: *sni, Target: targetValue}); err != nil {
					return err
				}
				_, portValue, err := net.SplitHostPort(targetValue)
				if err != nil {
					return errors.New("REALITY目标须为主机:端口")
				}
				port, err := strconv.Atoi(portValue)
				if err != nil || port < 1 || port > 65535 {
					return errors.New("REALITY目标端口无效")
				}
			}
			switch *fingerprint {
			case "chrome", "firefox", "safari", "ios", "edge":
			default:
				return errors.New("不支持该 fingerprint")
			}
		}
		if node.ProtocolRequiresCertificate(*protocol) && (*cert != "" || *key != "" || *email != "") {
			c, err := loadCert(*sni, *cert, *key, *email)
			if err != nil {
				return err
			}
			if err := node.ValidateCertificateResource(node.CertificateResource{Certificate: *c}, time.Now(), true); err != nil {
				return err
			}
		}
		return nil
	}
	created := ""
	mutate := a.mutate
	if cmd == "install" {
		mutate = a.mutateInstall
	}
	err := mutate(func(s *node.State) error {
		if cmd == "install" && *certificateID != "" {
			r, err := s.FindCertificate(*certificateID)
			if err != nil || r.ID != *certificateID {
				return errors.New("需要现有证书资源稳定ID")
			}
		}
		if (cmd == "init" || cmd == "install") && len(s.Nodes) > 0 {
			if cmd == "install" {
				// Reinstall preserves the old node, but supplied options must not
				// trigger a download when they cannot describe a valid node.
				if *egress != "" && *egress != "direct" {
					if _, err := node.ResolveEgressID(*s, *egress); err != nil {
						return err
					}
				}
				if *protocol == "reality" && (flagSet(f, "sni") || flagSet(f, "target") || flagSet(f, "fingerprint")) {
					if *sni == "" || !node.ValidHost(*sni) || net.ParseIP(*sni) != nil {
						return errors.New("REALITY 需要有效 SNI 域名")
					}
					r, err := node.NewReality(*sni, *target)
					if err != nil {
						return err
					}
					r.Fingerprint = *fingerprint
					adapter, _ := node.Protocol("reality")
					if err := adapter.Validate(node.Node{Reality: r}); err != nil {
						return err
					}
					if err := node.RealityTargetPolicy(r); err != nil {
						return err
					}
				}
				if node.ProtocolRequiresCertificate(*protocol) && (*cert != "" || *key != "" || *email != "") {
					c, err := loadCert(*sni, *cert, *key, *email)
					if err != nil {
						return err
					}
					if err := node.ValidateCertificateResource(node.CertificateResource{Certificate: *c}, time.Now(), true); err != nil {
						return err
					}
				}
			}
			fmt.Fprintln(os.Stderr, "已经初始化，保留所有节点和凭据；新增节点请用 add。")
			return nil
		}
		var e error
		if *auto {
			if node.ProtocolRequiresCertificate(*protocol) && *certificateID == "" && (*sni == "" || (*email == "" && (*cert == "" || *key == ""))) {
				return errors.New("TLS协议自动安装需要 --sni 和 --cert/--key、--acme-email，或已有 --certificate-id")
			}
			*host, *sni, *target, e = autoEndpoint(*protocol, *host, *sni, *target, probes)
			if e != nil {
				return e
			}
			fmt.Fprintln(os.Stderr, "[INFO] 客户端连接地址："+*host)
			if *protocol == "reality" {
				fmt.Fprintf(os.Stderr, "[INFO] REALITY 目标已通过 TLS 1.3 / HTTP2 验证：%s（SNI %s）\n", *target, *sni)
			}
		}
		if *host == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("缺少 --server 公网 IP 或域名")
			}
			*host, e = a.prompt("公网 IP 或连接域名", "")
			if e != nil {
				return e
			}
		}
		if *sni == "" && *protocol != "ss2022" && *protocol != "ss-aead" && *certificateID == "" {
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
		n := node.Node{ID: node.Token(8), Name: *name, Protocol: *protocol, Host: *host, Listen: *listen, Port: *port, Enabled: true, Users: []node.User{node.NewUser(*uname, *protocol)}, EgressID: directEgress(*egress)}
		if *protocol == "reality" {
			if *cert != "" || *key != "" || *email != "" || *certificateID != "" {
				return errors.New("REALITY 不使用证书参数")
			}
			n.Reality, e = node.NewReality(*sni, *target)
			if e == nil {
				n.Reality.Fingerprint = *fingerprint
				e = node.RealityTargetPolicy(n.Reality)
				if e == nil && !*auto && !a.offline {
					e = node.CheckReality(n.Reality)
				}
			}
		} else if node.ProtocolRequiresCertificate(*protocol) {
			if *target != "" || flagSet(f, "fingerprint") {
				return errors.New("该TLS协议不使用REALITY目标或指纹")
			}
			if *certificateID != "" {
				if *sni != "" || *cert != "" || *key != "" || *email != "" {
					return errors.New("--certificate-id不与SNI/PEM/ACME输入混用；证书资源已声明名称")
				}
				r, err := s.FindCertificate(*certificateID)
				if err != nil || r.ID != *certificateID {
					return errors.New("需要现有证书资源稳定ID")
				}
				n.CertificateID = r.ID
				c := r.Certificate
				n.Certificate = &c
			} else {
				n.Certificate, e = loadCert(*sni, *cert, *key, *email)
			}
		} else if *protocol == "ss2022" || *protocol == "ss-aead" {
			if *sni != "" || *target != "" || *cert != "" || *key != "" || *email != "" || *certificateID != "" || flagSet(f, "fingerprint") {
				return fmt.Errorf("%s 不使用 SNI、REALITY 或 TLS 参数", *protocol)
			}
			if *protocol == "ss-aead" {
				n.Shadowsocks, e = node.NewShadowsocksAEAD(*method)
			} else {
				n.Shadowsocks = node.NewShadowsocks()
			}
		} else {
			return errors.New("不支持该协议")
		}
		if e != nil {
			return e
		}
		if *auto {
			n.Port, e = autoPort(*s, n, flagSet(f, "port"), *randomPort, probes)
			if e != nil {
				return e
			}
			fmt.Fprintf(os.Stderr, "[INFO] 监听端口：%s\n", node.PortLabel(n))
		} else if *randomPort {
			if flagSet(f, "port") {
				return errors.New("--port 与 --random-port 不能同时使用")
			}
			n.Port, e = node.RandomPort(*s, n, node.SSHPorts())
			if e != nil {
				return e
			}
		}
		if !*auto && !a.offline && node.AvailablePort(n) != nil {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("端口 %s 被占用；运行 qingnode ports 查看进程，或使用 --random-port", node.PortLabel(n))
			}
			n.Port, e = a.choosePort(*s, n)
			if e != nil {
				return e
			}
		}
		connectionPort := *connectPort
		if !flagSet(f, "connect-port") {
			connectionPort = n.Port
		}
		n.ConnectPort = &connectionPort
		s.Nodes = append(s.Nodes, n)
		if a.menuPreview || cmd == "install" {
			// Complete field/certificate validation precedes any core download.
			// The same generated ID and credentials go to Preview and Apply.
			if err := s.Validate(); err != nil {
				return err
			}
			if err := node.ValidateCertificateDates(*s); err != nil {
				return err
			}
			if a.menuPreview {
				if err := a.previewMenuMutation(*s); err != nil {
					return err
				}
			}
			if a.menuPreview && !a.offline {
				fmt.Fprintln(os.Stderr, "字段预检通过；准备校验或下载此版本官方核心，再校验候选配置。不会修改SSH或全局默认路由。")
				if err := a.installCore(s.CoreVersion, s.CoreArchiveSHA256); err != nil {
					return err
				}
			}
		}
		created = n.ID
		return nil
	})
	if err != nil {
		return err
	}
	if created != "" && !*quiet {
		return a.info([]string{"--id", created})
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
		return nil, errors.New("TLS 节点需要 --cert 和 --key，或 --acme-email")
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
	asJSON := f.Bool("json", false, "版本1公共节点列表；不输出用户凭据或内部出口秘密")
	if e := parse(f, args); e != nil {
		return e
	}
	return a.inspectState(func(s *node.State) error {
		nodes := s.Nodes
		if *id != "" {
			n, e := s.Find(*id)
			if e != nil {
				return e
			}
			nodes = []node.Node{*n}
		}
		if *asJSON {
			type endpoint struct {
				ID   string `json:"id"`
				Host string `json:"host"`
				Port int    `json:"port"`
			}
			type item struct {
				ID              string     `json:"id"`
				Name            string     `json:"name"`
				Protocol        string     `json:"protocol"`
				Enabled         bool       `json:"enabled"`
				Listen          string     `json:"listen"`
				ListenPort      int        `json:"listen_port"`
				Networks        []string   `json:"networks"`
				Endpoints       []endpoint `json:"endpoints"`
				CredentialCount int        `json:"credential_count"`
			}
			rows := make([]item, 0, len(nodes))
			for _, n := range nodes {
				eps := []endpoint{{"default", n.Host, node.EffectiveConnectPort(n)}}
				for _, extra := range n.AdditionalEndpoints {
					eps = append(eps, endpoint{extra.ID, extra.Host, extra.Port})
				}
				rows = append(rows, item{n.ID, ui.SanitizeText(node.Redact(n.Name, *s)), n.Protocol, n.Enabled, n.Listen, n.Port, node.Networks(n), eps, len(n.Users)})
			}
			return json.NewEncoder(os.Stdout).Encode(struct {
				Version     int    `json:"version"`
				CoreVersion string `json:"core_version"`
				Nodes       []item `json:"nodes"`
			}{1, s.CoreVersion, rows})
		}
		w := newStateTextWriter(os.Stdout, *s)
		fmt.Fprintf(w, "核心：sing-box %s；配置格式：%d\n", s.CoreVersion, s.Schema)
		if len(nodes) == 0 {
			fmt.Fprintln(w, "尚无节点，请运行 init。")
		}
		for _, n := range nodes {
			status := "停用"
			if n.Enabled {
				status = "启用"
			}
			fmt.Fprintf(w, "\n%s  %s  %s\n  ID: %s\n  地址: %s  监听: %s/%s  凭据数: %d  出口: %s\n", n.Name, n.Protocol, status, n.ID, net.JoinHostPort(n.Host, strconv.Itoa(node.EffectiveConnectPort(n))), net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)), strings.Join(node.Networks(n), "+"), len(n.Users), displayEgress(n.EgressID))
			for _, u := range n.Users {
				fmt.Fprintf(w, "  凭据: %s (%s)，认证信息已隐藏\n", u.Name, u.ID)
			}
		}
		return w.Flush()
	})
}
func (a *app) edit(args []string) error {
	f := fs("edit")
	id := f.String("id", "", "节点 ID 或名称")
	name := f.String("name", "", "新名称")
	host := f.String("server", "", "新公网 IP/域名")
	listen := f.String("listen", "", "新监听 IP")
	port := portFlag(f, 0)
	connectPort := namedPortFlag(f, "connect-port", 0, "新客户端连接端口（十进制）；--port只改本地监听")
	randomPort := f.Bool("random-port", false, "选择随机端口")
	fingerprint := f.String("fingerprint", "", "新 REALITY 客户端指纹")
	sni := f.String("sni", "", "新 SNI")
	target := f.String("target", "", "新 REALITY 目标")
	cert := f.String("cert", "", "替换证书链")
	key := f.String("key", "", "替换私钥")
	email := f.String("acme-email", "", "改用 ACME HTTP-01")
	method := f.String("method", "", "仅传统ss-aead：更换方法但保留用户密码；客户端须重新导入")
	preview := f.Bool("preview", false, "只读显示影响，不保存、不恢复事务、不启停服务")
	asJSON := f.Bool("json", false, "仅--preview：输出版本1变更影响JSON")
	egress := f.String("egress", "", "入口的出口/策略稳定ID；direct明确改回直连")
	if e := parse(f, args); e != nil {
		return e
	}
	if *asJSON && !*preview {
		return errors.New("edit --json仅与--preview一起使用；未执行任何修改")
	}
	e := nodeEdit{ID: *id, Name: editString(*name), Server: editString(*host), Listen: editString(*listen),
		Fingerprint: editString(*fingerprint), SNI: editString(*sni), Target: editString(*target),
		Cert: editString(*cert), Key: editString(*key), ACMEEmail: editString(*email)}
	if flagSet(f, "method") {
		if *method == "" {
			return errors.New("方法不能为空")
		}
		e.Method = method
	}
	if flagSet(f, "port") {
		e.Port = port
	}
	if flagSet(f, "connect-port") {
		e.ConnectPort = connectPort
	}
	if flagSet(f, "egress") {
		if *egress == "" {
			return errors.New("--egress不能为空；直连请显式填写direct")
		}
		e.EgressID = egress
	}
	if *randomPort && flagSet(f, "port") {
		return errors.New("--port 与 --random-port 不能同时使用")
	}
	if *preview {
		if *randomPort {
			return errors.New("只读预览不选择随机端口；请用 --port 显式指定候选端口")
		}
		return a.previewEdits([]nodeEdit{e}, *asJSON)
	}
	return a.mutate(func(s *node.State) error {
		if *randomPort {
			n, err := s.Find(e.ID)
			if err != nil {
				return err
			}
			// Consider all requested listen/protocol settings before probing the port.
			candidate := s.Clone()
			cn, _ := candidate.Find(n.ID)
			if err = e.apply(cn); err != nil {
				return err
			}
			p, err := node.RandomPort(candidate, *cn, node.SSHPorts())
			if err != nil {
				return err
			}
			e.Port = &p
		}
		ids, err := applyNodeEdits(s, []nodeEdit{e})
		if err != nil {
			return err
		}
		return a.checkEditedReality(*s, ids)
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
			if *keys || *shortID || cmd != "rotate" || n.Protocol != "ss2022" || n.Shadowsocks == nil {
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
			return 0, errMenuCanceled
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

// The same official core installer is used only after the candidate validates.
func (a *app) installCore(version, sum string) error {
	if a.installCoreFn != nil {
		return a.installCoreFn(a.store.Root, version, sum, "")
	}
	return node.InstallCore(a.store.Root, version, sum, "")
}
