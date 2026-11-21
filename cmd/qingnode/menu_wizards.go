package main

import (
	"bytes"
	"encoding/json"
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

	"github.com/skip2/go-qrcode"
	"golang.org/x/term"
	"qingnode/internal/node"
	"qingnode/internal/subscription"
	"qingnode/internal/ui"
)

func (a *app) secretPrompt(label string, required bool) (string, error) {
	promptText := label + "（输入不回显，:cancel返回）"
	if !required {
		promptText = label + "（输入不回显，可留空，:cancel返回）"
	}
	var raw string
	switch {
	case a.readSecretFn != nil:
		b, err := a.readSecretFn(promptText)
		if err != nil {
			return "", err
		}
		raw = string(b)
	case a.stdinFromOS && term.IsTerminal(int(os.Stdin.Fd())) && (a.in == nil || a.in.Buffered() == 0):
		fmt.Fprint(os.Stderr, ui.WrapText(promptText+": ", ui.Width(os.Stderr)))
		b, err := readTerminalPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		raw = string(b)
	default:
		val, err := a.wizardPrompt(promptText, "")
		if err != nil {
			return "", err
		}
		raw = val
	}
	if raw == ":cancel" {
		return "", errMenuCanceled
	}
	if !utf8.ValidString(raw) || len(raw) > 4096 || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("输入包含控制字符、无效文字或超过4096字节；尚未提交本次表单")
	}
	for _, r := range raw {
		if r == '\ufffd' || r == '\u202a' || r == '\u202b' || r == '\u202c' || r == '\u202d' || r == '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return "", errors.New("输入包含控制字符或无效编码；本次未应用")
		}
	}
	if required && strings.TrimSpace(raw) == "" {
		return "", errors.New("此项不能留空；输入:cancel取消，不会提交表单")
	}
	return raw, nil
}

func (a *app) printTerminalQR(content string) error {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return errors.New("订阅链接过长，无法生成二维码")
	}
	rendered := q.ToSmallString(false)
	needed := ui.DisplayWidth(rendered)
	cols := a.termWidth
	if cols <= 0 {
		cols = ui.Width(os.Stdout)
	}
	if cols <= 0 {
		cols = ui.Width(os.Stderr)
	}
	if cols > 0 && needed > cols {
		return fmt.Errorf("当前终端宽度（%d 列）不足以完整显示二维码（至少需要 %d 列）；请拉宽终端窗口，或用 qingnode subscription qr --token-file <令牌文件> --format auto --out <私有文件> 保存", cols, needed)
	}
	fmt.Fprintln(ui.HumanWriter(os.Stderr), "统一订阅链接二维码（支持客户端按 User-Agent 自动识别格式）：")
	_, err = io.WriteString(os.Stdout, rendered)
	return err
}

func (a *app) precheckWizardCandidate(change func(*node.State) error) error {
	if _, err := os.Lstat(a.store.Root); errors.Is(err, os.ErrNotExist) {
		candidate := node.NewState()
		if err := change(&candidate); err != nil {
			return err
		}
		if err := candidate.Validate(); err != nil {
			return errors.New(node.Redact(err.Error(), candidate))
		}
		return nil
	}
	return a.store.InspectExisting(func() error {
		if err := rejectPending(a.store.Root); err != nil {
			return err
		}
		st, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = st.Validate(); err != nil {
			return err
		}
		candidate := st.Clone()
		if err = change(&candidate); err != nil {
			return err
		}
		if err = candidate.Validate(); err != nil {
			return errors.New(node.Redact(err.Error(), candidate))
		}
		return nil
	})
}

func (a *app) applyWizardMutation(change func(*node.State) error) error {
	if err := a.precheckWizardCandidate(change); err != nil {
		return err
	}
	return a.withMenuPreview(func() error {
		return a.mutate(func(s *node.State) error {
			candidate := s.Clone()
			if err := change(&candidate); err != nil {
				return err
			}
			if err := candidate.Validate(); err != nil {
				return errors.New(node.Redact(err.Error(), candidate))
			}
			*s = candidate
			return nil
		})
	})
}

func (a *app) wizardBool(label string, def bool) (bool, error) {
	defStr := "n"
	if def {
		defStr = "y"
	}
	raw, err := a.wizardPrompt(label, defStr)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0":
		return false, errMenuCanceled
	case "y", "yes", "true", "1":
		return true, nil
	case "n", "no", "false":
		return false, nil
	default:
		return false, errors.New("请输入 y 或 n（输入 0 或 :cancel 取消）")
	}
}

func (a *app) wizardPort(label string, def int, allowZero bool) (int, error) {
	defStr := ""
	if def > 0 || (allowZero && def == 0) {
		defStr = strconv.Itoa(def)
	}
	var raw string
	var err error
	if defStr != "" {
		raw, err = a.wizardPrompt(label, defStr)
	} else {
		raw, err = a.menuRequired(label)
	}
	if err != nil {
		return 0, err
	}
	n, convErr := strconv.Atoi(strings.TrimSpace(raw))
	if convErr != nil || (allowZero && (n < 0 || n > 65535)) || (!allowZero && (n < 1 || n > 65535)) {
		if allowZero {
			return 0, errors.New("端口须为十进制 0–65535（0 表示使用默认端口）")
		}
		return 0, errors.New("端口须为十进制 1–65535")
	}
	return n, nil
}

// --- 1. Certificate Wizards ---

func (a *app) selectCertificate() (node.CertificateResource, error) {
	var st node.State
	if err := a.inspectState(func(s *node.State) error {
		st = s.Clone()
		return s.Validate()
	}); err != nil {
		return node.CertificateResource{}, err
	}
	if len(st.Certificates) == 0 {
		return node.CertificateResource{}, errors.New("当前没有证书资源；请先创建或导入证书")
	}
	w := ui.HumanWriter(os.Stderr)
	for i, c := range st.Certificates {
		mode := c.Certificate.Mode
		if mode == "acme" && c.Certificate.ACME != nil && c.Certificate.ACME.Challenge != "" {
			mode = "acme/" + c.Certificate.ACME.Challenge
		}
		refs := node.CertificateReferences(st, c.ID)
		fmt.Fprintf(w, "%d. %s (%s) [%s / %s] 引用节点:%v\n", i+1, node.Redact(c.Name, st), c.ID, mode, c.Certificate.ServerName, refs)
	}
	defaultChoice := ""
	if len(st.Certificates) == 1 {
		defaultChoice = "1"
	}
	for {
		ans, err := a.wizardPrompt("证书序号或ID，0 返回", defaultChoice)
		if err != nil {
			return node.CertificateResource{}, err
		}
		if ans == "0" {
			return node.CertificateResource{}, errMenuCanceled
		}
		if idx, convErr := strconv.Atoi(ans); convErr == nil && idx >= 1 && idx <= len(st.Certificates) {
			return st.Certificates[idx-1], nil
		}
		if idx, findErr := certificateIndex(st, ans); findErr == nil {
			return st.Certificates[idx], nil
		}
		a.message("WARN", "请输入列表中的证书序号、稳定ID，或输入 0 返回")
	}
}

func (a *app) promptCertificateResource(existing *node.CertificateResource) (node.CertificateResource, error) {
	w := ui.HumanWriter(os.Stderr)
	defaultName := ""
	defaultDomain := ""
	defaultEmail := ""
	defaultMode := "1"
	defaultCA := ""
	defaultKeyType := ""
	defaultHTTPPort := 0
	defaultTLSPort := 0
	defaultDNSProvider := "1"
	defaultRegion := "cn-hangzhou"
	defaultCertPath := ""
	defaultKeyPath := ""
	if existing != nil {
		defaultName = existing.Name
		defaultDomain = existing.Certificate.ServerName
		defaultEmail = existing.Certificate.Email
		defaultCertPath = existing.Certificate.CertificatePath
		defaultKeyPath = existing.Certificate.KeyPath
		switch existing.Certificate.Mode {
		case "file":
			defaultMode = "4"
		case "acme":
			if existing.Certificate.ACME != nil {
				defaultCA = existing.Certificate.ACME.Provider
				defaultKeyType = existing.Certificate.ACME.KeyType
				defaultHTTPPort = existing.Certificate.ACME.AlternativeHTTPPort
				defaultTLSPort = existing.Certificate.ACME.AlternativeTLSPort
				switch existing.Certificate.ACME.Challenge {
				case "dns-01":
					defaultMode = "2"
					if existing.Certificate.ACME.DNS01 != nil {
						switch existing.Certificate.ACME.DNS01.Provider {
						case "alidns":
							defaultDNSProvider = "2"
							if existing.Certificate.ACME.DNS01.RegionID != "" {
								defaultRegion = existing.Certificate.ACME.DNS01.RegionID
							}
						case "acmedns":
							defaultDNSProvider = "3"
						default:
							defaultDNSProvider = "1"
						}
					}
				case "tls-alpn-01":
					defaultMode = "3"
				default:
					defaultMode = "1"
				}
			}
		}
	}

	var name string
	var err error
	if defaultName != "" {
		name, err = a.wizardPrompt("证书资源名称（:cancel返回）", defaultName)
	} else {
		name, err = a.menuRequired("证书资源名称")
	}
	if err != nil {
		return node.CertificateResource{}, err
	}
	if name == "0" {
		return node.CertificateResource{}, errMenuCanceled
	}

	fmt.Fprintln(w, "\n选择证书签发或引用方式\n1 ACME HTTP-01（需公网 TCP 80 可达）\n2 ACME DNS-01（支持 cloudflare / alidns / acmedns，API Token 隐藏输入）\n3 ACME TLS-ALPN-01（需公网 TCP 443 可达且不与节点 TCP 443 冲突）\n4 引用本机已有证书与私钥文件路径（mode: file）\n0 返回")
	modeChoice, err := a.wizardPrompt("选择方式", defaultMode)
	if err != nil {
		return node.CertificateResource{}, err
	}
	if modeChoice == "0" {
		return node.CertificateResource{}, errMenuCanceled
	}
	if modeChoice != "1" && modeChoice != "2" && modeChoice != "3" && modeChoice != "4" {
		return node.CertificateResource{}, menuInvalid()
	}

	var domain string
	if defaultDomain != "" {
		domain, err = a.wizardPrompt("证书域名（SNI / SAN，:cancel返回）", defaultDomain)
	} else {
		domain, err = a.menuRequired("证书域名（SNI / SAN）")
	}
	if err != nil {
		return node.CertificateResource{}, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !node.ValidHost(domain) || (modeChoice != "4" && net.ParseIP(domain) != nil) {
		return node.CertificateResource{}, errors.New("证书域名无效（ACME 须使用有效域名，不能填写纯 IP）")
	}

	cert := node.Certificate{ServerName: domain}
	if modeChoice == "4" {
		cert.Mode = "file"
		if defaultCertPath != "" {
			cert.CertificatePath, err = a.wizardPrompt("本机证书链绝对路径（PEM）", defaultCertPath)
		} else {
			cert.CertificatePath, err = a.menuRequired("本机证书链绝对路径（PEM）")
		}
		if err != nil {
			return node.CertificateResource{}, err
		}
		if defaultKeyPath != "" {
			cert.KeyPath, err = a.wizardPrompt("本机私钥绝对路径（权限须为 600）", defaultKeyPath)
		} else {
			cert.KeyPath, err = a.menuRequired("本机私钥绝对路径（权限须为 600）")
		}
		if err != nil {
			return node.CertificateResource{}, err
		}
	} else {
		cert.Mode = "acme"
		if defaultEmail != "" {
			cert.Email, err = a.wizardPrompt("ACME 联系邮箱", defaultEmail)
		} else {
			cert.Email, err = a.menuRequired("ACME 联系邮箱")
		}
		if err != nil {
			return node.CertificateResource{}, err
		}
		if !strings.Contains(cert.Email, "@") || strings.ContainsAny(cert.Email, " \t\r\n") {
			return node.CertificateResource{}, errors.New("ACME 需要有效联系邮箱")
		}
		caProvider, err := a.wizardPrompt("CA 提供方（留空默认 letsencrypt；可选 zerossl 或自定义 HTTPS 目录地址）", defaultCA)
		if err != nil {
			return node.CertificateResource{}, err
		}
		keyType, err := a.wizardPrompt("证书密钥算法（留空默认 p256；可选 p256/p384/rsa2048/rsa4096）", defaultKeyType)
		if err != nil {
			return node.CertificateResource{}, err
		}
		acme := &node.ACMESettings{
			Provider: strings.TrimSpace(caProvider),
			KeyType:  strings.TrimSpace(keyType),
		}
		switch modeChoice {
		case "1":
			acme.Challenge = "http-01"
			altPort, err := a.wizardPort("本地 HTTP-01 替代监听端口（0 使用默认 80）", defaultHTTPPort, true)
			if err != nil {
				return node.CertificateResource{}, err
			}
			acme.AlternativeHTTPPort = altPort
		case "2":
			acme.Challenge = "dns-01"
			fmt.Fprintln(w, "\n选择 DNS-01 服务商\n1 cloudflare（Cloudflare API Token）\n2 alidns（阿里云 AccessKey ID / Secret）\n3 acmedns（自建或受控 acme-dns 服务）\n0 返回")
			dnsChoice, err := a.wizardPrompt("选择 DNS 服务商", defaultDNSProvider)
			if err != nil {
				return node.CertificateResource{}, err
			}
			switch strings.ToLower(strings.TrimSpace(dnsChoice)) {
			case "0":
				return node.CertificateResource{}, errMenuCanceled
			case "1", "cloudflare":
				apiToken, err := a.secretPrompt("Cloudflare DNS API Token", true)
				if err != nil {
					return node.CertificateResource{}, err
				}
				zoneToken, err := a.secretPrompt("Cloudflare Zone Token", false)
				if err != nil {
					return node.CertificateResource{}, err
				}
				acme.DNS01 = &node.ACMEDNS01{
					Provider:  "cloudflare",
					APIToken:  apiToken,
					ZoneToken: zoneToken,
				}
			case "2", "alidns":
				akID, err := a.menuRequired("阿里云 AccessKey ID")
				if err != nil {
					return node.CertificateResource{}, err
				}
				akSecret, err := a.secretPrompt("阿里云 AccessKey Secret", true)
				if err != nil {
					return node.CertificateResource{}, err
				}
				regionID, err := a.wizardPrompt("阿里云 Region ID", defaultRegion)
				if err != nil {
					return node.CertificateResource{}, err
				}
				if regionID == "" {
					return node.CertificateResource{}, errors.New("alidns 需要有效 Region ID")
				}
				acme.DNS01 = &node.ACMEDNS01{
					Provider:        "alidns",
					AccessKeyID:     akID,
					AccessKeySecret: akSecret,
					RegionID:        regionID,
				}
			case "3", "acmedns":
				serverURL, err := a.menuRequired("acme-dns HTTPS 服务地址（如 https://auth.example.com）")
				if err != nil {
					return node.CertificateResource{}, err
				}
				username, err := a.menuRequired("acme-dns Username")
				if err != nil {
					return node.CertificateResource{}, err
				}
				password, err := a.secretPrompt("acme-dns Password", true)
				if err != nil {
					return node.CertificateResource{}, err
				}
				subdomain, err := a.menuRequired("acme-dns Subdomain")
				if err != nil {
					return node.CertificateResource{}, err
				}
				acme.DNS01 = &node.ACMEDNS01{
					Provider:  "acmedns",
					ServerURL: serverURL,
					Username:  username,
					Password:  password,
					Subdomain: subdomain,
				}
			default:
				return node.CertificateResource{}, errors.New("仅支持选择 1(cloudflare)、2(alidns) 或 3(acmedns)")
			}
		case "3":
			acme.Challenge = "tls-alpn-01"
			altPort, err := a.wizardPort("本地 TLS-ALPN-01 替代监听端口（0 使用默认 443）", defaultTLSPort, true)
			if err != nil {
				return node.CertificateResource{}, err
			}
			acme.AlternativeTLSPort = altPort
		}
		cert.ACME = acme
	}

	res := node.CertificateResource{
		ID:          node.Token(8),
		Name:        name,
		Certificate: cert,
	}
	if existing != nil {
		res.ID = existing.ID
		res.LegacyStorage = existing.LegacyStorage && res.Certificate.Mode == "acme"
	}
	if err := node.ValidateCertificateResource(res, time.Now().UTC(), true); err != nil {
		return node.CertificateResource{}, err
	}
	return res, nil
}

func (a *app) certificateCreateWizard() error {
	res, err := a.promptCertificateResource(nil)
	if err != nil {
		return err
	}
	if err := a.applyWizardMutation(func(st *node.State) error {
		for _, existing := range st.Certificates {
			if existing.ID == res.ID {
				return errors.New("证书ID冲突，请重试")
			}
		}
		next, e := node.PutCertificateResource(*st, res)
		if e != nil {
			return e
		}
		*st = next
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(ui.HumanWriter(os.Stderr), "已创建证书资源：%s（%s）\n", res.Name, res.ID)
	return nil
}

func (a *app) certificateUpdateWizard() error {
	existing, err := a.selectCertificate()
	if err != nil {
		return err
	}
	res, err := a.promptCertificateResource(&existing)
	if err != nil {
		return err
	}
	change := func(st *node.State) error {
		next, e := node.PutCertificateResource(*st, res)
		if e != nil {
			return e
		}
		*st = next
		return nil
	}
	if err := a.precheckWizardCandidate(change); err != nil {
		return err
	}
	if !a.confirm("将更新证书资源（若被节点共享引用可能重启核心），输入yes继续") {
		return errMenuCanceled
	}
	return a.applyWizardMutation(change)
}

func (a *app) certificateBindWizard() error {
	n, err := a.selectNode()
	if err != nil {
		return err
	}
	c, err := a.selectCertificate()
	if err != nil {
		return err
	}
	return a.applyWizardMutation(func(st *node.State) error {
		next, e := node.BindCertificate(*st, n.ID, c.ID)
		if e != nil {
			return e
		}
		*st = next
		return nil
	})
}

func (a *app) certificateUnbindOrRemoveWizard() error {
	w := ui.HumanWriter(os.Stderr)
	fmt.Fprintln(w, "\n解绑替换或删除证书资源\n1 替换节点当前绑定的证书（解绑旧证书）\n2 解除已停用 TLS 节点的证书引用\n3 删除未被引用的证书资源\n0 返回")
	sub, err := a.wizardPrompt("选择操作", "")
	if err != nil {
		return err
	}
	switch sub {
	case "0":
		return errMenuCanceled
	case "1":
		n, err := a.selectNode()
		if err != nil {
			return err
		}
		if n.CertificateID == "" {
			return errors.New("所选节点尚未绑定证书资源")
		}
		replacement, err := a.selectCertificate()
		if err != nil {
			return err
		}
		if replacement.ID == n.CertificateID {
			return errors.New("替换证书不能与当前已绑定证书相同")
		}
		change := func(st *node.State) error {
			next, e := node.BindCertificate(*st, n.ID, replacement.ID)
			if e != nil {
				return e
			}
			*st = next
			return nil
		}
		if err := a.precheckWizardCandidate(change); err != nil {
			return err
		}
		if !a.confirm("将切换该节点的TLS证书引用，输入yes继续") {
			return errMenuCanceled
		}
		return a.applyWizardMutation(change)
	case "2":
		n, err := a.selectNode()
		if err != nil {
			return err
		}
		change := func(st *node.State) error {
			next, e := node.BindCertificate(*st, n.ID, "")
			if e != nil {
				return e
			}
			*st = next
			return nil
		}
		if err := a.precheckWizardCandidate(change); err != nil {
			return err
		}
		if !a.confirm("将解除该已停用节点的证书引用，输入yes继续") {
			return errMenuCanceled
		}
		return a.applyWizardMutation(change)
	case "3":
		c, err := a.selectCertificate()
		if err != nil {
			return err
		}
		change := func(st *node.State) error {
			next, e := node.RemoveCertificateResource(*st, c.ID)
			if e != nil {
				return e
			}
			*st = next
			return nil
		}
		if err := a.precheckWizardCandidate(change); err != nil {
			return err
		}
		if !a.confirm("确认删除此未被引用的证书资源？输入yes继续") {
			return errMenuCanceled
		}
		return a.applyWizardMutation(change)
	default:
		return menuInvalid()
	}
}

// --- 2. Topology Wizards (PortForwards, Remote Egresses & Node Routing) ---

func (a *app) topologyTaskMenu() error {
	return a.taskMenu("topology", func(choice string) error {
		switch choice {
		case "1":
			for _, command := range [][]string{{"egress", "list"}, {"forward", "list"}, {"egress", "policy", "list"}, {"list"}} {
				if err := a.menuCommand(command); err != nil {
					return err
				}
			}
			return nil
		case "2":
			return a.forwardAddWizard()
		case "3":
			return a.forwardRemoveWizard()
		case "4":
			return a.egressAddWizard()
		case "5":
			return a.egressRemoveWizard()
		case "6":
			return a.routeBindWizard()
		}
		return menuInvalid()
	})
}

func (a *app) selectRouteTarget(promptLabel string) (string, error) {
	var st node.State
	if _, err := os.Lstat(a.store.Root); err == nil {
		if err := a.inspectState(func(s *node.State) error {
			st = s.Clone()
			return s.Validate()
		}); err != nil {
			return "", err
		}
	}
	type routeOption struct {
		id    string
		label string
	}
	options := []routeOption{{id: "", label: "direct（本机直连出站）"}}
	for _, e := range st.Egresses {
		options = append(options, routeOption{
			id:    e.ID,
			label: fmt.Sprintf("%s (%s) [出口 %s %s UDP:%t]", node.Redact(e.Name, st), e.ID, e.Protocol, net.JoinHostPort(e.Server, strconv.Itoa(e.Port)), e.UDP),
		})
	}
	for _, p := range st.EgressPolicies {
		options = append(options, routeOption{
			id:    p.ID,
			label: fmt.Sprintf("%s (%s) [策略 %s 主:%s]", node.Redact(p.Name, st), p.ID, p.Mode, p.Primary),
		})
	}
	w := ui.HumanWriter(os.Stderr)
	for i, opt := range options {
		fmt.Fprintf(w, "%d. %s\n", i+1, opt.label)
	}
	for {
		ans, err := a.wizardPrompt(promptLabel, "1")
		if err != nil {
			return "", err
		}
		if ans == "0" {
			return "", errMenuCanceled
		}
		if strings.EqualFold(ans, "direct") {
			return "", nil
		}
		if idx, convErr := strconv.Atoi(ans); convErr == nil && idx >= 1 && idx <= len(options) {
			return options[idx-1].id, nil
		}
		if i, findErr := egressIndex(st, ans); findErr == nil {
			return st.Egresses[i].ID, nil
		}
		if i, findErr := policyIndex(st, ans); findErr == nil {
			return st.EgressPolicies[i].ID, nil
		}
		a.message("WARN", "请输入列表序号、direct 或稳定出口/策略ID（输入 0 返回）")
	}
}

func (a *app) forwardAddWizard() error {
	name, err := a.menuRequired("端口中转名称")
	if err != nil {
		return err
	}
	listen, err := a.wizardPrompt("本地监听 IP", "0.0.0.0")
	if err != nil {
		return err
	}
	if net.ParseIP(listen) == nil {
		return errors.New("本地监听须为有效 IP 地址（如 0.0.0.0 或 127.0.0.1）")
	}
	port, err := a.wizardPort("本地监听端口（1–65535）", 0, false)
	if err != nil {
		return err
	}
	fmt.Fprintln(ui.HumanWriter(os.Stderr), "\n选择转发传输协议\n1 tcp\n2 udp\n3 tcp+udp\n0 返回")
	netChoice, err := a.wizardPrompt("选择协议", "3")
	if err != nil {
		return err
	}
	var netProto string
	switch strings.ToLower(strings.TrimSpace(netChoice)) {
	case "0":
		return errMenuCanceled
	case "1", "tcp":
		netProto = "tcp"
	case "2", "udp":
		netProto = "udp"
	case "3", "tcp+udp":
		netProto = "tcp+udp"
	default:
		return errors.New("转发协议仅支持 1(tcp)、2(udp) 或 3(tcp+udp)")
	}
	rawTargetHost, err := a.menuRequired("固定转发目标主机 IP 或域名")
	if err != nil {
		return err
	}
	targetHost, err := node.NormalizeEndpointHost(rawTargetHost)
	if err != nil {
		return err
	}
	targetPort, err := a.wizardPort("固定转发目标端口（1–65535）", 0, false)
	if err != nil {
		return err
	}
	egressID, err := a.selectRouteTarget("选择转发出口（1 为 direct，0 返回）")
	if err != nil {
		return err
	}
	fwd := node.PortForward{
		ID:         node.Token(8),
		Name:       name,
		Listen:     listen,
		Port:       port,
		Network:    netProto,
		TargetHost: targetHost,
		TargetPort: targetPort,
		EgressID:   egressID,
		Enabled:    true,
	}
	if err := a.applyWizardMutation(func(st *node.State) error {
		st.Forwards = append(st.Forwards, fwd)
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(ui.HumanWriter(os.Stderr), "已添加端口中转：%s（%s）\n", fwd.Name, fwd.ID)
	return nil
}

func (a *app) forwardRemoveWizard() error {
	var st node.State
	if err := a.inspectState(func(s *node.State) error {
		st = s.Clone()
		return s.Validate()
	}); err != nil {
		return err
	}
	if len(st.Forwards) == 0 {
		return errors.New("当前没有端口中转规则")
	}
	w := ui.HumanWriter(os.Stderr)
	for i, v := range st.Forwards {
		fmt.Fprintf(w, "%d. %s (%s)  %s  %s -> %s  出口:%s\n", i+1, node.Redact(v.Name, st), v.ID, v.Network, net.JoinHostPort(v.Listen, strconv.Itoa(v.Port)), net.JoinHostPort(v.TargetHost, strconv.Itoa(v.TargetPort)), displayEgress(v.EgressID))
	}
	defaultChoice := ""
	if len(st.Forwards) == 1 {
		defaultChoice = "1"
	}
	ans, err := a.wizardPrompt("选择要删除的中转序号或ID，0 返回", defaultChoice)
	if err != nil {
		return err
	}
	if ans == "0" {
		return errMenuCanceled
	}
	targetIdx := -1
	if idx, convErr := strconv.Atoi(ans); convErr == nil && idx >= 1 && idx <= len(st.Forwards) {
		targetIdx = idx - 1
	} else if idx, findErr := forwardIndex(st, ans); findErr == nil {
		targetIdx = idx
	} else {
		return errors.New("请输入有效的端口中转序号或ID")
	}
	targetID := st.Forwards[targetIdx].ID
	change := func(s *node.State) error {
		idx, e := forwardIndex(*s, targetID)
		if e != nil {
			return e
		}
		s.Forwards = append(s.Forwards[:idx], s.Forwards[idx+1:]...)
		return nil
	}
	if err := a.precheckWizardCandidate(change); err != nil {
		return err
	}
	if !a.confirm("确认删除选中的端口中转规则？输入yes继续") {
		return errMenuCanceled
	}
	return a.applyWizardMutation(change)
}

func (a *app) egressAddWizard() error {
	w := ui.HumanWriter(os.Stderr)
	fmt.Fprintln(w, "\n选择远程出口协议\n1 socks5（远程 SOCKS5 代理）\n2 ss2022（Shadowsocks 2022）\n3 reality（VLESS REALITY / Vision）\n4 hysteria2（Hysteria2 UDP/QUIC）\n0 返回")
	protoChoice, err := a.wizardPrompt("选择协议", "2")
	if err != nil {
		return err
	}
	var protocol string
	switch strings.ToLower(strings.TrimSpace(protoChoice)) {
	case "0":
		return errMenuCanceled
	case "1", "socks5":
		protocol = "socks5"
	case "2", "ss2022":
		protocol = "ss2022"
	case "3", "reality":
		protocol = "reality"
	case "4", "hysteria2":
		protocol = "hysteria2"
	default:
		return errors.New("仅支持选择 1(socks5)、2(ss2022)、3(reality) 或 4(hysteria2)")
	}
	name, err := a.menuRequired("远程出口名称")
	if err != nil {
		return err
	}
	rawServer, err := a.menuRequired("远程出口服务器 IP 或域名")
	if err != nil {
		return err
	}
	server, err := node.NormalizeEndpointHost(rawServer)
	if err != nil {
		return err
	}
	port, err := a.wizardPort("远程出口端口（1–65535）", 0, false)
	if err != nil {
		return err
	}
	udpDefault := protocol != "socks5"
	udpSupported, err := a.wizardBool("声明该远程出口支持 UDP 转发？(y/n)", udpDefault)
	if err != nil {
		return err
	}
	e := node.Egress{
		ID:       node.Token(8),
		Name:     name,
		Protocol: protocol,
		Server:   server,
		Port:     port,
		UDP:      udpSupported,
	}
	switch protocol {
	case "socks5":
		username, err := a.wizardPrompt("远程 SOCKS5 用户名（无认证请直接回车留空）", "")
		if err != nil {
			return err
		}
		var password string
		if username != "" {
			password, err = a.secretPrompt("远程 SOCKS5 密码", true)
			if err != nil {
				return err
			}
		}
		e.Socks = &node.RemoteSOCKS{Username: username, Password: password}
	case "ss2022":
		password, err := a.secretPrompt("远程 SS2022 密钥（32字节 Base64 或服务端:用户组合密钥）", true)
		if err != nil {
			return err
		}
		e.Shadowsocks = &node.RemoteSS{Method: node.SS2022Method, Password: password}
	case "reality":
		uuidVal, err := a.secretPrompt("远程 REALITY 用户 UUID", true)
		if err != nil {
			return err
		}
		sni, err := a.menuRequired("远程 REALITY SNI 域名")
		if err != nil {
			return err
		}
		pubKey, err := a.menuRequired("远程 REALITY 公钥（Base64 RawURL）")
		if err != nil {
			return err
		}
		shortID, err := a.menuRequired("远程 REALITY short ID（1–8字节十六进制）")
		if err != nil {
			return err
		}
		fp, err := a.wizardPrompt("浏览器指纹（chrome/firefox/safari/ios/edge）", "chrome")
		if err != nil {
			return err
		}
		e.Reality = &node.RemoteReality{
			UUID:        strings.TrimSpace(uuidVal),
			ServerName:  strings.ToLower(strings.TrimSpace(sni)),
			PublicKey:   strings.TrimSpace(pubKey),
			ShortID:     strings.ToLower(strings.TrimSpace(shortID)),
			Fingerprint: strings.TrimSpace(fp),
		}
	case "hysteria2":
		defaultSNI := ""
		if net.ParseIP(server) == nil {
			defaultSNI = server
		}
		var sni string
		if defaultSNI != "" {
			sni, err = a.wizardPrompt("远程 Hysteria2 TLS SNI 名称", defaultSNI)
		} else {
			sni, err = a.menuRequired("远程 Hysteria2 TLS SNI 名称")
		}
		if err != nil {
			return err
		}
		password, err := a.secretPrompt("远程 Hysteria2 密码", true)
		if err != nil {
			return err
		}
		caPath, err := a.wizardPrompt("远程自定义 CA 证书路径（使用公共可信证书请留空）", "")
		if err != nil {
			return err
		}
		var caPEM string
		if caPath != "" {
			b, readErr := readLimited(caPath, 256<<10)
			if readErr != nil {
				return errors.New("无法读取远程 Hysteria2 CA 证书文件")
			}
			caPEM = string(b)
		}
		e.HY2 = &node.RemoteHY2{
			ServerName:     strings.ToLower(strings.TrimSpace(sni)),
			Password:       password,
			CertificatePEM: caPEM,
		}
	}

	if err := a.applyWizardMutation(func(st *node.State) error {
		st.Egresses = append(st.Egresses, e)
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(w, "已添加远程出口：%s（%s）\n", e.Name, e.ID)
	return nil
}

func (a *app) egressRemoveWizard() error {
	var st node.State
	if err := a.inspectState(func(s *node.State) error {
		st = s.Clone()
		return s.Validate()
	}); err != nil {
		return err
	}
	if len(st.Egresses) == 0 {
		return errors.New("当前没有已配置的远程出口")
	}
	w := ui.HumanWriter(os.Stderr)
	for i, e := range st.Egresses {
		fmt.Fprintf(w, "%d. %s (%s)  %s  %s  UDP:%t\n", i+1, node.Redact(e.Name, st), e.ID, e.Protocol, net.JoinHostPort(e.Server, strconv.Itoa(e.Port)), e.UDP)
	}
	defaultChoice := ""
	if len(st.Egresses) == 1 {
		defaultChoice = "1"
	}
	ans, err := a.wizardPrompt("选择要删除的出口序号或ID，0 返回", defaultChoice)
	if err != nil {
		return err
	}
	if ans == "0" {
		return errMenuCanceled
	}
	targetIdx := -1
	if idx, convErr := strconv.Atoi(ans); convErr == nil && idx >= 1 && idx <= len(st.Egresses) {
		targetIdx = idx - 1
	} else if idx, findErr := egressIndex(st, ans); findErr == nil {
		targetIdx = idx
	} else {
		return errors.New("请输入有效的远程出口序号或ID")
	}
	targetID := st.Egresses[targetIdx].ID
	change := func(s *node.State) error {
		idx, e := egressIndex(*s, targetID)
		if e != nil {
			return e
		}
		s.Egresses = append(s.Egresses[:idx], s.Egresses[idx+1:]...)
		return nil
	}
	if err := a.precheckWizardCandidate(change); err != nil {
		return err
	}
	if !a.confirm("确认删除此未被引用的远程出口？输入yes继续") {
		return errMenuCanceled
	}
	return a.applyWizardMutation(change)
}

func (a *app) routeBindWizard() error {
	n, err := a.selectNode()
	if err != nil {
		return err
	}
	fmt.Fprintf(ui.HumanWriter(os.Stderr), "当前入口节点 %s（%s）路由：%s\n", n.Name, n.ID, displayEgress(n.EgressID))
	targetEgressID, err := a.selectRouteTarget("选择目标出站路由（1 切回 direct，0 返回）")
	if err != nil {
		return err
	}
	return a.applyWizardMutation(func(st *node.State) error {
		found, e := st.Find(n.ID)
		if e != nil {
			return e
		}
		found.EgressID = targetEgressID
		return nil
	})
}

// --- 3. Device & Subscription Quick Wizards ---

func (a *app) selectDevice() (node.DeviceProfile, error) {
	var st node.State
	if err := a.inspectState(func(s *node.State) error {
		st = s.Clone()
		return s.Validate()
	}); err != nil {
		return node.DeviceProfile{}, err
	}
	if len(st.Devices) == 0 {
		return node.DeviceProfile{}, errors.New("当前尚无设备配置；请先创建设备配置")
	}
	w := ui.HumanWriter(os.Stderr)
	for i, p := range st.Devices {
		fmt.Fprintf(w, "%d. %s (%s)  策略=%s  分流=%s  绑定=%d  停用=%t\n", i+1, node.Redact(p.Name, st), p.ID, p.Strategy, p.Routing, len(p.Bindings), p.Disabled)
	}
	defaultChoice := ""
	if len(st.Devices) == 1 {
		defaultChoice = "1"
	}
	for {
		ans, err := a.wizardPrompt("设备序号或ID，0 返回", defaultChoice)
		if err != nil {
			return node.DeviceProfile{}, err
		}
		if ans == "0" {
			return node.DeviceProfile{}, errMenuCanceled
		}
		if idx, convErr := strconv.Atoi(ans); convErr == nil && idx >= 1 && idx <= len(st.Devices) {
			return st.Devices[idx-1], nil
		}
		if p, findErr := node.FindDevice(&st, ans); findErr == nil {
			return *p, nil
		}
		a.message("WARN", "请输入列表中的设备序号、稳定ID，或输入 0 返回")
	}
}

func (a *app) deviceCreateWizard() error {
	w := ui.HumanWriter(os.Stderr)
	name, err := a.menuRequired("设备名称")
	if err != nil {
		return err
	}
	var bindings []node.DeviceBinding
	seen := map[string]bool{}
	for {
		n, err := a.selectNode()
		if err != nil {
			return err
		}
		u, err := a.selectUser(n)
		if err != nil {
			return err
		}
		epID := "default"
		eps := node.EffectiveEndpoints(n)
		if len(eps) > 1 {
			for i, ep := range eps {
				fmt.Fprintf(w, "%d. %s (%s:%d)\n", i+1, ep.ID, ep.Host, ep.Port)
			}
			epAns, err := a.wizardPrompt("连接端点序号或ID", "1")
			if err != nil {
				return err
			}
			if epAns == "0" {
				return errMenuCanceled
			}
			if idx, convErr := strconv.Atoi(epAns); convErr == nil && idx >= 1 && idx <= len(eps) {
				epID = eps[idx-1].ID
			} else {
				epID = epAns
			}
		}
		key := n.ID + ":" + u + ":" + epID
		if seen[key] {
			a.message("WARN", "该节点凭据已添加，请勿重复绑定")
		} else {
			seen[key] = true
			bindings = append(bindings, node.DeviceBinding{NodeID: n.ID, UserID: u, EndpointID: epID})
			fmt.Fprintf(w, "已加入绑定 #%d：%s（%s）\n", len(bindings), n.Name, n.ID)
		}
		more, err := a.wizardBool("是否继续绑定其他节点凭据？(y/n)", false)
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}

	fmt.Fprintln(w, "\n选择节点切换策略\n1 manual（手动选择，默认）\n2 auto（自动测速择优 URLTest）\n3 fallback（Mihomo 有序主备，sing-box 完整配置不支持）\n0 返回")
	stratChoice, err := a.wizardPrompt("选择策略", "1")
	if err != nil {
		return err
	}
	var strategy string
	switch strings.ToLower(strings.TrimSpace(stratChoice)) {
	case "0":
		return errMenuCanceled
	case "1", "manual":
		strategy = "manual"
	case "2", "auto":
		strategy = "auto"
	case "3", "fallback":
		strategy = "fallback"
	default:
		return errors.New("策略仅支持 1(manual)、2(auto) 或 3(fallback)")
	}

	testURL := ""
	allowDegradedAuto := false
	interval := 0
	tolerance := 0
	if strategy == "auto" || strategy == "fallback" {
		testURL, err = a.menuRequired("受控 HTTPS 测速/健康探测地址（如 https://cp.cloudflare.com/generate_204）")
		if err != nil {
			return err
		}
		interval = 300
		if strategy == "auto" {
			tolerance = 50
			allowDegradedAuto, err = a.wizardBool("是否允许导出 Mihomo 降级版 auto 策略组（若同时发布 Mihomo 完整配置/订阅请选 y）？(y/n)", false)
			if err != nil {
				return err
			}
		}
	}

	fmt.Fprintln(w, "\n选择客户端分流与防污染 DNS 预设\n1 global（默认全局代理）\n2 basic（局域网与保留私有网段直连）\n3 cn-direct（国内外分流 + 加密远端 DNS 防泄漏）\n4 global-secure-dns（全局代理 + 加密远端 DNS）\n0 返回")
	routeChoice, err := a.wizardPrompt("选择分流模式", "1")
	if err != nil {
		return err
	}
	var routing string
	switch strings.ToLower(strings.TrimSpace(routeChoice)) {
	case "0":
		return errMenuCanceled
	case "1", "global":
		routing = "global"
	case "2", "basic":
		routing = "basic"
	case "3", "cn-direct":
		routing = "cn-direct"
	case "4", "global-secure-dns":
		routing = "global-secure-dns"
	default:
		return errors.New("分流模式仅支持 1(global)、2(basic)、3(cn-direct) 或 4(global-secure-dns)")
	}

	enableTUN, err := a.wizardBool("是否开启客户端 TUN 入站模式？(y/n)", false)
	if err != nil {
		return err
	}
	enableCtrl, err := a.wizardBool("是否开启仅绑定 127.0.0.1 的本地控制端口？(y/n)", false)
	if err != nil {
		return err
	}
	var ctrl *node.ClientController
	if enableCtrl {
		ctrlPort, err := a.wizardPort("本地控制端口（1–65535）", 9090, false)
		if err != nil {
			return err
		}
		ctrl = &node.ClientController{
			Enabled: true,
			Port:    ctrlPort,
			Secret:  node.Token(16),
		}
	}
	defaultSubFormat, err := a.wizardPrompt("统一订阅未识别客户端时的默认格式（留空自动回退；可选 sing-box/mihomo/provider/base64/uri）", "")
	if err != nil {
		return err
	}

	profile := node.DeviceProfile{
		ID:                        node.Token(8),
		Name:                      name,
		Strategy:                  strategy,
		AllowDegradedAuto:         allowDegradedAuto,
		Routing:                   routing,
		DefaultSubscriptionFormat: strings.TrimSpace(defaultSubFormat),
		TUN:                       enableTUN,
		Controller:                ctrl,
		TestURL:                   testURL,
		IntervalSeconds:           interval,
		ToleranceMS:               tolerance,
		Bindings:                  bindings,
	}
	if err := a.applyWizardMutation(func(st *node.State) error {
		return applyDevices(st, []node.DeviceProfile{profile})
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "设备ID：%s\n", profile.ID)
	return nil
}

func (a *app) subscriptionIssueWizard() error {
	w := ui.HumanWriter(os.Stderr)
	c, initialized, err := a.publisherConfig()
	if err != nil {
		return err
	}
	if !initialized {
		return errors.New("尚未初始化在线订阅发布目录；请先运行 qingnode subscription init --dir <独立目录> 并部署可信 HTTPS")
	}
	fmt.Fprintln(w, "令牌只写入所选设备的权限 600 私有文件，不持久化明文到状态目录。")
	p, err := a.selectDevice()
	if err != nil {
		return err
	}
	if p.Disabled {
		return errors.New("所选设备已停用；请先启用后再签发令牌")
	}
	snap, err := subscription.Read(c.Directory)
	if err != nil {
		return err
	}
	hasExisting := false
	for _, r := range snap.Records {
		if r.DeviceID == p.ID {
			hasExisting = true
			break
		}
	}
	subCmd := "issue"
	var extra []string
	if hasExisting {
		if !a.confirm("该设备已有下载令牌记录；继续将轮换令牌并使旧订阅链接失效。输入yes继续") {
			return errMenuCanceled
		}
		subCmd = "rotate"
		extra = append(extra, "--yes")
	}
	origin, err := a.menuRequired("已有可信HTTPS源地址（如 https://sub.example.com）")
	if err != nil {
		return err
	}
	if _, err := parseSubscriptionOrigin(origin); err != nil {
		return err
	}
	out, err := a.menuRequired("新令牌私有文件路径")
	if err != nil {
		return err
	}
	if err := a.probeOutput(out); err != nil {
		return err
	}
	args := append([]string{"subscription", subCmd, "--device", p.ID, "--base-url", origin, "--out", out}, extra...)
	if err := a.menuCommand(args); err != nil {
		return err
	}
	showQR, err := a.wizardBool("是否在当前终端直接显示统一订阅二维码 (/s/<TOKEN>)？(y/n)", false)
	if err != nil {
		if errors.Is(err, errMenuCanceled) {
			return nil
		}
		return err
	}
	if !showQR {
		return nil
	}
	raw, err := readTopologyFile(out)
	if err != nil {
		return err
	}
	var m tokenMaterial
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&m); err != nil {
		return errors.New("无法解析刚签发的令牌私有文件")
	}
	targetURL := m.UnifiedURL
	if targetURL == "" && len(m.Links) > 0 {
		targetURL = m.Links[0].URL
	}
	if targetURL == "" {
		return errors.New("令牌材料中不包含公开 HTTPS 订阅链接，无法展示二维码")
	}
	return a.printTerminalQR(targetURL)
}
