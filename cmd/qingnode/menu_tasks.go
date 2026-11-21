package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

// The candidate is built once under the Store lock. Printing its derived
// impact never regenerates credentials or authorizes a different later State.
func (a *app) previewMenuMutation(candidate node.State) error {
	if a.menuPreviewDone {
		return nil
	}
	impact, err := a.store.Preview(candidate)
	if err != nil {
		return err
	}
	w := ui.HumanWriter(os.Stderr)
	label := func(value bool) string {
		if value {
			return "会变化"
		}
		return "保持"
	}
	fmt.Fprintln(w, "本次实际影响（校验后统一应用）：")
	fmt.Fprintf(w, "客户端链接/配置：%s；服务器运行配置：%s；宿主网络/服务效果：%s。\n", label(impact.ClientExport), label(impact.ServerRuntime), label(impact.HostEffects))
	if impact.NeedsRestart {
		fmt.Fprintln(w, "需要按现有启用策略启动、重启或停止核心，已有连接可能断开。")
	} else {
		fmt.Fprintln(w, "无需重启核心，保持原运行/停止和开机自启状态。")
	}
	if impact.RepairDerived {
		fmt.Fprintln(w, "派生文件需要重建；原恢复材料会保留。")
	}
	for _, changed := range impact.Nodes {
		if !changed.Changed && !changed.ClientExport && !changed.ServerRuntime && !changed.Display && !changed.HostEffects {
			continue
		}
		name := node.Redact(changed.Name, candidate)
		fmt.Fprintf(w, "节点：%s（%s）\n", name, changed.ID)
		for _, n := range candidate.Nodes {
			if n.ID == changed.ID {
				fmt.Fprintf(w, "本地监听：%s；客户端连接：%s；传输：%s。\n", node.PortLabel(n), net.JoinHostPort(n.Host, strconv.Itoa(node.EffectiveConnectPort(n))), strings.Join(node.Networks(n), "+"))
			}
		}
	}
	for _, fwd := range impact.Forwards {
		if !fwd.Changed && !fwd.ServerRuntime && !fwd.Display && !fwd.HostEffects {
			continue
		}
		fmt.Fprintf(w, "端口中转：%s（%s）\n", node.Redact(fwd.Name, candidate), fwd.ID)
	}
	for _, dev := range impact.Devices {
		if !dev.Changed && !dev.ClientExport && !dev.Display {
			continue
		}
		fmt.Fprintf(w, "设备配置：%s（%s）\n", node.Redact(dev.Name, candidate), dev.ID)
	}
	if a.offline {
		fmt.Fprintln(w, "离线环境只保存配置；上面的运行变化未在宿主执行。")
	}
	a.menuPreviewDone = true
	return nil
}

func (a *app) menuCommand(args []string) error {
	return a.withMenuPreview(func() error { return a.command(args) })
}

func (a *app) withMenuPreview(run func() error) error {
	before, done := a.menuPreview, a.menuPreviewDone
	a.menuPreview, a.menuPreviewDone = true, false
	defer func() { a.menuPreview, a.menuPreviewDone = before, done }()
	return run()
}

func (a *app) taskMenu(key string, action func(string) error) error {
	for {
		choice, err := a.menuChoice(key)
		if err != nil {
			return err
		}
		if choice == "0" {
			return nil
		}
		if err = action(choice); errors.Is(err, io.EOF) {
			return err
		} else if err != nil && !errors.Is(err, errMenuCanceled) {
			a.message("ERROR", node.Redact(err.Error()))
		}
	}
}
func menuInvalid() error { return errors.New("请选择菜单中的数字，或输入0返回") }
func (a *app) menuRequired(label string) (string, error) {
	value, err := a.wizardPrompt(label+"（:cancel返回）", "")
	if err == nil && value == "" {
		err = errors.New("此项不能留空；输入:cancel取消，不会提交表单")
	}
	return value, err
}
func (a *app) exportTaskMenu() error {
	return a.taskMenu("exports", func(choice string) error {
		switch choice {
		case "1":
			return a.menuCommand([]string{"device", "list"})
		case "2":
			return a.deviceCreateWizard()
		case "3":
			p, err := a.selectDevice()
			if err != nil {
				return err
			}
			format, err := a.wizardPrompt("完整配置格式 sing-box / mihomo", "sing-box")
			if err != nil {
				return err
			}
			defaultVer := "1.14.0"
			if format == "mihomo" {
				defaultVer = "1.19.30"
			} else if format != "sing-box" {
				return errors.New("这里仅导出sing-box或mihomo完整配置")
			}
			version, err := a.wizardPrompt("目标客户端版本", defaultVer)
			if err != nil {
				return err
			}
			out, err := a.menuRequired("新私有配置文件路径")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"export", "--device", p.ID, "--format", format, "--client-version", version, "--out", out})
		case "4":
			return a.menuCommand([]string{"subscription", "status"})
		case "5":
			return a.subscriptionIssueWizard()
		case "6":
			p, err := a.selectDevice()
			if err != nil {
				return err
			}
			if !a.confirm("将拒绝此设备后续下载，已下载的代理凭据仍有效。输入yes继续") {
				return errMenuCanceled
			}
			return a.menuCommand([]string{"subscription", "revoke", "--device", p.ID, "--yes"})
		case "7":
			file, err := a.menuRequired("权限600的设备配置批量JSON文件")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"device", "apply", "--file", file})
		}
		return menuInvalid()
	})
}
func (a *app) diagnosticTaskMenu() error {
	return a.taskMenu("tests", func(choice string) error {
		switch choice {
		case "1":
			return a.menuCommand([]string{"diagnose"})
		case "2":
			return a.menuCommand([]string{"probe", "local"})
		case "3", "4":
			fmt.Fprintln(ui.HumanWriter(os.Stderr), "测试由这台服务器发起，不能代表手机所在运营商；默认light，8个样本、20秒上限，不下载大文件。HTTPS成功不代表UDP可用。")
			target, err := a.menuRequired("自己的受控HTTPS目标")
			if err != nil {
				return err
			}
			args := []string{"probe", "run", "--path", "server-outbound", "--target", target, "--mode", "light", "--samples", "8", "--timeout", "20s"}
			if choice == "4" {
				n, err := a.selectNode()
				if err != nil {
					return err
				}
				u, err := a.selectUser(n)
				if err != nil {
					return err
				}
				args[3] = "client-proxy"
				args = append(args, "--id", n.ID, "--user", u)
			}
			out, err := a.wizardPrompt("新脱敏JSON报告路径（留空仅终端）", "")
			if err != nil {
				return err
			}
			if out != "" {
				args = append(args, "--out", out)
			}
			return a.menuCommand(args)
		case "5":
			return a.menuCommand([]string{"ports"})
		case "6":
			return a.publicCheckWizard()
		case "7":
			return a.menuCommand([]string{"monitor", "status"})
		case "8":
			return a.menuCommand([]string{"status"})
		}
		return menuInvalid()
	})
}
func (a *app) certificateTaskMenu() error {
	return a.taskMenu("certificates", func(choice string) error {
		switch choice {
		case "1":
			return a.menuCommand([]string{"certificate", "list"})
		case "2":
			c, err := a.selectCertificate()
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"certificate", "status", "--id", c.ID})
		case "3":
			return a.certificateCreateWizard()
		case "4":
			return a.certificateUpdateWizard()
		case "5":
			return a.certificateBindWizard()
		case "6":
			return a.certificateUnbindOrRemoveWizard()
		case "7":
			file, err := a.menuRequired("权限600的证书资源JSON文件（私钥不从命令行输入）")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"certificate", "import", "--file", file})
		}
		return menuInvalid()
	})
}
func (a *app) advancedTaskMenu() error {
	return a.taskMenu("advanced", func(choice string) error {
		switch choice {
		case "1":
			n, err := a.selectNode()
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"endpoint", "material", "--id", n.ID})
		case "2":
			return a.topologyTaskMenu()
		case "3":
			file, err := a.menuRequired("私有、类型化拓扑JSON文件")
			if err != nil {
				return err
			}
			// The product validates and previews this one candidate under its
			// existing mutation lock. No external JSON fields become shell code.
			return a.menuCommand([]string{"topology", "batch", "--file", file})
		case "4":
			if err := a.menuCommand([]string{"dns", "show"}); err != nil {
				return err
			}
			fmt.Fprintln(ui.HumanWriter(os.Stderr), "需要解析诊断时：qingnode dns diagnose --name 自己的域名 --samples 3；只调整本项目resolver，不覆盖/etc/resolv.conf。")
			return nil
		case "5":
			if err := a.menuCommand([]string{"hy2", "show"}); err != nil {
				return err
			}
			fmt.Fprintln(ui.HumanWriter(os.Stderr), "性能变更先用qingnode hy2 plan生成带测量依据的计划，再review/apply；默认不调参，不把系统TCP BBR当作HY2 QUIC开关。")
			return nil
		case "6":
			return a.systemMenu()
		case "7":
			return a.certificateTaskMenu()
		case "8":
			return a.exportTaskMenu()
		case "9":
			return a.menuCommand([]string{"capabilities"})
		case "10":
			return a.menuCommand([]string{"protocols", "list"})
		}
		return menuInvalid()
	})
}
