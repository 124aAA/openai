package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"qingnode/internal/ui"
)

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
			a.message("ERROR", err.Error())
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
func (a *app) quickMenu() error {
	return a.taskMenu("quick", func(choice string) error {
		switch choice {
		case "1":
			return a.installWizard(false, "", false)
		case "2":
			selected, err := a.guidedProtocol()
			if err != nil {
				return err
			}
			return a.installWizardOptions(false, selected.Protocol, false, selected.NAT)
		case "3":
			return a.installWizardOptions(false, "", false, true)
		case "4":
			return a.menuCommand([]string{"protocols", "list"})
		}
		return menuInvalid()
	})
}
func (a *app) exportTaskMenu() error {
	return a.taskMenu("exports", func(choice string) error {
		switch choice {
		case "1":
			return a.exportWizard()
		case "2":
			return a.menuCommand([]string{"device", "list"})
		case "3":
			n, err := a.selectNode()
			if err != nil {
				return err
			}
			u, err := a.selectUser(n)
			if err != nil {
				return err
			}
			name, err := a.menuRequired("设备名称")
			if err != nil {
				return err
			}
			fmt.Fprintln(ui.HumanWriter(os.Stderr), "本设备仅绑定所选节点和凭据，默认手动选择；自动/主备策略请在完整Profile中明确配置。")
			return a.menuCommand([]string{"device", "create", "--name", name, "--binding", n.ID + ":" + u, "--strategy", "manual"})
		case "4":
			id, err := a.menuRequired("设备ID或名称（先用2查看）")
			if err != nil {
				return err
			}
			format, err := a.wizardPrompt("完整配置格式 sing-box / mihomo", "sing-box")
			if err != nil {
				return err
			}
			version := "1.14.0"
			if format == "mihomo" {
				version = "1.19.30"
			} else if format != "sing-box" {
				return errors.New("这里仅导出sing-box或mihomo完整配置")
			}
			out, err := a.menuRequired("新私有配置文件路径")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"export", "--device", id, "--format", format, "--client-version", version, "--out", out})
		case "5":
			return a.menuCommand([]string{"subscription", "status"})
		case "6":
			fmt.Fprintln(ui.HumanWriter(os.Stderr), "须先按订阅指南初始化独立发布目录并部署可信HTTPS；这里不会接管80/443。令牌只写所选设备的私有文件，不显示在普通状态页。")
			id, err := a.menuRequired("设备ID或名称")
			if err != nil {
				return err
			}
			origin, err := a.menuRequired("已有可信HTTPS源地址")
			if err != nil {
				return err
			}
			out, err := a.menuRequired("新令牌私有文件路径")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"subscription", "issue", "--device", id, "--base-url", origin, "--out", out})
		case "7":
			id, err := a.menuRequired("仅撤销此设备下载权限：设备ID或名称")
			if err != nil {
				return err
			}
			if !a.confirm("将拒绝此设备后续下载，已下载的代理凭据仍有效。输入yes继续") {
				return errMenuCanceled
			}
			return a.menuCommand([]string{"subscription", "revoke", "--device", id, "--yes"})
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
			id, err := a.menuRequired("证书资源ID或名称")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"certificate", "status", "--id", id})
		case "3":
			file, err := a.menuRequired("权限600的证书资源JSON文件（私钥不从命令行输入）")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"certificate", "import", "--file", file})
		case "4":
			n, err := a.selectNode()
			if err != nil {
				return err
			}
			id, err := a.menuRequired("已有证书资源ID或名称")
			if err != nil {
				return err
			}
			return a.menuCommand([]string{"certificate", "bind", "--id", id, "--node", n.ID})
		case "5":
			return a.maintenanceMenu()
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
			for _, command := range [][]string{{"egress", "list"}, {"forward", "list"}, {"egress", "policy", "list"}, {"list"}} {
				if err := a.menuCommand(command); err != nil {
					return err
				}
			}
			return nil
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
		}
		return menuInvalid()
	})
}
func (a *app) maintenanceTaskMenu() error {
	return a.taskMenu("maintenance-system", func(choice string) error {
		switch strings.TrimSpace(choice) {
		case "1":
			return a.serviceMenu()
		case "2":
			return a.maintenanceMenu()
		case "3":
			return a.menuCommand([]string{"capabilities"})
		case "4":
			return a.menuCommand([]string{"monitor", "status"})
		case "5":
			return a.menuCommand([]string{"check-updates"})
		}
		return menuInvalid()
	})
}
