package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"qingnode/internal/node"
	"strings"
	"time"
)

func bootstrap(args []string) error {
	bin, e := os.Executable()
	if e != nil {
		return e
	}
	dir := filepath.Dir(bin)
	if e = node.VerifyBundle(dir); e != nil {
		return fmt.Errorf("尚未安装，请在完整发行包中运行 sudo bash install.sh：%w", e)
	}
	if len(args) > 0 {
		args = args[1:] // install flags are shared with the bootstrap.
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(dir, "install.sh"), "--reinstall"}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func (a *app) network(args []string) error {
	if a.offline {
		return errors.New("离线模式不修改或查询宿主网络参数")
	}
	if len(args) == 0 {
		args = []string{"status"}
	}
	if len(args) != 1 {
		return errors.New("用法：network status|bbr")
	}
	h := node.Host{}
	if args[0] == "status" {
		out, e := h.BBRStatus()
		fmt.Println(out)
		return e
	}
	if args[0] != "bbr" {
		return errors.New("只支持查看状态或启用系统内核 BBR")
	}
	return a.store.WithLock(func() error {
		changed, e := h.EnableBBR()
		if e != nil {
			return e
		}
		if changed {
			a.message("SUCCESS", "已启用 BBR + fq；既有连接和网卡队列是否变化由内核决定")
		} else {
			a.message("SUCCESS", "已经是 BBR + fq，没有重复修改")
		}
		return nil
	})
}
func (a *app) firewall(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	if len(args) != 1 {
		return errors.New("用法：firewall status|enable|disable|sync")
	}
	if a.offline {
		return errors.New("离线模式不操作本机防火墙")
	}
	if args[0] == "status" {
		for _, c := range [][]string{{"ufw", "status", "verbose"}, {"firewall-cmd", "--state"}, {"nft", "list", "tables"}, {"iptables", "-S", "INPUT"}} {
			if _, e := exec.LookPath(c[0]); e != nil {
				continue
			}
			b, e := node.Run(8*time.Second, c[0], c[1:]...)
			fmt.Printf("\n%s：\n%s\n", c[0], node.Redact(string(b)))
			if e != nil {
				a.message("WARN", c[0]+" 查询未成功")
			}
		}
		fmt.Println("只对已启用 UFW 的本项目规则提供自动管理；firewalld/nftables/iptables 的复杂策略请手动处理。云安全组须另行检查。")
		return a.locked(func(s *node.State) error {
			fmt.Printf("项目自动防火墙模式：%s（空为手动）\n", s.Firewall)
			for _, n := range s.Nodes {
				if n.Enabled {
					fmt.Println(n.Name + " 需要 " + node.PortLabel(n))
					if n.Certificate != nil && n.Certificate.Mode == "acme" {
						fmt.Println("ACME 还需要 TCP 80；由用户管理该共享端口")
					}
				}
			}
			return nil
		})
	}
	if args[0] == "sync" {
		return a.locked(func(s *node.State) error {
			if s.Firewall != "ufw" {
				return errors.New("尚未启用项目 UFW 管理")
			}
			return (node.Firewall{}).Sync(*s, true)
		})
	}
	if args[0] != "enable" && args[0] != "disable" {
		return errors.New("未知防火墙操作")
	}
	return a.mutate(func(s *node.State) error {
		if args[0] == "enable" {
			s.Firewall = "ufw"
		} else {
			s.Firewall = ""
		}
		return nil
	})
}
func (a *app) selfUpdate(args []string) error {
	if a.offline {
		return errors.New("离线模式不更新已安装的管理器")
	}
	f := fs("self-update")
	bundle := f.String("bundle", "", "已解压并核验来源的新版发行包目录")
	repo := f.String("repo", "", "GitHub 仓库 owner/repo；默认 124aAA/openai")
	v := f.String("version", "", "明确目标 tag，例如 v0.2.4")
	if e := parse(f, args); e != nil {
		return e
	}
	if *bundle != "" && *repo != "" {
		return errors.New("本地包与 GitHub 下载二选一")
	}
	installer := "/usr/local/lib/qingnode/install.sh"
	cmdArgs := []string{"--reinstall"}
	if *bundle != "" {
		abs, e := filepath.Abs(*bundle)
		if e != nil {
			return e
		}
		if i, e := os.Lstat(abs); e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("本地发行包目录无效")
		}
		installer = filepath.Join(abs, "install.sh")
		if e := node.VerifyBundle(abs); e != nil {
			return e
		}
		if _, e := os.Stat(filepath.Join(abs, "SHA256SUMS")); e != nil {
			return e
		}
	} else if *v != "" {
		if *repo == "" {
			*repo = "124aAA/openai"
		}
		cmdArgs = append(cmdArgs, "--repo", *repo, "--version", *v)
	} else {
		return errors.New("需要 --bundle 新版目录，或 --version v版本；默认下载 124aAA/openai 的发行包")
	}
	if i, e := os.Lstat(installer); e != nil || !i.Mode().IsRegular() {
		return errors.New("未找到普通文件形式的安装器")
	}
	// Do not hold the state lock while the bootstrap invokes the new manager.
	cmd := exec.Command("bash", append([]string{installer}, cmdArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("管理器更新未完成；检查安装日志：%w", e)
	}
	a.message("SUCCESS", "管理器更新完成；重新打开 qingnode 菜单使用新版本")
	return nil
}
func (a *app) coreVersions() error {
	return a.locked(func(s *node.State) error {
		fmt.Println("当前版本：" + s.CoreVersion)
		r, e := node.LatestStable("SagerNet/sing-box")
		if e != nil {
			return e
		}
		fmt.Printf("官方最新稳定版：%s\n当前管理器适配：%t\n", r.Tag, node.SupportedVersion(strings.TrimPrefix(r.Tag, "v")))
		return nil
	})
}
