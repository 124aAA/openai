package main

import (
	"encoding/json"
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
	return a.networkWithHost(args, node.NetworkHost{})
}

func (a *app) networkWithHost(args []string, h node.NetworkHost) error {
	if a.offline {
		return errors.New("离线模式不修改或查询宿主网络参数")
	}
	if len(args) == 0 {
		args = []string{"status"}
	}
	if args[0] == "status" {
		f := fs("network status")
		asJSON := f.Bool("json", false, "输出版本化 JSON 状态")
		if e := parse(f, args[1:]); e != nil {
			return e
		}
		if h.ProcessPID == 0 {
			if backend, ok := a.store.Backend.(interface{ PID() int }); ok {
				h.ProcessPID = backend.PID()
			}
		}
		s := h.Status()
		if *asJSON {
			b, e := json.MarshalIndent(s, "", "  ")
			if e != nil {
				return e
			}
			fmt.Println(string(b))
		} else {
			fmt.Print(node.FormatNetworkStatus(s))
		}
		return nil
	}
	if args[0] == "restore" {
		f := fs("network restore")
		id := f.String("snapshot", "", "原始恢复快照 ID")
		preview := f.Bool("preview", false, "只读预览恢复，不写文件或运行参数")
		if e := parse(f, args[1:]); e != nil {
			return e
		}
		if *id == "" {
			return errors.New("恢复需要 --snapshot 完整快照ID；先用 network status 查看")
		}
		p, e := h.RestorePlan(*id)
		if e != nil {
			return e
		}
		fmt.Print(node.FormatNetworkPlan(p))
		if *preview {
			return nil
		}
		r, e := h.Restore(*id)
		if e != nil {
			return e
		}
		fmt.Printf("宿主网络恢复完成；已恢复 %d 项，保留外部手动修改 %d 项。原始材料：%s\n", len(r.Restored), len(r.Preserved), r.RecoveryFile)
		for _, key := range r.Preserved {
			fmt.Println("保持外部值：" + key)
		}
		return nil
	}
	if args[0] != "plan" && args[0] != "apply" && args[0] != "bbr" {
		return errors.New("用法：network status [--json] | plan|apply [--tcp 名称] [--qdisc fq|fq_codel] [--rmem-max 字节] [--wmem-max 字节] [--preview] | restore --snapshot ID [--preview]；bbr 为显式 BBR+fq 应用别名")
	}
	f := fs("network " + args[0])
	tcp := f.String("tcp", "", "明确选择内核已列出的 TCP 算法")
	qdisc := f.String("qdisc", "", "新建队列默认值 fq 或 fq_codel，不改当前接口队列")
	rmem := f.Uint64("rmem-max", 0, "明确设置 socket 接收缓冲上限字节，0 保持原值，最大 16 MiB")
	wmem := f.Uint64("wmem-max", 0, "明确设置 socket 发送缓冲上限字节，0 保持原值，最大 16 MiB")
	preview := f.Bool("preview", false, "只读预览，不写入宿主参数或恢复记录")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	if args[0] == "bbr" {
		if *tcp != "" || *qdisc != "" || *rmem != 0 || *wmem != 0 {
			return errors.New("network bbr 固定选择 bbr+fq；其他参数请使用 network plan/apply")
		}
		*tcp, *qdisc = "bbr", "fq"
	}
	p, e := h.Plan(node.NetworkRequest{TCP: *tcp, Qdisc: *qdisc, RmemMax: *rmem, WmemMax: *wmem})
	if e != nil {
		return e
	}
	fmt.Print(node.FormatNetworkPlan(p))
	if args[0] == "plan" || *preview {
		return nil
	}
	r, e := h.Apply(p)
	if e != nil {
		return e
	}
	if !r.Changed {
		a.message("SUCCESS", "没有参数或受管持久文件需要改变")
	} else {
		fmt.Printf("宿主网络应用完成，字段已逐项读回。快照：%s\n恢复材料：%s\n恢复命令：qingnode network restore --snapshot %s\n", r.SnapshotID, r.RecoveryFile, r.SnapshotID)
	}
	return nil
}
func (a *app) firewall(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	f := fs("firewall " + args[0])
	backend := f.String("backend", "ufw", "enable时显式选择ufw或firewalld；不启动全局防火墙")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	if args[0] != "enable" && flagSet(f, "backend") {
		return errors.New("--backend仅用于firewall enable")
	}
	if *backend != "ufw" && *backend != "firewalld" {
		return errors.New("防火墙后端仅支持ufw或firewalld")
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
		fmt.Println("只对显式选择且已运行的UFW/firewalld增加本项目规则；不启用、清空或重载全局防火墙。云安全组须另行检查。")
		return a.inspectState(func(s *node.State) error {
			fmt.Printf("项目自动防火墙模式：%s（空为手动）\n", s.Firewall)
			for _, n := range s.Nodes {
				if n.Enabled {
					fmt.Println(n.Name + " 需要 " + node.PortLabel(n))
					if n.Certificate != nil && n.Certificate.Mode == "acme" {
						fmt.Println("ACME 还需要 TCP 80；由用户管理该共享端口")
					}
				}
			}
			for _, v := range s.Forwards {
				if v.Enabled {
					fmt.Print(node.Redact(fmt.Sprintf("中转%s 需要本地%d/%s；目标端口不作为本机入站开放\n", v.Name, v.Port, v.Network), *s))
				}
			}
			for _, e := range s.Egresses {
				if e.WireGuard != nil && e.WireGuard.ListenPort > 0 {
					fmt.Printf("用户态WireGuard %s 需要本地%d/udp；只管理自身UFW规则\n", e.ID, e.WireGuard.ListenPort)
				}
			}
			return nil
		})
	}
	if args[0] == "sync" {
		return a.locked(func(s *node.State) error {
			if s.Firewall != "ufw" && s.Firewall != "firewalld" {
				return errors.New("尚未启用项目自动防火墙管理")
			}
			return (node.Firewall{}).Sync(*s, true)
		})
	}
	if args[0] != "enable" && args[0] != "disable" {
		return errors.New("未知防火墙操作")
	}
	return a.mutate(func(s *node.State) error {
		if args[0] == "enable" {
			s.Firewall = *backend
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
	v := f.String("version", "", "明确目标 tag，例如 v0.2.7")
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
	return a.store.Inspect(func() error {
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		fmt.Println("当前版本：" + s.CoreVersion)
		r, e := node.LatestStable("SagerNet/sing-box")
		if e != nil {
			return e
		}
		fmt.Printf("官方最新稳定版：%s\n当前管理器适配：%t\n", r.Tag, node.SupportedVersion(strings.TrimPrefix(r.Tag, "v")))
		return nil
	})
}
