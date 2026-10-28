package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"qingnode/internal/node"
	"qingnode/internal/platform"
)

// Capability queries intentionally work before installation and never load State.
func (a *app) capabilities(args []string) error {
	f := fs("capabilities")
	asJSON := f.Bool("json", false, "版本1 JSON；未知值保留null")
	out := f.String("out", "", "新结果文件；不得位于受管目录")
	skip := f.Bool("skip-loopback", false, "仅读取本机事实，不执行小包回环试验")
	if err := parse(f, args); err != nil {
		return err
	}
	if *out != "" {
		if err := a.probeOutput(*out); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	host := platform.ProbeHost(platform.HostProbeOptions{})
	definitionPath := "/etc/systemd/system"
	if host.Init.Kind == platform.InitOpenRC {
		definitionPath = "/etc/init.d"
	}
	r := node.ProbeCapabilities(node.CapabilityOptions{Context: ctx, Paths: []string{a.store.Root, definitionPath, "/usr/local/bin", "/run"}, SkipLoopback: *skip})
	if ctx.Err() != nil {
		return errors.New("能力探测已取消；未修改配置或宿主网络")
	}
	if *asJSON || *out != "" {
		b, err := json.MarshalIndent(struct {
			node.RuntimeCapabilities
			Host platform.HostCapabilities `json:"host"`
		}{r, host}, "", "  ")
		if err != nil {
			return err
		}
		return writeOutput(*out, append(b, '\n'))
	}
	fmt.Printf("本机能力 %s/%s（报告版本%d）\n", r.GOOS, r.GOARCH, r.Version)
	fmt.Printf("发行版：%s %s；安装目标：%s；包管理器：%s（命令存在=%t）\n", host.Distro, host.DistroVersion, host.InstallTarget, host.PackageManager, host.PackageManagerPresent)
	fmt.Printf("服务管理器：%s；工具存在=%t；控制器可用=%t；%s\n", host.Init.Kind, host.Init.ToolPresent, host.Init.ControllerAvailable, host.Init.Reason)
	fmt.Printf("SELinux：%s；%s\n", host.SELinux.Value, host.SELinux.Reason)
	value := func(v *bool) string {
		if v == nil {
			return "未知"
		}
		if *v {
			return "可用"
		}
		return "不可用"
	}
	if r.PID1.Value != nil {
		fmt.Printf("PID1：%s\n", *r.PID1.Value)
	} else {
		fmt.Println("PID1：未知")
	}
	if r.Memory.EffectiveAvailableBytes != nil {
		fmt.Printf("有效可用内存：%d字节\n", *r.Memory.EffectiveAvailableBytes)
	} else {
		fmt.Println("有效可用内存：未知")
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		p := r.Loopback[network]
		fmt.Printf("%s 本机绑定：%s；回环收发：%s；%s\n", network, value(p.Available), value(p.ExchangeSucceeded), p.Reason)
	}
	fmt.Printf("TUN：%s；%s\n", value(r.TUN.Available), r.TUN.Reason)
	for _, p := range r.Paths {
		fmt.Printf("路径 %s：写权限%s（未实际写入）\n", p.Path, value(p.Writable))
	}
	fmt.Println("外部链路：未知。回环成功不代表公网入站、云NAT或代理认证成功。IPv6不可用不否定IPv4。")
	return nil
}
