package main

import (
	"fmt"
	"net"
	"runtime"
	"strconv"

	"qingnode/internal/node"
	"qingnode/internal/platform"
)

// The preview observes the target only. It never installs an archived binary,
// renders a service into /etc, opens a production listener or repairs a journal.
func (a *app) printMigrationTargetPreflight(st node.State) {
	fmt.Printf("目标架构：%s/%s；核心期望版本：%s。\n", runtime.GOOS, runtime.GOARCH, st.CoreVersion)
	host := platform.ProbeHost(platform.HostProbeOptions{})
	servicePath := "/etc/systemd/system"
	if host.Init.Kind == platform.InitOpenRC {
		servicePath = "/etc/init.d"
	}
	fmt.Printf("目标发行版：%s %s；服务管理器：%s；工具存在=%t，控制器可用=%t。服务文件按目标平台生成，不执行备份中的脚本。\n", host.Distro, host.DistroVersion, host.Init.Kind, host.Init.ToolPresent, host.Init.ControllerAvailable)
	capability := node.ProbeCapabilities(node.CapabilityOptions{Paths: []string{a.store.Root, servicePath, "/run"}, SkipLoopback: true})
	if capability.PID1.Value != nil {
		fmt.Printf("目标PID1：%s；运行时的unit/权限/端口就绪仍由现有候选事务检查。\n", *capability.PID1.Value)
	} else {
		fmt.Println("目标PID1：未知；未验证服务管理器可用。")
	}
	if a.offline {
		fmt.Println("离线模式：不验证已安装核心，不启动真实服务；不能据此报告目标机已可运行。")
	} else if err := node.VerifyCore(a.store.Root, st.CoreVersion); err != nil {
		fmt.Printf("目标核心校验未通过：%s；需先按现有可信安装流程准备，不使用迁移包覆盖程序。\n", node.Redact(err.Error(), st))
	} else {
		fmt.Println("目标已安装核心：摘要、版本与构建标签校验通过；尚未执行候选配置或传输验收。")
	}
	for _, p := range capability.Paths {
		writable := "未知"
		if p.Writable != nil {
			writable = "不可写"
			if *p.Writable {
				writable = "访问位允许写入（未实际写入）"
			}
		}
		fmt.Printf("目标路径 %s：%s。\n", p.Path, writable)
	}
	for _, n := range st.Nodes {
		fmt.Printf("节点 %s：本地监听 %s；客户端入口 %s；公网DNS/NAT可达性未知。\n", n.ID, net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)), net.JoinHostPort(n.Host, strconv.Itoa(node.EffectiveConnectPort(n))))
	}
}
