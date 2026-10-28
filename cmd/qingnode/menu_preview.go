package main

import (
	"fmt"
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
	if a.offline {
		fmt.Fprintln(w, "离线环境只保存配置；上面的运行变化未在宿主执行。")
	}
	a.menuPreviewDone = true
	return nil
}

func (a *app) menuCommand(args []string) error {
	before, done := a.menuPreview, a.menuPreviewDone
	a.menuPreview, a.menuPreviewDone = true, false
	defer func() { a.menuPreview, a.menuPreviewDone = before, done }()
	return a.command(args)
}
