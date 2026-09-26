package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"qingnode/internal/node"
)

func displayTime(at time.Time) string { return at.Local().Format("2006-01-02 15:04 MST") }
func recordAge(at, now time.Time) string {
	if at.IsZero() || at.After(now.Add(time.Minute)) {
		return "记录时间无效，待重查"
	}
	if now.Sub(at) > 24*time.Hour {
		return "超过24小时，待复查"
	}
	return "历史结果"
}
func bytesLabel(v *uint64) string {
	if v == nil {
		return "未知"
	}
	return fmt.Sprintf("%.1f GiB", float64(*v)/(1<<30))
}
func publicLabel(s node.State, n node.Node, h dashboardHistory, now time.Time) string {
	r, ok := h.Public[n.ID]
	if !ok {
		return "待验证（尚无客户端实测记录）"
	}
	if r.At.IsZero() || r.At.After(now.Add(time.Minute)) {
		return "记录时间无效，待重新验证"
	}
	if r.Fingerprint != publicFingerprint(s, n) {
		return "配置已改变，待重新验证；上次 " + displayTime(r.At)
	}
	if !validProbeResult(r.TCP) || !validProbeResult(r.UDP) || !validSource(r.Source) {
		return "记录无效，待重新验证"
	}
	names := map[string]string{"pass": "通过", "fail": "失败", "untested": "待验证"}
	return fmt.Sprintf("TCP %s / UDP %s；%s；%s；管理员登记：%s", names[r.TCP], names[r.UDP], displayTime(r.At), recordAge(r.At, now), r.Source)
}
func certificateLabel(n node.Node, now time.Time) string {
	c := n.Certificate
	if c == nil {
		return "不适用（无需自有TLS证书）"
	}
	if c.Mode == "acme" {
		return "ACME 管理，期限未知（需检查实际签发证书）"
	}
	rest := []byte(c.CertPEM)
	var b *pem.Block
	for len(rest) > 0 {
		b, rest = pem.Decode(rest)
		if b == nil || b.Type == "CERTIFICATE" {
			break
		}
		b = nil
	}
	if b == nil {
		return "证书无法解析"
	}
	leaf, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return "证书无法解析"
	}
	if e = leaf.VerifyHostname(c.ServerName); e != nil {
		return "证书域名不匹配"
	}
	if now.Before(leaf.NotBefore) {
		return "尚未生效：" + displayTime(leaf.NotBefore)
	}
	if !now.Before(leaf.NotAfter) {
		return "已过期：" + displayTime(leaf.NotAfter)
	}
	if leaf.NotAfter.Sub(now) < 24*time.Hour {
		return "不足1天，需续期；到期 " + displayTime(leaf.NotAfter)
	}
	return fmt.Sprintf("剩余%d天；到期 %s", int(math.Floor(leaf.NotAfter.Sub(now).Hours()/24)), displayTime(leaf.NotAfter))
}
func updateLabel(r updateRecord, installed string, core bool, now time.Time) string {
	if r.CheckedAt.IsZero() {
		return "尚未检查（选择8联网查询）"
	}
	failure := ""
	if r.Failed {
		failure = "最近查询失败（" + displayTime(r.CheckedAt) + "）；"
	}
	if r.At.IsZero() {
		return failure + "可用版本未知"
	}
	if r.Installed != installed {
		return failure + "当前版本已变化，待重新检查"
	}
	label := "查询列表未发现更新"
	if core {
		if r.Compatible != "" && node.CompareVersion(r.Compatible, installed) > 0 {
			label = "已适配更新 " + r.Compatible
		}
		if r.Latest != "" && !node.SupportedVersion(strings.TrimPrefix(r.Latest, "v")) {
			label += "；官方 " + r.Latest + " 尚未适配"
		}
	} else if node.CompareVersion(r.Latest, installed) > 0 {
		label = "可用 " + r.Latest + "（含预发布，兼容性需升级前校验）"
	}
	return failure + label + "；" + displayTime(r.At) + "；" + recordAge(r.At, now)
}

// No probes, downloads, recovery or writes. All displayed validation is historical.
func (a *app) overview(w io.Writer) error {
	var s node.State
	var h dashboardHistory
	var historyErr error
	err := a.store.Inspect(func() error {
		var e error
		s, e = a.store.Load()
		if e != nil {
			return e
		}
		if e = s.Validate(); e != nil {
			return e
		}
		h, historyErr = readDashboardHistory(a.store.Root)
		return nil
	})
	service := node.ServiceOverview{}
	if !a.offline {
		service = node.OverviewService(nil)
	}
	resources := node.OverviewResources(a.store.Root)
	return renderOverview(w, s, h, err, historyErr, service, resources, a.offline, time.Now())
}
func renderOverview(w io.Writer, s node.State, h dashboardHistory, stateErr, historyErr error, service node.ServiceOverview, r node.ResourceOverview, offline bool, now time.Time) error {
	fmt.Fprintln(w, "\n━━━━━━━━ QingNode 青节点 · 管理与说明 ━━━━━━━━")
	core := s.CoreVersion
	if stateErr != nil {
		core = "未知"
	}
	fmt.Fprintf(w, "管理器 %s | 配置核心 %s\n", version, core)
	if offline {
		fmt.Fprintln(w, "服务：离线模式，未查询服务")
	} else {
		status := map[string]string{"active": "运行中", "inactive": "已停止", "failed": "启动失败", "activating": "启动中", "deactivating": "停止中"}[service.ActiveState]
		if status == "" {
			status = "未知"
		}
		if service.ActiveState == "active" && service.SubState != "running" {
			status = "进程未确认运行"
		}
		uptime, restarts, enabled := "未知", "未知", "未知"
		if service.Runtime != nil {
			uptime = service.Runtime.Round(time.Second).String()
		}
		if service.AutoRestarts != nil {
			restarts = fmt.Sprint(*service.AutoRestarts)
		}
		switch service.UnitFileState {
		case "enabled":
			enabled = "已启用"
		case "disabled":
			enabled = "未启用"
		}
		fmt.Fprintf(w, "服务：%s | 自启：%s | 本次运行：%s | 自动重启：%s 次（systemd计数，可重置）\n", status, enabled, uptime, restarts)
	}
	load := "未知"
	if r.Load1 != nil {
		load = fmt.Sprintf("%.2f", *r.Load1)
	}
	fmt.Fprintf(w, "CPU：%d 核 | 1分钟负载：%s（非CPU使用率）\n内存可用/总量：%s / %s | 数据磁盘可用/总量：%s / %s\n", r.CPUs, load, bytesLabel(r.MemoryAvailable), bytesLabel(r.MemoryTotal), bytesLabel(r.DiskAvailable), bytesLabel(r.DiskTotal))
	if stateErr != nil {
		fmt.Fprintln(w, "节点与历史状态未知："+node.Redact(stateErr.Error()))
		return nil
	}
	enabled := 0
	for _, n := range s.Nodes {
		if n.Enabled {
			enabled++
		}
	}
	fmt.Fprintf(w, "节点：共%d个，启用%d个\n", len(s.Nodes), enabled)
	if historyErr != nil {
		fmt.Fprintln(w, "观测记录不可用："+node.Redact(historyErr.Error()))
		h = dashboardHistory{}
	}
	if h.Backup == nil {
		fmt.Fprintln(w, "最近成功备份：暂无记录（旧版备份未登记）")
	} else {
		label := "文件已缺失或变化"
		if i, e := os.Lstat(h.Backup.Path); e == nil && i.Mode().IsRegular() && i.Size() == h.Backup.Size {
			label = "文件存在，尚不代表已验证恢复"
		}
		fmt.Fprintf(w, "最近成功备份：%s；%s\n", displayTime(h.Backup.At), label)
	}
	if h.Diagnostic == nil {
		fmt.Fprintln(w, "最近服务器侧自检：待检查（选择9，会联网）")
	} else {
		r := h.Diagnostic
		label := recordAge(r.At, now)
		if r.Fingerprint != stateFingerprint(s) {
			label = "配置已改变，待重新自检"
		}
		if r.Offline {
			label += "；离线环境记录"
		}
		fmt.Fprintf(w, "最近服务器侧自检：%d错误 / %d警告；%s；%s\n", r.Errors, r.Warnings, displayTime(r.At), label)
	}
	for _, n := range s.Nodes {
		mode := "启用"
		if !n.Enabled {
			mode = "停用"
		}
		fmt.Fprintf(w, "  %s [%s / %s]\n    证书：%s\n", n.Name, n.Protocol, mode, certificateLabel(n, now))
		if historyErr != nil {
			fmt.Fprintln(w, "    公网：记录不可用，待验证")
		} else {
			fmt.Fprintln(w, "    公网："+publicLabel(s, n, h, now))
		}
	}
	if historyErr == nil {
		fmt.Fprintln(w, "管理器更新："+updateLabel(h.Updates["manager"], version, false, now))
		fmt.Fprintln(w, "核心更新："+updateLabel(h.Updates["core"], s.CoreVersion, true, now))
	}
	fmt.Fprintln(w, "说明：服务运行不等于公网可用；首页只读本机，历史验证不代表持续在线。")
	return nil
}
