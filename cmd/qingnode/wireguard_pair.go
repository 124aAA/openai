package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"qingnode/internal/node"
)

// Only material is written here. Applying each end remains a separate explicit
// topology transaction; the generator never logs into the other host.
func (a *app) wireguardPair(args []string) error {
	if len(args) == 0 || args[0] != "pair" {
		return errors.New("用法：wireguard pair --id 配对ID --entry-tunnel IP/32 --landing-tunnel IP/32 --landing-server 地址 --connect-port 外部UDP端口 --listen-port 落地本地UDP端口 --allowed-ips CIDR[,CIDR] --out-dir 新私有目录")
	}
	f := fs("wireguard pair")
	id := f.String("id", "", "配对ID，1–24位；新建材料不修改现有节点")
	entry := f.String("entry-tunnel", "", "入口隧道IP，IPv4 /32或IPv6 /128")
	landing := f.String("landing-tunnel", "", "落地隧道IP，须与入口同族且不同")
	host := f.String("landing-server", "", "落地的明确连接地址，不自动探测公网")
	connect := namedPortFlag(f, "connect-port", 0, "落地外部UDP端口，须明确填写")
	listen := namedPortFlag(f, "listen-port", 0, "落地本地UDP监听端口，须明确填写")
	allowed := f.String("allowed-ips", "", "入口经隧道到达的目标CIDR，逗号分隔；不改宿主路由")
	mtu := f.Int("mtu", 0, "0保留核心默认，或1280–1500")
	keepalive := f.Int("keepalive", 0, "入口向落地保活秒数，0关闭；NAT按需要明确填25")
	out := f.String("out-dir", "", "必须不存在的新私有目录；包含密钥，不可公开")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *out == "" || !flagSet(f, "connect-port") || !flagSet(f, "listen-port") {
		return errors.New("需要新的--out-dir，并明确填写--connect-port及--listen-port")
	}
	if err := a.probeOutput(*out); err != nil {
		return err
	}
	var targets []string
	if *allowed != "" {
		for _, value := range strings.Split(*allowed, ",") {
			targets = append(targets, strings.TrimSpace(value))
		}
	}
	pair, err := node.NewWireGuardPair(node.WireGuardPairOptions{ID: *id, EntryTunnel: *entry, LandingTunnel: *landing, LandingHost: *host, ConnectPort: *connect, ListenPort: *listen, AllowedIPs: targets, MTU: *mtu, Keepalive: *keepalive})
	if err != nil {
		return err
	}
	for _, egress := range []node.Egress{pair.Entry, pair.Landing} {
		state := node.NewState()
		state.Egresses = []node.Egress{egress}
		if err = state.Validate(); err != nil {
			return err
		}
	}
	operation := func(e node.Egress) any {
		return map[string]any{"version": 1, "operations": []any{map[string]any{"action": "egress-put", "egress": e}}}
	}
	manifest := map[string]any{"version": 1, "pair_id": *id, "entry_status": "generated_not_applied", "landing_status": "generated_not_applied", "mode": "sing-box-userland", "host_network_changed": false, "cross_host_atomic": false, "landing_udp_connect_port": *connect, "landing_udp_listen_port": *listen, "entry_tunnel": *entry, "landing_tunnel": *landing, "target_allowed_ips": targets, "landing_accepted_peer_sources": pair.Landing.WireGuard.Peers[0].AllowedIPs, "handshake": "unknown", "target_data": "unknown", "actual_exit": "unknown"}
	files := map[string][]byte{}
	for name, object := range map[string]any{"entry.json": operation(pair.Entry), "landing.json": operation(pair.Landing), "manifest.json": manifest} {
		files[name], err = json.MarshalIndent(object, "", "  ")
		if err != nil {
			return err
		}
	}
	files["README.txt"] = []byte(fmt.Sprintf("本目录包含WireGuard私钥和预共享密钥，只分别传给两台自己的服务器。\n两端不是一个原子事务；生成不等于已应用、握手或目标流量通过。\n\n先在落地主机：qingnode topology apply --file landing.json --preview\n确认后：qingnode topology apply --file landing.json\n自行核验云UDP映射/安全组：外部%d -> 本地%d；工具没有替你修改。\n\n入口主机：qingnode topology apply --file entry.json --preview\n确认后：qingnode topology apply --file entry.json\nqingnode route set --id NODE --egress %s --preview\n确认后：qingnode route set --id NODE --egress %s\n\n仅本项目流量走用户态隧道；没有系统wg0/TUN、默认路由、DNS或其它Peer变更。AllowedIPs是目标选择/对端认证源范围，不是宿主路由。\n保活0表示关闭；入口在NAT后需要时显式选择25秒。MTU为0保留核心默认，实际链路仍需测试。\n落地入站明确转direct，须具备普通TCP/UDP出站能力；只握手不等于可用。\n分别测试受控HTTPS、序号UDP和目标看到的出口地址，再停掉所选落地验证失败，保留发起端/目标日志。\n撤回：入口先把引用恢复到原出口（需要直连时显式route set --egress direct）。\n入口预览：qingnode egress remove --id %s --preview\n入口实际撤回：qingnode egress remove --id %s --yes\n落地预览：qingnode egress remove --id %s --preview\n落地实际撤回：qingnode egress remove --id %s --yes\n不删除别人Peer或服务。应用失败沿各自主机recover/rollback；保管各端原备份与生成材料。\n", *connect, *listen, pair.Entry.ID, pair.Entry.ID, pair.Entry.ID, pair.Entry.ID, pair.Landing.ID, pair.Landing.ID))
	if err = writeNewPairDirectory(*out, files); err != nil {
		return err
	}
	fmt.Printf("已生成两端私有材料：%s；尚未应用、未验证握手/目标/实际出口。\n", *out)
	return nil
}

func writeNewPairDirectory(path string, files map[string][]byte) (err error) {
	for name := range files {
		if filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
			return errors.New("配对输出文件名无效")
		}
	}
	parent, err := pinNewOutput(path)
	if err != nil {
		return err
	}
	defer parent.root.Close()
	if err = parent.unchanged(); err != nil {
		return err
	}
	if err = parent.root.Mkdir(parent.name, 0700); err != nil {
		return err
	}
	created, err := parent.root.Lstat(parent.name)
	if err != nil {
		return err
	}
	directory, err := parent.root.OpenRoot(parent.name)
	if err != nil {
		return err
	}
	defer directory.Close()
	opened, err := directory.Stat(".")
	if err != nil || !os.SameFile(created, opened) {
		return errors.New("新配对目录在检查期间改变")
	}
	owned := []string{}
	defer func() {
		if err != nil {
			for _, file := range owned {
				_ = directory.Remove(file)
			}
			if current, e := parent.root.Lstat(parent.name); e == nil && os.SameFile(created, current) {
				_ = parent.root.Remove(parent.name) // Never recursively delete an unknown child.
			}
		}
	}()
	for name, data := range files {
		if filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
			return errors.New("配对输出文件名无效")
		}
		f, openErr := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return openErr
		}
		owned = append(owned, name)
		_, writeErr := f.Write(data)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err = parent.unchanged(); err != nil {
		return err
	}
	if current, e := parent.root.Lstat(parent.name); e != nil || !os.SameFile(created, current) {
		return errors.New("配对目录已改变；拒绝把替换路径当生成结果")
	}
	return nil
}
