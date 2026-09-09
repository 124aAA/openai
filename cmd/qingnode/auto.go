package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"qingnode/internal/node"
)

// Probes are passed explicitly so tests can exercise deployment decisions without
// external network access or changes to host services.
type autoProbes struct {
	publicIP      func(string) (string, error)
	checkReality  func(*node.Reality) error
	probeReality  func(*node.Reality) (time.Duration, error)
	availablePort func(node.Node) error
	sshPorts      func() []int
	randomPort    func(node.State, node.Node, []int) (int, error)
}

func defaultAutoProbes() autoProbes {
	return autoProbes{publicIP: node.PublicIP, checkReality: node.CheckReality, probeReality: node.ProbeReality, availablePort: node.AvailablePort, sshPorts: node.SSHPorts, randomPort: node.RandomPort}
}

func autoEndpoint(protocol, host, sni, target string, probes autoProbes) (string, string, string, error) {
	fail := func(e error) (string, string, string, error) { return "", "", "", e }
	if _, ok := node.Protocol(protocol); !ok {
		return fail(errors.New("不支持该协议；可用 reality、ss2022 或 hysteria2"))
	}
	if protocol == "reality" && target != "" && sni == "" {
		return fail(errors.New("显式 --target 必须搭配 --sni，不能推测目标证书名称"))
	}
	if host == "" {
		for _, family := range []string{"4", "6"} {
			found, e := probes.publicIP(family)
			if e == nil && found != "" {
				host = found
				break
			}
		}
		if host == "" {
			return fail(errors.New("自动查询公网 IPv4 和 IPv6 均失败；检查 DNS/HTTPS 出站，或用 --server 公网IP/连接域名 重试"))
		}
	}
	if protocol != "reality" {
		return host, sni, target, nil
	}
	if sni != "" {
		if target == "" {
			target = net.JoinHostPort(sni, "443")
		}
		if e := node.RealityTargetPolicy(&node.Reality{ServerName: sni, Target: target}); e != nil {
			return fail(e)
		}
		if e := probes.checkReality(&node.Reality{ServerName: sni, Target: target}); e != nil {
			return fail(fmt.Errorf("指定 REALITY 目标验证失败；检查 --sni、--target 和服务器出站网络：%w", e))
		}
		return host, sni, target, nil
	}
	fmt.Fprintln(os.Stderr, "[INFO] 正在筛选并测速 REALITY 目标…")
	results := rankRealityTargets(probes.probeReality)
	printRealityTargets(os.Stderr, results, 3)
	if results[0].err == nil {
		return host, results[0].name, net.JoinHostPort(results[0].name, "443"), nil
	}
	return fail(errors.New("所有自动 REALITY 目标均未通过 TLS 1.3 / HTTP2 验证；检查服务器出站网络，或用 --sni 域名（可加 --target 主机:端口）重试"))
}

func autoPort(s node.State, n node.Node, explicit, random bool, probes autoProbes) (int, error) {
	if explicit && random {
		return 0, errors.New("--port 与 --random-port 不能同时使用")
	}
	if n.Port < 1 || n.Port > 65535 {
		return 0, errors.New("端口须为 1–65535")
	}
	ssh := probes.sshPorts()
	if random {
		return probes.randomPort(s, n, ssh)
	}
	var conflict error
	for _, p := range ssh {
		if p == n.Port {
			conflict = errors.New("与 SSH 配置端口相同")
		}
	}
	for _, old := range s.Nodes {
		if old.Enabled && old.Port == n.Port {
			for _, network := range node.Networks(n) {
				for _, oldNetwork := range node.Networks(old) {
					if network == oldNetwork {
						conflict = errors.New("已被现有节点使用")
					}
				}
			}
		}
	}
	if conflict == nil {
		conflict = probes.availablePort(n)
	}
	if conflict == nil {
		return n.Port, nil
	}
	if explicit {
		return 0, fmt.Errorf("指定端口 %s 不可用：%w；运行 qingnode ports 查看占用，或移除 --port 并使用 --random-port", node.PortLabel(n), conflict)
	}
	return probes.randomPort(s, n, ssh)
}
