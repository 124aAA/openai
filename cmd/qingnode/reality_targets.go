package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"

	"qingnode/internal/node"
)

func realityCandidates() []string {
	return []string{"www.microsoft.com", "www.apple.com", "www.samsung.com", "www.nvidia.com", "www.sony.com", "www.bing.com"}
}

type realityResult struct {
	name    string
	latency time.Duration
	err     error
}

// The pool is small and fixed. Each candidate gets three fresh connections;
// any failed sample excludes it rather than making a flaky target look fast.
func rankRealityTargets(probe func(*node.Reality) (time.Duration, error)) []realityResult {
	pool := realityCandidates()
	done := make(chan realityResult, len(pool))
	for _, name := range pool {
		go func(name string) {
			r := realityResult{name: name}
			var samples []time.Duration
			for i := 0; i < 3; i++ {
				duration, e := probe(&node.Reality{ServerName: name, Target: net.JoinHostPort(name, "443")})
				if e != nil {
					r.err = e
					done <- r
					return
				}
				samples = append(samples, duration)
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			r.latency = samples[1]
			done <- r
		}(name)
	}
	var results []realityResult
	for range pool {
		results = append(results, <-done)
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if (a.err == nil) != (b.err == nil) {
			return a.err == nil
		}
		if a.latency != b.latency {
			return a.latency < b.latency
		}
		return a.name < b.name
	})
	return results
}

func printRealityTargets(w io.Writer, results []realityResult, top int) {
	fmt.Fprintln(w, "REALITY 候选：VPS → 目标 DNS+TCP+TLS 耗时，3 次成功样本的中位数")
	shown := 0
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(w, "  排除 %s：%s\n", r.name, node.Redact(r.err.Error()))
		} else if shown < top {
			shown++
			fmt.Fprintf(w, "  %d. %s  %.1f ms  TLS1.3 / h2 / 证书通过\n", shown, r.name, float64(r.latency)/float64(time.Millisecond))
		}
	}
	fmt.Fprintln(w, "已排除已知 Cloudflare 目标；其它共享 CDN 风险仍需评估。此排名不代表客户端延迟或下载速度。")
}

func realityTargets(args []string) error {
	f := fs("reality-targets")
	top := f.Int("top", 3, "展示前几个合格候选（1–6）")
	if e := parse(f, args); e != nil {
		return e
	}
	if *top < 1 || *top > len(realityCandidates()) {
		return errors.New("--top 须为 1–6")
	}
	fmt.Fprintln(os.Stderr, "正在探测 REALITY 候选，请稍候（不修改现有节点）…")
	results := rankRealityTargets(node.ProbeReality)
	printRealityTargets(os.Stdout, results, *top)
	if results[0].err != nil {
		return errors.New("没有合格目标；检查出站网络，或使用经验证的自有目标")
	}
	fmt.Fprintf(os.Stdout, "本次建议：%s；自动安装会重新测速后选择，手动选择可用 --sni 域名。\n", results[0].name)
	return nil
}
