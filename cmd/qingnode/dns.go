package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"qingnode/internal/node"
)

func parseProjectResolver(raw string) (*node.DNSSettings, error) {
	if raw == "system" {
		return &node.DNSSettings{Type: "system"}, nil
	}
	if !strings.HasPrefix(raw, "udp://") {
		return nil, errors.New("resolver须为system或udp://字面IP:端口")
	}
	host, port, err := net.SplitHostPort(strings.TrimPrefix(raw, "udp://"))
	if err != nil {
		return nil, errors.New("UDP解析器须写成udp://IP:端口，IPv6加方括号")
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return nil, errors.New("DNS端口须为数字")
	}
	d := &node.DNSSettings{Type: "udp", Server: host, Port: &n}
	return d, node.ValidateDNS(d)
}
func (a *app) dns(args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "show":
		f := fs("dns show")
		machine := f.Bool("json", false, "版本1项目解析器声明，不执行DNS查询")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		return a.inspectState(func(s *node.State) error {
			if err := s.Validate(); err != nil {
				return err
			}
			if *machine {
				return queryJSON("qingnode-project-dns", struct {
					Resolver            node.M `json:"resolver"`
					Scope               string `json:"scope"`
					HostResolverChanged bool   `json:"host_resolver_changed"`
					Resolution          string `json:"resolution"`
				}{node.ProjectDNS(s.DNS), "qingnode-server-process", false, "not-tested"})
			}
			b, _ := json.MarshalIndent(node.ProjectDNS(s.DNS), "", "  ")
			fmt.Println(string(b))
			fmt.Println("仅作用本项目服务器进程；客户端bootstrap与宿主resolv.conf保持各自设置。")
			return nil
		})
	case "set", "reset":
		f := fs("dns " + args[0])
		resolver := f.String("resolver", "", "system或udp://IP:端口")
		preview := f.Bool("preview", false, "只读预览实际服务器配置影响")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		var d *node.DNSSettings
		var err error
		if args[0] == "set" {
			d, err = parseProjectResolver(*resolver)
			if err != nil {
				return err
			}
		} else if *resolver != "" {
			return errors.New("reset不接受resolver参数")
		}
		if *preview {
			return a.inspectReadyState(func(s *node.State) error {
				next := s.Clone()
				next.DNS = d
				impact, err := a.store.Preview(next)
				if err != nil {
					return err
				}
				b, _ := json.MarshalIndent(map[string]any{"resolver": node.ProjectDNS(d), "impact": impact}, "", "  ")
				fmt.Println(string(b))
				return nil
			})
		}
		return a.mutate(func(s *node.State) error { s.DNS = d; return nil })
	case "diagnose":
		if a.offline {
			return errors.New("--offline不执行DNS网络诊断")
		}
		f := fs("dns diagnose")
		o := node.DNSDiagnosticOptions{}
		f.StringVar(&o.Name, "name", "", "待查询域名")
		f.StringVar(&o.Family, "family", "ipv4", "ipv4或ipv6")
		f.IntVar(&o.Samples, "samples", 3, "样本1–8")
		f.DurationVar(&o.Timeout, "timeout", 3*time.Second, "每样本预算，全部最多30s")
		resolver := f.String("resolver", "system", "system、project或udp://IP:端口")
		expected := f.String("expected", "", "逗号分隔的预期IP或CIDR；未提供时正确性未知")
		out := f.String("out", "", "新JSON结果文件")
		machine := f.Bool("json", false, "标准DNS报告写到stdout；--out仍可保存同一结果")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		if *expected != "" {
			o.Expected = strings.Split(*expected, ",")
		}
		if *resolver == "project" {
			if err := a.inspectReadyState(func(s *node.State) error { o.Resolver = s.DNS; return nil }); err != nil {
				return err
			}
		} else {
			var err error
			o.Resolver, err = parseProjectResolver(*resolver)
			if err != nil {
				return err
			}
		}
		if *out != "" {
			if err := a.probeOutput(*out); err != nil {
				return err
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		r, err := node.DiagnoseDNS(ctx, o, nil)
		if err != nil {
			return err
		}
		if *out != "" {
			if err = writeResultJSON(*out, r); err != nil {
				return err
			}
		}
		if *machine {
			if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
				return err
			}
		} else {
			fmt.Print(node.FormatDNSDiagnostic(r))
		}
		if r.Status != "completed" {
			return errors.New("DNS诊断有失败；没有修改运行策略")
		}
		return nil
	case "help", "--help":
		fmt.Println("dns show [--json] | diagnose --name 域名 [--family ipv4|ipv6 --resolver system|project|udp://IP:端口 --expected IP,CIDR --samples 3 --timeout 3s --out 新文件 --json] | set --resolver system|udp://IP:端口 [--preview] | reset [--preview]")
		return nil
	default:
		return errors.New("未知DNS操作；使用dns --help")
	}
}
func (a *app) inspectReadyState(fn func(*node.State) error) error {
	return a.store.InspectExisting(func() error {
		for _, name := range []string{"transaction.json", "uninstall.json"} {
			if _, err := os.Lstat(a.store.Root + string(os.PathSeparator) + name); err == nil {
				return errors.New("存在中断事务；只读操作不自动修复，请先显式recover")
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		s, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = s.Validate(); err != nil {
			return err
		}
		return fn(&s)
	})
}
func writeResultJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
