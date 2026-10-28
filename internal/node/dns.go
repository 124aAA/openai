package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DNSSettings applies only to this project's server process. Client exports
// retain their own bootstrap resolver; no host resolv.conf is ever written.
type DNSSettings struct {
	Type   string `json:"type"` // system or udp
	Server string `json:"server,omitempty"`
	Port   *int   `json:"port,omitempty"`
}

func ValidateDNS(d *DNSSettings) error {
	if d == nil {
		return nil
	}
	switch d.Type {
	case "system":
		if d.Server != "" || d.Port != nil {
			return errors.New("系统DNS不接受自定义服务器或端口")
		}
	case "udp":
		if _, err := netip.ParseAddr(d.Server); err != nil {
			return errors.New("项目UDP DNS须使用字面IP，避免循环依赖解析")
		}
		if d.Port != nil && (*d.Port < 1 || *d.Port > 65535) {
			return errors.New("DNS端口须为1–65535")
		}
	default:
		return errors.New("项目DNS仅支持system或udp；不改宿主resolv.conf")
	}
	return nil
}
func ProjectDNS(d *DNSSettings) M {
	server := M{"type": "local", "tag": "system"}
	if d != nil && d.Type == "udp" {
		server = M{"type": "udp", "tag": "system", "server": d.Server}
		if d.Port != nil {
			server["server_port"] = *d.Port
		}
	}
	return M{"servers": []any{server}}
}

type DNSDiagnosticOptions struct {
	Name     string
	Family   string
	Resolver *DNSSettings
	Expected []string
	Samples  int
	Timeout  time.Duration
}
type DNSDiagnosticSample struct {
	Sequence      int      `json:"sequence"`
	ElapsedMS     float64  `json:"elapsed_ms"`
	Addresses     []string `json:"addresses"`
	Correct       *bool    `json:"matches_expected"`
	ErrorCategory string   `json:"error_category,omitempty"`
}
type DNSDiagnosticReport struct {
	Version     int                   `json:"version"`
	Source      string                `json:"source"`
	StartedAt   time.Time             `json:"started_at"`
	FinishedAt  time.Time             `json:"finished_at"`
	Initiator   string                `json:"initiator"`
	Name        string                `json:"name"`
	Family      string                `json:"address_family"`
	Resolver    *DNSSettings          `json:"resolver,omitempty"`
	Expected    []string              `json:"expected,omitempty"`
	Samples     []DNSDiagnosticSample `json:"samples"`
	Status      string                `json:"status"`
	Limitations []string              `json:"limitations"`
}
type DNSLookup func(context.Context, string, string) ([]net.IP, error)

func DiagnoseDNS(parent context.Context, o DNSDiagnosticOptions, lookup DNSLookup) (DNSDiagnosticReport, error) {
	var r DNSDiagnosticReport
	if !ValidHost(o.Name) || net.ParseIP(o.Name) != nil {
		return r, errors.New("DNS诊断需要域名，不能填IP或URL")
	}
	if o.Family == "" {
		o.Family = "ipv4"
	}
	if o.Family != "ipv4" && o.Family != "ipv6" {
		return r, errors.New("DNS地址族须为ipv4或ipv6")
	}
	if o.Samples == 0 {
		o.Samples = 3
	}
	if o.Samples < 1 || o.Samples > 8 {
		return r, errors.New("DNS诊断样本须为1–8")
	}
	if o.Timeout == 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Timeout < time.Millisecond || o.Timeout > 10*time.Second || time.Duration(o.Samples)*o.Timeout > 30*time.Second {
		return r, errors.New("DNS单次预算1ms–10s，全部样本预算最多30s")
	}
	if err := ValidateDNS(o.Resolver); err != nil {
		return r, err
	}
	expected := []netip.Prefix{}
	for _, s := range o.Expected {
		if a, e := netip.ParseAddr(s); e == nil {
			expected = append(expected, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return r, errors.New("预期DNS结果须为IP或CIDR网段")
		}
		expected = append(expected, p.Masked())
	}
	if len(expected) > 32 {
		return r, errors.New("DNS预期范围最多32项")
	}
	if lookup == nil {
		resolver := net.DefaultResolver
		if o.Resolver != nil && o.Resolver.Type == "udp" {
			port := 53
			if o.Resolver.Port != nil {
				port = *o.Resolver.Port
			}
			address := net.JoinHostPort(o.Resolver.Server, strconv.Itoa(port))
			resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}}
		}
		lookup = resolver.LookupIP
	}
	host, _ := os.Hostname()
	r = DNSDiagnosticReport{Version: 1, Source: "qingnode-dns-diagnostic", StartedAt: time.Now().UTC(), Initiator: host, Name: o.Name, Family: o.Family, Resolver: o.Resolver, Expected: o.Expected, Samples: []DNSDiagnosticSample{}, Status: "completed", Limitations: []string{"耗时是命令所在机器向所选解析器完成查询的总时间，不是客户端经代理的独立DNS时间。", "不验证DNSSEC；没有提供预期IP或网段时，内容正确性未知。系统缓存、递归解析器缓存和网络都会影响耗时。"}}
	network := "ip4"
	if o.Family == "ipv6" {
		network = "ip6"
	}
	for i := 0; i < o.Samples; i++ {
		ctx, cancel := context.WithTimeout(parent, o.Timeout)
		start := time.Now()
		ips, err := lookup(ctx, network, o.Name)
		elapsed := time.Since(start)
		s := DNSDiagnosticSample{Sequence: i + 1, ElapsedMS: float64(elapsed) / float64(time.Millisecond), Addresses: []string{}}
		if err != nil {
			s.ErrorCategory = "dns_failed"
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				s.ErrorCategory = "dns_nxdomain_or_nodata"
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				s.ErrorCategory = "timeout"
			}
			if errors.Is(parent.Err(), context.Canceled) {
				s.ErrorCategory = "canceled"
			}
		} else {
			matches := len(ips) > 0
			seen := map[string]bool{}
			for _, ip := range ips {
				a, ok := netip.AddrFromSlice(ip)
				if !ok {
					matches = false
					continue
				}
				a = a.Unmap()
				if (o.Family == "ipv4") != a.Is4() {
					matches = false
					continue
				}
				text := a.String()
				if !seen[text] {
					s.Addresses = append(s.Addresses, text)
					seen[text] = true
				}
				if len(expected) > 0 {
					found := false
					for _, p := range expected {
						if p.Contains(a) {
							found = true
							break
						}
					}
					if !found {
						matches = false
					}
				}
			}
			sort.Strings(s.Addresses)
			if len(s.Addresses) == 0 {
				s.ErrorCategory = "dns_no_address"
			}
			if len(expected) > 0 {
				s.Correct = &matches
				if !matches {
					s.ErrorCategory = "dns_unexpected_answer"
				}
			}
		}
		cancel()
		if s.ErrorCategory != "" {
			r.Status = "failed"
		}
		r.Samples = append(r.Samples, s)
		if parent.Err() != nil {
			r.Status = "canceled"
			if errors.Is(parent.Err(), context.DeadlineExceeded) {
				r.Status = "timeout"
			}
			break
		}
	}
	r.FinishedAt = time.Now().UTC()
	return r, nil
}

func FormatDNSDiagnostic(r DNSDiagnosticReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS诊断：%s；发起端：%s；域名：%s；地址族：%s\n", r.Status, r.Initiator, r.Name, r.Family)
	for _, s := range r.Samples {
		correct := "未提供预期，内容正确性未知"
		if s.Correct != nil {
			correct = fmt.Sprintf("符合预期：%t", *s.Correct)
		}
		fmt.Fprintf(&b, "样本%d：%.3f ms；地址%s；%s；错误类别%s\n", s.Sequence, s.ElapsedMS, strings.Join(s.Addresses, ","), correct, s.ErrorCategory)
	}
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "限制：%s\n", l)
	}
	return b.String()
}
