// Package probecli shares bounded network-test commands between the Linux
// manager and the portable desktop helper. It has no State or service backend.
package probecli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"qingnode/internal/probe"
)

type Hooks struct {
	Out                   io.Writer
	Version               string
	SelectProfile         func(id, user string) (probe.Profile, error)
	SelectEndpointProfile func(id, user, endpoint string) (probe.Profile, error)
	DefaultCore           func(probe.Profile) (probe.SandboxOptions, error)
	ValidateOutput        func(string) error
}

var ErrMeasurement = errors.New("测试未全部完成或有失败；已保留实际结果")

const Help = `隔离网络测试（不会修改节点、服务或 public-check 登记）
  local [--out report.json]                 本机只读指标，不联网
  profile --id ID [--user ID] [--endpoint default或ID] --out profile.json  导出私密测试凭据（仅管理器）
  run --path server-outbound|client-proxy|controlled-link --target https://目标
      [--mode light|download] [--timeout 20s] [--bytes 65536] [--samples 8]
      [--concurrency 1] [--family auto|ipv4|ipv6] [--initiator 测试机器说明]
      [--udp 受控回包IP:端口] [--udp-timeout 1s] [--ca 目标CA.pem] [--out report.json]
      client-proxy: --id ID [--user ID] [--endpoint default或ID] 或 --profile profile.json
                    [--core 核心绝对路径 --core-sha256 已核验二进制摘要]
                    [--proxy-ca 节点CA.pem]
  compare --before report.json --after report.json  比较条件一致的有效样本
  udp-echo --listen IP:端口 [--duration 30s]   显式启动受限的受控回包端点

默认 light 只发有限 HEAD 请求；download 须显式选择，默认8MiB。
硬上限：120秒、64MiB有效载荷、4个HTTP连接、64样本；light最多64KiB。
并发设为1时报告单连接下载吞吐；负载采样与下载共享4个连接槽，满额时等待。
代理指定ipv4/ipv6须用字面IP，域名目标使用auto并由所选节点解析。
目标无默认公共测速站；UDP只支持本工具的受控回包端点，不将DNS回包算丢包率。
--ca/--proxy-ca用于受控证书，不关闭证书验证；报告不含查询串或凭据。
含内部出口的Profile/报告使用v2链路摘要；它只声明导出时路径，不证明远端当前配置。
测试失败仍可写报告并返回非零；结果文件须为新文件。
`

func Execute(ctx context.Context, args []string, h Hooks) error {
	if h.Out == nil {
		h.Out = os.Stdout
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(h.Out, Help)
		return nil
	}
	switch args[0] {
	case "local":
		return local(ctx, args[1:], h)
	case "profile":
		return profile(args[1:], h)
	case "run":
		return run(ctx, args[1:], h)
	case "compare":
		return compare(args[1:], h)
	case "udp-echo":
		return echo(ctx, args[1:], h)
	default:
		return errors.New("未知测试命令；追加 --help 查看帮助")
	}
}
func flags(name string, h Hooks) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(h.Out)
	f.Usage = func() { fmt.Fprint(h.Out, Help) }
	return f
}
func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if len(f.Args()) != 0 {
		return errors.New("测试参数含多余的位置参数")
	}
	return nil
}
func initiator() string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown-host"
	}
	return host + "/" + runtime.GOOS + "/" + runtime.GOARCH
}
func local(ctx context.Context, args []string, h Hooks) error {
	f := flags("local", h)
	out := f.String("out", "", "新JSON报告路径")
	if err := parse(f, args); err != nil {
		return err
	}
	if err := checkOutput(h, *out); err != nil {
		return err
	}
	r, err := probe.Run(ctx, probe.Options{Path: "local", Initiator: initiator(), ToolVersions: map[string]string{"qingprobe": h.Version}}, probe.Dependencies{})
	if err != nil {
		return err
	}
	return deliver(h, *out, r)
}
func profile(args []string, h Hooks) error {
	f := flags("profile", h)
	id := f.String("id", "", "节点ID")
	user := f.String("user", "", "凭据ID")
	endpoint := f.String("endpoint", "", "管理器声明的连接端点ID")
	out := f.String("out", "", "新私密文件路径")
	if err := parse(f, args); err != nil {
		return err
	}
	if h.SelectProfile == nil && h.SelectEndpointProfile == nil {
		return errors.New("桌面工具读取已导出的 --profile；导出须在管理器执行")
	}
	if *id == "" || *out == "" {
		return errors.New("profile 需要 --id 和 --out")
	}
	if err := checkOutput(h, *out); err != nil {
		return err
	}
	p, err := selectEndpointProfile(h, *id, *user, *endpoint)
	if err != nil {
		return err
	}
	if err = probe.WriteProfile(*out, p); err != nil {
		return err
	}
	fmt.Fprintln(h.Out, "已保存私密测试凭据。请安全传到测试机器，用后删除；它不是脱敏报告。")
	if p.ServerPathSHA256 != "" {
		fmt.Fprintln(h.Out, probe.ServerPathLimitation)
	}
	return nil
}
func run(parent context.Context, args []string, h Hooks) error {
	f := flags("run", h)
	o := probe.Options{}
	f.StringVar(&o.Path, "path", "", "明确选择测试路径")
	f.StringVar(&o.TargetURL, "target", "", "明确HTTPS目标")
	f.StringVar(&o.Mode, "mode", "light", "light或download")
	f.StringVar(&o.Family, "family", "auto", "auto/ipv4/ipv6")
	f.DurationVar(&o.Timeout, "timeout", 20*time.Second, "含核心启动的总时间预算")
	f.Int64Var(&o.MaxBytes, "bytes", 0, "有效载荷总预算；按mode取默认")
	f.IntVar(&o.Samples, "samples", 8, "样本数1..64")
	f.IntVar(&o.Concurrency, "concurrency", 1, "下载并发1..4")
	f.StringVar(&o.Initiator, "initiator", initiator(), "测试机器/接入网络说明")
	f.StringVar(&o.UDPAddress, "udp", "", "受控UDP回包目标")
	f.DurationVar(&o.UDPTimeout, "udp-timeout", time.Second, "每UDP样本超时")
	out := f.String("out", "", "新JSON报告路径")
	id := f.String("id", "", "管理器的所选节点")
	user := f.String("user", "", "所选凭据ID")
	endpoint := f.String("endpoint", "", "管理器连接端点ID；私密Profile已经固定端点")
	path := f.String("profile", "", "私密测试凭据路径")
	core := f.String("core", "", "官方核心绝对路径")
	sum := f.String("core-sha256", "", "预先校验的核心二进制SHA256")
	ca := f.String("ca", "", "HTTPS目标CA PEM")
	proxyCA := f.String("proxy-ca", "", "代理节点CA PEM")
	if err := parse(f, args); err != nil {
		return err
	}
	if err := checkOutput(h, *out); err != nil {
		return err
	}
	if o.Path == "" || o.Path == "local" {
		return errors.New("run 须明确选择网络路径；本机诊断使用 local")
	}
	if o.Timeout <= 0 || o.Samples <= 0 || o.Concurrency <= 0 || o.UDPTimeout <= 0 {
		return errors.New("时间、样本量和并发须为正数")
	}
	invalidBytes := false
	f.Visit(func(v *flag.Flag) {
		if v.Name == "bytes" && o.MaxBytes <= 0 {
			invalidBytes = true
		}
	})
	if invalidBytes {
		return errors.New("显式 --bytes 须为正数")
	}
	var err error
	o, err = probe.NormalizeOptions(o)
	if err != nil {
		return err
	}
	if o.Path != "client-proxy" && (*id != "" || *user != "" || *endpoint != "" || *path != "" || *core != "" || *sum != "" || *proxyCA != "") {
		return errors.New("代理参数只用于 client-proxy")
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	started := time.Now().UTC()
	o.ToolVersions = map[string]string{"qingprobe": h.Version, "go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH}
	deps := probe.Dependencies{}
	var transport *http.Transport
	var sandbox *probe.Sandbox
	if o.Path == "client-proxy" {
		if (*path == "") == (*id == "") {
			return errors.New("client-proxy 必须只选一种：--id 或 --profile")
		}
		if *path != "" && (*user != "" || *endpoint != "") {
			return errors.New("--profile 已固定凭据和端点，不接受 --user/--endpoint")
		}
		var p probe.Profile
		if *path != "" {
			p, err = probe.ReadProfile(*path)
		} else if h.SelectProfile != nil || h.SelectEndpointProfile != nil {
			p, err = selectEndpointProfile(h, *id, *user, *endpoint)
		} else {
			return errors.New("桌面工具使用 --profile，不读取服务器State")
		}
		if err != nil {
			return err
		}
		if *proxyCA != "" {
			p, err = withProxyCA(p, *proxyCA)
			if err != nil {
				return err
			}
		}
		opts := probe.SandboxOptions{CoreBinary: *core, SHA256: *sum}
		if *core == "" && *sum == "" && h.DefaultCore != nil {
			opts, err = h.DefaultCore(p)
			if err != nil {
				return err
			}
		}
		o.NodeID = p.NodeID
		o.ConfigSHA256 = p.ConfigSHA256
		o.ServerPathSHA256 = p.ServerPathSHA256
		o.CoreVersion = p.CoreVersion
		s, err := probe.StartSandbox(ctx, p, opts)
		if err != nil {
			r := setupFailure(o, started, ctx)
			if e := deliver(h, *out, r); e != nil {
				return e
			}
			return errors.New("隔离客户端启动或校验失败；报告不含私密核心日志")
		}
		defer s.Close()
		sandbox = s
		o.ClientVersion = s.Version
		o.UDPProxyAddress = s.Address
		o.UDPProxyUsername = s.Username
		o.UDPProxyPassword = s.Password
		transport = s.Transport()
		deps.MetricsPID = s.PID
	} else {
		transport = http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
	}
	if *ca != "" {
		pool, err := readCA(*ca)
		if err != nil {
			return err
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	deps.Transport = transport
	measureCtx, stopMeasure := context.WithCancel(ctx)
	defer stopMeasure()
	if sandbox != nil {
		go func() {
			select {
			case <-sandbox.Done():
				stopMeasure()
			case <-measureCtx.Done():
			}
		}()
	}
	r, err := probe.Run(measureCtx, o, deps)
	if err != nil {
		return err
	}
	r.StartedAt = started
	if sandbox != nil && ctx.Err() == nil {
		select {
		case <-sandbox.Done():
			r.Status = "failed"
			r.Errors = append(r.Errors, probe.Failure{Category: "client_core_exited", Detail: "isolated client process exited during measurement"})
		default:
		}
	}
	if sandbox != nil {
		if cleanupErr := sandbox.Close(); cleanupErr != nil {
			r.Status = "failed"
			r.Errors = append(r.Errors, probe.Failure{Category: "client_cleanup_failed", Detail: "本次临时客户端已退出，但自有目录清理失败"})
		}
	}
	if err = deliver(h, *out, r); err != nil {
		return err
	}
	if r.Status != "completed" {
		return ErrMeasurement
	}
	return nil
}
func deliver(h Hooks, path string, r probe.Report) error {
	if path != "" {
		if err := probe.WriteReport(path, r); err != nil {
			return err
		}
	}
	fmt.Fprint(h.Out, probe.FormatText(r))
	return nil
}
func checkOutput(h Hooks, path string) error {
	if path != "" && h.ValidateOutput != nil {
		return h.ValidateOutput(path)
	}
	return nil
}
func setupFailure(o probe.Options, start time.Time, ctx context.Context) probe.Report {
	status := "failed"
	cat := "client_setup_failed"
	if ctx.Err() != nil {
		status = "timeout"
		cat = "timeout"
		if errors.Is(ctx.Err(), context.Canceled) {
			status = "canceled"
			cat = "canceled"
		}
	}
	r := probe.Report{Version: probe.ReportVersionFor(o), Source: "qingnode-automatic-probe", StartedAt: start, FinishedAt: time.Now().UTC(), Status: status,
		Conditions: probe.ReportConditions(o),
		DNS:        probe.Stage{Status: "unknown"}, Connection: probe.Stage{Status: "unknown"}, TLS: probe.Stage{Status: "unknown"}, Samples: []probe.Sample{}, Statistics: map[string]probe.Statistics{}, Errors: []probe.Failure{{Category: cat, Detail: "isolated client failed before network samples"}}, Limitations: []string{"No end-to-end samples were collected; core/configuration startup failure is not a target result."}}
	if o.ServerPathSHA256 != "" {
		r.Limitations = append(r.Limitations, probe.ServerPathLimitation)
	}
	return r
}
func readCA(path string) (*x509.CertPool, error) {
	b, err := readBounded(path, 128<<10)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("CA文件没有可用PEM证书")
	}
	return pool, nil
}
func withProxyCA(p probe.Profile, path string) (probe.Profile, error) {
	if err := p.Validate(); err != nil {
		return p, err
	}
	b, err := readBounded(path, 64<<10)
	if err != nil {
		return p, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return p, errors.New("节点CA文件没有可用PEM证书")
	}
	var o map[string]any
	if err = json.Unmarshal(p.Outbound, &o); err != nil {
		return p, err
	}
	t, ok := o["tls"].(map[string]any)
	if !ok {
		return p, errors.New("此协议不使用节点TLS证书")
	}
	t["certificate"] = []string{string(b)}
	raw, _ := json.Marshal(o)
	updated, err := probe.NewProfile(p.NodeID, p.CoreVersion, raw)
	if err != nil || p.ServerPathSHA256 == "" {
		return updated, err
	}
	return probe.WithServerPathDigest(updated, p.ServerPathSHA256)
}
func readBounded(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("输入须为普通文件")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("输入文件超过大小上限")
	}
	return b, err
}
func compare(args []string, h Hooks) error {
	f := flags("compare", h)
	before := f.String("before", "", "前次自动报告")
	after := f.String("after", "", "本次自动报告")
	if err := parse(f, args); err != nil {
		return err
	}
	if *before == "" || *after == "" {
		return errors.New("compare 需要 --before 和 --after")
	}
	read := func(path string) (probe.Report, error) {
		var r probe.Report
		b, err := readBounded(path, 1<<20)
		if err != nil {
			return r, err
		}
		if err = probe.StrictJSON(b, &r); err != nil {
			return r, err
		}
		return r, probe.ValidateReport(r)
	}
	a, err := read(*before)
	if err != nil {
		return err
	}
	b, err := read(*after)
	if err != nil {
		return err
	}
	c := probe.Compare(a, b)
	data, _ := json.MarshalIndent(c, "", "  ")
	fmt.Fprintln(h.Out, string(data))
	if !c.Comparable {
		return errors.New("两份结果不可直接比较；原因已列出")
	}
	return nil
}
func echo(parent context.Context, args []string, h Hooks) error {
	f := flags("udp-echo", h)
	listen := f.String("listen", "", "明确监听IP:端口")
	duration := f.Duration("duration", 30*time.Second, "运行期限，最多120s")
	if err := parse(f, args); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || port == "0" || *duration <= 0 || *duration > probe.MaxDuration {
		return errors.New("udp-echo 需要明确IP:非零端口，duration为正且最多120s")
	}
	ctx, cancel := context.WithTimeout(parent, *duration)
	defer cancel()
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		return err
	}
	defer pc.Close()
	fmt.Fprintf(h.Out, "受控回包端点 %s；最长%s，最多1024请求/1MiB。到期自动退出。\n", pc.LocalAddr(), *duration)
	_, err = probe.ServeUDPEcho(ctx, pc, probe.EchoOptions{MaxPackets: 1024, MaxBytes: 1 << 20, IdleTimeout: *duration})
	return err
}

func selectEndpointProfile(h Hooks, id, user, endpoint string) (probe.Profile, error) {
	if h.SelectEndpointProfile != nil {
		return h.SelectEndpointProfile(id, user, endpoint)
	}
	if endpoint != "" && endpoint != "default" {
		return probe.Profile{}, errors.New("此入口不支持选择连接端点")
	}
	if h.SelectProfile == nil {
		return probe.Profile{}, errors.New("需要管理器生成私密Profile")
	}
	return h.SelectProfile(id, user)
}
