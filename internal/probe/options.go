// Package probe runs bounded measurements without changing a managed node.
package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ReportVersion          = 1
	MaxDuration            = 120 * time.Second
	MaxDownloadBytes int64 = 64 << 20
	MaxConcurrency         = 4
	MaxSamples             = 64
)

type Options struct {
	Path             string
	Mode             string
	TargetURL        string
	Family           string
	Timeout          time.Duration
	MaxBytes         int64
	Samples          int
	Concurrency      int
	Initiator        string
	NodeID           string
	ConfigSHA256     string
	ServerPathSHA256 string
	CoreVersion      string
	ClientVersion    string
	ToolVersions     map[string]string
	UDPAddress       string
	UDPProxyAddress  string
	UDPProxyUsername string `json:"-"`
	UDPProxyPassword string `json:"-"`
	UDPTimeout       time.Duration
}

type Dependencies struct {
	// A proxy path requires an explicitly supplied transport. No environment
	// proxy or direct transport is substituted after it fails.
	Transport  http.RoundTripper
	Resolve    func(context.Context, string) ([]net.IPAddr, error)
	UDPProbe   func(context.Context, UDPOptions) (UDPResult, error)
	Metrics    func() Metrics
	MetricsPID int
}

type Engine struct{ Dependencies Dependencies }

func (e Engine) Run(ctx context.Context, o Options) (Report, error) {
	return Run(ctx, o, e.Dependencies)
}

func NormalizeOptions(o Options) (Options, error) {
	if o.Path == "" {
		o.Path = "local"
	}
	switch o.Path {
	case "local", "server-outbound", "client-proxy", "controlled-link":
	default:
		return o, errors.New("路径必须为local、server-outbound、client-proxy或controlled-link")
	}
	if o.Mode == "" {
		o.Mode = "light"
	}
	if o.Mode != "light" && o.Mode != "download" {
		return o, errors.New("模式必须为light（轻量探测）或download（下载测速）")
	}
	if o.Family == "" {
		o.Family = "auto"
	}
	if o.Family != "auto" && o.Family != "ipv4" && o.Family != "ipv6" {
		return o, errors.New("地址族必须为auto、ipv4或ipv6")
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Timeout < time.Millisecond || o.Timeout > MaxDuration {
		return o, errors.New("总时间预算必须为正数，最多120秒")
	}
	if o.MaxBytes == 0 {
		if o.Mode == "download" {
			o.MaxBytes = 8 << 20
		} else {
			o.MaxBytes = 64 << 10
		}
	}
	if o.MaxBytes < 1 || o.MaxBytes > MaxDownloadBytes {
		return o, errors.New("有效载荷预算必须为1到67108864字节")
	}
	if o.Mode == "light" && o.MaxBytes > 64<<10 {
		return o, errors.New("轻量探测最多65536字节；大流量测速请明确选择download模式")
	}
	if o.Samples == 0 {
		o.Samples = 8
	}
	if o.Samples < 1 || o.Samples > MaxSamples {
		return o, errors.New("样本数必须为1到64")
	}
	if o.Concurrency == 0 {
		o.Concurrency = 1
	}
	if o.Concurrency < 1 || o.Concurrency > MaxConcurrency {
		return o, errors.New("下载并发必须为1到4")
	}
	if o.Mode == "light" && o.Concurrency != 1 {
		return o, errors.New("轻量探测只允许一次一个连接")
	}
	if o.UDPTimeout == 0 {
		o.UDPTimeout = time.Second
	}
	if o.UDPTimeout < time.Millisecond || o.UDPTimeout > 5*time.Second {
		return o, errors.New("每个UDP样本的等待时间必须为1毫秒到5秒")
	}
	if o.Initiator == "" {
		o.Initiator = "unspecified"
	}
	for _, value := range []string{o.Initiator, o.NodeID, o.CoreVersion, o.ClientVersion} {
		if len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return o, errors.New("测试身份或版本说明含控制字符或过长")
		}
	}
	if len(o.ConfigSHA256) != 0 && (len(o.ConfigSHA256) != 64 || strings.Trim(o.ConfigSHA256, "0123456789abcdef") != "") {
		return o, errors.New("配置摘要必须是64位小写SHA-256校验值")
	}
	if o.ServerPathSHA256 != "" && (!validSHA256(o.ServerPathSHA256) || o.Path != "client-proxy" || o.NodeID == "" || !validSHA256(o.ConfigSHA256)) {
		return o, errors.New("服务端链路摘要须为64位小写SHA-256，并绑定指定节点和客户端配置的代理测试")
	}
	if o.Path == "local" {
		if o.TargetURL != "" || o.UDPAddress != "" || o.Mode != "light" {
			return o, errors.New("本机只读诊断不接受网络目标或下载模式")
		}
		return o, nil
	}
	u, err := url.Parse(o.TargetURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return o, errors.New("请明确提供HTTPS目标；不能在地址中放用户名、密码或#片段")
	}
	if strings.ContainsAny(o.TargetURL, "\r\n\x00") || len(o.TargetURL) > 4096 {
		return o, errors.New("目标地址无效或过长")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && ((o.Family == "ipv4" && ip.To4() == nil) || (o.Family == "ipv6" && ip.To4() != nil)) {
		return o, errors.New("目标IP与要求的IPv4或IPv6地址族不符")
	}
	if o.Path == "client-proxy" && o.Family != "auto" && net.ParseIP(u.Hostname()) == nil {
		return o, errors.New("经代理测试指定IPv4或IPv6时，必须使用对应的字面IP目标；域名请选auto")
	}
	if o.UDPAddress != "" {
		if err := validateUDPOptions(UDPOptions{Target: o.UDPAddress, ProxyAddress: o.UDPProxyAddress, ProxyUsername: o.UDPProxyUsername, ProxyPassword: o.UDPProxyPassword, Family: o.Family, Samples: o.Samples, PayloadBytes: 64, Interval: 10 * time.Millisecond, Timeout: o.UDPTimeout, MaxBytes: int64(o.Samples) * 129}); err != nil {
			return o, err
		}
		if int64(o.Samples)*129 > o.MaxBytes {
			return o, errors.New("有效载荷预算不足，无法容纳所要求的UDP样本")
		}
	}
	return o, nil
}
