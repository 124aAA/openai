package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

type Conditions struct {
	Path             string            `json:"path"`
	Mode             string            `json:"mode"`
	Target           string            `json:"target,omitempty"`
	TargetSHA256     string            `json:"target_sha256,omitempty"`
	Family           string            `json:"address_family"`
	Initiator        string            `json:"initiator"`
	NodeID           string            `json:"node_id,omitempty"`
	ConfigSHA256     string            `json:"config_sha256,omitempty"`
	ServerPathSHA256 string            `json:"server_path_sha256,omitempty"`
	CoreVersion      string            `json:"server_core_version,omitempty"`
	ClientVersion    string            `json:"client_core_version,omitempty"`
	ToolVersions     map[string]string `json:"tool_versions,omitempty"`
	Limits           Limits            `json:"limits"`
	UDPAddress       string            `json:"udp_target,omitempty"`
}

type Limits struct {
	TimeoutMS       int64 `json:"timeout_ms"`
	MaxPayloadBytes int64 `json:"max_payload_bytes"`
	Samples         int   `json:"samples"`
	Concurrency     int   `json:"concurrency"`
	UDPTimeoutMS    int64 `json:"udp_sample_timeout_ms,omitempty"`
}

type Report struct {
	Version       int                   `json:"version"`
	Source        string                `json:"source"`
	StartedAt     time.Time             `json:"started_at"`
	FinishedAt    time.Time             `json:"finished_at"`
	Status        string                `json:"status"`
	Conditions    Conditions            `json:"conditions"`
	DNS           Stage                 `json:"dns"`
	Connection    Stage                 `json:"connection"`
	TLS           Stage                 `json:"tls"`
	Samples       []Sample              `json:"samples"`
	Statistics    map[string]Statistics `json:"statistics"`
	UDP           *UDPResult            `json:"udp,omitempty"`
	MetricsBefore Metrics               `json:"metrics_before"`
	MetricsAfter  Metrics               `json:"metrics_after"`
	Traffic       Traffic               `json:"traffic"`
	Errors        []Failure             `json:"errors,omitempty"`
	Limitations   []string              `json:"limitations"`
}

type Stage struct {
	Status    string   `json:"status"`
	ElapsedMS *float64 `json:"elapsed_ms"`
	Category  string   `json:"error_category,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

type Sample struct {
	Sequence       int      `json:"sequence"`
	Kind           string   `json:"kind"`
	Status         string   `json:"status"`
	HTTPStatus     *int     `json:"http_status"`
	ElapsedMS      *float64 `json:"elapsed_ms"`
	TTFBMS         *float64 `json:"ttfb_ms"`
	PayloadBytes   int64    `json:"payload_bytes"`
	ThroughputMbps *float64 `json:"throughput_mbps"`
	ErrorCategory  string   `json:"error_category,omitempty"`
	Error          string   `json:"error,omitempty"`
	BudgetLimited  bool     `json:"budget_limited,omitempty"`
}

type Statistics struct {
	Attempts    int      `json:"attempts"`
	Successes   int      `json:"successes"`
	Values      int      `json:"valid_values"`
	SuccessRate *float64 `json:"success_rate"`
	Median      *float64 `json:"median"`
	P95         *float64 `json:"p95"`
	Unit        string   `json:"unit"`
}

type Failure struct {
	Category string `json:"category"`
	Detail   string `json:"detail"`
}
type Traffic struct {
	PayloadBytesReceived    int64  `json:"payload_bytes_received"`
	UDPPayloadBytesSent     int64  `json:"udp_payload_bytes_sent"`
	UDPPayloadBytesReceived int64  `json:"udp_payload_bytes_received"`
	WireBytes               *int64 `json:"wire_bytes"`
	Accounting              string `json:"accounting"`
}

func conditions(o Options) Conditions {
	target := o.TargetURL
	digest := ""
	if target != "" {
		sum := sha256.Sum256([]byte(target))
		digest = hex.EncodeToString(sum[:])
	}
	if u, err := url.Parse(target); err == nil {
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		u.User = nil
		// The URL path may itself contain a signed token. Report the origin and
		// a digest of the exact target instead of retaining path/query secrets.
		u.Path = ""
		u.RawPath = ""
		target = u.String()
	}
	tools := make(map[string]string, len(o.ToolVersions))
	for k, v := range o.ToolVersions {
		if len(k) <= 64 && len(v) <= 128 && !strings.ContainsAny(k+v, "\r\n\x00") {
			tools[k] = v
		}
	}
	if len(tools) == 0 {
		tools = nil
	}
	return Conditions{Path: o.Path, Mode: o.Mode, Target: target, TargetSHA256: digest, Family: o.Family, Initiator: o.Initiator, NodeID: o.NodeID, ConfigSHA256: o.ConfigSHA256, ServerPathSHA256: o.ServerPathSHA256, CoreVersion: o.CoreVersion, ClientVersion: o.ClientVersion, ToolVersions: tools, Limits: Limits{o.Timeout.Milliseconds(), o.MaxBytes, o.Samples, o.Concurrency, o.UDPTimeout.Milliseconds()}, UDPAddress: o.UDPAddress}
}

const ServerPathLimitation = "服务端链路摘要只声明导出Profile时的配置；测试无法证明远端当前仍使用该配置。"

// ReportVersionFor preserves legacy report bytes unless a declared server path
// is present. Reports carrying the new identity require explicit version 2.
func ReportVersionFor(o Options) int {
	if o.ServerPathSHA256 != "" {
		return 2
	}
	return ReportVersion
}

// ReportConditions records sanitized identity even when client setup fails
// before Engine.Run can collect any network samples. Pass normalized options.
func ReportConditions(o Options) Conditions { return conditions(o) }

// WriteReport writes only the sanitized report, with private file permissions.
// The caller chooses the destination; reports never enter the managed State.
func WriteReport(path string, r Report) error {
	if err := ValidateReport(r); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(b, '\n'))
}

func ReadReport(path string) (Report, error) {
	var r Report
	info, err := os.Stat(path)
	if err != nil {
		return r, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return r, errors.New("报告必须是最多1MiB的普通文件；不读取管道或设备")
	}
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return r, err
	}
	if !i.Mode().IsRegular() || i.Size() > 1<<20 {
		return r, errors.New("报告必须是最多1MiB的普通文件；不读取管道或设备")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return r, err
	}
	if err = StrictJSON(b, &r); err != nil {
		return r, err
	}
	if err = validatePathFieldVersion(b, r.Version, true); err != nil {
		return r, err
	}
	return r, ValidateReport(r)
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "测试结果: %s（%s，自动测量，报告 v%d）\n发起端: %s；路径: %s；模式: %s；地址族: %s\n", humanStatus(r.Status), r.Status, r.Version, r.Conditions.Initiator, humanPath(r.Conditions.Path), r.Conditions.Mode, r.Conditions.Family)
	fmt.Fprintf(&b, "节点ID: %s；服务器核心: %s；客户端核心: %s\n", known(r.Conditions.NodeID), known(r.Conditions.CoreVersion), known(r.Conditions.ClientVersion))
	if r.Conditions.ServerPathSHA256 != "" {
		fmt.Fprintf(&b, "服务端链路声明摘要: %s\n", r.Conditions.ServerPathSHA256)
	}
	if r.Conditions.Target != "" {
		fmt.Fprintf(&b, "目标: %s\n", r.Conditions.Target)
	}
	fmt.Fprintf(&b, "时间预算: %d ms；有效载荷上限: %d bytes；实际下载: %d bytes\n", r.Conditions.Limits.TimeoutMS, r.Conditions.Limits.MaxPayloadBytes, r.Traffic.PayloadBytesReceived)
	for _, k := range []string{"idle_request", "load_request", "https_ttfb", "download_throughput"} {
		if s, ok := r.Statistics[k]; ok {
			label := map[string]string{"idle_request": "空闲HTTPS请求往返", "load_request": "下载期间HTTPS请求往返", "https_ttfb": "HTTPS首字节总耗时", "download_throughput": "单连接下载吞吐"}[k]
			fmt.Fprintf(&b, "%s: 成功 %d/%d", label, s.Successes, s.Attempts)
			if s.Median != nil {
				fmt.Fprintf(&b, "；中位数 %.3f %s", *s.Median, s.Unit)
			}
			if s.P95 != nil {
				fmt.Fprintf(&b, "；p95 %.3f %s", *s.P95, s.Unit)
			}
			b.WriteByte('\n')
		}
	}
	fmt.Fprintf(&b, "DNS（域名解析）: %s；独立连接时间: %s；独立TLS（加密连接）时间: %s\n", humanStatus(r.DNS.Status), humanStatus(r.Connection.Status), humanStatus(r.TLS.Status))
	if u := r.UDP; u != nil {
		fmt.Fprintf(&b, "UDP: %s；发送 %d，收到 %d，完整等待超时 %d，未完成 %d\n", humanStatus(u.Status), u.Sent, u.Received, u.Lost, u.Unfinished)
		if u.LossPercent != nil {
			fmt.Fprintf(&b, "UDP丢包: %.3f%%\n", *u.LossPercent)
		} else {
			b.WriteString("UDP丢包: 未知（未完成请求不能算作丢包样本）\n")
		}
		if u.MedianRTTMS != nil {
			fmt.Fprintf(&b, "UDP请求往返中位数: %.3f ms\n", *u.MedianRTTMS)
		}
		if u.P95RTTMS != nil {
			fmt.Fprintf(&b, "UDP请求往返p95: %.3f ms（95%%样本不超过此值）\n", *u.P95RTTMS)
		}
		if u.JitterMS != nil {
			fmt.Fprintf(&b, "UDP相邻成功样本RTT变化均值: %.3f ms\n", *u.JitterMS)
		}
		if u.Error != "" {
			fmt.Fprintf(&b, "UDP失败类别: %s\n", u.Error)
		}
		if u.LimitNote != "" {
			fmt.Fprintf(&b, "UDP限制: %s\n", u.LimitNote)
		}
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "失败类别: %s（%s）\n", e.Category, e.Detail)
	}
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "限制: %s\n", l)
	}
	return b.String()
}

func known(s string) string {
	if s == "" {
		return "未知"
	}
	return s
}
func humanStatus(s string) string {
	if v, ok := map[string]string{"completed": "通过", "success": "成功", "passed": "通过", "failed": "未通过", "canceled": "已取消", "timeout": "超时", "unknown": "未知", "not-requested": "未请求", "not-applicable": "不适用"}[s]; ok {
		return v
	}
	return s
}
func humanPath(s string) string {
	if v, ok := map[string]string{"local": "本机只读诊断", "server-outbound": "服务器出站", "client-proxy": "客户端经所选代理", "controlled-link": "受控机器链路"}[s]; ok {
		return v
	}
	return s
}
