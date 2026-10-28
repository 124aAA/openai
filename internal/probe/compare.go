package probe

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"
)

type Comparison struct {
	Version          int                     `json:"version"`
	Comparable       bool                    `json:"comparable"`
	Reasons          []string                `json:"reasons,omitempty"`
	Changes          map[string]MetricChange `json:"changes,omitempty"`
	Limitations      []string                `json:"limitations"`
	ControlledChange *ControlledChange       `json:"controlled_change,omitempty"`
}

// ControlledChange permits one declared configuration change. The caller must
// obtain these digests from the saved, reviewed plan, never rewrite reports.
// This is an association with a plan, not proof that the plan was applied on
// another host or that the change caused an observed performance difference.
type ControlledChange struct {
	Version            int    `json:"version"`
	PlanSHA256         string `json:"plan_sha256"`
	NodeID             string `json:"node_id"`
	BeforeClientSHA256 string `json:"before_client_sha256"`
	AfterClientSHA256  string `json:"after_client_sha256"`
	BeforeServerSHA256 string `json:"before_server_sha256"`
	AfterServerSHA256  string `json:"after_server_sha256"`
}

type MetricChange struct {
	Before        float64  `json:"before_median"`
	After         float64  `json:"after_median"`
	Delta         float64  `json:"delta"`
	Percent       *float64 `json:"percent"`
	Unit          string   `json:"unit"`
	BeforeSamples int      `json:"before_samples"`
	AfterSamples  int      `json:"after_samples"`
}

// Compare requires the same initiator, route, target, versions and budgets.
// A missing value is never converted to zero. It does not infer causation.
func Compare(a, b Report) Comparison {
	return compare(a, b, nil)
}

func CompareControlled(a, b Report, change ControlledChange) Comparison {
	return compare(a, b, &change)
}

func compare(a, b Report, change *ControlledChange) Comparison {
	c := Comparison{Version: 1, Changes: map[string]MetricChange{}, Limitations: []string{"结果只描述本次样本；数值变化不能证明变化原因。"}}
	beforeConditions, afterConditions := a.Conditions, b.Conditions
	if change != nil {
		c.Version = 2
		c.ControlledChange = change
		validDigest := func(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
		if change.Version != 1 || change.NodeID == "" || !validDigest(change.PlanSHA256) ||
			!validDigest(change.BeforeClientSHA256) || !validDigest(change.AfterClientSHA256) ||
			!validDigest(change.BeforeServerSHA256) || !validDigest(change.AfterServerSHA256) {
			c.Reasons = append(c.Reasons, "性能方案缺少有效版本、节点或配置摘要")
		}
		if a.Conditions.Path != "client-proxy" || b.Conditions.Path != "client-proxy" ||
			a.Conditions.NodeID != change.NodeID || b.Conditions.NodeID != change.NodeID ||
			a.Conditions.ConfigSHA256 != change.BeforeClientSHA256 || b.Conditions.ConfigSHA256 != change.AfterClientSHA256 {
			c.Reasons = append(c.Reasons, "报告的指定代理、节点或前后配置摘要与方案不一致")
		}
		if change.BeforeClientSHA256 == change.AfterClientSHA256 && change.BeforeServerSHA256 == change.AfterServerSHA256 {
			c.Reasons = append(c.Reasons, "方案没有实际运行或客户端配置变化，请用普通probe compare")
		}
		// Compare all other conditions unchanged. The original reports, including
		// their configuration identities, are validated below without alteration.
		beforeConditions.ConfigSHA256, afterConditions.ConfigSHA256 = "", ""
		c.Limitations = append(c.Limitations, "只允许保存方案中声明的配置差异；报告不能证明远端已应用该方案，也不能排除同时发生的公网变化。", "不自动判断显著收益，不自动选择或回退性能设置；保留原始报告复核。")
	}
	if err := ValidateReport(a); err != nil {
		c.Reasons = append(c.Reasons, "前一份报告格式不支持，或原始样本与统计不一致")
	}
	if err := ValidateReport(b); err != nil {
		c.Reasons = append(c.Reasons, "后一份报告格式不支持，或原始样本与统计不一致")
	}
	if (a.Version != 1 && a.Version != 2) || (b.Version != 1 && b.Version != 2) {
		c.Reasons = append(c.Reasons, "报告版本不受支持")
	}
	if a.Source != "qingnode-automatic-probe" || b.Source != "qingnode-automatic-probe" {
		c.Reasons = append(c.Reasons, "手动public-check登记不是自动测量结果")
	}
	if a.Status != "completed" || b.Status != "completed" {
		c.Reasons = append(c.Reasons, "两份报告都须完整通过；失败、取消或未完成结果不能直接比较")
	}
	if !reflect.DeepEqual(beforeConditions, afterConditions) {
		c.Reasons = append(c.Reasons, "测试条件不同：发起端、路径、目标、地址族、配置、版本、UDP端点或预算存在差异")
	}
	if a.StartedAt.IsZero() || b.StartedAt.IsZero() {
		c.Reasons = append(c.Reasons, "缺少测试时间")
	} else if d := a.StartedAt.Sub(b.StartedAt); d > 24*time.Hour || d < -24*time.Hour {
		c.Reasons = append(c.Reasons, "两次测试相隔超过24小时")
	}
	if len(c.Reasons) > 0 {
		return c
	}
	for k, x := range a.Statistics {
		y, ok := b.Statistics[k]
		if !ok || x.Median == nil || y.Median == nil || x.Values == 0 || y.Values == 0 || x.Unit != y.Unit {
			continue
		}
		v := MetricChange{Before: *x.Median, After: *y.Median, Delta: *y.Median - *x.Median, Unit: x.Unit, BeforeSamples: x.Values, AfterSamples: y.Values}
		if *x.Median != 0 {
			p := v.Delta / *x.Median * 100
			v.Percent = &p
		}
		c.Changes[k] = v
		if x.Values < 20 || y.Values < 20 {
			c.Limitations = append(c.Limitations, fmt.Sprintf("%s 的有效样本少于20个；p95与变化只作描述，可信度有限。", k))
		}
	}
	if len(c.Changes) == 0 {
		c.Reasons = append(c.Reasons, "没有两份报告共同具备的有效指标")
		return c
	}
	c.Comparable = true
	return c
}

func ValidateReport(r Report) error {
	if (r.Version != 1 && r.Version != 2) || (r.Version == 1 && r.Conditions.ServerPathSHA256 != "") || (r.Version == 2 && !validSHA256(r.Conditions.ServerPathSHA256)) {
		return errors.New("unsupported probe report version")
	}
	if r.Source != "qingnode-automatic-probe" {
		return errors.New("report is not an automatic probe result")
	}
	if r.Status != "completed" && r.Status != "failed" && r.Status != "canceled" && r.Status != "timeout" {
		return errors.New("invalid probe status")
	}
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return errors.New("invalid report timestamps")
	}
	c := r.Conditions
	if c.Path != "local" && c.Path != "server-outbound" && c.Path != "client-proxy" && c.Path != "controlled-link" {
		return errors.New("报告缺少有效测试路径")
	}
	if (c.Mode != "light" && c.Mode != "download") || (c.Family != "auto" && c.Family != "ipv4" && c.Family != "ipv6") || c.Initiator == "" {
		return errors.New("报告缺少模式、地址族或发起端")
	}
	o := Options{Path: c.Path, Mode: c.Mode, TargetURL: c.Target, Family: c.Family, Timeout: time.Duration(c.Limits.TimeoutMS) * time.Millisecond, MaxBytes: c.Limits.MaxPayloadBytes, Samples: c.Limits.Samples, Concurrency: c.Limits.Concurrency, Initiator: c.Initiator, NodeID: c.NodeID, ConfigSHA256: c.ConfigSHA256, ServerPathSHA256: c.ServerPathSHA256, CoreVersion: c.CoreVersion, ClientVersion: c.ClientVersion, UDPAddress: c.UDPAddress, UDPTimeout: time.Duration(c.Limits.UDPTimeoutMS) * time.Millisecond}
	if c.Limits.TimeoutMS <= 0 || c.Limits.MaxPayloadBytes <= 0 || c.Limits.Samples < 1 || c.Limits.Concurrency < 1 {
		return errors.New("report has missing measurement limits")
	}
	if _, err := NormalizeOptions(o); err != nil {
		return errors.New("invalid report measurement conditions")
	}
	if c.Path == "local" {
		if c.TargetSHA256 != "" || len(r.Samples) != 0 || r.UDP != nil {
			return errors.New("local report contains network measurements")
		}
	} else {
		if len(c.TargetSHA256) != 64 || strings.Trim(c.TargetSHA256, "0123456789abcdef") != "" {
			return errors.New("missing or invalid target digest")
		}
		u, err := url.Parse(c.Target)
		if err != nil || u.Path != "" || u.RawQuery != "" || u.User != nil {
			return errors.New("report target must be a sanitized HTTPS origin")
		}
	}
	validNumber := func(p *float64) bool { return p == nil || (!math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0) }
	failed := len(r.Errors) > 0
	for _, stage := range []Stage{r.DNS, r.Connection, r.TLS} {
		switch stage.Status {
		case "unknown", "not-requested", "not-applicable", "success", "failed":
		default:
			return errors.New("invalid report stage status")
		}
		if !validNumber(stage.ElapsedMS) {
			return errors.New("invalid stage duration")
		}
		if stage.Status == "failed" {
			failed = true
		}
		if stage.Status == "unknown" && stage.ElapsedMS != nil {
			return errors.New("unknown stage cannot have a measured duration")
		}
	}
	if c.Path == "client-proxy" && (r.DNS.Status != "unknown" || r.Connection.Status != "unknown" || r.TLS.Status != "unknown") {
		return errors.New("proxy report claims unobserved independent stages")
	}
	seen := map[string]bool{}
	var downloaded int64
	for _, s := range r.Samples {
		limit := c.Limits.Samples
		switch s.Kind {
		case "idle", "load", "load_partial_overlap":
		case "download":
			limit = c.Limits.Concurrency
		default:
			return errors.New("invalid sample kind")
		}
		key := fmt.Sprintf("%s/%d", s.Kind, s.Sequence)
		if seen[key] || s.Sequence < 1 || s.Sequence > limit {
			return errors.New("duplicate or out-of-range sample sequence")
		}
		seen[key] = true
		if s.Status != "success" && s.Status != "failed" {
			return errors.New("invalid sample status")
		}
		if !validNumber(s.ElapsedMS) || !validNumber(s.TTFBMS) || !validNumber(s.ThroughputMbps) || s.PayloadBytes < 0 {
			return errors.New("invalid sample measurement")
		}
		if s.TTFBMS != nil && s.ElapsedMS != nil && *s.TTFBMS > *s.ElapsedMS+1 {
			return errors.New("TTFB exceeds total request time")
		}
		if s.HTTPStatus != nil && (*s.HTTPStatus < 100 || *s.HTTPStatus > 599) {
			return errors.New("invalid HTTP status")
		}
		if s.Status == "success" {
			if s.HTTPStatus == nil || *s.HTTPStatus < 200 || *s.HTTPStatus >= 400 || s.ErrorCategory != "" || s.Error != "" {
				return errors.New("successful sample has failure evidence")
			}
		} else {
			failed = true
			if s.ErrorCategory == "" {
				return errors.New("failed sample lacks error category")
			}
		}
		if s.Kind != "download" && (s.PayloadBytes != 0 || s.ThroughputMbps != nil) {
			return errors.New("non-download sample contains throughput")
		}
		if s.ThroughputMbps != nil {
			if s.Status != "success" || s.PayloadBytes == 0 || s.ElapsedMS == nil || *s.ElapsedMS == 0 {
				return errors.New("invalid throughput sample")
			}
			expected := float64(s.PayloadBytes) * 8 / (*s.ElapsedMS * 1000)
			if math.Abs(expected-*s.ThroughputMbps) > 1e-9*math.Max(1, expected) {
				return errors.New("throughput does not match bytes and elapsed time")
			}
		}
		downloaded += s.PayloadBytes
	}
	if downloaded != r.Traffic.PayloadBytesReceived || r.Traffic.UDPPayloadBytesSent < 0 || r.Traffic.UDPPayloadBytesReceived < 0 || downloaded+r.Traffic.UDPPayloadBytesSent+r.Traffic.UDPPayloadBytesReceived > c.Limits.MaxPayloadBytes {
		return errors.New("report traffic counters do not match samples or budget")
	}
	if !reflect.DeepEqual(r.Statistics, statistics(r.Samples)) {
		return errors.New("report statistics do not match raw samples")
	}
	if r.UDP != nil {
		if c.UDPAddress == "" || r.UDP.Target != c.UDPAddress || (r.UDP.Status != "passed" && r.UDP.Status != "failed") {
			return errors.New("invalid UDP report identity or status")
		}
		if r.UDP.Status != "passed" || r.UDP.Lost > 0 || r.UDP.Unfinished > 0 {
			failed = true
		}
		if r.UDP.SentBytes != r.Traffic.UDPPayloadBytesSent || r.UDP.ReceivedBytes+r.UDP.DiscardedBytes != r.Traffic.UDPPayloadBytesReceived {
			return errors.New("UDP traffic counters do not match")
		}
		if err := validateUDPResult(*r.UDP, c.Limits.Samples); err != nil {
			return err
		}
	}
	if r.Status == "completed" {
		if failed {
			return errors.New("completed report contains failed or incomplete measurements")
		}
		if c.Path != "local" {
			idle := r.Statistics["idle_request"]
			if idle.Attempts != c.Limits.Samples || idle.Successes != idle.Attempts {
				return errors.New("completed report lacks requested idle samples")
			}
			if c.Mode == "download" && r.Statistics["download_throughput"].Attempts == 0 {
				return errors.New("completed report lacks download measurements")
			}
			if c.UDPAddress != "" && r.UDP == nil {
				return errors.New("completed report lacks requested UDP measurements")
			}
		}
	}
	if r.Status == "failed" && !failed {
		return errors.New("failed report lacks failure evidence")
	}
	return nil
}

func validateUDPResult(u UDPResult, limit int) error {
	if u.Sent < 0 || u.Received < 0 || u.Lost < 0 || u.Unfinished < 0 || u.Sent > limit || u.Received+u.Lost+u.Unfinished != u.Sent || len(u.Samples) > limit || u.DiscardedBytes < 0 {
		return errors.New("UDP sample counts are inconsistent")
	}
	if u.ReceivedBytes != int64(u.Received)*64 || u.SentBytes < int64(u.Sent)*64 || u.SentBytes > int64(u.Sent+1)*64 {
		return errors.New("UDP payload counters are inconsistent")
	}
	values := []float64{}
	lost := 0
	var previous *float64
	previousSeq := -1
	changes := []float64{}
	for i, s := range u.Samples {
		if s.Sequence != i || s.Discarded < 0 {
			return errors.New("invalid UDP sample sequence")
		}
		if s.RTTMS != nil {
			if s.Error != "" || math.IsNaN(*s.RTTMS) || math.IsInf(*s.RTTMS, 0) || *s.RTTMS < 0 {
				return errors.New("invalid UDP RTT sample")
			}
			values = append(values, *s.RTTMS)
			if previous != nil && previousSeq == s.Sequence-1 {
				changes = append(changes, math.Abs(*s.RTTMS-*previous))
			}
			previous = s.RTTMS
			previousSeq = s.Sequence
		} else if s.Error == "" {
			return errors.New("missing UDP sample result")
		}
		if s.Error == "udp_no_response" {
			lost++
		}
	}
	if len(values) != u.Received || lost != u.Lost {
		return errors.New("UDP result does not match raw samples")
	}
	near := func(a, b *float64) bool {
		if a == nil || b == nil {
			return a == nil && b == nil
		}
		return !math.IsNaN(*a) && !math.IsInf(*a, 0) && math.Abs(*a-*b) <= 1e-9*math.Max(1, math.Abs(*b))
	}
	var median, p95, jitter, loss *float64
	if len(values) > 0 {
		sort.Float64s(values)
		v := medianUDP(values)
		median = &v
		p := percentile(values, .95)
		p95 = &p
	}
	if len(changes) > 0 {
		sum := 0.0
		for _, v := range changes {
			sum += v
		}
		v := sum / float64(len(changes))
		jitter = &v
	}
	if u.Sent > 0 && u.Unfinished == 0 && u.Error != "cancelled" && u.Error != "timeout" && u.Error != "byte_limit" {
		v := float64(u.Lost) * 100 / float64(u.Sent)
		loss = &v
	}
	if !near(u.MedianRTTMS, median) || !near(u.P95RTTMS, p95) || !near(u.JitterMS, jitter) || !near(u.LossPercent, loss) {
		return errors.New("UDP statistics do not match raw samples")
	}
	if u.Status == "passed" && (u.Sent != limit || u.Received != limit || u.Lost != 0 || u.Unfinished != 0 || u.Error != "") {
		return errors.New("successful UDP result contains unfinished samples")
	}
	return nil
}
