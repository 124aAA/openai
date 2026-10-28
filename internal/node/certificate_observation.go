package node

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"qingnode/internal/platform"
)

// CertificateJournalObservation reports actual journal events. Empty fields mean
// unknown: normal warn logging need not record successful issuance. Certificate
// NotBefore, file timestamps and ACME lock files are never used as event times.
type CertificateJournalObservation struct {
	LastSuccess     *time.Time `json:"last_success,omitempty"`
	LastFailure     *time.Time `json:"last_failure,omitempty"`
	FailureCategory string     `json:"failure_category,omitempty"`
	FailureReason   string     `json:"failure_reason,omitempty"`
	Issuing         *bool      `json:"issuing,omitempty"`
	ObservedAt      time.Time  `json:"observed_at"`
	Phase           string     `json:"last_observed_phase,omitempty"`
	PhaseObservedAt *time.Time `json:"phase_observed_at,omitempty"`
	Evidence        string     `json:"evidence"`
	Limitation      string     `json:"limitation,omitempty"`
}

var certificateEventLine = regexp.MustCompile(`^(?:[+-][0-9]{4} [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?(?:INFO|ERROR)[ \t]*(?:\[[0-9]{4,12}\][ \t]*)?(certificate-provider/acme\[certificate-[a-f0-9]{16}\]|inbound/hysteria2\[[a-f0-9]{16}\]): (obtain|renew): (obtaining certificate|renewing certificate|certificate obtained successfully|certificate renewed successfully|could not get certificate from issuer): (\{[^\r\n]*\})$`)
var invocationIDRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (b SystemBackend) InspectCertificateJournal(st State, r CertificateResource, now time.Time) (CertificateJournalObservation, error) {
	result := CertificateJournalObservation{ObservedAt: now.UTC(), Evidence: "systemd-journal; exact fixed-core events only", Limitation: "最近128条日志；默认warn级别可能没有成功/签发中事件，缺失为未知"}
	if b.ServiceManager().ResolvedKind() != platform.InitSystemd {
		result.Evidence = "unavailable; no verified journal invocation epoch on this init"
		result.Limitation = "此init没有已验证的签发事件运行标识；证书文件状态仍可读取，签发中/最近成功或失败为未知"
		return result, nil
	}
	if r.Certificate.Mode != "acme" {
		result.Limitation = "手工证书没有核心ACME签发事件"
		return result, nil
	}
	matching := map[string]bool{}
	for _, n := range st.Nodes {
		if n.Enabled && n.Certificate != nil && n.Certificate.Mode == "acme" && strings.EqualFold(n.Certificate.ServerName, r.Certificate.ServerName) {
			matching[n.CertificateID] = true
		}
	}
	if len(matching) != 1 || !matching[r.ID] {
		result.Limitation = "资源未由启用节点引用，或同域名有多个资源；不能准确归属签发事件"
		return result, nil
	}
	properties, e := b.run(5*time.Second, "systemctl", "show", "qingnode.service", "--property=InvocationID,ActiveState,MainPID")
	if e != nil {
		return result, errors.New("无法读取受管服务本次运行标识；证书事件未知")
	}
	invocation, active, pid, e := parseCertificateInvocation(properties)
	if e != nil {
		return result, e
	}
	data, e := b.run(5*time.Second, "journalctl", "--unit=qingnode.service", "--output=json", "--no-pager", "--lines=128", "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_INVOCATION_ID,MESSAGE")
	if e != nil {
		return result, errors.New("无法读取受管服务日志；证书事件未知")
	}
	owners := map[string]bool{}
	if r.Certificate.ACME != nil {
		owners["certificate-provider/acme[certificate-"+r.ID+"]"] = true
	} else {
		for _, n := range st.Nodes {
			if n.Enabled && n.CertificateID == r.ID {
				owners["inbound/hysteria2["+n.ID+"]"] = true
			}
		}
	}
	return parseCertificateJournalOwned(data, r.Certificate.ServerName, invocation, active, pid, now, result, owners)
}
func parseCertificateInvocation(data []byte) (string, string, int, error) {
	if len(data) > 4096 {
		return "", "", 0, errors.New("服务运行标识响应超限")
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, v, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return "", "", 0, errors.New("服务运行标识不完整或重复")
		}
		values[key] = v
		seen[key] = true
	}
	for _, key := range []string{"InvocationID", "ActiveState", "MainPID"} {
		if !seen[key] {
			return "", "", 0, errors.New("服务运行标识缺少字段")
		}
	}
	active := values["ActiveState"]
	if active != "active" && active != "activating" && active != "inactive" && active != "failed" && active != "deactivating" {
		return "", "", 0, errors.New("服务运行状态未知")
	}
	pid, e := strconv.Atoi(values["MainPID"])
	if e != nil || pid < 0 {
		return "", "", 0, errors.New("服务进程标识无效")
	}
	invocation := values["InvocationID"]
	if invocation != "" && !invocationIDRE.MatchString(invocation) {
		return "", "", 0, errors.New("服务本次运行标识无效")
	}
	if (active == "active" || active == "activating") && (invocation == "" || pid == 0) {
		return "", "", 0, errors.New("活动服务缺少本次运行或进程标识")
	}
	return invocation, active, pid, nil
}
func parseCertificateJournal(data []byte, domain, invocation, active string, pid int, now time.Time, result CertificateJournalObservation) (CertificateJournalObservation, error) {
	return parseCertificateJournalOwned(data, domain, invocation, active, pid, now, result, nil)
}
func parseCertificateJournalOwned(data []byte, domain, invocation, active string, pid int, now time.Time, result CertificateJournalObservation, owners map[string]bool) (CertificateJournalObservation, error) {
	if len(data) > 1<<20 {
		return result, errors.New("证书日志观测超过1MiB上限")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 32<<10)
	var newestCurrent time.Time
	currentEvent := ""
	count := 0
	for scanner.Scan() {
		count++
		if count > 128 {
			return result, errors.New("证书日志观测超过128条上限")
		}
		var entry struct {
			Timestamp  string `json:"__REALTIME_TIMESTAMP"`
			Invocation string `json:"_SYSTEMD_INVOCATION_ID"`
			Message    string `json:"MESSAGE"`
		}
		if rejectStateDuplicateFields(scanner.Bytes()) != nil || json.Unmarshal(scanner.Bytes(), &entry) != nil || !invocationIDRE.MatchString(entry.Invocation) {
			continue
		}
		micros, e := strconv.ParseInt(entry.Timestamp, 10, 64)
		if e != nil || micros <= 0 {
			continue
		}
		at := time.UnixMicro(micros).UTC()
		if at.After(now.Add(time.Second)) || at.Before(now.Add(-7*24*time.Hour)) {
			continue
		}
		match := certificateEventLine.FindStringSubmatch(entry.Message)
		if len(match) != 5 || owners != nil && !owners[match[1]] {
			continue
		}
		// Legacy inline providers log their node ID, not a certificate resource
		// ID. Older invocations could have used different certificate material.
		if strings.HasPrefix(match[1], "inbound/") && entry.Invocation != invocation {
			continue
		}
		var fields struct {
			Identifier string `json:"identifier"`
			Error      string `json:"error"`
		}
		if rejectStateDuplicateFields([]byte(match[4])) != nil || json.Unmarshal([]byte(match[4]), &fields) != nil || !strings.EqualFold(fields.Identifier, domain) {
			continue
		}
		phase, event := match[2], match[3]
		if event == "obtaining certificate" && phase != "obtain" || event == "renewing certificate" && phase != "renew" || event == "certificate obtained successfully" && phase != "obtain" || event == "certificate renewed successfully" && phase != "renew" {
			continue
		}
		switch event {
		case "certificate obtained successfully", "certificate renewed successfully":
			if result.LastSuccess == nil || at.After(*result.LastSuccess) {
				copy := at
				result.LastSuccess = &copy
			}
		case "could not get certificate from issuer":
			if result.LastFailure == nil || at.After(*result.LastFailure) {
				copy := at
				result.LastFailure = &copy
				result.FailureCategory, result.FailureReason = certificateFailureClass(fields.Error)
			}
		}
		if invocation != "" && entry.Invocation == invocation && at.After(newestCurrent) {
			newestCurrent, currentEvent = at, event
		}
	}
	if e := scanner.Err(); e != nil {
		return result, errors.New("证书日志单条超限或读取失败")
	}
	if active == "inactive" || active == "failed" {
		value := false
		result.Issuing = &value
	} else if (active == "active" || active == "activating") && pid > 0 && !newestCurrent.IsZero() {
		at := newestCurrent
		result.PhaseObservedAt = &at
		switch currentEvent {
		case "certificate obtained successfully", "certificate renewed successfully", "could not get certificate from issuer":
			value := false
			result.Issuing = &value
		case "obtaining certificate", "renewing certificate":
			if now.Sub(newestCurrent) <= 2*time.Minute {
				result.Phase = "issuing"
				value := true
				result.Issuing = &value
				result.Limitation = "本次运行最近两分钟存在明确签发/续期开始事件；未观察到终止事件，不能保证任务仍在执行"
			}
		}
	}
	return result, nil
}
func certificateFailureClass(detail string) (string, string) {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "ratelimited") || strings.Contains(lower, "rate limit"):
		return "ca_rate_limit", "CA报告速率限制，请遵守重试时间并先使用测试CA排查"
	case strings.Contains(lower, "rejectedidentifier") || strings.Contains(lower, "rejected identifier"):
		return "ca_policy", "CA拒绝该域名或签发策略，请核对域名与CA限制"
	case strings.Contains(lower, "propagation") || strings.Contains(lower, "dns"):
		return "dns_validation", "DNS记录或传播验证失败，请核对权限、委派和传播状态"
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "timeout") || strings.Contains(lower, "dial tcp"):
		return "network", "CA或挑战链路连接失败，请核对实际公网端口与网络"
	case strings.Contains(lower, "unauthorized") || strings.Contains(lower, "challenge"):
		return "challenge_validation", "CA挑战验证失败，请核对域名及公网80/443或DNS记录"
	default:
		return "ca_issuance", fmt.Sprint("核心记录了CA签发/续期失败；原始错误不在状态接口回显，避免泄露提供者凭据")
	}
}
