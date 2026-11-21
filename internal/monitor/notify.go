package monitor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"qingnode/internal/node"
)

var notifyInlineSecret = regexp.MustCompile(`(?i)((?:(?:obfs|reality|pre[ _-]?shared|preshared|server|private)[ _-]?)?(?:password|key)|key_pem|(?:subscription[ _-]?)?token|api[ _-]?(?:key|token|secret)|secret|密码|私钥|混淆密码|服务密钥)([ \t]*[:：=][ \t]*)[^\s,;，；)]+`)

// Notifier deliberately returns only a stable delivery category. Raw network
// errors, response bodies, destination URLs and credentials never enter logs.
// A custom client is useful for controlled httptest endpoints; redirect and
// timeout policy are always imposed here, including on injected clients.
type Notifier struct {
	Client *http.Client
	Redact func(string) string
	Now    func() time.Time
	mu     sync.Mutex
	gate   chan struct{}
}

func (n *Notifier) now() time.Time {
	if n != nil && n.Now != nil {
		return n.Now().UTC()
	}
	return time.Now().UTC()
}

func (n *Notifier) scrub(s string, nc NotificationConfig, extra func(string) string) string {
	if s == "" {
		return ""
	}
	out := node.Redact(s)
	out = notifyInlineSecret.ReplaceAllString(out, `${1}${2}[凭据已隐藏]`)
	if n != nil && n.Redact != nil {
		out = n.Redact(out)
	}
	if extra != nil {
		out = extra(out)
	}
	for _, secret := range []string{nc.Token, nc.Secret, nc.ChatID, nc.Endpoint} {
		if secret != "" {
			out = strings.ReplaceAll(out, secret, "[redacted]")
		}
	}
	return out
}

func sanitizeEvent(ev Event, scrub func(string) string) Event {
	ev.Host = scrub(ev.Host)
	ev.TargetName = scrub(ev.TargetName)
	ev.TargetID = scrub(ev.TargetID)
	ev.Reason = scrub(ev.Reason)
	ev.RecoveryResult = scrub(ev.RecoveryResult)
	if len(ev.Signals) > 0 {
		sigs := make([]string, len(ev.Signals))
		for i, s := range ev.Signals {
			sigs[i] = scrub(s)
		}
		ev.Signals = sigs
	}
	return ev
}

func formatNotificationTitle(ev Event) string {
	switch ev.Kind {
	case "recovery":
		return "[QingNode] 监控恢复通知"
	case "cert-expiring":
		return "[QingNode] 证书临近过期提醒"
	case "quota-warning":
		return "[QingNode] 流量配额软告警"
	case "quota-disabled":
		return "[QingNode] 流量配额达限已停用"
	default:
		return "[QingNode] 监控状态变更"
	}
}

func formatNotificationText(ev Event) string {
	var lines []string
	lines = append(lines, formatNotificationTitle(ev))
	if ev.Host != "" {
		lines = append(lines, "主机: "+ev.Host)
	}
	switch {
	case ev.TargetName != "" && ev.TargetID != "" && ev.TargetName != ev.TargetID:
		lines = append(lines, fmt.Sprintf("对象: %s (%s)", ev.TargetName, ev.TargetID))
	case ev.TargetID != "":
		lines = append(lines, "对象: "+ev.TargetID)
	case ev.TargetName != "":
		lines = append(lines, "对象: "+ev.TargetName)
	}
	lines = append(lines, fmt.Sprintf("任务: %s | 状态: %s -> %s (%s)", ev.JobID, ev.From, ev.To, ev.Kind))
	if len(ev.Signals) > 0 {
		lines = append(lines, "异常信号: "+strings.Join(ev.Signals, ", "))
	}
	if ev.Reason != "" {
		lines = append(lines, "原因: "+ev.Reason)
	}
	if ev.RecoveryResult != "" {
		lines = append(lines, "恢复结果: "+ev.RecoveryResult)
	}
	if ev.CertDaysLeft != nil {
		lines = append(lines, fmt.Sprintf("证书剩余: %d 天", *ev.CertDaysLeft))
	}
	if !ev.At.IsZero() {
		lines = append(lines, "时间: "+ev.At.UTC().Format(time.RFC3339))
	}
	return strings.Join(lines, "\n")
}

func truncateUTF8Runes(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= maxRunes-1 {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func feishuSign(ts, secret string) string {
	mac := hmac.New(sha256.New, []byte(ts+"\n"+secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func dingtalkSign(ts, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts + "\n" + secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func buildNotificationRequest(nc NotificationConfig, baseURL *url.URL, ev Event, now time.Time, scrub func(string) string) (string, []byte, error) {
	clean := sanitizeEvent(ev, scrub)
	if clean.Host == "" {
		if nc.HostLabel != "" {
			clean.Host = scrub(nc.HostLabel)
		} else if h, err := os.Hostname(); err == nil && h != "" {
			clean.Host = scrub(h)
		}
	}
	title := scrub(formatNotificationTitle(clean))
	text := scrub(formatNotificationText(clean))
	reqURL := *baseURL

	switch nc.Kind {
	case "webhook":
		b, err := json.Marshal(clean)
		return reqURL.String(), b, err
	case "telegram":
		b, err := json.Marshal(struct {
			ChatID          string `json:"chat_id"`
			MessageThreadID int64  `json:"message_thread_id,omitempty"`
			Text            string `json:"text"`
		}{ChatID: nc.ChatID, MessageThreadID: nc.MessageThreadID, Text: truncateUTF8Runes(text, 1500)})
		return reqURL.String(), b, err
	case "bark":
		b, err := json.Marshal(struct {
			Title     string `json:"title"`
			Body      string `json:"body"`
			Group     string `json:"group"`
			DeviceKey string `json:"device_key,omitempty"`
		}{Title: truncateUTF8Runes(title, 120), Body: truncateUTF8Runes(text, 1200), Group: "QingNode", DeviceKey: nc.Token})
		return reqURL.String(), b, err
	case "discord":
		b, err := json.Marshal(struct {
			Content string `json:"content"`
		}{Content: truncateUTF8Runes(text, 1800)})
		return reqURL.String(), b, err
	case "feishu":
		var ts, sign string
		if nc.Secret != "" {
			ts = strconv.FormatInt(now.Unix(), 10)
			sign = feishuSign(ts, nc.Secret)
		}
		type feishuContent struct {
			Text string `json:"text"`
		}
		b, err := json.Marshal(struct {
			Timestamp string        `json:"timestamp,omitempty"`
			Sign      string        `json:"sign,omitempty"`
			MsgType   string        `json:"msg_type"`
			Content   feishuContent `json:"content"`
		}{Timestamp: ts, Sign: sign, MsgType: "text", Content: feishuContent{Text: truncateUTF8Runes(text, 1500)}})
		return reqURL.String(), b, err
	case "dingtalk":
		if nc.Secret != "" {
			ts := strconv.FormatInt(now.UnixMilli(), 10)
			sign := dingtalkSign(ts, nc.Secret)
			q := reqURL.Query()
			q.Set("timestamp", ts)
			q.Set("sign", sign)
			reqURL.RawQuery = q.Encode()
		}
		type dingtalkText struct {
			Content string `json:"content"`
		}
		b, err := json.Marshal(struct {
			MsgType string       `json:"msgtype"`
			Text    dingtalkText `json:"text"`
		}{MsgType: "text", Text: dingtalkText{Content: truncateUTF8Runes(text, 1500)}})
		return reqURL.String(), b, err
	default:
		return "", nil, fmt.Errorf("unsupported notification kind %q", nc.Kind)
	}
}

func checkNotificationResponse(kind string, responseBody []byte) bool {
	trimmed := bytes.TrimSpace(responseBody)
	switch kind {
	case "telegram":
		var result struct {
			OK bool `json:"ok"`
		}
		return json.Unmarshal(trimmed, &result) == nil && result.OK
	case "bark":
		if len(trimmed) == 0 {
			return true
		}
		var result struct {
			Code *int `json:"code"`
		}
		if json.Unmarshal(trimmed, &result) == nil && result.Code != nil {
			return *result.Code == 200
		}
		return true
	case "feishu":
		if len(trimmed) == 0 {
			return true
		}
		var result struct {
			Code       *int `json:"code"`
			StatusCode *int `json:"StatusCode"`
		}
		if json.Unmarshal(trimmed, &result) != nil {
			return false
		}
		if result.Code != nil {
			return *result.Code == 0
		}
		if result.StatusCode != nil {
			return *result.StatusCode == 0
		}
		return true
	case "dingtalk":
		if len(trimmed) == 0 {
			return true
		}
		var result struct {
			ErrCode *int `json:"errcode"`
		}
		if json.Unmarshal(trimmed, &result) != nil {
			return false
		}
		if result.ErrCode != nil {
			return *result.ErrCode == 0
		}
		return true
	default:
		return true
	}
}

func (n *Notifier) Send(ctx context.Context, c Config, event Event) string {
	return n.SendRedacted(ctx, c, event, nil)
}

func (n *Notifier) SendRedacted(ctx context.Context, c Config, event Event, extraRedact func(string) string) string {
	if !c.Enabled || !c.Notifications.Enabled {
		return "disabled"
	}
	if !c.privateNotifications || c.privateNotificationHash != notificationHash(c.Notifications) {
		return "private_config_required"
	}
	if _, err := NormalizeConfig(c); err != nil {
		return "invalid_configuration"
	}
	sendCtx, cancel := context.WithTimeout(ctx, time.Duration(c.Notifications.TimeoutMS)*time.Millisecond)
	defer cancel()
	n.mu.Lock()
	if n.gate == nil {
		n.gate = make(chan struct{}, 1)
	}
	gate := n.gate
	n.mu.Unlock()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-sendCtx.Done():
		if ctx.Err() != nil {
			return "cancelled"
		}
		return "failed"
	}
	if ctx.Err() != nil {
		return "cancelled"
	}
	nc := c.Notifications
	u, err := notificationURL(nc)
	if err != nil {
		return "invalid_configuration"
	}
	scrub := func(s string) string { return n.scrub(s, nc, extraRedact) }
	targetURL, body, err := buildNotificationRequest(nc, u, event, n.now(), scrub)
	if err != nil || len(body) > 4096 {
		return "body_limit"
	}
	client := http.Client{}
	if n.Client != nil {
		client = *n.Client
	} else {
		// Explicit notification destinations never inherit an environment proxy.
		client.Transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Duration(nc.TimeoutMS) * time.Millisecond}).DialContext, TLSHandshakeTimeout: time.Duration(nc.TimeoutMS) * time.Millisecond, ResponseHeaderTimeout: time.Duration(nc.TimeoutMS) * time.Millisecond, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, DisableKeepAlives: true}
	}
	client.Timeout = time.Duration(nc.TimeoutMS) * time.Millisecond
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Timeout covers all attempts, semaphore wait, response reads and backoff.
	for attempt := 0; attempt <= nc.Retries; attempt++ {
		if sendCtx.Err() != nil {
			if ctx.Err() != nil {
				return "cancelled"
			}
			return "failed"
		}
		// Revoke delivery while a previous attempt is in flight or backing off.
		latest, readErr := ReadConfigFile(c.privateConfigPath)
		if readErr != nil {
			return "private_config_required"
		}
		if !latest.Enabled || !latest.Notifications.Enabled {
			return "disabled"
		}
		if notificationHash(latest.Notifications) != c.privateNotificationHash {
			return "configuration_changed"
		}
		if attempt > 0 && (nc.Kind == "feishu" || nc.Kind == "dingtalk") && nc.Secret != "" {
			targetURL, body, err = buildNotificationRequest(nc, u, event, n.now(), scrub)
			if err != nil || len(body) > 4096 {
				return "body_limit"
			}
		}
		req, e := http.NewRequestWithContext(sendCtx, http.MethodPost, targetURL, bytes.NewReader(body))
		if e != nil {
			return "invalid_configuration"
		}
		req.Header.Set("Content-Type", "application/json")
		if nc.Kind == "webhook" {
			req.Header.Set("Authorization", "Bearer "+nc.Token)
		}
		response, e := client.Do(req)
		if ctx.Err() != nil {
			if response != nil {
				response.Body.Close()
			}
			return "cancelled"
		}
		retry := false
		if e != nil {
			retry = true
		} else {
			responseBody, re := io.ReadAll(io.LimitReader(response.Body, 4097))
			response.Body.Close()
			if re == nil && len(responseBody) <= 4096 && response.StatusCode >= 200 && response.StatusCode < 300 {
				if !checkNotificationResponse(nc.Kind, responseBody) {
					return "failed"
				}
				return "delivered"
			}
			if response.StatusCode >= 300 && response.StatusCode < 400 {
				return "redirect_rejected"
			}
			retry = response.StatusCode == 429 || response.StatusCode >= 500
			if re != nil || len(responseBody) > 4096 {
				return "response_limit"
			}
		}
		if !retry || attempt == nc.Retries {
			return "failed"
		}
		t := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-sendCtx.Done():
			if !t.Stop() {
				<-t.C
			}
			if ctx.Err() != nil {
				return "cancelled"
			}
			return "failed"
		case <-t.C:
		}
	}
	return "failed"
}

// RedactedConfigJSON exposes operational settings without notification secrets.
func RedactedConfigJSON(c Config) ([]byte, error) {
	b, err := json.Marshal(c)
	// Do not rely on callers to avoid reusing a credential as a visible label.
	if err == nil {
		for _, secret := range []string{c.Notifications.Token, c.Notifications.Secret, c.Notifications.ChatID, c.Notifications.Endpoint} {
			if secret != "" {
				b = []byte(strings.ReplaceAll(string(b), secret, "[redacted]"))
			}
		}
	}
	return b, err
}
