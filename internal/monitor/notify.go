package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Notifier deliberately returns only a stable delivery category. Raw network
// errors, response bodies, destination URLs and credentials never enter logs.
// A custom client is useful for controlled httptest endpoints; redirect and
// timeout policy are always imposed here, including on injected clients.
type Notifier struct {
	Client *http.Client
	mu     sync.Mutex
	gate   chan struct{}
}

func (n *Notifier) Send(ctx context.Context, c Config, event Event) string {
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
	body, err := json.Marshal(event)
	if nc.Kind == "telegram" {
		text := "QingNode monitor: " + event.JobID + " " + string(event.From) + " -> " + string(event.To)
		body, err = json.Marshal(struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}{nc.ChatID, text})
	}
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
		req, e := http.NewRequestWithContext(sendCtx, http.MethodPost, u.String(), bytes.NewReader(body))
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
				if nc.Kind == "telegram" {
					var result struct {
						OK bool `json:"ok"`
					}
					if json.Unmarshal(responseBody, &result) != nil || !result.OK {
						return "failed"
					}
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
		for _, secret := range []string{c.Notifications.Token, c.Notifications.ChatID, c.Notifications.Endpoint} {
			if secret != "" {
				b = []byte(strings.ReplaceAll(string(b), secret, "[redacted]"))
			}
		}
	}
	return b, err
}
