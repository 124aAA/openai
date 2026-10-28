package node

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"
)

// AnyTLSOptions describes client session reuse, independently of the server's
// TLS certificate. Unset values retain the clients' defaults, including zero
// idle sessions kept open. A non-nil zero preserves an explicit user choice.
type AnyTLSOptions struct {
	IdleSessionCheckInterval string `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string `json:"idle_session_timeout,omitempty"`
	IdleSessionMinKeep       *int   `json:"idle_session_min_keep,omitempty"`
}

func anytlsCredential(u *User) {
	u.UUID = ""
	u.Password = Token(24)
}

func validateAnyTLS(n Node) error { return validateTLSNode(n, true) }

func validateAnyTLSOptions(p *AnyTLSOptions) error {
	if p == nil {
		return nil
	}
	for _, raw := range []string{p.IdleSessionCheckInterval, p.IdleSessionTimeout} {
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		// Both fixed clients replace values <=5s with 30s. Whole seconds keep
		// the Mihomo representation exact; the upper bound is our resource rule.
		if err != nil || d <= 5*time.Second || d > 24*time.Hour || d%time.Second != 0 {
			return errors.New("AnyTLS 空闲检查和超时须为 6 秒至 24 小时的整秒时长；更短值会被客户端改回 30 秒")
		}
	}
	if p.IdleSessionMinKeep != nil && (*p.IdleSessionMinKeep < 0 || *p.IdleSessionMinKeep > 1024) {
		return errors.New("AnyTLS 保留空闲连接数须为 0–1024；默认不强制保留")
	}
	return nil
}

func AnyTLSClientSettingsPresent(p *AnyTLSOptions) bool {
	return p != nil && (p.IdleSessionCheckInterval != "" || p.IdleSessionTimeout != "" || p.IdleSessionMinKeep != nil)
}

func anytlsInbound(n Node, root string) M {
	return M{"type": "anytls", "users": tlsPasswordUsers(n), "tls": tlsInbound(n, root)}
}

func anytlsURI(n Node, u User) string {
	// The official basic URI has no representation for client session options.
	// The public export entry points report an error instead of losing them.
	if AnyTLSClientSettingsPresent(n.AnyTLS) {
		return ""
	}
	x := url.URL{Scheme: "anytls", User: url.User(u.Password), Host: net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))), Path: "/", RawQuery: url.Values{"sni": {n.Certificate.ServerName}, "insecure": {"0"}}.Encode(), Fragment: n.Name + " / " + u.Name}
	return x.String()
}

func anytlsOutbound(n Node, u User) M {
	out := M{"type": "anytls", "password": u.Password, "tls": tlsOutbound(n)}
	if p := n.AnyTLS; p != nil {
		if p.IdleSessionCheckInterval != "" {
			out["idle_session_check_interval"] = p.IdleSessionCheckInterval
		}
		if p.IdleSessionTimeout != "" {
			out["idle_session_timeout"] = p.IdleSessionTimeout
		}
		if p.IdleSessionMinKeep != nil {
			out["min_idle_session"] = *p.IdleSessionMinKeep
		}
	}
	return out
}

func anytlsMihomo(n Node, u User) M {
	out := M{"type": "anytls", "password": u.Password, "udp": true, "skip-cert-verify": false, "sni": n.Certificate.ServerName}
	if p := n.AnyTLS; p != nil {
		if p.IdleSessionCheckInterval != "" {
			d, _ := time.ParseDuration(p.IdleSessionCheckInterval)
			out["idle-session-check-interval"] = int(d / time.Second)
		}
		if p.IdleSessionTimeout != "" {
			d, _ := time.ParseDuration(p.IdleSessionTimeout)
			out["idle-session-timeout"] = int(d / time.Second)
		}
		if p.IdleSessionMinKeep != nil {
			out["min-idle-session"] = *p.IdleSessionMinKeep
		}
	}
	return out
}
