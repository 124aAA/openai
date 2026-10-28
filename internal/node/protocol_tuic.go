package node

import (
	"errors"
	"strings"
	"time"
)

func tuicCredential(u *User) {
	realityCredential(u)
	u.Password = Token(24)
}

func validateTUIC(n Node) error { return validateTUICCertificate(n, true) }

// Restore defers only access to externally owned files, preserving the complete
// protocol, credential and option checks before a candidate can be applied.
func validateTUICCertificate(n Node, checkExternalFiles bool) error {
	if n.Certificate == nil || !ValidHost(n.Certificate.ServerName) {
		return errors.New("TUIC 需要有效证书名称")
	}
	if n.Reality != nil || n.Shadowsocks != nil || n.HY2 != nil || n.AnyTLS != nil {
		return errors.New("TUIC 不能混入其他协议参数")
	}
	if err := validateTUICOptions(n.TUIC); err != nil {
		return err
	}
	uuids := map[string]bool{}
	for _, u := range n.Users {
		identity := strings.ToLower(u.UUID)
		if !uuidRE.MatchString(u.UUID) || uuids[identity] {
			return errors.New("TUIC 每个用户须使用不同的有效 UUID，大小写不能区分同一个 UUID")
		}
		if safeTLSCredential(User{Password: u.Password}) != nil {
			return errors.New("TUIC 密码须为 16–512 字节的有效 UTF-8，且不含控制字符")
		}
		uuids[identity] = true
	}
	return validateCertificateResource(CertificateResource{Certificate: *n.Certificate}, time.Time{}, false, checkExternalFiles)
}

func validateTUICOptions(p *TUICOptions) error {
	if p == nil {
		return nil
	}
	for _, cc := range []string{p.ServerCongestionControl, p.ClientCongestionControl} {
		switch cc {
		case "", "cubic", "new_reno", "bbr":
		default:
			return errors.New("TUIC 拥塞控制仅支持 cubic、new_reno、bbr")
		}
	}
	if p.AuthTimeout != "" {
		d, err := time.ParseDuration(p.AuthTimeout)
		if err != nil || d < time.Second || d > time.Minute {
			return errors.New("TUIC 服务端认证等待须为 1–60 秒")
		}
	}
	for _, raw := range []string{p.ServerHeartbeat, p.ClientHeartbeat} {
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Second || d > 2*time.Minute || d%time.Millisecond != 0 {
			return errors.New("TUIC 心跳须为 1 秒至 2 分钟的整毫秒时长")
		}
	}
	switch p.UDPRelayMode {
	case "", "native", "quic":
	default:
		return errors.New("TUIC UDP 转发仅支持 native 或 quic")
	}
	if p.ZeroRTTHandshake != nil && *p.ZeroRTTHandshake {
		return errors.New("TUIC 0-RTT 可能受重放攻击，本项目只接受关闭")
	}
	return nil
}

func tuicInbound(n Node, root string) M {
	users := make([]any, 0, len(n.Users))
	for _, u := range n.Users {
		users = append(users, M{"name": u.ID, "uuid": u.UUID, "password": u.Password})
	}
	tls := tlsInbound(n, root)
	tls["alpn"] = []string{"h3"}
	out := M{"type": "tuic", "users": users, "tls": tls, "zero_rtt_handshake": false}
	if p := n.TUIC; p != nil {
		if p.ServerCongestionControl != "" {
			out["congestion_control"] = p.ServerCongestionControl
		}
		if p.AuthTimeout != "" {
			out["auth_timeout"] = p.AuthTimeout
		}
		if p.ServerHeartbeat != "" {
			out["heartbeat"] = p.ServerHeartbeat
		}
	}
	return out
}

func tuicURI(Node, User) string { return "" }

func tuicOutbound(n Node, u User) M {
	tls := tlsOutbound(n)
	tls["alpn"] = []string{"h3"}
	out := M{"type": "tuic", "uuid": u.UUID, "password": u.Password, "tls": tls, "zero_rtt_handshake": false}
	if p := n.TUIC; p != nil {
		if p.ClientCongestionControl != "" {
			out["congestion_control"] = p.ClientCongestionControl
		}
		if p.ClientHeartbeat != "" {
			out["heartbeat"] = p.ClientHeartbeat
		}
		if p.UDPRelayMode != "" {
			out["udp_relay_mode"] = p.UDPRelayMode
		}
	}
	return out
}

func tuicMihomo(n Node, u User) M {
	out := M{"type": "tuic", "uuid": u.UUID, "password": u.Password, "sni": n.Certificate.ServerName, "skip-cert-verify": false, "alpn": []string{"h3"}, "reduce-rtt": false}
	if p := n.TUIC; p != nil {
		if p.ClientCongestionControl != "" {
			out["congestion-controller"] = p.ClientCongestionControl
		}
		if p.ClientHeartbeat != "" {
			d, _ := time.ParseDuration(p.ClientHeartbeat)
			out["heartbeat-interval"] = int(d / time.Millisecond)
		}
		if p.UDPRelayMode != "" {
			out["udp-relay-mode"] = p.UDPRelayMode
		}
	}
	return out
}
