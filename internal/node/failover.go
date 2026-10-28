package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// FailoverObservation is separate from State and its backup. Restoring a policy
// without this observation starts a fresh, conservative cooldown window.
type FailoverObservation struct {
	Version      int       `json:"version"`
	ConfigSHA256 string    `json:"config_sha256"`
	Selected     string    `json:"selected"`
	Failures     int       `json:"consecutive_failures"`
	Recoveries   int       `json:"consecutive_recoveries"`
	LastObserved time.Time `json:"last_observed"`
	LastSwitch   time.Time `json:"last_switch"`
}

type FailoverDecision struct {
	Observation FailoverObservation `json:"observation"`
	From        string              `json:"from"`
	To          string              `json:"to"`
	Changed     bool                `json:"changed"`
	Reason      string              `json:"reason"`
}

func PolicyHealthDigest(st State, p EgressPolicy) (string, error) {
	p.Selected = "" // A completed choice must retain its cooldown observation.
	a, b, tag, err := BuildEgressGraph(st, p.Primary)
	if err != nil {
		return "", err
	}
	c, d, other, err := BuildEgressGraph(st, p.Backup)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{p, st.CoreVersion, st.DNS, a, b, tag, c, d, other})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

func (o FailoverObservation) Validate() error {
	if o.Version != 1 || len(o.ConfigSHA256) != 64 || strings.Trim(o.ConfigSHA256, "0123456789abcdef") != "" || (o.Selected != "primary" && o.Selected != "backup") || o.Failures < 0 || o.Failures > 20 || o.Recoveries < 0 || o.Recoveries > 20 || o.LastObserved.IsZero() || o.LastSwitch.After(o.LastObserved) {
		return errors.New("主备观测版本、摘要、计数或时间无效")
	}
	return nil
}

// EvaluateFailover is deterministic. It neither sends traffic nor applies a
// config. Unknown/canceled/local-tool failures never count as remote failures.
func EvaluateFailover(p EgressPolicy, old FailoverObservation, binding, primary, backup string, now time.Time) (FailoverDecision, error) {
	if p.Mode != "failover" || validateHealth(p.Health) != nil || p.Primary == "" || p.Backup == "" || p.Primary == p.Backup || len(binding) != 64 || strings.Trim(binding, "0123456789abcdef") != "" || now.IsZero() {
		return FailoverDecision{}, errors.New("主备决策需要完整有效策略、配置摘要和时间")
	}
	for _, v := range []string{primary, backup} {
		if v != "healthy" && v != "unhealthy" && v != "unknown" {
			return FailoverDecision{}, errors.New("健康样本只允许healthy、unhealthy或unknown")
		}
	}
	selected := p.Selected
	if selected == "" {
		selected = "primary"
	}
	if selected != "primary" && selected != "backup" {
		return FailoverDecision{}, errors.New("主备保存的选择无效")
	}
	o := old
	if old.Version != 0 {
		if err := old.Validate(); err != nil {
			return FailoverDecision{}, err
		}
	}
	if old.Version == 0 || old.ConfigSHA256 != binding || old.Selected != selected {
		o = FailoverObservation{Version: 1, ConfigSHA256: binding, Selected: selected}
		if selected == "backup" {
			o.LastSwitch = now // Missing history must not immediately flap back.
		}
	}
	if now.Before(o.LastObserved) || now.Before(o.LastSwitch) {
		return FailoverDecision{}, errors.New("时钟早于主备观测，拒绝绕过冷却期")
	}
	o.LastObserved = now
	switch primary {
	case "unhealthy":
		o.Recoveries = 0
		if o.Failures < p.Health.FailureThreshold {
			o.Failures++
		}
	case "healthy":
		o.Failures = 0
		if o.Recoveries < p.Health.RecoveryThreshold {
			o.Recoveries++
		}
	default:
		o.Failures, o.Recoveries = 0, 0
	}
	d := FailoverDecision{Observation: o, From: selected, To: selected, Reason: "阈值未满足，保持明确保存的出口"}
	ready := o.LastSwitch.IsZero() || now.Sub(o.LastSwitch) >= time.Duration(p.Health.CooldownSeconds)*time.Second
	if !ready {
		d.Reason = "冷却期内保持出口；不会迁移既有会话"
		return d, nil
	}
	if selected == "primary" && o.Failures >= p.Health.FailureThreshold && backup == "healthy" {
		d.To, d.Reason = "backup", "主出口连续失败且备用应用测试通过"
	} else if selected == "backup" && o.Recoveries >= p.Health.RecoveryThreshold {
		d.To, d.Reason = "primary", "主出口连续恢复且冷却期已结束"
	}
	d.Changed = d.To != selected
	if d.Changed {
		d.Observation.Selected = d.To
		d.Observation.LastSwitch = now
		d.Observation.Failures, d.Observation.Recoveries = 0, 0
	}
	return d, nil
}
