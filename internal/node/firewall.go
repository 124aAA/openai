package node

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Firewall struct {
	Execute Runner
	SSH     []int
}
type FirewallRule struct {
	Port         int
	Network, Tag string
}
type ufwRule struct {
	FirewallRule
	Number   int
	External bool
}

var ufwLine = regexp.MustCompile(`^\[\s*([0-9]+)\]\s+([0-9]+)/(tcp|udp)(?:\s+\(v6\))?\s+ALLOW IN\s+Anywhere(?:\s+\(v6\))?(?:\s+#\s*(.*))?\s*$`)
var ourTag = regexp.MustCompile(`^qingnode:[a-f0-9]{16}:(tcp|udp)$`)

func (f Firewall) run(args ...string) ([]byte, error) {
	r := f.Execute
	if r == nil {
		r = Run
	}
	return r(15*time.Second, "ufw", args...)
}
func (f Firewall) rules() ([]ufwRule, error) {
	b, e := f.run("status", "numbered")
	if e != nil {
		return nil, errors.New("无法查询 UFW；不会自动启用、重置或替换防火墙")
	}
	if !strings.Contains(string(b), "Status: active") {
		return nil, errors.New("UFW 未启用；请自行确认 SSH 与现有策略后设置防火墙，QingNode 不自动启用 UFW")
	}
	var rules []ufwRule
	for _, line := range strings.Split(string(b), "\n") {
		m := ufwLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			if strings.Contains(line, "qingnode:") {
				return nil, errors.New("项目防火墙规则已被外部修改，无法安全判断；请手动检查 UFW")
			}
			continue
		}
		n, _ := strconv.Atoi(m[1])
		p, _ := strconv.Atoi(m[2])
		tag := strings.TrimSpace(m[4])
		owned := ourTag.MatchString(tag) && strings.HasSuffix(tag, ":"+m[3])
		rules = append(rules, ufwRule{FirewallRule: FirewallRule{Port: p, Network: m[3], Tag: tag}, Number: n, External: !owned})
	}
	return rules, nil
}
func RequiredRules(s State) []FirewallRule {
	var rules []FirewallRule
	if s.Firewall != "ufw" {
		return rules
	}
	for _, n := range s.Nodes {
		if n.Enabled {
			for _, network := range Networks(n) {
				rules = append(rules, FirewallRule{Port: n.Port, Network: network, Tag: "qingnode:" + n.ID + ":" + network})
			}
		}
	}
	// ACME TCP 80 is reported separately; never take ownership of a web server's port.
	return rules
}
func (f Firewall) Check(s State) error {
	if s.Firewall != "ufw" {
		return nil
	}
	_, e := f.rules()
	if e != nil {
		return e
	}
	ssh := f.SSH
	if ssh == nil {
		ssh = SSHPorts()
	}
	for _, rule := range RequiredRules(s) {
		for _, port := range ssh {
			if rule.Network == "tcp" && rule.Port == port {
				return errors.New("节点端口与 SSH 配置端口相同，拒绝自动管理该防火墙规则")
			}
		}
	}
	return nil
}

// Add before activation, prune only after the replacement listener has started.
func (f Firewall) Sync(s State, prune bool) error {
	rules, e := f.rules()
	if e != nil {
		return e
	}
	wanted := RequiredRules(s)
	for _, want := range wanted {
		exists := false
		for _, r := range rules {
			if r.Port == want.Port && r.Network == want.Network {
				exists = true
				break
			}
		}
		// UFW changes comments on duplicate allow rules. Never tag/take over an existing rule.
		if exists {
			continue
		}
		if _, e = f.run("allow", "in", "proto", want.Network, "to", "any", "port", strconv.Itoa(want.Port), "comment", want.Tag); e != nil {
			return fmt.Errorf("添加项目 UFW 规则失败：%w", e)
		}
	}
	if !prune {
		return nil
	}
	rules, e = f.rules()
	if e != nil {
		return e
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Number > rules[j].Number })
	ssh := f.SSH
	if ssh == nil {
		ssh = SSHPorts()
	}
	for _, r := range rules {
		if r.External {
			continue
		}
		keep := false
		for _, want := range wanted {
			if r.Port == want.Port && r.Network == want.Network {
				keep = true
				break
			}
		}
		if keep {
			continue
		}
		for _, port := range ssh {
			if r.Network == "tcp" && r.Port == port {
				return errors.New("旧项目规则的端口已被 SSH 使用，保留该规则；请手动处理")
			}
		}
		// Refresh and verify the numbered rule immediately before deleting it.
		fresh, e := f.rules()
		if e != nil {
			return e
		}
		valid := false
		for _, x := range fresh {
			if x.Number == r.Number && !x.External && x.FirewallRule == r.FirewallRule {
				valid = true
			}
		}
		if !valid {
			return errors.New("UFW 规则编号发生并发变更，已停止删除，请重试")
		}
		if _, e = f.run("--force", "delete", strconv.Itoa(r.Number)); e != nil {
			return fmt.Errorf("删除项目 UFW 规则失败：%w", e)
		}
	}
	return nil
}
func (b SystemBackend) PrepareEffects(old, next State) error {
	if old.Firewall != "ufw" && next.Firewall != "ufw" {
		return nil
	}
	return (Firewall{Execute: b.Execute}).Sync(next, false)
}
func (b SystemBackend) FinishEffects(old, next State) error {
	if old.Firewall != "ufw" && next.Firewall != "ufw" {
		return nil
	}
	return (Firewall{Execute: b.Execute}).Sync(next, true)
}
