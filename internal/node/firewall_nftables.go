package node

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const NftFirewallTable = "qingnode"

func (f Firewall) runNft(args ...string) ([]byte, error) {
	r := f.Execute
	if r == nil {
		r = Run
	}
	return r(15*time.Second, "nft", args...)
}

// NftablesWanted returns canonical nftables rule expressions for the dedicated
// `table inet qingnode` input chain. Loopback listeners and the local core API
// socket are never exposed publicly.
func NftablesWanted(s State) []string {
	if s.Firewall != "nftables" {
		return nil
	}
	seen := map[string]bool{}
	addRule := func(address, network, portSpec, tag string) {
		ip := net.ParseIP(address)
		if ip == nil || ip.IsLoopback() {
			return
		}
		proto := bindingTransport(network)
		prefix := ""
		if ip.To4() != nil {
			if ip.IsUnspecified() {
				prefix = "meta nfproto ipv4 "
			} else {
				prefix = "ip daddr " + ip.String() + " "
			}
		} else {
			if !ip.IsUnspecified() {
				prefix = "ip6 daddr " + ip.String() + " "
			} else if strings.HasSuffix(network, "6") {
				prefix = "meta nfproto ipv6 "
			}
		}
		expr := fmt.Sprintf(`%s%s dport %s accept comment %q`, prefix, proto, portSpec, tag)
		seen[expr] = true
	}
	for _, b := range StateBindings(s) {
		if b.NodeID == "qingnode-api" {
			continue
		}
		id := strings.TrimPrefix(b.NodeID, "egress-")
		proto := bindingTransport(b.Network)
		tag := "qingnode:" + id + ":" + proto
		addRule(b.Address, b.Network, strconv.Itoa(b.Port), tag)
	}
	for _, hop := range RequiredHY2Redirects(s) {
		tag := "qingnode:" + hop.NodeID + ":hy2hop:udp"
		addRule(hop.Listen, "udp", fmt.Sprintf("%d-%d", hop.PortStart, hop.PortEnd), tag)
	}
	if len(seen) == 0 {
		return nil
	}
	rules := make([]string, 0, len(seen))
	for expr := range seen {
		rules = append(rules, expr)
	}
	sort.Strings(rules)
	return rules
}

// RenderNftFirewallScript renders an atomic single-command nft script that
// manages ONLY `table inet qingnode` with `policy accept`, never touching
// host tables or global default policies.
func RenderNftFirewallScript(rules []string) string {
	var b strings.Builder
	b.WriteString("add table inet ")
	b.WriteString(NftFirewallTable)
	b.WriteString("; flush table inet ")
	b.WriteString(NftFirewallTable)
	b.WriteString("; add chain inet ")
	b.WriteString(NftFirewallTable)
	b.WriteString(" input { type filter hook input priority filter; policy accept; }; ")
	for _, expr := range rules {
		b.WriteString("add rule inet ")
		b.WriteString(NftFirewallTable)
		b.WriteString(" input ")
		b.WriteString(expr)
		b.WriteString("; ")
	}
	return strings.TrimSpace(b.String())
}

// inspectNftOwnedTable verifies that if `table inet qingnode` already exists,
// it contains only QingNode-tagged input rules, returning any currently active
// rule expressions so add-before-remove (`prune == false`) preserves them.
func (f Firewall) inspectNftOwnedTable() (exists bool, ownedRules []string, err error) {
	out, e := f.runNft("list", "table", "inet", NftFirewallTable)
	if e != nil {
		if nftTableMissing(out, e) {
			return false, nil, nil
		}
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return false, nil, fmt.Errorf("查询 nftables 自有表失败：%w（%s）", e, detail)
		}
		return false, nil, fmt.Errorf("查询 nftables 自有表失败：%w", e)
	}
	for _, rawLine := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || line == "}" || strings.HasPrefix(line, "table inet "+NftFirewallTable) {
			continue
		}
		if strings.HasPrefix(line, "chain ") {
			if !strings.HasPrefix(line, "chain input ") && line != "chain input {" {
				return true, nil, errors.New("nftables 表 inet qingnode 含非本项目链定义，拒绝自动覆盖")
			}
			continue
		}
		if strings.HasPrefix(line, "type filter hook input ") {
			continue
		}
		if !strings.Contains(line, `comment "qingnode:`) {
			return true, nil, errors.New("nftables 表 inet qingnode 含非本项目规则，拒绝自动覆盖")
		}
		ownedRules = append(ownedRules, line)
	}
	return true, ownedRules, nil
}

func (f Firewall) nftablesCheck(s State) error {
	if _, e := f.runNft("list", "tables"); e != nil {
		return errors.New("无法查询本机 nftables；确认已安装 nft 且具备管理权限，QingNode 不会改写全局防火墙")
	}
	if _, _, e := f.inspectNftOwnedTable(); e != nil {
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

func (f Firewall) nftablesSync(s State, prune bool) error {
	return f.nftablesSyncTransition(State{}, s, prune)
}

func (f Firewall) nftablesSyncTransition(old, next State, prune bool) error {
	exists, currentOwned, err := f.inspectNftOwnedTable()
	if err != nil {
		return err
	}
	wanted := NftablesWanted(next)
	if !prune {
		merged := map[string]bool{}
		for _, expr := range currentOwned {
			merged[expr] = true
		}
		for _, expr := range NftablesWanted(old) {
			merged[expr] = true
		}
		for _, expr := range wanted {
			merged[expr] = true
		}
		if len(merged) == 0 {
			return nil
		}
		union := make([]string, 0, len(merged))
		for expr := range merged {
			union = append(union, expr)
		}
		sort.Strings(union)
		script := RenderNftFirewallScript(union)
		if out, e := f.runNft(script); e != nil {
			detail := strings.TrimSpace(string(out))
			if detail != "" {
				return fmt.Errorf("同步 nftables 项目入站表失败：%w（%s）", e, detail)
			}
			return fmt.Errorf("同步 nftables 项目入站表失败：%w", e)
		}
		return nil
	}
	if len(wanted) == 0 {
		if !exists {
			return nil
		}
		if out, e := f.runNft("delete", "table", "inet", NftFirewallTable); e != nil && !nftTableMissing(out, e) {
			detail := strings.TrimSpace(string(out))
			if detail != "" {
				return fmt.Errorf("清理 nftables 项目入站表失败：%w（%s）", e, detail)
			}
			return fmt.Errorf("清理 nftables 项目入站表失败：%w", e)
		}
		return nil
	}
	script := RenderNftFirewallScript(wanted)
	if out, e := f.runNft(script); e != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return fmt.Errorf("应用 nftables 项目入站表失败：%w（%s）", e, detail)
		}
		return fmt.Errorf("应用 nftables 项目入站表失败：%w", e)
	}
	return nil
}
