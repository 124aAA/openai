package node

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const HY2NftTable = "qingnode_hy2"

// HY2RedirectRule describes an owned local UDP port-hopping redirect entry
// inside the dedicated `table inet qingnode_hy2` nftables table.
type HY2RedirectRule struct {
	NodeID     string `json:"node_id"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
	PortStart  int    `json:"port_start"`
	PortEnd    int    `json:"port_end"`
}

type HY2Redirect struct {
	Execute Runner
}

func (m HY2Redirect) run(args ...string) ([]byte, error) {
	r := m.Execute
	if r == nil {
		r = Run
	}
	return r(15*time.Second, "nft", args...)
}

// RequiredHY2Redirects returns the sorted set of local nftables UDP port-range
// redirects required by enabled Hysteria2 nodes configured with hop_mode="nftables".
// Client-only declarations (hop_mode="" or "external") never touch host nftables.
func RequiredHY2Redirects(s State) []HY2RedirectRule {
	var rules []HY2RedirectRule
	for _, n := range s.Nodes {
		if !n.Enabled || n.Protocol != "hysteria2" || n.HY2 == nil || n.HY2.HopPorts == "" || n.HY2.HopMode != "nftables" {
			continue
		}
		start, end, err := ParseHY2HopPorts(n.HY2.HopPorts)
		if err != nil {
			continue
		}
		ip := net.ParseIP(n.Listen)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		rules = append(rules, HY2RedirectRule{
			NodeID:     n.ID,
			Listen:     n.Listen,
			ListenPort: n.Port,
			PortStart:  start,
			PortEnd:    end,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].PortStart != rules[j].PortStart {
			return rules[i].PortStart < rules[j].PortStart
		}
		if rules[i].PortEnd != rules[j].PortEnd {
			return rules[i].PortEnd < rules[j].PortEnd
		}
		if rules[i].ListenPort != rules[j].ListenPort {
			return rules[i].ListenPort < rules[j].ListenPort
		}
		if rules[i].Listen != rules[j].Listen {
			return rules[i].Listen < rules[j].Listen
		}
		return rules[i].NodeID < rules[j].NodeID
	})
	return rules
}

// RenderHY2NftScript builds an atomic single-transaction nftables command string
// scoped exclusively to `table inet qingnode_hy2`. Global tables and chains are untouched.
func RenderHY2NftScript(rules []HY2RedirectRule) string {
	var b strings.Builder
	b.WriteString("add table inet ")
	b.WriteString(HY2NftTable)
	b.WriteString("; flush table inet ")
	b.WriteString(HY2NftTable)
	b.WriteString("; add chain inet ")
	b.WriteString(HY2NftTable)
	b.WriteString(" prerouting { type nat hook prerouting priority dstnat; policy accept; };")
	for _, r := range rules {
		ip := net.ParseIP(r.Listen)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		b.WriteString(" add rule inet ")
		b.WriteString(HY2NftTable)
		b.WriteString(" prerouting ")
		if ip4 := ip.To4(); ip4 != nil {
			if ip.IsUnspecified() {
				b.WriteString("meta nfproto ipv4 ")
			} else {
				b.WriteString("ip daddr ")
				b.WriteString(ip4.String())
				b.WriteString(" ")
			}
		} else if !ip.IsUnspecified() {
			b.WriteString("ip6 daddr ")
			b.WriteString(ip.String())
			b.WriteString(" ")
		}
		b.WriteString("udp dport ")
		b.WriteString(strconv.Itoa(r.PortStart))
		b.WriteString("-")
		b.WriteString(strconv.Itoa(r.PortEnd))
		b.WriteString(" redirect to :")
		b.WriteString(strconv.Itoa(r.ListenPort))
		b.WriteString(` comment "qingnode:hy2:`)
		b.WriteString(r.NodeID)
		b.WriteString(`";`)
	}
	return b.String()
}

func nftTableMissing(out []byte, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	msg := strings.ToLower(string(out) + " " + err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "executable file not found")
}

// Sync reconciles the owned `table inet qingnode_hy2` table with State.
// When no enabled Hysteria2 node requires local nftables redirection, any
// existing `table inet qingnode_hy2` is deleted cleanly.
func (m HY2Redirect) Sync(s State) error {
	wanted := RequiredHY2Redirects(s)
	if len(wanted) == 0 {
		out, err := m.run("list", "table", "inet", HY2NftTable)
		if err != nil {
			if nftTableMissing(out, err) {
				return nil
			}
			return fmt.Errorf("查询 Hysteria2 nftables 受管表失败：%w", err)
		}
		if _, err = m.run("delete", "table", "inet", HY2NftTable); err != nil {
			return fmt.Errorf("清理 Hysteria2 nftables 受管表失败：%w", err)
		}
		return nil
	}
	script := RenderHY2NftScript(wanted)
	if _, err := m.run(script); err != nil {
		return fmt.Errorf("同步 Hysteria2 nftables 端口跳跃规则失败：%w", err)
	}
	return nil
}
