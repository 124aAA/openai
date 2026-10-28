package node

// firewalld support deliberately does not reload its global configuration or
// change zones, interfaces, default targets, SELinux, or external services.
// Its service XML is a project-owned manifest. Explicit rich rules are applied
// to runtime and permanent separately: a new permanent service is not assumed
// to be present in the runtime service registry before a global reload.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const firewalldManifest = "qingnode-managed.xml"
const firewalldReceipt = ".qingnode-managed.json"

type firewalldOwnership struct {
	Version int      `json:"version"`
	Zone    string   `json:"zone"`
	Rules   []string `json:"rules"`
	Pending bool     `json:"pending"`
}

func (f Firewall) firewalldRun(args ...string) ([]byte, error) {
	run := f.Execute
	if run == nil {
		run = Run
	}
	return run(15*time.Second, "firewall-cmd", args...)
}
func (f Firewall) firewalldDir() string {
	if f.FirewalldDir != "" {
		return f.FirewalldDir
	}
	return "/etc/firewalld/services"
}
func (f Firewall) firewalldZone() (string, error) {
	out, e := f.firewalldRun("--state")
	if e != nil || strings.TrimSpace(string(out)) != "running" {
		return "", errors.New("firewalld未运行或不可控制；不会自动启用防火墙")
	}
	out, e = f.firewalldRun("--get-default-zone")
	if e != nil {
		return "", errors.New("无法读取firewalld默认zone")
	}
	zone := strings.TrimSpace(string(out))
	if len(zone) < 1 || len(zone) > 64 {
		return "", errors.New("firewalld zone无效")
	}
	for _, c := range zone {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", errors.New("firewalld zone无效")
		}
	}
	out, e = f.firewalldRun("--get-active-zones")
	if e != nil {
		return "", errors.New("无法读取firewalld活动zone")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' && strings.TrimSpace(line) != zone {
			return "", errors.New("存在非默认活动firewalld zone；须手动管理该复杂策略")
		}
	}
	return zone, nil
}

func firewalldWanted(s State) []string {
	if s.Firewall != "firewalld" {
		return nil
	}
	seen := map[string]bool{}
	for _, b := range StateBindings(s) {
		if b.NodeID == "qingnode-api" {
			continue
		}
		ip := net.ParseIP(b.Address)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		families := []string{"ipv6"}
		if ip.To4() != nil {
			families = []string{"ipv4"}
		} else if ip.IsUnspecified() && !strings.HasSuffix(b.Network, "6") {
			families = []string{"ipv4", "ipv6"}
		}
		for _, family := range families {
			rule := `rule family="` + family + `"`
			if !ip.IsUnspecified() {
				rule += ` destination address="` + ip.String() + `"`
			}
			rule += ` port port="` + strconv.Itoa(b.Port) + `" protocol="` + bindingTransport(b.Network) + `" accept`
			seen[rule] = true
		}
	}
	var rules []string
	for r := range seen {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	return rules
}

func firewalldXML() []byte {
	// No user text or executable material. Rules live in the receipt and the two
	// zone stores; the empty service must never be added to a zone by QingNode.
	return []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<service version=\"1\"><short>QingNode managed ownership</short><description>Managed by QingNode. Explicit family rich rules; do not edit this ownership marker.</description></service>\n")
}
func firewallReadOwned(path string) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 || i.Size() > 1<<20 {
		return nil, errors.New("firewalld恢复材料类型、权限或大小异常")
	}
	return os.ReadFile(path)
}
func (f Firewall) firewalldLoad() (firewalldOwnership, bool, error) {
	r := firewalldOwnership{Version: 1}
	manifest, me := firewallReadOwned(filepath.Join(f.firewalldDir(), firewalldManifest))
	receipt, re := firewallReadOwned(filepath.Join(f.firewalldDir(), firewalldReceipt))
	if os.IsNotExist(me) && os.IsNotExist(re) {
		return r, false, nil
	}
	if me != nil || re != nil || !bytes.Equal(manifest, firewalldXML()) {
		return r, false, errors.New("firewalld项目文件碰撞、缺失或被外部修改；拒绝接管")
	}
	d := json.NewDecoder(bytes.NewReader(receipt))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil || r.Version != 1 || len(r.Rules) > 4096 {
		return r, false, errors.New("firewalld所有权记录格式无效")
	}
	for _, rule := range r.Rules {
		if !strings.HasPrefix(rule, `rule family="ipv`) || len(rule) > 512 || strings.ContainsAny(rule, "\r\n\x00") {
			return r, false, errors.New("firewalld所有权规则无效")
		}
	}
	return r, true, nil
}
func (f Firewall) firewalldLists(zone string) ([2]map[string]bool, error) {
	var lists [2]map[string]bool
	for i := range lists {
		args := []string{"--zone=" + zone, "--list-rich-rules"}
		if i == 1 {
			args = append([]string{"--permanent"}, args...)
		}
		out, e := f.firewalldRun(args...)
		if e != nil {
			return lists, errors.New("无法读取firewalld运行/持久规则")
		}
		if len(out) > 1<<20 {
			return lists, errors.New("firewalld规则超过检查上限")
		}
		lists[i] = map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lists[i][line] = true
			}
		}
	}
	return lists, nil
}
func (f Firewall) firewalldCheck(s State) error {
	zone, e := f.firewalldZone()
	if e != nil {
		return e
	}
	owned, exists, e := f.firewalldLoad()
	if e != nil {
		return e
	}
	if exists && owned.Zone != zone {
		return errors.New("firewalld默认zone已改变；保留旧所有权材料并要求手动检查")
	}
	lists, e := f.firewalldLists(zone)
	if e != nil {
		return e
	}
	old := map[string]bool{}
	for _, r := range owned.Rules {
		old[r] = true
		if !owned.Pending && (!lists[0][r] || !lists[1][r]) {
			return errors.New("项目firewalld规则被外部移除；拒绝猜测原策略")
		}
	}
	for _, r := range firewalldWanted(s) {
		if !old[r] && (lists[0][r] || lists[1][r]) {
			return errors.New("已有同形firewalld规则，拒绝认领用户规则")
		}
	}
	ssh := f.SSH
	if ssh == nil {
		ssh = SSHPorts()
	}
	for _, r := range RequiredRules(s) {
		for _, p := range ssh {
			if r.Network == "tcp" && r.Port == p {
				return errors.New("节点与SSH端口相同；拒绝自动firewalld规则")
			}
		}
	}
	return nil
}

func (f Firewall) firewalldSave(r firewalldOwnership) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(f.firewalldDir(), firewalldReceipt), append(b, '\n'), 0600)
}
func (f Firewall) firewalldChange(zone, rule string, permanent, add bool) error {
	verb := "--remove-rich-rule="
	if add {
		verb = "--add-rich-rule="
	}
	args := []string{"--zone=" + zone, verb + rule}
	if permanent {
		args = append([]string{"--permanent"}, args...)
	}
	if _, e := f.firewalldRun(args...); e != nil {
		return errors.New("firewalld运行或持久规则写入失败")
	}
	lists, e := f.firewalldLists(zone)
	if e != nil {
		return e
	}
	i := 0
	if permanent {
		i = 1
	}
	if lists[i][rule] != add {
		return errors.New("firewalld写入后读回不一致")
	}
	return nil
}

func (f Firewall) firewalldSync(s State, prune bool) error {
	dir := f.firewalldDir()
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("firewalld目录不安全")
	}
	fd, e := syscall.Open(filepath.Join(dir, ".qingnode-managed.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("firewalld受管规则正由另一个进程修改")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	zone, e := f.firewalldZone()
	if e != nil {
		return e
	}
	old, exists, e := f.firewalldLoad()
	if e != nil {
		return e
	}
	if exists && old.Zone != zone {
		return errors.New("firewalld默认zone已改变；拒绝跨zone清理")
	}
	if s.Firewall == "firewalld" {
		if e = f.firewalldCheck(s); e != nil {
			return e
		}
	}
	if !exists && s.Firewall != "firewalld" {
		return nil
	}
	before, e := f.firewalldLists(zone)
	if e != nil {
		return e
	}
	wanted := firewalldWanted(s)
	if !prune {
		wanted = append(wanted, old.Rules...)
	}
	set := map[string]bool{}
	for _, r := range wanted {
		set[r] = true
	}
	wanted = nil
	for r := range set {
		wanted = append(wanted, r)
	}
	sort.Strings(wanted)
	union := map[string]bool{}
	for _, r := range append(append([]string{}, old.Rules...), wanted...) {
		union[r] = true
	}
	journal := firewalldOwnership{Version: 1, Zone: zone, Pending: true}
	for r := range union {
		journal.Rules = append(journal.Rules, r)
	}
	sort.Strings(journal.Rules)
	if !exists {
		if e = AtomicWrite(filepath.Join(dir, firewalldManifest), firewalldXML(), 0644); e != nil {
			return e
		}
	}
	if e = f.firewalldSave(journal); e != nil {
		return e
	}
	apply := func() error {
		for i := range before {
			for _, r := range wanted {
				if !before[i][r] {
					if e := f.firewalldChange(zone, r, i == 1, true); e != nil {
						return e
					}
				}
			}
			if prune {
				for _, r := range old.Rules {
					if before[i][r] && !set[r] {
						if e := f.firewalldChange(zone, r, i == 1, false); e != nil {
							return e
						}
					}
				}
			}
		}
		return nil
	}
	if e = apply(); e != nil {
		// Only restore exact rules in our persisted journal; foreign rules are untouched.
		lists, re := f.firewalldLists(zone)
		if re == nil {
			for i := range lists {
				for _, r := range journal.Rules {
					if lists[i][r] != before[i][r] {
						if re = f.firewalldChange(zone, r, i == 1, before[i][r]); re != nil {
							break
						}
					}
				}
				if re != nil {
					break
				}
			}
		}
		if re != nil {
			return fmt.Errorf("%w；回退失败，已保留pending所有权材料：%v", e, re)
		}
		if exists {
			if re = f.firewalldSave(old); re != nil {
				return errors.Join(e, re)
			}
		} else {
			if re = os.Remove(filepath.Join(dir, firewalldReceipt)); re == nil {
				re = os.Remove(filepath.Join(dir, firewalldManifest))
			}
			if re != nil {
				return errors.Join(e, re)
			}
		}
		return e
	}
	if len(wanted) == 0 {
		if e = os.Remove(filepath.Join(dir, firewalldReceipt)); e != nil {
			return e
		}
		return os.Remove(filepath.Join(dir, firewalldManifest))
	}
	return f.firewalldSave(firewalldOwnership{Version: 1, Zone: zone, Rules: wanted})
}
