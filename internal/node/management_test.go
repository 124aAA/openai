package node

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBBRFailureRestoresRuntimeAndOwnedFile(t *testing.T) {
	values := map[string]string{"net.core.default_qdisc": "fq_codel", "net.ipv4.tcp_congestion_control": "cubic", "net.ipv4.tcp_available_congestion_control": "cubic bbr"}
	path := filepath.Join(t.TempDir(), "90-qingnode.conf")
	old := []byte("# Managed by QingNode\n# previous\n")
	os.WriteFile(path, old, 0644)
	failed := false
	h := Host{SysctlFile: path, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name != "sysctl" {
			t.Fatal(name)
		}
		if args[0] == "-n" {
			return []byte(values[args[1]]), nil
		}
		if args[0] != "-w" {
			t.Fatal(args)
		}
		pair := strings.SplitN(args[1], "=", 2)
		if pair[1] == "bbr" && !failed {
			failed = true
			return nil, errors.New("injected sysctl failure")
		}
		values[pair[0]] = pair[1]
		return nil, nil
	}}
	if _, e := h.EnableBBR(); e == nil {
		t.Fatal("failure ignored")
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, old) || values["net.core.default_qdisc"] != "fq_codel" || values["net.ipv4.tcp_congestion_control"] != "cubic" {
		t.Fatal("BBR rollback incomplete")
	}
	changed, e := h.EnableBBR()
	if e != nil || !changed {
		t.Fatal(e)
	}
	before, _ := os.Stat(path)
	changed, e = h.EnableBBR()
	after, _ := os.Stat(path)
	if e != nil || changed || !os.SameFile(before, after) {
		t.Fatal("BBR re-enable not idempotent")
	}
}

type ufwFixture struct {
	rules       []FirewallRule
	failAddPort int
	mutations   int
}

func (u *ufwFixture) run(_ time.Duration, name string, args ...string) ([]byte, error) {
	if name != "ufw" {
		return nil, errors.New("not installed")
	}
	if strings.Join(args, " ") == "status numbered" {
		out := "Status: active\n"
		for i, r := range u.rules {
			out += fmt.Sprintf("[%d] %d/%s ALLOW IN Anywhere # %s\n", i+1, r.Port, r.Network, r.Tag)
		}
		return []byte(out), nil
	}
	u.mutations++
	if len(args) == 10 && args[0] == "allow" {
		p, _ := strconv.Atoi(args[7])
		if p == u.failAddPort {
			return nil, errors.New("injected add failure")
		}
		u.rules = append(u.rules, FirewallRule{p, args[3], args[9]})
		return nil, nil
	}
	if len(args) == 3 && args[0] == "--force" && args[1] == "delete" {
		n, e := strconv.Atoi(args[2])
		if e != nil || n < 1 || n > len(u.rules) {
			return nil, errors.New("invalid rule index")
		}
		u.rules = append(u.rules[:n-1], u.rules[n:]...)
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected mutation: %v", args)
}
func TestFirewallPreservesExternalRulesAndSynchronizesOwn(t *testing.T) {
	s := fixture(t)
	s.Firewall = "ufw"
	s.Nodes[0].Port = 23456
	ssh := FirewallRule{22, "tcp", "SSH administrator"}
	external := FirewallRule{23456, "tcp", "existing application"}
	u := &ufwFixture{rules: []FirewallRule{ssh, external}}
	f := Firewall{Execute: u.run, SSH: []int{22}}
	if e := f.Sync(s, true); e != nil {
		t.Fatal(e)
	}
	if u.mutations != 0 {
		t.Fatal("external rule was retagged")
	}
	s.Nodes[0].Port = 24567
	if e := f.Sync(s, true); e != nil {
		t.Fatal(e)
	}
	if len(u.rules) != 3 {
		t.Fatal(u.rules)
	}
	before := u.mutations
	if e := f.Sync(s, true); e != nil {
		t.Fatal(e)
	}
	if u.mutations != before {
		t.Fatal("duplicate firewall write")
	}
	s.Nodes[0].Port = 25678
	if e := f.Sync(s, true); e != nil {
		t.Fatal(e)
	}
	if len(u.rules) != 3 || !reflect.DeepEqual(u.rules[:2], []FirewallRule{ssh, external}) || u.rules[2].Port != 25678 {
		t.Fatal("wrong rule deleted", u.rules)
	}
	if e := f.Sync(NewState(), true); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(u.rules, []FirewallRule{ssh, external}) {
		t.Fatal("uninstall touched external rules")
	}
}

type effectFixture struct {
	*fakeBackend
	fw         Firewall
	failFinish bool
}

func (f *effectFixture) PrepareEffects(_, next State) error { return f.fw.Sync(next, false) }
func (f *effectFixture) FinishEffects(_, next State) error {
	if f.failFinish {
		f.failFinish = false
		return errors.New("injected finalize failure")
	}
	return f.fw.Sync(next, true)
}
func TestFirewallFailureRollsBackConfigAndRules(t *testing.T) {
	u := &ufwFixture{rules: []FirewallRule{{22, "tcp", "SSH"}}}
	fx := &effectFixture{fakeBackend: &fakeBackend{}, fw: Firewall{Execute: u.run, SSH: []int{22}}}
	st := &Store{Root: t.TempDir(), Backend: fx, GID: -1}
	s := fixture(t)
	s.Firewall = "ufw"
	s.Nodes[0].Port = 24567
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	before, _ := st.current()
	s.Nodes[0].Port = 25678
	fx.failFinish = true
	if st.WithLock(func() error { return st.Apply(s) }) == nil {
		t.Fatal("failure ignored")
	}
	cur, _ := st.current()
	if cur != before || len(u.rules) != 2 || u.rules[1].Port != 24567 || !fx.active {
		t.Fatal("configuration/firewall recovery failed", u.rules)
	}
}
func TestSnapshotV2AndLegacyV1Restore(t *testing.T) {
	s := fixture(t)
	password := "test long password 2026"
	snap := Snapshot{Format: 2, State: s, Service: ServiceUnit, ManagerVersion: "0.2.0"}
	b, e := BackupSnapshot(snap, password)
	if e != nil {
		t.Fatal(e)
	}
	got, e := RestoreSnapshot(b, password)
	if e != nil || got.Service != ServiceUnit || got.State.Nodes[0].Reality.PrivateKey != s.Nodes[0].Reality.PrivateKey {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(s.Nodes[0].Reality.PrivateKey)) {
		t.Fatal("snapshot leaked secret")
	}
	legacy, e := Backup(s, password)
	if e != nil {
		t.Fatal(e)
	}
	got, e = RestoreSnapshot(legacy, password)
	if e != nil || got.Format != 1 {
		t.Fatal("legacy backup rejected", e)
	}
}
func TestRandomPortAvoidsListeningNodesAndSSH(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s := fixture(t)
	n := s.Nodes[0]
	n.Listen = "127.0.0.1"
	busy := l.Addr().(*net.TCPAddr).Port
	for i := 0; i < 10; i++ {
		p, e := RandomPort(s, n, []int{22, 23456})
		if e != nil {
			t.Fatal(e)
		}
		if p == busy || p == 23456 || p == s.Nodes[0].Port || p < 10000 {
			t.Fatal("reserved port selected")
		}
	}
}
