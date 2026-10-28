package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type firewalldFixture struct {
	lists             [2]map[string]bool
	calls             []string
	failNextPermanent bool
	active            string
}

func newFirewalldFixture() *firewalldFixture {
	return &firewalldFixture{lists: [2]map[string]bool{{}, {}}, active: "public\n  interfaces: eth0\n"}
}
func (x *firewalldFixture) run(_ time.Duration, name string, args ...string) ([]byte, error) {
	if name != "firewall-cmd" {
		return nil, errors.New("unexpected tool")
	}
	line := strings.Join(args, " ")
	x.calls = append(x.calls, line)
	switch line {
	case "--state":
		return []byte("running\n"), nil
	case "--get-default-zone":
		return []byte("public\n"), nil
	case "--get-active-zones":
		return []byte(x.active), nil
	}
	i := 0
	if len(args) > 0 && args[0] == "--permanent" {
		i = 1
		args = args[1:]
	}
	if len(args) != 2 || args[0] != "--zone=public" {
		return nil, errors.New("unexpected command")
	}
	if args[1] == "--list-rich-rules" {
		var rules []string
		for r := range x.lists[i] {
			rules = append(rules, r)
		}
		sort.Strings(rules)
		return []byte(strings.Join(rules, "\n")), nil
	}
	if i == 1 && x.failNextPermanent {
		x.failNextPermanent = false
		return nil, errors.New("injected permanent failure")
	}
	if strings.HasPrefix(args[1], "--add-rich-rule=") {
		x.lists[i][strings.TrimPrefix(args[1], "--add-rich-rule=")] = true
		return nil, nil
	}
	if strings.HasPrefix(args[1], "--remove-rich-rule=") {
		delete(x.lists[i], strings.TrimPrefix(args[1], "--remove-rich-rule="))
		return nil, nil
	}
	return nil, errors.New("unexpected mutation")
}
func firewalldTestState(t *testing.T) State {
	s := fixture(t)
	s.Firewall = "firewalld"
	s.Nodes[0].Listen = "::"
	s.Nodes[0].Port = 24567
	return s
}
func TestFirewalldFamilyNetworkAndLocalAddressScopes(t *testing.T) {
	s := firewalldTestState(t)
	r := firewalldWanted(s)
	if len(r) != 2 || !strings.Contains(r[0], `family="ipv4"`) || !strings.Contains(r[1], `family="ipv6"`) {
		t.Fatal(r)
	}
	s.Nodes[0].Listen = "192.0.2.3"
	r = firewalldWanted(s)
	if len(r) != 1 || !strings.Contains(r[0], `destination address="192.0.2.3"`) {
		t.Fatal(r)
	}
	s.Nodes[0].Listen = "127.0.0.1"
	if len(firewalldWanted(s)) != 0 {
		t.Fatal("loopback publicly opened")
	}
	s.Nodes[0].Listen = "2001:db8::1"
	r = firewalldWanted(s)
	if len(r) != 1 || !strings.Contains(r[0], `family="ipv6"`) {
		t.Fatal(r)
	}
}
func TestFirewalldRuntimePermanentSyncRollbackAndExternalPreservation(t *testing.T) {
	s := firewalldTestState(t)
	x := newFirewalldFixture()
	external := `rule family="ipv4" port port="22" protocol="tcp" accept`
	x.lists[0][external] = true
	x.lists[1][external] = true
	f := Firewall{Execute: x.run, SSH: []int{22}, FirewalldDir: t.TempDir()}
	if e := f.Sync(s, true); e != nil {
		t.Fatal(e)
	}
	for _, rules := range x.lists {
		if len(rules) != 3 || !rules[external] {
			t.Fatal(rules)
		}
	}
	before := [2]map[string]bool{{}, {}}
	for i := range x.lists {
		for r := range x.lists[i] {
			before[i][r] = true
		}
	}
	s.Nodes[0].Port++
	x.failNextPermanent = true
	if e := f.Sync(s, true); e == nil {
		t.Fatal("ignored failure")
	}
	if !reflect.DeepEqual(x.lists, before) {
		t.Fatal("incomplete rollback", x.lists, before)
	}
	if e := f.Sync(s, true); e != nil {
		t.Fatal(e)
	}
	for _, rules := range x.lists {
		if len(rules) != 3 || !rules[external] {
			t.Fatal(rules)
		}
	}
	if e := f.firewalldSync(NewState(), true); e != nil {
		t.Fatal(e)
	}
	for _, rules := range x.lists {
		if len(rules) != 1 || !rules[external] {
			t.Fatal("deleted external", rules)
		}
	}
	for _, c := range x.calls {
		if strings.Contains(c, "reload") || strings.Contains(c, "--set-") || strings.Contains(c, "--add-service") {
			t.Fatal("global takeover", c)
		}
	}
}
func TestFirewalldRefusesCollisionsAndExternalChanges(t *testing.T) {
	t.Run("same rule", func(t *testing.T) {
		s := firewalldTestState(t)
		x := newFirewalldFixture()
		x.lists[0][firewalldWanted(s)[0]] = true
		f := Firewall{Execute: x.run, FirewalldDir: t.TempDir()}
		if e := f.Sync(s, true); e == nil {
			t.Fatal("adopted external rule")
		}
	})
	t.Run("file", func(t *testing.T) {
		s := firewalldTestState(t)
		x := newFirewalldFixture()
		dir := t.TempDir()
		path := filepath.Join(dir, firewalldManifest)
		os.WriteFile(path, []byte("user service"), 0644)
		f := Firewall{Execute: x.run, FirewalldDir: dir}
		if e := f.Sync(s, true); e == nil {
			t.Fatal("overwrote collision")
		}
		b, _ := os.ReadFile(path)
		if string(b) != "user service" {
			t.Fatal("changed user file")
		}
	})
	t.Run("changed managed rule", func(t *testing.T) {
		s := firewalldTestState(t)
		x := newFirewalldFixture()
		f := Firewall{Execute: x.run, FirewalldDir: t.TempDir()}
		if e := f.Sync(s, true); e != nil {
			t.Fatal(e)
		}
		delete(x.lists[1], firewalldWanted(s)[0])
		if e := f.Sync(s, true); e == nil {
			t.Fatal("ignored external removal")
		}
	})
	t.Run("multiple zone", func(t *testing.T) {
		x := newFirewalldFixture()
		x.active += "trusted\n  interfaces: eth1\n"
		if e := (Firewall{Execute: x.run, FirewalldDir: t.TempDir()}).Check(firewalldTestState(t)); e == nil {
			t.Fatal("guessed nondefault zone")
		}
	})
}
func TestFirewalldPendingJournalCanBeRecoveredWithoutOwningForeignRules(t *testing.T) {
	s := firewalldTestState(t)
	x := newFirewalldFixture()
	dir := t.TempDir()
	f := Firewall{Execute: x.run, FirewalldDir: dir}
	rules := firewalldWanted(s)
	os.WriteFile(filepath.Join(dir, firewalldManifest), firewalldXML(), 0644)
	if e := f.firewalldSave(firewalldOwnership{Version: 1, Zone: "public", Rules: rules, Pending: true}); e != nil {
		t.Fatal(e)
	}
	// Interrupted after one runtime addition, before permanent and second family.
	x.lists[0][rules[0]] = true
	external := `rule family="ipv4" port port="2022" protocol="tcp" accept`
	x.lists[0][external] = true
	if e := f.firewalldSync(NewState(), true); e != nil {
		t.Fatal(e)
	}
	if len(x.lists[0]) != 1 || !x.lists[0][external] || len(x.lists[1]) != 0 {
		t.Fatal(x.lists)
	}
}
func TestStateSchema8MigrationKeepsNewProtocolAndRejectsFirewalld(t *testing.T) {
	s := NewState()
	s.Schema = 8
	s.Nodes = nil
	b, _ := json.Marshal(s)
	got, e := DecodeState(b)
	if e != nil || got.Schema != 9 {
		t.Fatal(got.Schema, e)
	}
	s.Firewall = "firewalld"
	b, _ = json.Marshal(s)
	if _, e = DecodeState(b); e == nil {
		t.Fatal("schema8 accepted new firewall meaning")
	}
	s.Schema = 9
	b, _ = json.Marshal(s)
	got, e = DecodeState(b)
	if e != nil || got.Firewall != "firewalld" {
		t.Fatal(got, e)
	}
	if !bytes.Contains(b, []byte(`"schema":9`)) {
		t.Fatal("schema not explicit")
	}
}
