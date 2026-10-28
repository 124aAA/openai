package platform

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOpenRCDisableAlreadyDisabledIsProvenNoop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "disable", true: "disable-now"}[stop], func(t *testing.T) {
			var actions []string
			m := Manager{Kind: InitOpenRC, RunlevelRoot: t.TempDir(), RuntimeRoot: t.TempDir(), ProcRoot: t.TempDir(), Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
				actions = append(actions, name+" "+strings.Join(args, " "))
				if name != "rc-service" {
					t.Fatal("already disabled service called rc-update", name, args)
				}
				if args[1] == "status" {
					return []byte("status: stopped\n"), errors.New("exit3")
				}
				if args[1] == "stop" {
					return nil, nil
				}
				t.Fatal("unexpected lifecycle action", name, args)
				return nil, errors.New("unexpected action")
			}}
			var e error
			if stop {
				e = m.DisableNow("qingnode")
			} else {
				e = m.Disable("qingnode")
			}
			if e != nil {
				t.Fatal(e)
			}
			if !stop && len(actions) != 0 {
				t.Fatal("no-op mutated service", actions)
			}
		})
	}
}

func TestOpenRCDisableExactRunlevelsAndReadback(t *testing.T) {
	for _, behavior := range []string{"remove", "false-success", "partial-failure"} {
		t.Run(behavior, func(t *testing.T) {
			levels, definitions := t.TempDir(), t.TempDir()
			unit := filepath.Join(definitions, "qingnode")
			if e := os.WriteFile(unit, []byte("fixture"), 0600); e != nil {
				t.Fatal(e)
			}
			for _, level := range []string{"boot", "custom"} {
				if e := os.Mkdir(filepath.Join(levels, level), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(unit, filepath.Join(levels, level, "qingnode")); e != nil {
					t.Fatal(e)
				}
			}
			foreign := filepath.Join(levels, "boot", "ssh-foreign")
			if e := os.WriteFile(foreign, []byte("foreign unchanged"), 0600); e != nil {
				t.Fatal(e)
			}
			var actions []string
			m := Manager{Kind: InitOpenRC, RunlevelRoot: levels, DefinitionRoot: definitions, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
				actions = append(actions, name+" "+strings.Join(args, " "))
				if name != "rc-update" || len(args) != 3 || args[0] != "del" || args[1] != "qingnode" {
					t.Fatal("disable used broad or foreign action", name, args)
				}
				if behavior == "false-success" {
					return nil, nil
				}
				if behavior == "partial-failure" && args[2] == "custom" {
					return nil, errors.New("write denied")
				}
				return nil, os.Remove(filepath.Join(levels, args[2], "qingnode"))
			}}
			e := m.Disable("qingnode")
			if (e == nil) != (behavior == "remove") {
				t.Fatal("incorrect success classification", behavior, e)
			}
			if !reflect.DeepEqual(actions, []string{"rc-update del qingnode boot", "rc-update del qingnode custom"}) {
				t.Fatal("exact runlevels not used", actions)
			}
			remaining, e := m.Runlevels("qingnode")
			if e != nil {
				t.Fatal(e)
			}
			if behavior == "remove" && len(remaining) != 0 || behavior == "false-success" && len(remaining) != 2 || behavior == "partial-failure" && !reflect.DeepEqual(remaining, []string{"custom"}) {
				t.Fatal("actual links do not match reported operation", remaining)
			}
			if data, e := os.ReadFile(foreign); e != nil || string(data) != "foreign unchanged" {
				t.Fatal("foreign runlevel entry changed", e)
			}
		})
	}
}

func TestOpenRCDisableCannotTreatUnreadableRunlevelsAsEmpty(t *testing.T) {
	m := Manager{Kind: InitOpenRC, RunlevelRoot: filepath.Join(t.TempDir(), "missing"), Execute: func(time.Duration, string, ...string) ([]byte, error) {
		t.Fatal("unknown runlevel snapshot mutated controller")
		return nil, nil
	}}
	if m.Disable("qingnode") == nil {
		t.Fatal("missing runlevel directory was treated as already disabled")
	}
}

func TestOpenRCExplicitRunlevelNamesMatchInstallerContract(t *testing.T) {
	for _, level := range []string{"default", "custom.blue", "_local-1", "A" + strings.Repeat("0", 63)} {
		var actions []string
		m := Manager{Kind: InitOpenRC, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
			actions = append(actions, name+" "+strings.Join(args, " "))
			return nil, nil
		}}
		if e := m.EnableRunlevels("qingnode", []string{level}); e != nil || !reflect.DeepEqual(actions, []string{"rc-update add qingnode " + level}) {
			t.Fatal("valid original runlevel could not be restored", level, actions, e)
		}
	}
	for _, level := range []string{"", ".hidden", "-option", "a/b", "custom blue", "中文", strings.Repeat("x", 65)} {
		m := Manager{Kind: InitOpenRC, Execute: func(time.Duration, string, ...string) ([]byte, error) {
			t.Fatal("invalid runlevel reached controller", level)
			return nil, nil
		}}
		if m.EnableRunlevels("qingnode", []string{"default", level}) == nil {
			t.Fatal("invalid runlevel was accepted", level)
		}
	}
}

func TestOpenRCRunlevelInventoryRejectsAbnormalDirectories(t *testing.T) {
	for _, level := range []string{".hidden", "-option", "custom blue", strings.Repeat("x", 65)} {
		root := t.TempDir()
		if e := os.Mkdir(filepath.Join(root, level), 0700); e != nil {
			t.Fatal(e)
		}
		m := Manager{Kind: InitOpenRC, RunlevelRoot: root, Execute: func(time.Duration, string, ...string) ([]byte, error) {
			t.Fatal("unknown inventory mutated controller")
			return nil, nil
		}}
		if _, e := m.Runlevels("qingnode"); e == nil {
			t.Fatal("abnormal runlevel directory was silently treated as disabled", level)
		}
		if m.Disable("qingnode") == nil {
			t.Fatal("abnormal inventory was treated as an already-disabled service")
		}
	}
}

func TestOpenRCDottedRunlevelCanBeRestoredAndDisabledPrecisely(t *testing.T) {
	root, definitions := t.TempDir(), t.TempDir()
	unit := filepath.Join(definitions, "qingnode")
	if e := os.WriteFile(unit, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	level := "custom.blue"
	if e := os.Mkdir(filepath.Join(root, level), 0700); e != nil {
		t.Fatal(e)
	}
	m := Manager{Kind: InitOpenRC, RunlevelRoot: root, DefinitionRoot: definitions, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name != "rc-update" || len(args) != 3 || args[1] != "qingnode" || args[2] != level {
			t.Fatal("wrong restore or disable target", name, args)
		}
		if args[0] == "add" {
			return nil, os.Symlink(unit, filepath.Join(root, level, "qingnode"))
		}
		if args[0] == "del" {
			return nil, os.Remove(filepath.Join(root, level, "qingnode"))
		}
		t.Fatal("unexpected lifecycle action", args)
		return nil, nil
	}}
	if e := m.EnableRunlevels("qingnode", []string{level}); e != nil {
		t.Fatal(e)
	}
	if levels, e := m.Runlevels("qingnode"); e != nil || !reflect.DeepEqual(levels, []string{level}) {
		t.Fatal("restored runlevel not preserved", levels, e)
	}
	if e := m.Disable("qingnode"); e != nil {
		t.Fatal(e)
	}
	if levels, e := m.Runlevels("qingnode"); e != nil || len(levels) != 0 {
		t.Fatal("exact dotted runlevel was not disabled", levels, e)
	}
}
