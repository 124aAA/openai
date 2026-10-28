package node

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotStopProofRejectsUnavailableAndLiveProcesses(t *testing.T) {
	stopped := "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=\n"
	for _, tc := range []struct {
		name, output string
		err          error
		valid        bool
	}{
		{"stopped", stopped, nil, true},
		{"failed-stopped", strings.ReplaceAll(strings.ReplaceAll(stopped, "inactive", "failed"), "dead", "failed"), nil, true},
		{"unavailable", stopped, errors.New("bus unavailable"), false},
		{"activating", strings.ReplaceAll(stopped, "inactive", "activating"), nil, false},
		{"pid", strings.ReplaceAll(stopped, "MainPID=0", "MainPID=1234"), nil, false},
		{"control-pid", strings.ReplaceAll(stopped, "ControlPID=0", "ControlPID=4567"), nil, false},
		{"missing", "ActiveState=inactive", nil, false},
		{"duplicate", stopped + "MainPID=0\n", nil, false},
		{"foreign", strings.ReplaceAll(stopped, "ControlGroup=", "ControlGroup=/system.slice/other.service"), nil, false},
		{"traversal", strings.ReplaceAll(stopped, "ControlGroup=", "ControlGroup=/../other"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			backend := SystemBackend{Execute: func(_ time.Duration, command string, args ...string) ([]byte, error) {
				calls++
				if command != "systemctl" || len(args) != 3 || args[0] != "show" || args[1] != "qingnode.service" {
					t.Fatal("stop proof made a lifecycle mutation or queried another service")
				}
				return []byte(tc.output), tc.err
			}}
			if err := backend.ConfirmStopped(); (err == nil) != tc.valid || calls != 1 {
				t.Fatal("stop proof accepted uncertain process state", err)
			}
		})
	}
}

func TestSnapshotStopProofChecksOwnedControlGroupProcesses(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory"), 0600); err != nil {
		t.Fatal(err)
	}
	group := filepath.Join(root, "system.slice", "qingnode.service")
	path := filepath.Join(group, "cgroup.procs")
	b := SystemBackend{CgroupRoot: root, Execute: func(time.Duration, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=/system.slice/qingnode.service\n"), nil
	}}
	if err := b.ConfirmStopped(); err != nil {
		t.Fatal("removed cgroup was not recognized", err)
	}
	if err := os.MkdirAll(group, 0700); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfirmStopped(); err == nil {
		t.Fatal("existing group without a process inventory was accepted")
	}
	if err := os.WriteFile(path, []byte("128\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfirmStopped(); err == nil {
		t.Fatal("surviving ACME writer was accepted")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(group, "cgroup.events")
	if err := os.WriteFile(events, []byte("populated 1\nfrozen 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfirmStopped(); err == nil {
		t.Fatal("empty parent with a surviving process in a child cgroup was accepted")
	}
	if err := os.WriteFile(events, []byte("populated 0\nfrozen 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfirmStopped(); err != nil {
		t.Fatal("empty owned group was rejected", err)
	}
}
