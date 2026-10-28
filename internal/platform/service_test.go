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

func TestSystemdAdapterPreservesExistingCommandArguments(t *testing.T) {
	var calls []string
	m := NewManager(InitSystemd, func(_ time.Duration, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "show" {
			return []byte("245\n"), nil
		}
		return nil, nil
	})
	if e := m.Start("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.Restart("qingnode.service"); e != nil {
		t.Fatal(e)
	}
	if e := m.TryRestart("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.Enable("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.Disable("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.Stop("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.ReloadDefinitions(); e != nil {
		t.Fatal(e)
	}
	if pid, e := m.PID("qingnode"); e != nil || pid != 245 {
		t.Fatal(pid, e)
	}
	want := []string{"systemctl start qingnode.service", "systemctl restart qingnode.service", "systemctl try-restart qingnode.service", "systemctl enable qingnode.service", "systemctl disable qingnode.service", "systemctl stop qingnode.service", "systemctl daemon-reload", "systemctl show qingnode.service --property=MainPID --value"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
}

func TestUnavailableManagerNeverCallsPresentServiceTool(t *testing.T) {
	m := NewManager(InitUnavailable, func(time.Duration, string, ...string) ([]byte, error) {
		t.Fatal("unavailable init called tool")
		return nil, nil
	})
	for _, call := range []func() error{func() error { return m.Start("qingnode") }, func() error { return m.Stop("qingnode") }, func() error { return m.Restart("qingnode") }, m.ReloadDefinitions} {
		if call() == nil {
			t.Fatal("unavailable manager reported success")
		}
	}
	if s, e := m.State("qingnode"); e == nil || s.Active != nil || s.Enabled != nil || s.State != "unknown" {
		t.Fatal(s, e)
	}
	for _, name := range []string{"sshd", "../qingnode", "qingnode;reboot", "qingnode.service/other", "qingnode-subscription.timer"} {
		if m.Start(name) == nil {
			t.Fatal("foreign or injected service accepted", name)
		}
	}
}

func TestOpenRCUsesChildPIDAndHonorsStoppedTryRestart(t *testing.T) {
	levels, definitions := t.TempDir(), t.TempDir()
	unit := filepath.Join(definitions, "qingnode")
	if e := os.WriteFile(unit, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(levels, "default"), 0700); e != nil {
		t.Fatal(e)
	}
	var calls []string
	m := NewManager(InitOpenRC, func(_ time.Duration, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "rc-service qingnode qingnode_pid":
			return []byte("345\n"), nil
		case "rc-service qingnode status":
			return []byte(" * status: stopped\n"), errors.New("exit status 3")
		case "rc-update add qingnode default":
			return nil, os.Symlink(unit, filepath.Join(levels, "default", "qingnode"))
		case "rc-update del qingnode default":
			return nil, os.Remove(filepath.Join(levels, "default", "qingnode"))
		}
		return nil, nil
	})
	m.RunlevelRoot, m.DefinitionRoot = levels, definitions
	if pid, e := m.PID("qingnode"); e != nil || pid != 345 {
		t.Fatal(pid, e)
	}
	if e := m.TryRestart("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.Enable("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.Disable("qingnode"); e != nil {
		t.Fatal(e)
	}
	if e := m.ReloadDefinitions(); e != nil {
		t.Fatal(e)
	}
	want := []string{"rc-service qingnode qingnode_pid", "rc-service qingnode status", "rc-update add qingnode default", "rc-update del qingnode default"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
}

func TestOpenRCStopRejectsUnknownAndSurvivingProcesses(t *testing.T) {
	for _, tc := range []struct {
		name         string
		activeBefore bool
		survivor     bool
		unknown      bool
		pass         bool
	}{
		{"already stopped", false, false, false, true}, {"live child terminated", true, false, false, true}, {"survivor", true, true, false, false}, {"unknown status", false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proc := t.TempDir()
			run := t.TempDir()
			if tc.survivor {
				if e := os.Mkdir(filepath.Join(proc, "12345"), 0700); e != nil {
					t.Fatal(e)
				}
			}
			stopped := false
			var actions []string
			m := Manager{Kind: InitOpenRC, ProcRoot: proc, RuntimeRoot: run, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
				actions = append(actions, name+" "+strings.Join(args, " "))
				if args[1] == "status" {
					if tc.unknown {
						return []byte("status: starting\n"), errors.New("exit8")
					}
					if tc.activeBefore && !stopped {
						return []byte("status: started\n"), nil
					}
					return []byte("status: stopped\n"), errors.New("exit3")
				}
				if args[1] == "qingnode_pid" {
					return []byte("12345\n"), nil
				}
				if args[1] == "stop" {
					stopped = true
					return nil, nil
				}
				t.Fatal(name, args)
				return nil, nil
			}}
			err := m.Stop("qingnode")
			if (err == nil) != tc.pass {
				t.Fatal(err)
			}
			if tc.unknown && len(actions) != 1 {
				t.Fatal("uncertain state mutated service", actions)
			}
		})
	}
}

func TestOpenRCStatusCannotPassOnSuccessfulButUnrecognizedOutput(t *testing.T) {
	m := NewManager(InitOpenRC, func(time.Duration, string, ...string) ([]byte, error) { return []byte("tool installed\n"), nil })
	if active, e := m.Active("qingnode"); e == nil || active {
		t.Fatal("mere tool success counted active")
	}
	if s, e := m.State("qingnode"); e == nil || s.Active != nil {
		t.Fatal(s, e)
	}
}

func TestServiceDefinitionIsSupervisedNonrootAndRejectsInjection(t *testing.T) {
	s := CoreServiceSpec()
	rendered, e := RenderOpenRC(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, part := range []string{"#!/sbin/openrc-run\n# Managed by QingNode\n", `supervisor="supervise-daemon"`, `command_user="qingnode:qingnode"`, `pidfile="/run/qingnode/qingnode.supervise.pid"`, `respawn_max=5`, `respawn_period=60`, `retry="TERM/15/KILL/5"`, `service_get_value child_pid`, `--owner root:root /run/qingnode`} {
		if !strings.Contains(rendered, part) {
			t.Fatal("missing supervisor contract", part)
		}
	}
	if strings.Contains(rendered, "reload()") || strings.Contains(rendered, "restart()") || strings.Contains(rendered, "command_background") {
		t.Fatal("invented incompatible supervisor behavior")
	}
	if !ManagedDefinition([]byte(rendered)) {
		t.Fatal("OpenRC marker not recognized")
	}
	for _, change := range []func(*ServiceSpec){func(s *ServiceSpec) { s.User = "root"; s.Group = "root" }, func(s *ServiceSpec) { s.Args = []string{"$(reboot)"} }, func(s *ServiceSpec) { s.Args = []string{"%n"} }, func(s *ServiceSpec) { s.Command = "/usr/local/bin/qingnode;reboot" }, func(s *ServiceSpec) { s.Name = "sshd" }} {
		bad := CoreServiceSpec()
		change(&bad)
		if _, e := RenderOpenRC(bad); e == nil {
			t.Fatal("unsafe definition accepted", bad)
		}
	}
	s.Name = "qingnode-monitor"
	s.User = "root"
	s.Group = "root"
	s.BindLowPorts = false
	s.Args = []string{"monitor", "watch"}
	if _, e := RenderOpenRC(s); e != nil {
		t.Fatal("private-state monitor denied", e)
	}
	s.Name = "qingnode-subscription"
	s.User = "qingnode-sub"
	s.Group = "qingnode-sub"
	s.Args = []string{"subscription", "serve"}
	if out, e := RenderSystemd(s); e != nil || !strings.Contains(out, "CapabilityBoundingSet=\n") || strings.Contains(out, "AmbientCapabilities") {
		t.Fatal(out, e)
	}
}

func TestOpenRCDelegatesOnlyBindAmbientAndProbesActualSupervisor(t *testing.T) {
	rendered, err := RenderOpenRC(CoreServiceSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`capabilities="^cap_net_bind_service"`, `no_new_privs="yes"`, `supervise-daemon "${RC_SVCNAME}" --help 2>&1`, `*--capabilities*)`, `*--no-new-privs*)`, `refusing a root fallback`} {
		if !strings.Contains(rendered, required) {
			t.Fatal("missing actual supervisor capability contract", required)
		}
	}
	for _, forbidden := range []string{`!^cap_net_bind_service`, `cap_net_admin`, `cap_setuid`, `setcap `, `command_user="root`, `ip_unprivileged_port_start`} {
		if strings.Contains(rendered, forbidden) {
			t.Fatal("unexpected privilege or host change", forbidden)
		}
	}
	for _, service := range []ServiceSpec{
		{Name: "qingnode-subscription", Description: "subscription", Command: "/usr/local/bin/qingnode", Args: []string{"subscription", "serve"}, User: "qingnode-sub", Group: "qingnode-sub"},
		{Name: "qingnode-monitor", Description: "monitor", Command: "/usr/local/bin/qingnode", Args: []string{"monitor", "watch"}, User: "root", Group: "root"},
	} {
		auxiliary, err := RenderOpenRC(service)
		if err != nil || strings.Contains(auxiliary, "capabilities=") || strings.Contains(auxiliary, "cap_net_bind_service") {
			t.Fatal("unrelated service acquired the core bind grant", auxiliary, err)
		}
	}
}

func TestServiceOwnershipRejectsExternalOverrides(t *testing.T) {
	root := t.TempDir()
	conf := t.TempDir()
	expected, _ := RenderOpenRC(CoreServiceSpec())
	path := filepath.Join(root, "qingnode")
	if e := os.WriteFile(path, []byte(expected), 0755); e != nil {
		t.Fatal(e)
	}
	m := Manager{Kind: InitOpenRC, DefinitionRoot: root, ConfigRoot: conf}
	if e := m.VerifyOwnership("qingnode", []byte(expected)); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(conf, "qingnode"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if m.VerifyOwnership("qingnode", []byte(expected)) == nil {
		t.Fatal("conf.d override accepted")
	}
	if e := os.Remove(filepath.Join(conf, "qingnode")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(expected+"\n# administrator edit\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if m.VerifyOwnership("qingnode", []byte(expected)) == nil {
		t.Fatal("external edit accepted")
	}
}
