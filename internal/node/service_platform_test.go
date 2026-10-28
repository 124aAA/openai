package node

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qingnode/internal/platform"
)

func TestServiceDefinitionsKeepExistingSystemdContract(t *testing.T) {
	systemd, e := ServiceDefinition(platform.InitSystemd)
	if e != nil || systemd != ServiceUnit {
		t.Fatal("existing systemd definition changed", e)
	}
	openrc, e := ServiceDefinition(platform.InitOpenRC)
	if e != nil || !platform.ManagedDefinition([]byte(openrc)) || !strings.Contains(openrc, `command_user="qingnode:qingnode"`) {
		t.Fatal(openrc, e)
	}
	if _, e := ServiceDefinition(platform.InitUnavailable); e == nil {
		t.Fatal("unavailable init rendered usable service")
	}
}

func TestOpenRCRestartDoesNotInventReloadResetOrEnable(t *testing.T) {
	var calls []string
	b := SystemBackend{ManagerKind: platform.InitOpenRC, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, errors.New("restart failure")
	}}
	if b.restartService(fixture(t)) == nil {
		t.Fatal("failure ignored")
	}
	if !reflect.DeepEqual(calls, []string{"rc-service qingnode restart"}) {
		t.Fatal(calls)
	}
}

func TestOpenRCStopProofRejectsOrphansAndUnknownProcessInventory(t *testing.T) {
	proc := t.TempDir()
	root := t.TempDir()
	b := SystemBackend{Root: root, ProcRoot: proc, OpenRCPIDFile: filepath.Join(t.TempDir(), "supervise.pid"), ManagerKind: platform.InitOpenRC, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name != "rc-service" || !reflect.DeepEqual(args, []string{"qingnode", "status"}) {
			t.Fatal(name, args)
		}
		return []byte("status: stopped\n"), errors.New("exit status 3")
	}}
	if e := b.ConfirmStopped(); e != nil {
		t.Fatal(e)
	}
	process := filepath.Join(proc, "1212")
	if e := os.Mkdir(process, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(CorePath(root, DefaultCore), filepath.Join(process, "exe")); e != nil {
		t.Fatal(e)
	}
	if b.ConfirmStopped() == nil {
		t.Fatal("orphan core accepted")
	}
	if e := os.Remove(filepath.Join(process, "exe")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(process, "exe"), []byte("not a proc exe link"), 0600); e != nil {
		t.Fatal(e)
	}
	if b.ConfirmStopped() == nil {
		t.Fatal("incomplete process inventory accepted")
	}
	if e := os.Remove(filepath.Join(process, "exe")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/usr/bin/external-service", filepath.Join(process, "exe")); e != nil {
		t.Fatal(e)
	}
	if e := b.ConfirmStopped(); e != nil {
		t.Fatal("foreign process mistaken for ours", e)
	}
	if e := os.WriteFile(b.OpenRCPIDFile, []byte("1212\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if b.ConfirmStopped() == nil {
		t.Fatal("surviving supervisor accepted")
	}
}

func TestOpenRCCoreCapabilitiesAreReadOnlyAndUnknownGrantsAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name, readback            string
		readFailure, legacy, pass bool
	}{
		{"plain file", "", false, false, true},
		{"old exact project grant", "/tmp/core cap_net_bind_service=ep\n", false, true, true},
		{"read denied", "", true, false, false},
		{"additional capability", "/tmp/core cap_net_admin,cap_net_bind_service=ep\n", false, false, false},
		{"different flags", "/tmp/core cap_net_bind_service=eip\n", false, false, false},
		{"unrelated path", "/tmp/foreign cap_net_bind_service=ep\n", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			legacy, e := openRCCoreFileCapabilityWithRunner("/tmp/core", func(_ time.Duration, name string, args ...string) ([]byte, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				if tc.readFailure {
					return nil, errors.New("EPERM")
				}
				return []byte(tc.readback), nil
			})
			if (e == nil) != tc.pass || legacy != tc.legacy {
				t.Fatal(legacy, e)
			}
			if len(calls) != 1 || calls[0] != "getcap /tmp/core" {
				t.Fatal(calls)
			}
		})
	}
}

func TestOpenRCCandidateCannotUseAFileCapability(t *testing.T) {
	for _, readback := range []string{"", "/tmp/core cap_net_bind_service=ep\n", "/tmp/core cap_net_admin=ep\n"} {
		var calls []string
		err := verifyOpenRCCoreFileCapabilityWithRunner("/tmp/core", func(_ time.Duration, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte(readback), nil
		})
		if (err == nil) != (readback == "") || len(calls) != 1 || calls[0] != "getcap /tmp/core" {
			t.Fatal(readback, err, calls)
		}
	}
}

func TestOpenRCRemovalRecoveryRestoresExactRunlevelsAndOwnedLogrotate(t *testing.T) {
	root := t.TempDir()
	units := t.TempDir()
	levels := t.TempDir()
	unit := filepath.Join(units, "qingnode")
	binary := filepath.Join(root, "manager")
	lib := filepath.Join(root, "lib")
	rotate := filepath.Join(root, "logrotate")
	definition, _ := ServiceDefinition(platform.InitOpenRC)
	for p, content := range map[string]string{unit + ".qingnode-uninstall": definition, binary + ".qingnode-uninstall": "manager", rotate + ".qingnode-uninstall": managedLogrotate} {
		if e := os.WriteFile(p, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range []string{filepath.Join(root, ".uninstall-cores"), lib + ".qingnode-uninstall"} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(lib+".qingnode-uninstall", ".qingnode-owner"), []byte(OwnerMarker), 0600); e != nil {
		t.Fatal(e)
	}
	journal, _ := json.Marshal(removalJournal{Full: true, Active: true, Enabled: true, Runlevels: []string{"boot", "custom"}})
	if e := os.WriteFile(filepath.Join(root, "uninstall.json"), journal, 0600); e != nil {
		t.Fatal(e)
	}
	var commands []string
	if e := os.Mkdir(filepath.Join(levels, "stale"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(unit, filepath.Join(levels, "stale", "qingnode")); e != nil {
		t.Fatal(e)
	}
	r := Removal{Root: root, Unit: unit, Binary: binary, Library: lib, Logrotate: rotate, RunlevelRoot: levels, DefinitionRoot: units, ConfigRoot: t.TempDir(), ManagerKind: platform.InitOpenRC, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		if name == "rc-update" && args[0] == "del" {
			return nil, os.Remove(filepath.Join(levels, args[2], "qingnode"))
		}
		if name == "rc-update" && args[0] == "add" {
			if e := os.Mkdir(filepath.Join(levels, args[2]), 0700); e != nil && !errors.Is(e, os.ErrExist) {
				return nil, e
			}
			return nil, os.Symlink(unit, filepath.Join(levels, args[2], "qingnode"))
		}
		return nil, nil
	}}
	if e := r.Recover(); e != nil {
		t.Fatal(e)
	}
	want := []string{"rc-update del qingnode stale", "rc-update add qingnode boot", "rc-update add qingnode custom", "rc-service qingnode restart"}
	if !reflect.DeepEqual(commands, want) {
		t.Fatal(commands)
	}
	if restored, e := r.manager().Runlevels("qingnode"); e != nil || !reflect.DeepEqual(restored, []string{"boot", "custom"}) {
		t.Fatal("exact runlevels were not restored", restored, e)
	}
	for _, p := range []string{unit, binary, lib, rotate, filepath.Join(root, "cores")} {
		if _, e := os.Stat(p); e != nil {
			t.Fatal("owned asset not recovered", p, e)
		}
	}
	if _, e := os.Stat(filepath.Join(root, "uninstall.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("journal not committed")
	}
}

func TestOpenRCCertificateEventsRemainUnknownWithoutEpoch(t *testing.T) {
	b := SystemBackend{ManagerKind: platform.InitOpenRC, Execute: func(time.Duration, string, ...string) ([]byte, error) {
		t.Fatal("OpenRC queried systemd journal")
		return nil, nil
	}}
	r, e := b.InspectCertificateJournal(State{}, CertificateResource{}, time.Now())
	if e != nil || r.LastSuccess != nil || r.LastFailure != nil || r.Issuing != nil || !strings.Contains(r.Evidence, "unavailable") {
		t.Fatal(r, e)
	}
}
