package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"qingnode/internal/platform"
)

// This fake models native controller state separately from definition bytes;
// atomic file writes do not implicitly reload init. Real lifecycle/transport
// acceptance remains a separate disposable-host gate.
type auxiliaryFixture struct {
	t                *testing.T
	root             string
	manager          platform.Manager
	units            map[string]*auxiliaryFixtureUnit
	mutations        []string
	failReload       bool
	failStart        bool
	unknown          bool
	stateLockChecked bool
	afterNative      func(string, []string)
}
type auxiliaryFixtureUnit struct {
	loaded, active, failed bool
	enabled, source        string
}

func newAuxiliaryFixture(t *testing.T, kind platform.InitKind) *auxiliaryFixture {
	t.Helper()
	f := &auxiliaryFixture{t: t, root: t.TempDir(), units: map[string]*auxiliaryFixtureUnit{}}
	store := &Store{Root: f.root, Backend: OfflineBackend{}, GID: -1}
	if err := store.WithLock(func() error { return store.Apply(NewState()) }); err != nil {
		t.Fatal(err)
	}
	f.manager = platform.Manager{Kind: kind, DefinitionRoot: t.TempDir(), ConfigRoot: t.TempDir(), RunlevelRoot: t.TempDir(), RuntimeRoot: t.TempDir(), ProcRoot: t.TempDir(), Execute: f.run}
	if err := os.Mkdir(filepath.Join(f.manager.RunlevelRoot, "default"), 0755); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *auxiliaryFixture) unit(member string) *auxiliaryFixtureUnit {
	if f.units[member] == nil {
		f.units[member] = &auxiliaryFixtureUnit{}
	}
	return f.units[member]
}
func (f *auxiliaryFixture) reload() {
	for _, name := range []string{"qingnode-monitor", "qingnode-subscription"} {
		for _, member := range auxiliaryMembers(f.manager, name) {
			u := f.unit(member)
			_, err := os.Stat(auxiliaryDefinitionPath(f.manager, member))
			u.loaded = err == nil
			if u.loaded {
				u.source = auxiliaryDefinitionPath(f.manager, member)
				if u.enabled == "" {
					u.enabled = "disabled"
					if member == "qingnode-monitor.service" {
						u.enabled = "static"
					}
				}
			} else {
				u.source, u.enabled = "", ""
			}
		}
	}
}
func (f *auxiliaryFixture) run(_ time.Duration, command string, args ...string) ([]byte, error) {
	if command == "systemctl" && len(args) > 1 && args[0] == "show" {
		member := args[1]
		u := f.unit(member)
		properties := strings.TrimPrefix(args[len(args)-1], "--property=")
		load, active, sub, pid := "not-found", "inactive", "dead", "0"
		if u.loaded {
			load = "loaded"
		}
		if u.active {
			active, sub = "active", "running"
			if strings.HasSuffix(member, ".service") {
				pid = "1234"
			}
			if strings.HasSuffix(member, ".timer") {
				sub = "waiting"
			}
		}
		if f.unknown {
			active = "unknown"
		}
		if u.failed {
			active, sub, pid = "failed", "failed", "0"
		}
		values := map[string]string{"LoadState": load, "ActiveState": active, "SubState": sub, "MainPID": pid, "UnitFileState": u.enabled, "FragmentPath": u.source, "DropInPaths": ""}
		var out strings.Builder
		for _, prop := range strings.Split(properties, ",") {
			// A timer does not implement the service-only MainPID property.
			if strings.HasSuffix(member, ".timer") && prop == "MainPID" {
				continue
			}
			fmt.Fprintf(&out, "%s=%s\n", prop, values[prop])
		}
		return []byte(out.String()), nil
	}
	if command == "rc-service" && len(args) == 2 {
		name, verb := args[0], args[1]
		u := f.unit(name)
		if verb == "status" {
			if u.active {
				return []byte(" * status: started\n"), nil
			}
			return []byte(" * status: stopped\n"), errors.New("inactive")
		}
		if verb == "qingnode_pid" {
			return []byte("1234\n"), nil
		}
	}
	f.mutations = append(f.mutations, command+" "+strings.Join(args, " "))
	if f.afterNative != nil {
		callback := f.afterNative
		copiedArgs := append([]string(nil), args...)
		defer callback(command, copiedArgs)
	}
	if err := (&Store{Root: f.root}).InspectExisting(func() error { return nil }); err != nil {
		f.t.Fatalf("State lock held while native service runs: %v", err)
	}
	f.stateLockChecked = true
	if command == "systemctl" && reflect.DeepEqual(args, []string{"daemon-reload"}) {
		if f.failReload {
			f.failReload = false
			return nil, errors.New("injected daemon-reload failure")
		}
		f.reload()
		return nil, nil
	}
	if command == "systemctl" && len(args) == 2 {
		u := f.unit(args[1])
		if !u.loaded {
			return nil, errors.New("not loaded")
		}
		switch args[0] {
		case "start":
			if f.failStart {
				f.failStart = false
				u.failed = true
				return nil, errors.New("injected start failure leaves native failed state")
			}
			u.active = args[1] != "qingnode-monitor.service"
		case "stop":
			u.active = false
		case "enable":
			u.enabled = "enabled"
		case "disable":
			if u.enabled != "static" {
				u.enabled = "disabled"
			}
		case "reset-failed":
			u.failed = false
		default:
			f.t.Fatalf("unexpected native action: %v", args)
		}
		return nil, nil
	}
	if command == "rc-service" && len(args) == 2 {
		u := f.unit(args[0])
		if args[1] == "start" {
			u.active = true
			_ = os.Mkdir(filepath.Join(f.manager.ProcRoot, "1234"), 0700)
		} else if args[1] == "stop" {
			u.active = false
			_ = os.Remove(filepath.Join(f.manager.ProcRoot, "1234"))
		} else {
			f.t.Fatalf("unexpected OpenRC action %v", args)
		}
		return nil, nil
	}
	if command == "rc-update" && len(args) == 3 {
		path := filepath.Join(f.manager.RunlevelRoot, args[2], args[1])
		if args[0] == "add" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return nil, err
			}
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				return nil, os.Symlink(auxiliaryDefinitionPath(f.manager, args[1]), path)
			}
			return nil, nil
		}
		return nil, os.Remove(path)
	}
	f.t.Fatalf("unexpected controller command %s %v", command, args)
	return nil, errors.New("unexpected command")
}
func (f *auxiliaryFixture) plan(name string) AuxiliaryServicePlan {
	f.t.Helper()
	public := ""
	if name == "qingnode-subscription" {
		public = "https://subscriptions.example.test"
	}
	p, err := NewAuxiliaryServicePlan(f.manager, name, public)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func TestAuxiliaryServiceInstallRemoveAndReadonlyPreview(t *testing.T) {
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		for _, name := range []string{"qingnode-monitor", "qingnode-subscription"} {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				f := newAuxiliaryFixture(t, kind)
				p := f.plan(name)
				stateBefore, _ := os.ReadFile(filepath.Join(f.root, "current", "state.json"))
				entriesBefore, _ := os.ReadDir(f.root)
				preview, err := PreviewAuxiliaryService(f.root, p, "install")
				entriesAfter, _ := os.ReadDir(f.root)
				if err != nil || preview.Installed || preview.Pending || len(f.mutations) != 0 || len(entriesBefore) != len(entriesAfter) {
					t.Fatalf("preview wrote or changed lifecycle: %+v %v", preview, err)
				}
				if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
					t.Fatal(err)
				}
				if kind == platform.InitSystemd && !f.stateLockChecked {
					t.Fatal("native action did not exercise unlocked State")
				}
				for _, file := range p.Definitions {
					b, _, _, err := auxiliaryReadDefinition(f.manager, file.Name, file.Mode)
					if err != nil || !bytes.Equal(b, file.Contents) {
						t.Fatalf("installed definition %s: %v", file.Name, err)
					}
				}
				minimal := AuxiliaryServicePlan{Name: name, Manager: f.manager}
				preview, err = PreviewAuxiliaryService(f.root, minimal, "inspect")
				if err != nil || !preview.Installed || preview.WasActive || preview.WasEnabled {
					t.Fatalf("fresh install was not stopped/disabled: %+v %v", preview, err)
				}
				if err := ApplyAuxiliaryService(f.root, minimal, "remove"); err != nil {
					t.Fatal(err)
				}
				for _, file := range p.Definitions {
					if _, err := os.Lstat(auxiliaryDefinitionPath(f.manager, file.Name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("definition retained after removal", err)
					}
				}
				if pending, err := AuxiliaryServicePending(f.root, name); pending || err != nil {
					t.Fatal("finished operation remained pending", err)
				}
				history, _ := filepath.Glob(filepath.Join(f.root, ".auxiliary-"+name+".recovery-*.json"))
				if len(history) != 2 {
					t.Fatalf("recovery material was not preserved: %v", history)
				}
				stateAfter, _ := os.ReadFile(filepath.Join(f.root, "current", "state.json"))
				if !bytes.Equal(stateBefore, stateAfter) {
					t.Fatal("optional-service installation changed proxy State")
				}
			})
		}
	}
}

func TestAuxiliaryServiceReinstallPreservesNativeState(t *testing.T) {
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		t.Run(string(kind), func(t *testing.T) {
			f := newAuxiliaryFixture(t, kind)
			p := f.plan("qingnode-monitor")
			if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
				t.Fatal(err)
			}
			member := p.Name
			if kind == platform.InitSystemd {
				member += ".timer"
			}
			if err := auxiliaryCommand(f.manager, "start", member); err != nil {
				t.Fatal(err)
			}
			if kind == platform.InitOpenRC {
				if err := f.manager.EnableRunlevels(p.Name, []string{"default", "custom"}); err != nil {
					t.Fatal(err)
				}
			} else if err := auxiliaryCommand(f.manager, "enable", member); err != nil {
				t.Fatal(err)
			}
			before, err := PreviewAuxiliaryService(f.root, p, "inspect")
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
				t.Fatal(err)
			}
			after, err := PreviewAuxiliaryService(f.root, p, "inspect")
			if err != nil || !reflect.DeepEqual(before.States, after.States) {
				t.Fatalf("reinstall changed independent service/timer/runlevel state: %v %+v %+v", err, before.States, after.States)
			}
		})
	}
}

func TestAuxiliaryServiceReloadFailureRestoresWorkingVersion(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-subscription")
	if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
		t.Fatal(err)
	}
	member := p.Name + ".service"
	if err := auxiliaryCommand(f.manager, "start", member); err != nil {
		t.Fatal(err)
	}
	if err := auxiliaryCommand(f.manager, "enable", member); err != nil {
		t.Fatal(err)
	}
	oldReceipt, err := auxiliaryReadPrivate(auxiliaryPath(f.root, p.Name, ".installed"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewAuxiliaryServicePlan(f.manager, p.Name, "https://replacement.example.test")
	if err != nil {
		t.Fatal(err)
	}
	f.failReload = true
	if err := ApplyAuxiliaryService(f.root, next, "install"); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatalf("failed install did not report rollback: %v", err)
	}
	b, _, _, err := auxiliaryReadDefinition(f.manager, member, 0644)
	if err != nil || !bytes.Equal(b, p.Definitions[0].Contents) {
		t.Fatal("old definition/mode not restored", err)
	}
	if !f.unit(member).active || f.unit(member).enabled != "enabled" {
		t.Fatal("old active/enabled state not restored")
	}
	restoredReceipt, _ := auxiliaryReadPrivate(auxiliaryPath(f.root, p.Name, ".installed"))
	if !bytes.Equal(oldReceipt, restoredReceipt) {
		t.Fatal("old deployment settings not restored")
	}
	if pending, _ := AuxiliaryServicePending(f.root, p.Name); pending {
		t.Fatal("successful automatic rollback remained pending")
	}
}

func TestAuxiliaryServiceInterruptedPairRequiresExplicitRecovery(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	before, err := auxiliaryCapture(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "install", Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(p)}
	if err := auxiliaryCreateJournal(auxiliaryPath(f.root, p.Name, ".journal"), j); err != nil {
		t.Fatal(err)
	}
	// Simulated interruption after the first atomic write, before timer write
	// and before daemon-reload. This is fault injection, not a real VM kill.
	if err := AtomicWrite(auxiliaryDefinitionPath(f.manager, p.Definitions[0].Name), p.Definitions[0].Contents, 0644); err != nil {
		t.Fatal(err)
	}
	mutations := len(f.mutations)
	preview, err := RecoverAuxiliaryService(f.root, AuxiliaryServicePlan{Name: p.Name, Manager: f.manager}, true)
	if err != nil || !preview.Pending || len(f.mutations) != mutations {
		t.Fatalf("recover preview mutated native state: %+v %v", preview, err)
	}
	if err := ApplyAuxiliaryService(f.root, p, "install"); err == nil {
		t.Fatal("a new write passed the pending journal")
	}
	if _, err := RecoverAuxiliaryService(f.root, AuxiliaryServicePlan{Name: p.Name, Manager: f.manager}, false); err != nil {
		t.Fatal(err)
	}
	for _, file := range p.Definitions {
		if _, err := os.Lstat(auxiliaryDefinitionPath(f.manager, file.Name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("partial new object remained after rollback", err)
		}
	}
	if pending, _ := AuxiliaryServicePending(f.root, p.Name); pending {
		t.Fatal("explicit recovery left pending material")
	}
}

func TestAuxiliaryServiceFailedCandidateStartRestoresWorkingService(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-subscription")
	if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
		t.Fatal(err)
	}
	member := p.Name + ".service"
	if err := auxiliaryCommand(f.manager, "start", member); err != nil {
		t.Fatal(err)
	}
	if err := auxiliaryCommand(f.manager, "enable", member); err != nil {
		t.Fatal(err)
	}
	next, err := NewAuxiliaryServicePlan(f.manager, p.Name, "https://replacement.example.test")
	if err != nil {
		t.Fatal(err)
	}
	f.failStart = true
	if err := ApplyAuxiliaryService(f.root, next, "install"); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatalf("candidate failed state did not trigger working-version rollback: %v", err)
	}
	if !f.unit(member).active || f.unit(member).failed || f.unit(member).enabled != "enabled" {
		t.Fatalf("native working state not restored: %+v", f.unit(member))
	}
	b, _, _, err := auxiliaryReadDefinition(f.manager, member, 0644)
	if err != nil || !bytes.Equal(b, p.Definitions[0].Contents) {
		t.Fatal("original fixed definition not restored", err)
	}
	resetSeen := false
	for _, action := range f.mutations {
		if action == "systemctl reset-failed "+member {
			resetSeen = true
		}
	}
	if !resetSeen {
		t.Fatal("failed controller state was assumed stopped without native reset proof")
	}
	if pending, _ := AuxiliaryServicePending(f.root, p.Name); pending {
		t.Fatal("working rollback still pending")
	}
	// A pre-existing failed service has no prepared transaction authorizing
	// repair. Inspection/install must continue to refuse that unknown baseline.
	f.unit(member).active, f.unit(member).failed = false, true
	mutations := len(f.mutations)
	if err := ApplyAuxiliaryService(f.root, p, "install"); err == nil {
		t.Fatal("pre-existing failure was silently repaired")
	}
	if len(f.mutations) != mutations {
		t.Fatal("preflight failure performed recovery without a journal")
	}
}

func TestAuxiliaryServiceRejectsExternalChangesAndUnknownNativeState(t *testing.T) {
	for _, variant := range []string{"contents", "mode", "symlink", "hardlink", "dropin", "source", "unknown"} {
		t.Run(variant, func(t *testing.T) {
			f := newAuxiliaryFixture(t, platform.InitSystemd)
			p := f.plan("qingnode-monitor")
			if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
				t.Fatal(err)
			}
			path := auxiliaryDefinitionPath(f.manager, p.Definitions[0].Name)
			switch variant {
			case "contents":
				if err := os.WriteFile(path, append(p.Definitions[0].Contents, []byte("# administrator change\n")...), 0644); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0664); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				external := filepath.Join(t.TempDir(), "external")
				if err := os.WriteFile(external, p.Definitions[0].Contents, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				var err error
				if variant == "symlink" {
					err = os.Symlink(external, path)
				} else {
					err = os.Link(external, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "dropin":
				if err := os.Mkdir(path+".d", 0700); err != nil {
					t.Fatal(err)
				}
			case "source":
				f.unit(p.Definitions[0].Name).source = "/usr/lib/systemd/system/external.service"
			case "unknown":
				f.unknown = true
			}
			mutations := len(f.mutations)
			if err := ApplyAuxiliaryService(f.root, p, "remove"); err == nil {
				t.Fatal("external or unknown service was accepted")
			}
			if len(f.mutations) != mutations {
				t.Fatal("failed ownership preflight performed native mutation")
			}
			if pending, err := AuxiliaryServicePending(f.root, p.Name); pending || err != nil {
				t.Fatal("preflight failure created pending transaction", err)
			}
		})
	}
	f := newAuxiliaryFixture(t, platform.InitOpenRC)
	p := f.plan("qingnode-monitor")
	if err := os.WriteFile(filepath.Join(f.manager.ConfigRoot, p.Name), []byte("external configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyAuxiliaryService(f.root, p, "install"); err == nil || len(f.mutations) != 0 {
		t.Fatal("external OpenRC conf.d override accepted", err)
	}
}

func TestAuxiliaryServiceRecoveryRejectsFutureAndExecutableInjection(t *testing.T) {
	for _, variant := range []string{"future", "unknown-json", "injected-unit", "wrong-name", "public-journal", "outside-change"} {
		t.Run(variant, func(t *testing.T) {
			f := newAuxiliaryFixture(t, platform.InitSystemd)
			p := f.plan("qingnode-subscription")
			if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
				t.Fatal(err)
			}
			_, receipt, err := auxiliaryReceipt(f.root, p)
			if err != nil {
				t.Fatal(err)
			}
			before, err := auxiliaryCapture(p, receipt)
			if err != nil {
				t.Fatal(err)
			}
			j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "remove", Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(p)}
			switch variant {
			case "future":
				j.Version = 2
			case "injected-unit":
				j.Before.Files[0].Contents = append(j.Before.Files[0].Contents, []byte("\nExecStart=/bin/untrusted\n")...)
			case "wrong-name":
				j.Candidate.Name = "sshd"
			}
			path := auxiliaryPath(f.root, p.Name, ".journal")
			if err := auxiliaryCreateJournal(path, j); err != nil {
				t.Fatal(err)
			}
			if variant == "unknown-json" {
				b, _ := os.ReadFile(path)
				b = append(b[:len(b)-1], []byte(",\"unknown\":true}")...)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "public-journal" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "outside-change" {
				if err := os.WriteFile(auxiliaryDefinitionPath(f.manager, p.Definitions[0].Name), []byte("external service"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			mutations := len(f.mutations)
			if _, err := RecoverAuxiliaryService(f.root, AuxiliaryServicePlan{Name: p.Name, Manager: f.manager}, false); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if len(f.mutations) != mutations {
				t.Fatal("unsafe recovery invoked native actions")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("unsafe recovery discarded original material", err)
			}
		})
	}
}

func TestPendingAuxiliaryServiceProtectsUninstallAndMigration(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	path := auxiliaryPath(f.root, "qingnode-monitor", ".journal")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PendingAuxiliaryService(f.root); err == nil || !strings.Contains(err.Error(), "recover") {
		t.Fatal("pending service not reported", err)
	}
	if err := (Removal{Root: f.root, ManagerKind: platform.InitSystemd, Execute: f.run}).Remove(true); err == nil || !strings.Contains(err.Error(), "recover") {
		t.Fatal("full uninstall could discard pending recovery", err)
	}
	if err := (&Store{Root: f.root}).RestoreMigrationAssets(MigrationPackage{}, MigrationTargets{}, false); err == nil || !strings.Contains(err.Error(), "recover") {
		t.Fatal("migration ignored pending service recovery", err)
	}
	if len(f.mutations) != 0 {
		t.Fatal("pending preflight mutated lifecycle")
	}
	b, _ := os.ReadFile(path)
	if string(b) != `{"version":1}` {
		t.Fatal("pending check modified recovery material")
	}
}

func TestAuxiliaryServiceRejectsArbitraryDefinitionInput(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	p.Definitions[0].Contents = []byte("# Managed by QingNode\nExecStart=/bin/external\n")
	if err := ApplyAuxiliaryService(f.root, p, "install"); err == nil {
		t.Fatal("arbitrary local definition input accepted")
	}
	if len(f.mutations) != 0 {
		t.Fatal("invalid plan performed native mutation")
	}
	if _, err := NewAuxiliaryServicePlan(f.manager, "sshd", ""); err == nil {
		t.Fatal("arbitrary service accepted")
	}
	for i, public := range []string{"http://example.test", "https://user:password@example.test", "https://example.test?token=private", "https://example.test#private"} {
		if _, err := NewAuxiliaryServicePlan(f.manager, "qingnode-subscription", public); err == nil {
			t.Fatal("unsafe typed URL accepted", strconv.Itoa(i))
		}
	}
}

func TestAuxiliaryServiceJournalRoundTripVersionIsExplicit(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	before, err := auxiliaryCapture(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "install", Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(p)}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var decoded auxiliaryJournal
	if err := auxiliaryDecode(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := auxiliaryValidateJournal(f.manager, p.Name, decoded); err != nil {
		t.Fatal(err)
	}
}

func TestAuxiliaryServiceRejectsDuplicateJournalAndInstallationKeys(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	before, err := auxiliaryCapture(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "install", Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(p)}
	encoded, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	for _, malicious := range []string{
		strings.Replace(string(encoded), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(encoded), `"name":"qingnode-monitor"`, `"name":"qingnode-monitor","name":"qingnode-monitor"`, 1),
		strings.Replace(string(encoded), `"version":1`, `"version":1,"Version":1`, 1),
	} {
		var decoded auxiliaryJournal
		if err := auxiliaryDecode([]byte(malicious), &decoded); err == nil {
			t.Fatal("ambiguous journal accepted")
		}
	}
	for _, malicious := range []string{
		`{"version":1,"version":1,"settings":{"name":"qingnode-monitor","manager":"systemd"}}`,
		`{"version":1,"settings":{"name":"qingnode-monitor","name":"qingnode-monitor","manager":"systemd"}}`,
		`{"version":1,"settings":{"name":"qingnode-monitor","manager":"systemd"},"settings":{"name":"qingnode-monitor","manager":"systemd"}}`,
	} {
		path := auxiliaryPath(f.root, p.Name, ".installed")
		if err := AtomicWrite(path, []byte(malicious), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := auxiliaryReceipt(f.root, p); err == nil {
			t.Fatal("ambiguous installation record accepted")
		}
	}
	if len(f.mutations) != 0 {
		t.Fatal("ambiguous metadata invoked native actions")
	}
}

func TestAuxiliaryServiceMigrationInventoryIncludesSubscriptionOnlyOffline(t *testing.T) {
	root := t.TempDir()
	name := "qingnode-subscription"
	// No proxy State, monitor plan, init controller or service definition is
	// needed to discover an explicitly typed deployment record offline.
	record := auxiliaryInstalled{Version: 1, Settings: auxiliarySettings{Name: name, Kind: platform.InitOpenRC, PublicURL: "https://private-deployment.example.test"}}
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := auxiliaryPath(root, name, ".installed")
	if err := AtomicWrite(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(root)
	gaps, err := AuxiliaryServiceMigrationGaps(root)
	after, _ := os.ReadDir(root)
	if err != nil || len(gaps) != 1 || !strings.Contains(gaps[0], name) || strings.Contains(gaps[0], record.Settings.PublicURL) || len(before) != len(after) {
		t.Fatalf("offline subscription-only inventory was incomplete or wrote/leaked settings: %v %v", gaps, err)
	}
	variants := [][]byte{
		[]byte(`{"version":2,"settings":{"name":"qingnode-subscription","manager":"openrc","public_url":"https://example.test"}}`),
		[]byte(`{"version":1,"settings":{"name":"sshd","manager":"openrc","public_url":"https://example.test"}}`),
		[]byte(`{"version":1,"settings":{"name":"qingnode-subscription","manager":"unknown","public_url":"https://example.test"}}`),
		[]byte(`{"version":1,"settings":{"name":"qingnode-subscription","manager":"openrc","public_url":"https://example.test?token=private"}}`),
	}
	for _, invalid := range variants {
		if err := AtomicWrite(path, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := AuxiliaryServiceMigrationGaps(root); err == nil {
			t.Fatal("invalid typed deployment metadata accepted")
		}
	}
	if err := AtomicWrite(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := AuxiliaryServiceMigrationGaps(root); err == nil {
		t.Fatal("public deployment metadata accepted")
	}
}
