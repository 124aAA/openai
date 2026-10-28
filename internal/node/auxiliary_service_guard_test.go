package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/platform"
)

func TestAuxiliaryServiceNativeWaitCannotOverwriteForeignMaterial(t *testing.T) {
	for _, direction := range []string{"apply", "rollback"} {
		for _, verb := range []string{"stop", "disable", "reload", "start"} {
			for _, target := range []string{"unit", "receipt", "journal"} {
				t.Run(direction+"/"+verb+"/"+target, func(t *testing.T) {
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
					next, err := NewAuxiliaryServicePlan(f.manager, p.Name, "https://changed.example.test")
					if err != nil {
						t.Fatal(err)
					}
					path := auxiliaryDefinitionPath(f.manager, member)
					foreign := []byte("# Managed by QingNode\n# foreign administrator definition\n")
					mode := os.FileMode(0644)
					if target == "receipt" {
						path, foreign, mode = auxiliaryPath(f.root, p.Name, ".installed"), []byte(`{"administrator":"foreign deployment record"}`), 0600
					}
					if target == "journal" {
						path, foreign, mode = auxiliaryPath(f.root, p.Name, ".journal"), []byte(`{"administrator":"foreign transaction record"}`), 0600
					}
					fired, failedCandidate, afterMutation := false, false, 0
					var originalJournal []byte
					if direction == "rollback" {
						f.failStart = true
					}
					f.afterNative = func(command string, args []string) {
						if len(args) == 0 || command != "systemctl" || fired {
							return
						}
						actualVerb := args[0]
						if actualVerb == "daemon-reload" {
							actualVerb = "reload"
						}
						if direction == "rollback" && actualVerb == "start" && f.unit(member).failed {
							failedCandidate = true
							return
						}
						if direction == "rollback" && !failedCandidate || actualVerb != verb {
							return
						}
						fired = true
						originalJournal, _ = os.ReadFile(auxiliaryPath(f.root, p.Name, ".journal"))
						if err := os.WriteFile(path, foreign, mode); err != nil {
							t.Fatal(err)
						}
						afterMutation = len(f.mutations)
					}
					action := "install"
					if direction == "apply" && verb == "disable" {
						action = "remove"
					}
					if err := ApplyAuxiliaryService(f.root, next, action); err == nil {
						t.Fatal("transaction accepted foreign material changed during a native wait")
					}
					if !fired {
						t.Fatal("the intended real controller callback boundary was not exercised")
					}
					actual, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(actual, foreign) {
						t.Fatalf("foreign %s was overwritten/deleted: %v %q", target, err, actual)
					}
					if len(f.mutations) != afterMutation {
						t.Fatalf("foreign material was followed by additional native mutations: %v", f.mutations[afterMutation:])
					}
					if target == "journal" {
						b, err := auxiliaryReadPrivate(auxiliaryPath(f.root, p.Name, ".conflict"))
						if err != nil {
							t.Fatal("original transaction witness not retained", err)
						}
						var witness auxiliaryConflict
						if err := auxiliaryDecode(b, &witness); err != nil || !bytes.Equal(witness.Original, originalJournal) {
							t.Fatal("original transaction bytes were not retained", err)
						}
					} else {
						b, _ := os.ReadFile(auxiliaryPath(f.root, p.Name, ".journal"))
						if !bytes.Equal(b, originalJournal) {
							t.Fatal("pending original journal changed after external mutation")
						}
					}
					if pending, err := AuxiliaryServicePending(f.root, p.Name); err != nil || !pending {
						t.Fatal("failed ownership guard lost pending recovery evidence", err)
					}
				})
			}
		}
	}
}

func TestAuxiliaryServiceStopCallbackProtectsOtherMonitorMember(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
		t.Fatal(err)
	}
	if err := auxiliaryCommand(f.manager, "start", p.Name+".timer"); err != nil {
		t.Fatal(err)
	}
	peer := auxiliaryDefinitionPath(f.manager, p.Name+".service")
	foreign := []byte("# foreign monitor service installed while timer stop waits\n")
	fired, afterMutation := false, 0
	f.afterNative = func(command string, args []string) {
		if fired || command != "systemctl" || len(args) != 2 || args[0] != "stop" {
			return
		}
		fired = true
		if err := os.WriteFile(peer, foreign, 0644); err != nil {
			t.Fatal(err)
		}
		afterMutation = len(f.mutations)
	}
	if err := ApplyAuxiliaryService(f.root, p, "remove"); err == nil {
		t.Fatal("timer callback allowed deletion of a changed peer service")
	}
	b, _ := os.ReadFile(peer)
	if !fired || !bytes.Equal(b, foreign) || len(f.mutations) != afterMutation {
		t.Fatal("changed peer service was touched or controlled after guard failed")
	}
}

func TestAuxiliaryServiceDeletedJournalRetainsBlockingWitness(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-subscription")
	if err := ApplyAuxiliaryService(f.root, p, "install"); err != nil {
		t.Fatal(err)
	}
	member := p.Name + ".service"
	if err := auxiliaryCommand(f.manager, "start", member); err != nil {
		t.Fatal(err)
	}
	fired := false
	var original []byte
	f.afterNative = func(command string, args []string) {
		if fired || command != "systemctl" || len(args) != 2 || args[0] != "stop" {
			return
		}
		fired = true
		path := auxiliaryPath(f.root, p.Name, ".journal")
		original, _ = os.ReadFile(path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplyAuxiliaryService(f.root, p, "remove"); err == nil {
		t.Fatal("missing primary journal was silently recreated or ignored")
	}
	if _, err := os.Lstat(auxiliaryPath(f.root, p.Name, ".journal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign journal deletion was silently overwritten", err)
	}
	b, err := auxiliaryReadPrivate(auxiliaryPath(f.root, p.Name, ".conflict"))
	if err != nil {
		t.Fatal(err)
	}
	var witness auxiliaryConflict
	if err := auxiliaryDecode(b, &witness); err != nil || !bytes.Equal(witness.Original, original) {
		t.Fatal("deleted primary's original bytes were lost", err)
	}
	if pending, err := AuxiliaryServicePending(f.root, p.Name); err != nil || !pending {
		t.Fatal("witness alone was not considered pending", err)
	}
	if err := PendingAuxiliaryService(f.root); err == nil {
		t.Fatal("global pending check ignored the only recovery witness")
	}
	if _, err := AuxiliaryServiceMigrationGaps(f.root); err == nil {
		t.Fatal("migration ignored conflict witness")
	}
	mutations := len(f.mutations)
	if err := (Removal{Root: f.root, ManagerKind: platform.InitSystemd, Execute: f.run}).Remove(true); err == nil {
		t.Fatal("full removal could discard the only witness")
	}
	if _, err := RecoverAuxiliaryService(f.root, AuxiliaryServicePlan{Name: p.Name, Manager: f.manager}, false); err == nil {
		t.Fatal("foreign journal disappearance was blindly repaired")
	}
	if len(f.mutations) != mutations {
		t.Fatal("witness verification controlled a service")
	}
}

func TestAuxiliaryServiceFinishRejectsDifferentPrivateJournal(t *testing.T) {
	for _, changed := range []string{"id", "phase", "settings", "format"} {
		t.Run(changed, func(t *testing.T) {
			f := newAuxiliaryFixture(t, platform.InitSystemd)
			p := f.plan("qingnode-monitor")
			before, err := auxiliaryCapture(p, nil)
			if err != nil {
				t.Fatal(err)
			}
			j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "install", Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(p)}
			path := auxiliaryPath(f.root, p.Name, ".journal")
			if err := auxiliaryCreateJournal(path, j); err != nil {
				t.Fatal(err)
			}
			foreign := j
			switch changed {
			case "id":
				foreign.ID = Token(16)
			case "phase":
				foreign.Phase = "committed"
			case "settings":
				foreign.Action = "remove"
			}
			b, err := json.MarshalIndent(foreign, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if changed == "format" {
				b = append(b, '\n')
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if err := auxiliaryFinish(f.root, f.manager, j, "rolled_back"); err == nil {
				t.Fatal("finish replaced a different private journal")
			}
			actual, _ := os.ReadFile(path)
			if !bytes.Equal(actual, b) {
				t.Fatal("finish overwrote or archived the foreign record")
			}
			history, _ := filepath.Glob(filepath.Join(f.root, ".auxiliary-"+p.Name+".recovery-*.json"))
			if len(history) != 0 {
				t.Fatal("finish incorrectly reported a completed archived transaction")
			}
			if len(f.mutations) != 0 {
				t.Fatal("finish of foreign journal invoked native actions")
			}
		})
	}
}

func TestAuxiliaryServiceRecoveryAcceptsExactPreviouslyCommittedRecord(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	before, err := auxiliaryCapture(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "install", Phase: "committed", Before: before, Candidate: auxiliarySettingsFor(p)}
	if err := auxiliaryCreateJournal(auxiliaryPath(f.root, p.Name, ".journal"), j); err != nil {
		t.Fatal(err)
	}
	for _, file := range p.Definitions {
		if err := AtomicWrite(auxiliaryDefinitionPath(f.manager, file.Name), file.Contents, file.Mode); err != nil {
			t.Fatal(err)
		}
	}
	f.reload()
	if _, err := RecoverAuxiliaryService(f.root, AuxiliaryServicePlan{Name: p.Name, Manager: f.manager}, false); err != nil {
		t.Fatal("exact committed interruption could not explicitly roll back", err)
	}
	if err := PendingAuxiliaryService(f.root); err != nil {
		t.Fatal(err)
	}
	for _, file := range p.Definitions {
		if _, err := os.Lstat(auxiliaryDefinitionPath(f.manager, file.Name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("explicit rollback did not restore absent before state", err)
		}
	}
}

func TestAuxiliaryServiceConflictMarkerRejectsUnknownOrForeignContent(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	path := auxiliaryPath(f.root, "qingnode-monitor", ".conflict")
	if err := os.WriteFile(path, []byte(`{"version":9,"original_record":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PendingAuxiliaryService(f.root); err == nil || !strings.Contains(err.Error(), "版本") {
		t.Fatal("future conflict witness was ignored", err)
	}
}

func TestAuxiliaryServiceFinishNeverReplacesConcurrentHistory(t *testing.T) {
	f := newAuxiliaryFixture(t, platform.InitSystemd)
	p := f.plan("qingnode-monitor")
	before, err := auxiliaryCapture(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := auxiliaryJournal{Version: 1, ID: Token(16), Action: "install", Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(p)}
	path := auxiliaryPath(f.root, p.Name, ".journal")
	if err := auxiliaryCreateJournal(path, j); err != nil {
		t.Fatal(err)
	}
	history := auxiliaryPath(f.root, p.Name, ".recovery-"+j.ID)
	foreign := []byte("administrator recovery evidence\n")
	fired := false
	manager := f.manager
	manager.Execute = func(timeout time.Duration, command string, args ...string) ([]byte, error) {
		out, err := f.run(timeout, command, args...)
		b, readErr := os.ReadFile(path)
		if !fired && readErr == nil && bytes.Contains(b, []byte(`"phase": "committed"`)) {
			fired = true
			if err := os.WriteFile(history, foreign, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return out, err
	}
	if err := auxiliaryFinish(f.root, manager, j, "committed"); err == nil {
		t.Fatal("finish replaced a history file created after the initial lstat")
	}
	b, err := os.ReadFile(history)
	if !fired || err != nil || !bytes.Equal(b, foreign) {
		t.Fatal("concurrent foreign history was not preserved", err)
	}
	if pending, err := AuxiliaryServicePending(f.root, p.Name); err != nil || !pending {
		t.Fatal("failed history archival lost the current recovery journal", err)
	}
}
