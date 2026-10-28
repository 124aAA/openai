package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/platform"
)

func TestSystemBackendActivityPreservesUnknownAndTransitionStates(t *testing.T) {
	for _, tc := range []struct {
		name, active, sub, pid string
		queryFailure           bool
		want                   bool
		pass                   bool
	}{
		{"running", "active", "running", "123", false, true, true},
		{"stopped", "inactive", "dead", "0", false, false, true},
		{"failed", "failed", "failed", "0", false, false, true},
		{"transport", "inactive", "dead", "0", true, false, false},
		{"transition", "activating", "auto-restart", "0", false, false, false},
		{"unknown", "unknown", "unknown", "0", false, false, false},
		{"running without PID", "active", "running", "0", false, false, false},
		{"stopped invalid PID", "inactive", "dead", "malformed", false, false, false},
		{"stopped missing PID", "inactive", "dead", "", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := SystemBackend{ManagerKind: platform.InitSystemd, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
				if name != "systemctl" || args[0] != "show" {
					t.Fatal("activity query attempted mutation", name, args)
				}
				if tc.queryFailure {
					return nil, errors.New("controller unavailable")
				}
				return []byte("LoadState=loaded\nActiveState=" + tc.active + "\nSubState=" + tc.sub + "\nMainPID=" + tc.pid + "\nUnitFileState=enabled\n"), nil
			}}
			active, e := backend.ActiveState()
			if (e == nil) != tc.pass || active != tc.want {
				t.Fatal(active, e)
			}
		})
	}
}

type uncertainActivityBackend struct {
	*fakeBackend
	queries int
}

func (b *uncertainActivityBackend) ActiveState() (bool, error) {
	b.queries++
	return false, errors.New("controller disconnected")
}

func TestApplyRefusesUnknownActivityBeforeJournalOrPublicationRevocation(t *testing.T) {
	store, backend := newStore(t)
	if e := store.WithLock(func() error { return store.Apply(fixture(t)) }); e != nil {
		t.Fatal(e)
	}
	loaded, e := store.Load()
	if e != nil {
		t.Fatal(e)
	}
	reliable := &uncertainActivityBackend{fakeBackend: backend}
	store.Backend = reliable
	loaded.Nodes[0].Name = "metadata remains independent of controller"
	if e = store.WithLock(func() error { return store.Apply(loaded) }); e != nil || reliable.queries != 0 {
		t.Fatal("metadata edit unnecessarily required service control", e)
	}
	beforeGeneration, e := store.current()
	if e != nil {
		t.Fatal(e)
	}
	statePath := filepath.Join(store.Root, "current", "state.json")
	beforeState, e := os.ReadFile(statePath)
	if e != nil {
		t.Fatal(e)
	}
	beforeDirectories, e := os.ReadDir(filepath.Join(store.Root, "generations"))
	if e != nil {
		t.Fatal(e)
	}
	beforeActivations := backend.activations
	revocations := 0
	store.BeforeCommit = func(State) error { revocations++; return nil }
	loaded.Nodes[0].Port++
	e = store.WithLock(func() error { return store.Apply(loaded) })
	if e == nil || !strings.Contains(e.Error(), "controller disconnected") {
		t.Fatal("unknown controller accepted", e)
	}
	if reliable.queries != 1 || revocations != 0 || backend.activations != beforeActivations || !backend.active {
		t.Fatal("failed observation performed a write effect", reliable.queries, revocations, backend.activations)
	}
	current, _ := store.current()
	actual, _ := os.ReadFile(statePath)
	directories, _ := os.ReadDir(filepath.Join(store.Root, "generations"))
	if current != beforeGeneration || !bytes.Equal(actual, beforeState) || len(directories) != len(beforeDirectories) {
		t.Fatal("unknown activity changed State, generation or retained a candidate")
	}
	if _, e = os.Lstat(filepath.Join(store.Root, "transaction.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unknown activity wrote a transaction", e)
	}
}

func TestRemovalServiceSnapshotRejectsUnknownWithoutStoppedFallback(t *testing.T) {
	for _, tc := range []struct {
		name, active, enabled, load string
		fail, pass                  bool
	}{
		{"running", "active", "enabled", "loaded", false, true},
		{"stopped", "inactive", "disabled", "loaded", false, true},
		{"transport", "inactive", "disabled", "loaded", true, false},
		{"transition", "activating", "enabled", "loaded", false, false},
		{"unloaded", "inactive", "disabled", "not-found", false, false},
		{"missing active", "", "disabled", "loaded", false, false},
		{"masked", "inactive", "masked", "loaded", false, false},
		{"runtime enabled cannot be flattened", "active", "enabled-runtime", "loaded", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unit := "/etc/systemd/system/qingnode.service"
			r := Removal{Unit: unit, ManagerKind: platform.InitSystemd, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
				if name != "systemctl" || args[0] != "show" {
					t.Fatal("snapshot attempted mutation", name, args)
				}
				if tc.fail {
					return nil, errors.New("controller disconnected")
				}
				return []byte("LoadState=" + tc.load + "\nActiveState=" + tc.active + "\nUnitFileState=" + tc.enabled + "\nFragmentPath=" + unit + "\n"), nil
			}}
			active, enabled, e := r.serviceSnapshot()
			if (e == nil) != tc.pass {
				t.Fatal(active, enabled, e)
			}
			if tc.pass && (active != (tc.active == "active") || enabled != (tc.enabled == "enabled")) {
				t.Fatal("valid snapshot lost selected service state", active, enabled)
			}
		})
	}
}
