package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type impactBackend struct {
	fakeBackend
	checks, stops, activeReads, prepares, finishes int
	identity                                       string
	changeOnCheck, failAllActivations              bool
}

func (b *impactBackend) Check(st State, path string) error {
	b.checks++
	if b.changeOnCheck {
		b.identity = "replaced-during-check"
		b.changeOnCheck = false
	}
	return b.fakeBackend.Check(st, path)
}
func (b *impactBackend) Active() bool { b.activeReads++; return b.fakeBackend.Active() }
func (b *impactBackend) Activate(st State) error {
	if b.failAllActivations {
		b.activations++
		return errors.New("injected unrecoverable activation")
	}
	return b.fakeBackend.Activate(st)
}
func (b *impactBackend) Stop() error                           { b.stops++; return b.fakeBackend.Stop() }
func (b *impactBackend) PrepareEffects(State, State) error     { b.prepares++; return nil }
func (b *impactBackend) FinishEffects(State, State) error      { b.finishes++; return nil }
func (b *impactBackend) RuntimeIdentity(State) ([]byte, error) { return []byte(b.identity), nil }

func impactStore(t *testing.T) (*Store, *impactBackend, State) {
	t.Helper()
	b := &impactBackend{identity: "fixed-core-and-unit"}
	store := &Store{Root: t.TempDir(), Backend: b, GID: -1}
	st := fixture(t)
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	st, _ = store.Load()
	return store, b, st
}

func TestMetadataAndClientChangesCheckAndSaveWithoutServiceOrEffects(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "stopped"}[stopped], func(t *testing.T) {
			store, b, st := impactStore(t)
			if stopped {
				if err := b.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := store.current()
			activations, stops, reads, prepares, finishes, checks := b.activations, b.stops, b.activeReads, b.prepares, b.finishes, b.checks
			identity := st.Nodes[0].Reality.PrivateKey
			st.Nodes[0].Name = "renamed"
			st.Nodes[0].Host = "export.example.com"
			st.Nodes[0].Reality.Fingerprint = "firefox"
			st.Nodes[0].Users[0].Name = "renamed-user"
			if err := store.Inspect(func() error {
				impact, err := store.Preview(st)
				if err != nil {
					return err
				}
				if !impact.Changed || !impact.Display || !impact.ClientExport || impact.ServerRuntime || impact.HostEffects || impact.NeedsRestart || len(impact.Nodes) != 1 {
					t.Fatalf("wrong impact: %+v", impact)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
				t.Fatal(err)
			}
			after, _ := store.current()
			parent, _ := os.ReadFile(filepath.Join(store.Root, after, "parent"))
			got, _ := store.Load()
			if before == after || string(parent) != before || got.Nodes[0].Name != "renamed" || got.Nodes[0].Reality.PrivateKey != identity {
				t.Fatal("metadata/history/identity not saved")
			}
			if b.checks != checks+1 || b.activations != activations || b.stops != stops || b.activeReads != reads || b.prepares != prepares || b.finishes != finishes || b.active == stopped {
				t.Fatal("metadata touched service/effects or skipped check")
			}
			if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
				t.Fatal(err)
			}
			repeated, _ := store.current()
			if repeated != after || b.checks != checks+1 {
				t.Fatal("repeat was not a no-op")
			}
		})
	}
}

func TestActualRuntimeAndFirewallInputsClassifyIndependently(t *testing.T) {
	store, b, st := impactStore(t)
	for _, tc := range []struct {
		name          string
		edit          func(*State)
		runtime, host bool
	}{
		{"listen", func(st *State) { st.Nodes[0].Listen = "127.0.0.1" }, true, false},
		{"port", func(st *State) { st.Nodes[0].Port++ }, true, false},
		{"credential", func(st *State) { st.Nodes[0].Users[0] = NewUser("new", "reality") }, true, false},
		{"core", func(st *State) { st.CoreVersion = "1.14.3" }, true, false},
		{"firewall", func(st *State) { st.Firewall = "ufw" }, false, true},
		{"archive-provenance", func(st *State) { st.CoreArchiveSHA256 = strings.Repeat("a", 64) }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := st.Clone()
			tc.edit(&next)
			impact, err := store.Preview(next)
			if err != nil {
				t.Fatal(err)
			}
			if impact.ServerRuntime != tc.runtime || impact.NeedsRestart != tc.runtime || impact.HostEffects != tc.host {
				t.Fatalf("wrong impact %+v", impact)
			}
		})
	}
	if err := b.Stop(); err != nil {
		t.Fatal(err)
	}
	st.Firewall = "ufw"
	activations, stops, prepares, finishes := b.activations, b.stops, b.prepares, b.finishes
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if b.active || b.activations != activations || b.stops != stops || b.prepares != prepares+1 || b.finishes != finishes+1 {
		t.Fatal("firewall-only edit changed service lifecycle or skipped effects")
	}
}

func TestDamagedDerivedFilesRequireCandidateCheckAndPreserveOriginal(t *testing.T) {
	for _, name := range []string{"server.json", "core-version"} {
		t.Run(name, func(t *testing.T) {
			store, b, st := impactStore(t)
			old, _ := store.current()
			path := filepath.Join(store.Root, old, name)
			if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
				t.Fatal(err)
			}
			st.Nodes[0].Name = "with-repair"
			impact, err := store.Preview(st)
			if err != nil || !impact.RepairDerived || impact.NeedsRestart {
				t.Fatalf("wrong repair impact: %+v %v", impact, err)
			}
			count := b.activations
			b.failCheck = true
			if store.WithLock(func() error { return store.Apply(st) }) == nil {
				t.Fatal("damaged metadata skipped candidate check")
			}
			cur, _ := store.current()
			if cur != old || b.activations != count {
				t.Fatal("rejected repair changed service/state")
			}
			b.failCheck = false
			if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
				t.Fatal(err)
			}
			cur, _ = store.current()
			original, _ := os.ReadFile(path)
			if cur == old || string(original) != "damaged" || b.activations != count {
				t.Fatal("repair changed active process or discarded raw recovery material")
			}
			impact, err = store.Preview(st)
			if err != nil || impact.Changed || impact.RepairDerived {
				t.Fatalf("repair not complete: %+v %v", impact, err)
			}
		})
	}
}

func TestMetadataRecoveryAndRollbackNeverRestartOrStop(t *testing.T) {
	store, b, st := impactStore(t)
	previous, _ := store.current()
	st.Nodes[0].Name = "uncommitted-name"
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	next, _ := store.current()
	j := journalV2{Version: 2, Previous: previous, Next: next}
	data, _ := json.Marshal(transactionEnvelope{Transaction: j})
	var legacy journal
	if err := json.Unmarshal(data, &legacy); err != nil || generationRE.MatchString(legacy.Next) {
		t.Fatal("old manager could misinterpret v2 journal", err)
	}
	if err := AtomicWrite(filepath.Join(store.Root, "transaction.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	activations, stops := b.activations, b.stops
	if err := store.InspectExisting(func() error { _, err := store.Load(); return err }); err != nil {
		t.Fatal(err)
	}
	still, _ := store.current()
	if still != next {
		t.Fatal("read-only inspection recovered")
	}
	if err := store.WithLock(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	cur, _ := store.current()
	if cur != previous || b.activations != activations || b.stops != stops {
		t.Fatal("metadata crash recovery touched service")
	}
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if err := store.WithLock(store.Rollback); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Load()
	if got.Nodes[0].Name == "uncommitted-name" || b.activations != activations || b.stops != stops {
		t.Fatal("metadata rollback touched service")
	}
}

func TestUnknownAndInconsistentJournalsRemainUntouched(t *testing.T) {
	store, b, st := impactStore(t)
	previous, _ := store.current()
	st.Nodes[0].Port++
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	next, _ := store.current()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"unknown-version", []byte(`{"transaction_v2":{"version":3,"previous":"` + previous + `","next":"` + next + `"}}`)},
		{"unknown-field", []byte(`{"transaction_v2":{"version":2,"previous":"` + previous + `","next":"` + next + `","unrecognized":true}}`)},
		{"false-runtime-classification", []byte(`{"transaction_v2":{"version":2,"previous":"` + previous + `","next":"` + next + `","runtime_changed":false}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(store.Root, "transaction.json")
			if err := AtomicWrite(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			activations := b.activations
			if store.WithLock(func() error { return nil }) == nil {
				t.Fatal("invalid recovery accepted")
			}
			cur, _ := store.current()
			data, _ := os.ReadFile(path)
			if cur != next || !bytes.Equal(data, tc.data) || b.activations != activations {
				t.Fatal("invalid journal changed state/evidence")
			}
		})
	}
}

func TestRuntimeReceiptReplacementAndValidationRace(t *testing.T) {
	store, b, st := impactStore(t)
	st.Nodes[0].Name = "metadata"
	before, _ := store.current()
	b.changeOnCheck = true
	activations := b.activations
	if err := store.WithLock(func() error { return store.Apply(st) }); err == nil || !strings.Contains(err.Error(), "验证期间") {
		t.Fatal("runtime replacement during validation accepted", err)
	}
	cur, _ := store.current()
	if cur != before || b.activations != activations {
		t.Fatal("validation race changed state/service")
	}
	impact, err := store.Preview(st)
	if err != nil || !impact.NeedsRestart || !impact.ServerRuntime || !impact.HostEffects {
		t.Fatalf("same-version core/unit replacement not detected: %+v %v", impact, err)
	}
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if b.activations != activations+1 {
		t.Fatal("runtime replacement did not activate exactly once")
	}
}

func TestRuntimeRecoveryFailureRetainsJournalAndBothGenerations(t *testing.T) {
	store, b, st := impactStore(t)
	previous, _ := store.current()
	st.Nodes[0].Port++
	b.failAllActivations = true
	if err := store.WithLock(func() error { return store.Apply(st) }); err == nil || !strings.Contains(err.Error(), "恢复未完成") {
		t.Fatal("recovery failure was hidden", err)
	}
	data, err := os.ReadFile(filepath.Join(store.Root, "transaction.json"))
	if err != nil {
		t.Fatal("recovery journal discarded", err)
	}
	j, err := decodeJournal(data)
	if err != nil || j.Previous != previous {
		t.Fatal(err)
	}
	for _, g := range []string{j.Previous, j.Next} {
		if _, err := ReadState(filepath.Join(store.Root, g, "state.json")); err != nil {
			t.Fatal("original/candidate evidence discarded", err)
		}
	}
	b.failAllActivations = false
	if err := store.WithLock(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	cur, _ := store.current()
	if cur != previous || !b.active {
		t.Fatal("explicit retry did not restore")
	}
}

func TestLegacyRuntimeReceiptIsEstablishedWithoutRestart(t *testing.T) {
	store, b, st := impactStore(t)
	previous, _ := store.current()
	if err := os.Remove(filepath.Join(store.Root, previous, "runtime-identity")); err != nil {
		t.Fatal(err)
	}
	impact, err := store.Preview(st)
	if err != nil || !impact.RepairDerived || impact.NeedsRestart {
		t.Fatalf("legacy receipt forced restart: %+v %v", impact, err)
	}
	activations, checks := b.activations, b.checks
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	cur, _ := store.current()
	identity, err := os.ReadFile(filepath.Join(store.Root, cur, "runtime-identity"))
	if err != nil || string(identity) != b.identity || cur == previous || b.activations != activations || b.checks != checks+1 {
		t.Fatal("legacy receipt not validated and registered", err)
	}
}

func TestRuntimeRecoveryRefusesChangedExternalInputs(t *testing.T) {
	store, b, st := impactStore(t)
	previous, _ := store.current()
	b.identity = "different-core-at-same-version"
	st.Nodes[0].Name = "requires-core-restart"
	b.failNext = true
	if err := store.WithLock(func() error { return store.Apply(st) }); err == nil || !strings.Contains(err.Error(), "恢复未完成") {
		t.Fatal("external replacement falsely claimed recovery", err)
	}
	cur, _ := store.current()
	if cur == previous {
		t.Fatal("changed core was presented as restored generation")
	}
	if _, err := os.Stat(filepath.Join(store.Root, "transaction.json")); err != nil {
		t.Fatal("recovery evidence lost", err)
	}
	b.identity = "fixed-core-and-unit"
	if err := store.WithLock(func() error { return nil }); err != nil {
		t.Fatal("restoring original external input did not allow recovery", err)
	}
	cur, _ = store.current()
	if cur != previous || !b.active {
		t.Fatal("restored identity did not recover original generation")
	}
}

func TestDisabledNodeClientDefinitionStillHasImpact(t *testing.T) {
	store, b, st := impactStore(t)
	st.Nodes[0].Enabled = false
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	st, _ = store.Load()
	activations, stops, checks := b.activations, b.stops, b.checks
	for _, edit := range []func(*Node){
		func(n *Node) { n.Name = "disabled-renamed" },
		func(n *Node) { n.Host = "disabled-export.example.com" },
		func(n *Node) { n.Reality.Fingerprint = "firefox" },
	} {
		next := st.Clone()
		edit(&next.Nodes[0])
		impact, err := store.Preview(next)
		if err != nil || !impact.Changed || !impact.ClientExport || impact.ServerRuntime || impact.HostEffects || impact.NeedsRestart || len(impact.Nodes) != 1 || !impact.Nodes[0].ClientExport {
			t.Fatalf("disabled sharing change misclassified: %+v %v", impact, err)
		}
	}
	st.Nodes[0].Name = "disabled-renamed"
	st.Nodes[0].Host = "disabled-export.example.com"
	st.Nodes[0].Reality.Fingerprint = "firefox"
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if b.active || b.activations != activations || b.stops != stops || b.checks != checks+1 {
		t.Fatal("disabled client edit changed lifecycle or skipped check")
	}
}
