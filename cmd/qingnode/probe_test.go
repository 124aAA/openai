package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"qingnode/internal/node"
	"qingnode/internal/probe"
)

func TestProbeProfilePreservesStateServiceAndManualHistory(t *testing.T) {
	a, s := batchFixture(t)
	b := &batchBackend{active: true}
	a.store.Backend = b
	g, before := savedBatchState(t, a)
	manual := filepath.Join(a.store.Root, "observations.json")
	old := []byte("manual-history-sentinel")
	if err := os.WriteFile(manual, old, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := a.probeProfile(s.Nodes[0].ID, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if _, err = wizardOutput(t, func() error { return a.command([]string{"probe", "profile", "--id", p.NodeID, "--out", path}) }); err != nil {
		t.Fatal(err)
	}
	loaded, err := probe.ReadProfile(path)
	if err != nil || loaded.NodeID != p.NodeID {
		t.Fatal(err)
	}
	afterG, after := savedBatchState(t, a)
	history, _ := os.ReadFile(manual)
	if b.activeCalls+b.checks+b.starts+b.stops != 0 || g != afterG || !bytes.Equal(before, after) || !bytes.Equal(history, old) {
		t.Fatal("probe inspected/modified runtime or manual history")
	}
	for _, journal := range []string{"transaction.json", "uninstall.json"} {
		jp := filepath.Join(a.store.Root, journal)
		_ = os.WriteFile(jp, []byte("pending-sentinel"), 0600)
		if _, err = a.probeProfile(p.NodeID, ""); err == nil {
			t.Fatal("profile silently used pending transaction")
		}
		data, _ := os.ReadFile(jp)
		if string(data) != "pending-sentinel" {
			t.Fatal("probe recovered journal")
		}
		_ = os.Remove(jp)
	}
}
func TestProbeRejectsManagedOutputAndDoesNotInitializeMissingState(t *testing.T) {
	a, _ := batchFixture(t)
	if err := a.probeOutput(filepath.Join(a.store.Root, "transaction.json")); err == nil {
		t.Fatal("result accepted as production journal")
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(a.store.Root, link); err != nil {
		t.Fatal(err)
	}
	if err := a.probeOutput(filepath.Join(link, "result.json")); err == nil {
		t.Fatal("linked production output accepted")
	}
	root := filepath.Join(t.TempDir(), "absent")
	a = &app{store: &node.Store{Root: root, GID: -1, Backend: node.OfflineBackend{}}, offline: true}
	if _, err := a.probeProfile("id", ""); err == nil {
		t.Fatal("missing profile accepted")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("profile created missing State")
	}
	if _, err := wizardOutput(t, func() error { return a.command([]string{"probe", "local"}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("local created missing State")
	}
}

func TestExternalOutputProtectsAllManagedRootsFilesAndAliases(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	future := filepath.Join(base, "future-host-state")
	third := filepath.Join(base, "other-state")
	sysctl := filepath.Join(base, "sysctl")
	outside := filepath.Join(base, "outside")
	for _, path := range []string{state, third, sysctl, outside, filepath.Join(base, "state-lookalike")} {
		if e := os.MkdirAll(path, 0700); e != nil {
			t.Fatal(e)
		}
	}
	stateAlias := filepath.Join(base, "state-alias")
	thirdAlias := filepath.Join(base, "third-alias")
	sysctlAlias := filepath.Join(base, "sysctl-alias")
	for _, pair := range [][2]string{{state, stateAlias}, {third, thirdAlias}, {sysctl, sysctlAlias}} {
		if e := os.Symlink(pair[0], pair[1]); e != nil {
			t.Fatal(e)
		}
	}
	files := []string{filepath.Join(sysctl, "90-network.conf"), filepath.Join(sysctl, "90-bbr.conf"), filepath.Join(sysctl, "90-other.conf")}
	sentinel := []byte("# original managed persistence\n")
	if e := os.WriteFile(files[0], sentinel, 0600); e != nil {
		t.Fatal(e)
	}
	roots := []string{state, future, thirdAlias}
	for _, output := range []string{state, filepath.Join(state, "new.json"), filepath.Join(stateAlias, "new.json"), future, filepath.Join(third, "new.json"), files[0], files[1], files[2], filepath.Join(sysctlAlias, "90-bbr.conf")} {
		if e := validateExternalOutput(output, roots, files); e == nil {
			t.Fatalf("managed result path accepted: %s", output)
		}
	}
	for _, output := range []string{filepath.Join(outside, "new.json"), filepath.Join(base, "state-lookalike", "new.json"), filepath.Join(sysctl, "unrelated-report.json")} {
		if e := validateExternalOutput(output, roots, files); e != nil {
			t.Fatal("external new result rejected", output, e)
		}
		if _, e := os.Stat(output); !os.IsNotExist(e) {
			t.Fatal("validation created output", output, e)
		}
	}
	if _, e := os.Stat(future); !os.IsNotExist(e) {
		t.Fatal("validation initialized a missing managed boundary", e)
	}
	after, e := os.ReadFile(files[0])
	if e != nil || !bytes.Equal(after, sentinel) {
		t.Fatal("validation modified managed persistence", e)
	}
}

func TestExternalOutputResolvesMissingBoundariesWithoutInitializingParents(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if e := os.Mkdir(real, 0700); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(base, "parent-alias")
	if e := os.Symlink(real, alias); e != nil {
		t.Fatal(e)
	}
	futureRoot := filepath.Join(alias, "future")
	futureFile := filepath.Join(alias, "future.conf")
	for _, out := range []string{filepath.Join(real, "future"), filepath.Join(real, "future.conf")} {
		if e := validateExternalOutput(out, []string{futureRoot}, []string{futureFile}); e == nil {
			t.Fatal("future managed boundary escaped through parent alias", out)
		}
	}
	missingParent := filepath.Join(base, "missing-parent")
	if e := validateExternalOutput(filepath.Join(missingParent, "report.json"), []string{futureRoot}, []string{futureFile}); e == nil {
		t.Fatal("output accepted without existing parent")
	}
	if _, e := os.Stat(missingParent); !os.IsNotExist(e) {
		t.Fatal("validation created missing output parent", e)
	}
	if _, e := os.Stat(filepath.Join(real, "future")); !os.IsNotExist(e) {
		t.Fatal("future managed directory was initialized", e)
	}
}

func TestExternalOutputRejectsDanglingManagedBoundaries(t *testing.T) {
	base := t.TempDir()
	for _, kind := range []string{"root", "file", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			target := filepath.Join(base, kind+"-missing-target")
			alias := filepath.Join(base, kind+"-alias")
			if e := os.Symlink(target, alias); e != nil {
				t.Fatal(e)
			}
			var roots, files []string
			switch kind {
			case "root":
				roots = []string{alias}
			case "file":
				files = []string{alias}
			case "ancestor":
				roots = []string{filepath.Join(alias, "future-state")}
			}
			if e := validateExternalOutput(target, roots, files); e == nil {
				t.Error("output could occupy the missing target of a managed dangling symlink")
			}
			if _, e := os.Lstat(target); !os.IsNotExist(e) {
				t.Fatal("boundary validation created the missing managed target", e)
			}
			if info, e := os.Lstat(alias); e != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("boundary validation changed the original dangling alias", e)
			}
		})
	}
}
