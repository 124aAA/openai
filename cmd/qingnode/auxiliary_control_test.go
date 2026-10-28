package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/platform"
)

func TestAuxiliaryControlKeepsServiceLeaseAndReleasesStateForOneshot(t *testing.T) {
	a, _ := batchFixture(t)
	dir := t.TempDir()
	definition := []byte(monitorSystemdService)
	started := 0
	var actions []string
	manager := auxiliaryCLIManager(t, dir, &actions, func() {
		started++
		// Simulate the actual oneshot's State read while systemctl waits for it.
		if err := a.store.InspectExisting(func() error { _, err := a.store.Load(); return err }); err != nil {
			t.Fatal("oneshot could not read State during its start", err)
		}
		if release, err := node.AuxiliaryControlLease(a.store.Root, "qingnode-monitor"); err == nil {
			release()
			t.Fatal("service-control serialization was released too early")
		}
	})
	plan, err := node.NewAuxiliaryServicePlan(manager, "qingnode-monitor", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range plan.Definitions {
		if err := os.WriteFile(filepath.Join(dir, file.Name), file.Contents, file.Mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.controlAuxiliaryService(manager, "start", "qingnode-monitor", definition); err != nil {
		t.Fatal(err)
	}
	if started != 1 {
		t.Fatal("native action count", started)
	}
	// Both locks must be usable after success, not retained by a child.
	if err := a.store.InspectExisting(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	release, err := node.AuxiliaryControlLease(a.store.Root, "qingnode-monitor")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestAuxiliaryControlStillRejectsExternalDefinitionWithoutAction(t *testing.T) {
	a, _ := batchFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "qingnode-monitor.service")
	expected := []byte(monitorSystemdService)
	modified := strings.Replace(monitorSystemdService, "monitor run", "external command", 1)
	if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
		t.Fatal(err)
	}
	manager := platform.Manager{Kind: platform.InitSystemd, DefinitionRoot: dir, Execute: func(_ time.Duration, _ string, _ ...string) ([]byte, error) {
		t.Fatal("externally edited definition reached native controller")
		return nil, errors.New("unreachable")
	}}
	if err := a.controlAuxiliaryService(manager, "start", "qingnode-monitor", expected); err == nil {
		t.Fatal("external definition taken over")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != modified {
		t.Fatal("external definition overwritten", err)
	}
	release, err := node.AuxiliaryControlLease(a.store.Root, "qingnode-monitor")
	if err != nil {
		t.Fatal("preflight failure retained control lease", err)
	}
	release()
}
