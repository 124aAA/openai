package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"qingnode/internal/monitor"
	"qingnode/internal/node"
	"strings"
	"testing"
	"time"
)

func TestMonitorExplicitExpiryAndClockRollback(t *testing.T) {
	a, s, backend, _, _ := subscriptionCLIFixture(t)
	now := time.Now().UTC()
	s.CredentialExpirations = []node.CredentialExpiration{{ID: "eeeeeeeeeeee0001", NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[0].ID, DeviceID: s.Devices[0].ID, ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)}}
	if e := a.store.WithLock(func() error { return a.store.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	backend.starts, backend.stops = 0, 0
	cfg := monitor.DefaultConfig()
	if e := a.monitorStore().SaveConfig(cfg); e != nil {
		t.Fatal(e)
	}
	future := now.Add(time.Hour)
	engine := monitor.Engine{Store: a.monitorStore()}
	snap, e := engine.RunOnce(context.Background(), cfg, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	snap.FinishedAt = future
	snap.StartedAt = now
	b, _ := json.Marshal(snap)
	if e = os.WriteFile(filepath.Join(a.monitorStore().Root, "status.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	generation, before := savedBatchState(t, a)
	if e = a.monitorExpireDue(now); e == nil || !strings.Contains(e.Error(), "时钟") {
		t.Fatal("clock rollback not refused", e)
	}
	afterGeneration, after := savedBatchState(t, a)
	if generation != afterGeneration || string(before) != string(after) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("clock rollback changed credentials/service")
	}
	if e = a.monitorExpireDue(future.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	current, e := a.store.Load()
	if e != nil || len(current.Nodes[0].Users) != 1 || current.Nodes[0].Users[0].ID != s.Nodes[0].Users[1].ID {
		t.Fatal("precise expiration failed", e)
	}
}

func TestMonitorMigrationInventoryCannotSilentlyOmitPrivatePolicy(t *testing.T) {
	a, s, _, _, _ := subscriptionCLIFixture(t)
	cfg := monitor.DefaultConfig()
	if e := a.monitorStore().SaveConfig(cfg); e != nil {
		t.Fatal(e)
	}
	roots, external, e := a.migrationInventory(s)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, r := range roots {
		if r.ID == "monitor" && r.Kind == "monitor-state" {
			found = true
		}
	}
	if !found || len(external) != 0 {
		t.Fatalf("monitor root not packaged as complete QNBK3 root: roots=%+v external=%+v", roots, external)
	}
}
