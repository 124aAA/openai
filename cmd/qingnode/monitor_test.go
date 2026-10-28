package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qingnode/internal/monitor"
	"qingnode/internal/node"
)

func monitorCLIConfig(st node.State) monitor.Config {
	config := monitor.DefaultConfig()
	config.Enabled = true
	config.Jobs = []monitor.Job{{ID: "cccccccccccccccc", NodeID: st.Nodes[0].ID, Enabled: true, Signals: []monitor.SignalKind{monitor.Process}}}
	return config
}

func monitorCLIFile(t *testing.T, config monitor.Config) string {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "monitor.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMonitorCLIConfigurationIsSeparateAndReadOnlyUntilConfirmed(t *testing.T) {
	a, st := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	config := monitorCLIConfig(st)
	input := monitorCLIFile(t, config)
	generation, before := savedBatchState(t, a)
	for _, command := range [][]string{{"status"}, {"history"}, {"configure", "--file", input, "--preview"}} {
		_, err := wizardOutput(t, func() error { return a.monitor(command) })
		if command[0] == "configure" && err != nil {
			t.Fatal(err)
		}
		if _, err = os.Lstat(a.monitorStore().Root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("read-only command initialized monitor directory", command, err)
		}
	}
	if err := a.monitor([]string{"configure", "--file", input}); err == nil {
		t.Fatal("configuration silently confirmed")
	}
	if err := a.monitor([]string{"configure", "--file", input, "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := a.monitorStore().LoadConfig()
	if err != nil || !loaded.Enabled || len(loaded.Jobs) != 1 {
		t.Fatal("configuration missing", err)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("saving observer policy changed State or service")
	}
	configPath := filepath.Join(a.monitorStore().Root, "config.json")
	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.monitor([]string{"disable", "--preview"}); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, saved) {
		t.Fatal("disable preview saved policy", err)
	}
	if err = a.monitor([]string{"disable", "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = a.monitorStore().LoadConfig()
	if err != nil || loaded.Enabled || loaded.Recovery.Mode != "observe" || loaded.Notifications.Enabled {
		t.Fatal("disable failed to revoke policy", err)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("disable changed State or service")
	}
}

func TestMonitorCLIRejectsUnstableReferencesAndCredentialPreview(t *testing.T) {
	a, st := batchFixture(t)
	for _, kind := range []string{"node-name", "missing-node", "user-name", "wrong-user", "missing-auth-user", "missing-endpoint"} {
		t.Run(kind, func(t *testing.T) {
			config := monitorCLIConfig(st)
			job := &config.Jobs[0]
			switch kind {
			case "node-name":
				job.NodeID = st.Nodes[0].Name
			case "missing-node":
				job.NodeID = "ffffffffffffffff"
			case "user-name":
				job.UserID = st.Nodes[0].Users[0].Name
			case "wrong-user":
				job.UserID = st.Nodes[1].Users[0].ID
			case "missing-auth-user":
				job.TargetURL = "https://example.test/check"
				job.Signals = []monitor.SignalKind{monitor.Authentication}
			case "missing-endpoint":
				job.EndpointID = "dddddddddddddddd"
			}
			if err := validateMonitorJobs(st, config); err == nil {
				t.Fatal("accepted ambiguous or missing exact binding")
			}
			if err := a.monitor([]string{"configure", "--file", monitorCLIFile(t, config), "--yes"}); err == nil {
				t.Fatal("saved invalid monitor references")
			}
		})
	}
	config := monitorCLIConfig(st)
	config.Jobs[0].TargetURL = "https://example.test/private-path-marker"
	config.Notifications.Endpoint = "https://notification.test/private-webhook-marker"
	config.Notifications.Token = "private-token-marker"
	config.Notifications.ChatID = "private-chat-marker"
	raw, err := json.Marshal(monitorConfigPreview(config))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-path-marker", "private-webhook-marker", "private-token-marker", "private-chat-marker"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("preview exposed private target/notification data")
		}
	}
}

func TestMonitorTimerOnlyExportsReviewedFiles(t *testing.T) {
	a, st := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	generation, before := savedBatchState(t, a)
	directory := t.TempDir()
	if err := a.monitor([]string{"timer", "--out", directory}); err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(directory, "qingnode-monitor.service"))
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(filepath.Join(directory, "qingnode-monitor.timer"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(service, []byte("qingnode monitor run")) || bytes.Contains(service, []byte("--apply-expiry")) || !bytes.Contains(timer, []byte("OnUnitInactiveSec=60s")) {
		t.Fatal("unexpected installed/expiry behavior in timer")
	}
	if err = a.monitor([]string{"timer", "--out", directory}); err == nil {
		t.Fatal("timer overwrote existing files")
	}
	if err = a.monitor([]string{"timer", "--out", a.store.Root}); err == nil {
		t.Fatal("timer wrote into managed root")
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) || backend.starts != 0 || backend.stops != 0 || len(st.Nodes) != 2 {
		t.Fatal("timer changed State/service")
	}
}

func TestMonitorSharedMeasurementLeaseRejectsOverlapAndCleansUp(t *testing.T) {
	a, st := batchFixture(t)
	config := monitorCLIConfig(st)
	config.Enabled = false
	var release func()
	if err := a.store.InspectExisting(func() error { var err error; release, err = node.MeasurementLease(a.store.Root); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := a.monitorRound(context.Background(), config); err == nil || !strings.Contains(err.Error(), "不排队") {
		release()
		t.Fatal("periodic overlapped active measurement", err)
	}
	release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.monitorRound(ctx, config); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled round unexpectedly ran", err)
	}
	// Error paths must release the common lease before another active probe.
	release, err := a.measurementLeaseIfManaged()
	if err != nil {
		t.Fatal("round leaked common lease", err)
	}
	release()
	config.Enabled = false
	if _, err = a.monitorRound(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	release, err = a.measurementLeaseIfManaged()
	if err != nil {
		t.Fatal("successful round leaked lease", err)
	}
	release()
	for _, command := range [][]string{{"run", "--cycles", "0"}, {"run", "--cycles", "101"}} {
		if err = a.monitor(command); err == nil {
			t.Fatal("accepted unbounded/offline run")
		}
	}
}
