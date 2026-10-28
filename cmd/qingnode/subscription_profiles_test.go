package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"qingnode/internal/node"
	"qingnode/internal/subscription"
)

func TestSubscriptionPerDeviceFormatsAndConfigurationPreflight(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	st.Devices[0].SubscriptionFormats = []string{"sing-box"}
	st.Devices[1].SubscriptionFormats = []string{"mihomo"}
	st.Devices[1].Strategy = "fallback"
	st.Devices[1].TestURL = "https://controlled.example/health"
	if err := a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	h, e := subscription.NewHandler(func() (subscription.Snapshot, error) { return subscription.Read(dir) }, subscription.HandlerOptions{})
	if e != nil {
		t.Fatal(e)
	}
	for i, format := range []string{"sing-box", "mihomo"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+materials[i].Token+"/"+format, nil))
		if w.Code != 200 {
			t.Fatal("explicit device format unavailable", w.Code)
		}
		other := []string{"mihomo", "sing-box"}[i]
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+materials[i].Token+"/"+other, nil))
		if w.Code != 404 {
			t.Fatal("device unexpectedly authorized another format", w.Code)
		}
	}
	configPath := filepath.Join(a.store.Root, publisherConfigName)
	configBefore, _ := os.ReadFile(configPath)
	snapshotBefore, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	generation, stateBefore := savedBatchState(t, a)
	if err := a.subscription([]string{"configure", "--formats", "mihomo,provider"}); err == nil {
		t.Fatal("configuration removing a required device format accepted")
	}
	configAfter, _ := os.ReadFile(configPath)
	snapshotAfter, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	if !bytes.Equal(configBefore, configAfter) || !bytes.Equal(snapshotBefore, snapshotAfter) {
		t.Fatal("invalid configure partly applied")
	}
	if err := a.subscription([]string{"configure", "--sing-box-version", "1.14.3"}); err != nil {
		t.Fatal(err)
	}
	config, ok, err := a.publisherConfig()
	if err != nil || !ok || config.SingBoxVersion != "1.14.3" || len(config.Formats) != 5 {
		t.Fatal("configure did not retain omitted choices", err)
	}
	backups, err := filepath.Glob(filepath.Join(a.store.Root, "subscription-publisher-before-*.json"))
	if err != nil || len(backups) != 1 {
		t.Fatal("publisher original recovery material missing", err)
	}
	original, _ := os.ReadFile(backups[0])
	if !bytes.Equal(bytes.TrimSpace(original), bytes.TrimSpace(configBefore)) {
		t.Fatal("publisher recovery material changed")
	}
	nextGeneration, nextState := savedBatchState(t, a)
	if generation != nextGeneration || !bytes.Equal(stateBefore, nextState) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("publication configure changed proxy State or service")
	}
}

func TestSubscriptionRevokeWithoutRegistryDoesNotClaimSuccess(t *testing.T) {
	a, st, _ := deviceCLIFixture(t)
	if err := a.subscription([]string{"revoke", "--device", st.Devices[0].ID, "--yes"}); err == nil {
		t.Fatal("uninitialized revoke claimed success")
	}
}

func TestDeviceCreateManualDefaultsAndExplicitSubscriptionFormats(t *testing.T) {
	a, st := batchFixture(t)
	args := []string{"create", "--name", "phone", "--binding", st.Nodes[0].ID + ":" + st.Nodes[0].Users[0].ID, "--subscription-formats", "sing-box"}
	if _, err := wizardOutput(t, func() error { return a.device(args) }); err != nil {
		t.Fatal(err)
	}
	saved, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p := saved.Devices[0]
	if p.IntervalSeconds != 0 || p.ToleranceMS != 0 || p.TimeoutMS != 0 || len(p.SubscriptionFormats) != 1 {
		t.Fatal("manual defaults invented active health tests")
	}
	p.ID = node.Token(8)
	p.Name = "bad-device"
	p.SubscriptionFormats = []string{"unknown"}
	if err := node.ValidateDeviceProfile(saved, p); err == nil {
		t.Fatal("unknown subscription output accepted")
	}
}
