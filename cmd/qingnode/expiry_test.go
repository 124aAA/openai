package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/subscription"
)

func expirationCLIArgs(st node.State, at time.Time) []string {
	return []string{"set", "--id", "eeeeeeeeeeee0001", "--node", st.Nodes[0].ID, "--user", st.Nodes[0].Users[0].ID, "--device", st.Devices[0].ID, "--expires-at", at.UTC().Format(time.RFC3339Nano)}
}

func TestExpirationCLIQueriesPreviewAndScheduleDoNotStartOrRenewCredentials(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	beforeGeneration, before := savedBatchState(t, a)
	publicationBefore, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	for _, args := range [][]string{{"list"}, append(expirationCLIArgs(st, now), "--preview")} {
		out, err := wizardOutput(t, func() error { return a.expirationAt(args, now) })
		if err != nil || !strings.Contains(out, "下载令牌到期独立") {
			t.Fatal("read-only expiry command", out, err)
		}
	}
	generation, after := savedBatchState(t, a)
	publicationAfter, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	if generation != beforeGeneration || !bytes.Equal(before, after) || !bytes.Equal(publicationBefore, publicationAfter) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("expiry query/preview changed State, token publication or service")
	}
	backend.active = true
	if _, err := wizardOutput(t, func() error { return a.expirationAt(append(expirationCLIArgs(st, now), "--yes"), now) }); err != nil {
		t.Fatal(err)
	}
	saved, err := a.store.Load()
	if err != nil || len(saved.CredentialExpirations) != 1 || saved.CredentialExpirations[0].DisabledAt != "" || !reflect.DeepEqual(st.Nodes, saved.Nodes) || !reflect.DeepEqual(st.Devices, saved.Devices) || backend.starts != 0 || backend.stops != 0 || !backend.active {
		t.Fatal("saving deadline changed live credential or restarted process", err)
	}
	for _, m := range materials {
		if code, _ := subscriptionCLIGet(t, dir, m.Token); code != 200 {
			t.Fatal("schedule update revoked download authorization")
		}
	}
	beforeGeneration, before = savedBatchState(t, a)
	for _, args := range [][]string{{"list"}, {"apply", "--preview"}} {
		if _, err := wizardOutput(t, func() error { return a.expirationAt(args, now) }); err != nil {
			t.Fatal(err)
		}
	}
	generation, after = savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("due plan query/preview performed stop")
	}
}

func TestExpirationCLIApplyKeepsOtherBindingsAndTokenThenDisablesOnlyLastBinding(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := a.expirationAt(append(expirationCLIArgs(st, now), "--yes"), now); err != nil {
		t.Fatal(err)
	}
	backend.active = true
	if _, err := wizardOutput(t, func() error { return a.expirationAt([]string{"apply", "--yes"}, now) }); err != nil {
		t.Fatal(err)
	}
	c, err := a.store.Load()
	if err != nil || len(c.Nodes[0].Users) != 1 || c.Nodes[0].Users[0] != st.Nodes[0].Users[1] || c.Devices[0].Disabled || len(c.Devices[0].Bindings) != 1 || !reflect.DeepEqual(c.Devices[1], st.Devices[1]) || backend.starts != 1 {
		t.Fatal("expiration touched unrelated credential, binding, device or applied more than once", err)
	}
	code, content := subscriptionCLIGet(t, dir, materials[0].Token)
	if code != 200 || strings.Contains(content, st.Nodes[0].Users[0].Password) || !strings.Contains(content, st.Nodes[1].Users[0].Password) {
		t.Fatal("remaining-binding device lost token or still exports expired credential")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[1].Token); code != 200 {
		t.Fatal("unrelated device token revoked")
	}
	generation, previous := savedBatchState(t, a)
	if err := a.expirationAt([]string{"apply", "--yes"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	newGeneration, after := savedBatchState(t, a)
	if generation != newGeneration || !bytes.Equal(previous, after) || backend.starts != 1 {
		t.Fatal("no-op expiry re-applied service transaction")
	}
	last := []string{"set", "--id", "eeeeeeeeeeee0002", "--node", c.Nodes[1].ID, "--user", c.Nodes[1].Users[0].ID, "--device", c.Devices[0].ID, "--expires-at", now.Format(time.RFC3339), "--yes"}
	if err := a.expirationAt(last, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := a.expirationAt([]string{"apply", "--yes"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err = a.store.Load()
	if err != nil || !c.Devices[0].Disabled || c.Nodes[1].Enabled || len(c.Nodes[1].Users) != 1 || c.Nodes[1].Users[0] != st.Nodes[1].Users[0] {
		t.Fatal("last binding/credential historical stop failed", err)
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
		t.Fatal("empty device retained download authorization")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[1].Token); code != 200 {
		t.Fatal("other device authorization changed at last-user stop")
	}
}

func TestExpirationCLISharedBlockNeverRevokesOrPartiallyCommits(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	profiles := st.Clone().Devices
	profiles[1].Bindings = append(profiles[1].Bindings, profiles[0].Bindings[0])
	if err := a.device([]string{"apply", "--file", deviceProfilesFile(t, profiles)}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := a.expirationAt(append(expirationCLIArgs(st, now), "--yes"), now); err != nil {
		t.Fatal(err)
	}
	beforeGeneration, before := savedBatchState(t, a)
	publicationBefore, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	backend.active = true
	err := a.expirationAt([]string{"apply", "--yes"}, now)
	if err == nil || !strings.Contains(err.Error(), "共享") {
		t.Fatal("shared device credential accepted", err)
	}
	generation, after := savedBatchState(t, a)
	publicationAfter, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	if generation != beforeGeneration || !bytes.Equal(before, after) || !bytes.Equal(publicationBefore, publicationAfter) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("shared blocker changed State, token or service")
	}
	for _, material := range materials {
		if code, _ := subscriptionCLIGet(t, dir, material.Token); code != 200 {
			t.Fatal("shared blocker revoked authorization")
		}
	}
}

func TestExpirationCLIRejectsUnsafeInputsAndDownloadExpiryIsIndependent(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	beforeGeneration, before := savedBatchState(t, a)
	for _, args := range [][]string{
		expirationCLIArgs(st, now), {"apply"}, {"remove", "--id", "eeeeeeeeeeee0001"},
		{"list", "--yes"}, {"apply", "--yes", "--now", "9999-01-01T00:00:00Z"},
		{"set", "--yes", "--node", st.Nodes[0].Name, "--user", st.Nodes[0].Users[0].ID, "--expires-at", now.Format(time.RFC3339)},
		{"set", "--yes", "--node", st.Nodes[0].ID, "--user", st.Nodes[0].Users[0].ID, "--expires-at", "2030-01-02T11:04:05+08:00"},
		{"remove", "--yes", "--id", "unknown"}, {"quota", "--yes"},
	} {
		if _, err := wizardOutput(t, func() error { return a.expirationAt(args, now) }); err == nil {
			t.Fatalf("unsafe/unknown request accepted: %v", args)
		}
	}
	generation, after := savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("rejected expiry input changed State/service")
	}
	if err := a.expirationAt(append(expirationCLIArgs(st, now.Add(time.Hour)), "--yes"), now); err != nil {
		t.Fatal(err)
	}
	scheduled, _ := a.store.Load()
	// Change the download token's own expiry only. The saved proxy deadline
	// and all live authentication secrets must remain byte-for-byte unchanged.
	snapshot, err := subscription.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range snapshot.Records {
		if snapshot.Records[i].DeviceID == st.Devices[0].ID {
			snapshot.Records[i].IssuedAt = time.Now().UTC().Add(-2 * time.Hour)
			snapshot.Records[i].ExpiresAt = time.Now().UTC().Add(-time.Hour)
		}
	}
	if err := subscription.Publish(dir, snapshot, -1); err != nil {
		t.Fatal(err)
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
		t.Fatal("expired download token still accepted")
	}
	if err := a.expirationAt([]string{"list"}, now); err != nil {
		t.Fatal(err)
	}
	afterState, _ := a.store.Load()
	if !reflect.DeepEqual(scheduled, afterState) || !reflect.DeepEqual(st.Nodes, afterState.Nodes) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("download expiry or proxy expiry query stopped/renewed proxy credentials")
	}
}

func TestExpirationCLIActivationFailureLeavesDeadlinePending(t *testing.T) {
	a, st, backend := deviceCLIFixture(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := a.expirationAt(append(expirationCLIArgs(st, now), "--yes"), now); err != nil {
		t.Fatal(err)
	}
	beforeGeneration, before := savedBatchState(t, a)
	backend.active, backend.failStarts = true, 1
	err := a.expirationAt([]string{"apply", "--yes"}, now)
	if err == nil || !strings.Contains(err.Error(), "不能据此认定代理已停") {
		t.Fatal("activation failure claimed successful stop", err)
	}
	generation, after := savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || !backend.active {
		t.Fatal("failed expiry transaction did not restore saved auth/schedule")
	}
}
