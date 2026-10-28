package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"qingnode/internal/probe"
)

func TestProbeSnapshotProfilesBuildConcurrentlyWithoutManagementLock(t *testing.T) {
	a, snapshot := batchFixture(t)
	id, user := snapshot.Nodes[0].ID, snapshot.Nodes[0].Users[0].ID
	want, err := buildProbeEndpointProfile(snapshot, id, user, "default")
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	generation, saved := savedBatchState(t, a)
	type outcome struct {
		profile probe.Profile
		err     error
	}
	const workers = 8
	results := make(chan outcome, workers)
	err = a.store.InspectExisting(func() error {
		// The public file-loading wrapper must still honor a busy management
		// lock. Snapshot workers have no reason to enter this lock again.
		if _, err := a.probeEndpointProfile(id, user, "default"); err == nil {
			t.Error("file-loading profile wrapper bypassed busy management lock")
		}
		var started sync.WaitGroup
		started.Add(workers)
		release := make(chan struct{})
		for range workers {
			go func() {
				started.Done()
				<-release
				profile, err := buildProbeEndpointProfile(snapshot, id, user, "default")
				results <- outcome{profile: profile, err: err}
			}()
		}
		started.Wait()
		close(release)
		for range workers {
			result := <-results
			if result.err != nil {
				t.Errorf("snapshot worker failed under unrelated management lock: %v", result.err)
				continue
			}
			if result.profile.ConfigSHA256 != want.ConfigSHA256 || result.profile.ServerPathSHA256 != want.ServerPathSHA256 || !bytes.Equal(result.profile.Outbound, want.Outbound) || result.profile.NodeID != id {
				t.Error("snapshot workers built different configuration or route identity")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("concurrent profile construction changed the shared State snapshot", err)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, saved) {
		t.Fatal("snapshot construction or busy wrapper changed persisted State")
	}
	// Once the lock is released, the wrapper remains compatible with the pure
	// builder and still refuses pending management journals without recovery.
	wrapped, err := a.probeEndpointProfile(id, user, "default")
	if err != nil || wrapped.ConfigSHA256 != want.ConfigSHA256 || wrapped.ServerPathSHA256 != want.ServerPathSHA256 {
		t.Fatal("ordinary wrapper profile changed after extraction", err)
	}
	for _, name := range []string{"transaction.json", "uninstall.json"} {
		journal := filepath.Join(a.store.Root, name)
		original := []byte("pending snapshot regression fixture")
		if err := os.WriteFile(journal, original, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := a.probeEndpointProfile(id, user, "default"); err == nil {
			t.Error("file-loading wrapper bypassed pending management journal", name)
		}
		if got, err := os.ReadFile(journal); err != nil || !bytes.Equal(got, original) {
			t.Fatal("wrapper repaired pending journal during profile lookup", err)
		}
		if err := os.Remove(journal); err != nil {
			t.Fatal(err)
		}
	}
}
