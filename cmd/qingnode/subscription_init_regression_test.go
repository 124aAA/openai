//go:build linux

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qingnode/internal/subscription"
)

// These regressions deliberately use only the pre-existing CLI and test
// helpers, so the same file can be overlaid on d2c5c4c to observe the failure.
func initRegressionHTTP(t *testing.T, dir string) func(string) int {
	t.Helper()
	handler, err := subscription.NewHandler(func() (subscription.Snapshot, error) { return subscription.Read(dir) }, subscription.HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	client := &http.Client{Timeout: time.Second}
	t.Cleanup(func() { client.CloseIdleConnections(); server.Close() })
	return func(token string) int {
		t.Helper()
		response, err := client.Get(server.URL + "/s/" + token + "/sing-box")
		if err != nil {
			t.Fatal("subscription HTTP read failed")
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal("subscription response did not complete")
		}
		return response.StatusCode
	}
}

func initRegressionBytes(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func TestSubscriptionInitRejectsExistingPublicationAcrossStates(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	if err := a.subscription([]string{"revoke", "--device", st.Devices[1].ID, "--yes"}); err != nil {
		t.Fatal(err)
	}
	readHTTP := initRegressionHTTP(t, dir)
	if readHTTP(materials[0].Token) != 200 || readHTTP(materials[1].Token) != 404 {
		t.Fatal("fixture must retain one active and one revoked authorization")
	}
	b, _, otherBackend := deviceCLIFixture(t)
	backend.active = true
	aGeneration, aState := savedBatchState(t, a)
	bGeneration, bState := savedBatchState(t, b)
	serverA := initRegressionBytes(t, filepath.Join(a.store.Root, "current", "server.json"))
	serverB := initRegressionBytes(t, filepath.Join(b.store.Root, "current", "server.json"))
	snapshot := initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))
	marker := initRegressionBytes(t, filepath.Join(dir, subscription.MarkerName))
	serviceA, serviceB := *backend, *otherBackend
	if err := b.subscription([]string{"init", "--dir", dir}); err == nil {
		t.Error("another State silently adopted and cleared an existing publication")
	}
	aNext, aAfter := savedBatchState(t, a)
	bNext, bAfter := savedBatchState(t, b)
	if aGeneration != aNext || bGeneration != bNext || !bytes.Equal(aState, aAfter) || !bytes.Equal(bState, bAfter) || !bytes.Equal(serverA, initRegressionBytes(t, filepath.Join(a.store.Root, "current", "server.json"))) || !bytes.Equal(serverB, initRegressionBytes(t, filepath.Join(b.store.Root, "current", "server.json"))) || *backend != serviceA || *otherBackend != serviceB {
		t.Error("rejected publication reuse changed State, generation, server, or service")
	}
	if !bytes.Equal(snapshot, initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))) || !bytes.Equal(marker, initRegressionBytes(t, filepath.Join(dir, subscription.MarkerName))) {
		t.Error("existing publication or original authorization evidence was overwritten")
	}
	if _, err := os.Lstat(filepath.Join(b.store.Root, publisherConfigName)); !os.IsNotExist(err) {
		t.Error("rejected init registered another State as publisher")
	}
	if readHTTP(materials[0].Token) != 200 || readHTTP(materials[1].Token) != 404 {
		t.Error("init reuse changed active or revoked HTTP authorization")
	}
}

func TestSubscriptionInitRejectsExistingSnapshotAfterPublisherConfigLoss(t *testing.T) {
	a, st, backend, dir, materials := subscriptionCLIFixture(t)
	if err := a.subscription([]string{"revoke", "--device", st.Devices[1].ID, "--yes"}); err != nil {
		t.Fatal(err)
	}
	readHTTP := initRegressionHTTP(t, dir)
	if readHTTP(materials[0].Token) != 200 || readHTTP(materials[1].Token) != 404 {
		t.Fatal("authorization fixture not ready")
	}
	if err := os.Remove(filepath.Join(a.store.Root, publisherConfigName)); err != nil {
		t.Fatal(err)
	}
	generation, saved := savedBatchState(t, a)
	server := initRegressionBytes(t, filepath.Join(a.store.Root, "current", "server.json"))
	snapshot := initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))
	service := *backend
	err := a.subscription([]string{"init", "--dir", dir})
	if err == nil {
		t.Error("missing publisher config allowed init to erase the existing registry")
	}
	if err != nil && (!strings.Contains(err.Error(), "保留") || !strings.Contains(err.Error(), "新")) {
		t.Error("refusal did not explain preservation and a new directory")
	}
	next, after := savedBatchState(t, a)
	if generation != next || !bytes.Equal(saved, after) || !bytes.Equal(server, initRegressionBytes(t, filepath.Join(a.store.Root, "current", "server.json"))) || !bytes.Equal(snapshot, initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))) || *backend != service {
		t.Error("reinitialization changed original State, publication, or service")
	}
	if _, err = os.Lstat(filepath.Join(a.store.Root, publisherConfigName)); !os.IsNotExist(err) {
		t.Error("refused init wrote a replacement publisher config")
	}
	if readHTTP(materials[0].Token) != 200 || readHTTP(materials[1].Token) != 404 {
		t.Error("reinitialization lost active access or revived revoked access")
	}
}

func TestSubscriptionInitRejectsExistingEmptySnapshotWithoutReplacingTime(t *testing.T) {
	a, _, backend := deviceCLIFixture(t)
	dir := filepath.Join(t.TempDir(), "published")
	if err := a.subscription([]string{"init", "--dir", dir}); err != nil {
		t.Fatal(err)
	}
	before := initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))
	if err := os.Remove(filepath.Join(a.store.Root, publisherConfigName)); err != nil {
		t.Fatal(err)
	}
	generation, saved := savedBatchState(t, a)
	service := *backend
	if err := a.subscription([]string{"init", "--dir", dir}); err == nil {
		t.Error("existing empty snapshot was silently replaced")
	}
	next, after := savedBatchState(t, a)
	if !bytes.Equal(before, initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))) || generation != next || !bytes.Equal(saved, after) || *backend != service {
		t.Error("empty registry's original time/bytes or State/service changed")
	}
}

func TestSubscriptionInitConcurrentStatesCreateOnlyOneInitialSnapshot(t *testing.T) {
	a, _, backendA := deviceCLIFixture(t)
	b, _, backendB := deviceCLIFixture(t)
	dir := filepath.Join(t.TempDir(), "published")
	// Initialize the marker only, a supported interrupted-initialization state.
	// Both CLI calls can therefore pass directory validation before either one
	// creates a snapshot; their separate management locks cannot serialize them.
	if err := subscription.Initialize(dir, -1); err != nil {
		t.Fatal(err)
	}
	genA, stateA := savedBatchState(t, a)
	genB, stateB := savedBatchState(t, b)
	serviceA, serviceB := *backendA, *backendB
	start := make(chan struct{})
	results := make([]error, 2)
	var done sync.WaitGroup
	for i, candidate := range []*app{a, b} {
		done.Add(1)
		go func(i int, candidate *app) {
			defer done.Done()
			<-start
			results[i] = candidate.subscription([]string{"init", "--dir", dir})
		}(i, candidate)
	}
	close(start)
	done.Wait()
	successes := 0
	for i, result := range results {
		_, registered := os.Stat(filepath.Join([]*app{a, b}[i].store.Root, publisherConfigName))
		if result == nil {
			successes++
			if registered != nil {
				t.Error("successful initializer did not register its own publisher")
			}
		} else if !os.IsNotExist(registered) {
			t.Error("rejected concurrent initializer registered a publisher")
		}
	}
	if successes != 1 {
		t.Error("exactly one concurrent State must create the initial snapshot", successes)
	}
	initial := initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))
	publication, err := subscription.Read(dir)
	if err != nil || publication.Version != 1 || len(publication.Records) != 0 {
		t.Fatal("initial publication is incomplete", err)
	}
	for _, candidate := range []*app{a, b} {
		if err := candidate.subscription([]string{"init", "--dir", dir}); err == nil {
			t.Error("later initializer overwrote the winner's snapshot")
		}
	}
	nextA, afterA := savedBatchState(t, a)
	nextB, afterB := savedBatchState(t, b)
	if genA != nextA || genB != nextB || !bytes.Equal(stateA, afterA) || !bytes.Equal(stateB, afterB) || !bytes.Equal(initial, initRegressionBytes(t, filepath.Join(dir, subscription.SnapshotName))) || *backendA != serviceA || *backendB != serviceB {
		t.Error("concurrent init or rejected retry changed State, original snapshot, or service")
	}
}
