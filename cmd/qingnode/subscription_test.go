package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/subscription"
)

func subscriptionCLIStderr(t *testing.T, call func() error) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = old; f.Close() }()
	err = call()
	if _, e := f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e != nil {
		t.Fatal(e)
	}
	return string(b), err
}

func subscriptionCLIFixture(t *testing.T) (*app, node.State, *batchBackend, string, []tokenMaterial) {
	t.Helper()
	a, s, backend := deviceCLIFixture(t)
	dir := filepath.Join(t.TempDir(), "published")
	if err := a.subscription([]string{"init", "--dir", dir}); err != nil {
		t.Fatal(err)
	}
	materials := make([]tokenMaterial, 0, len(s.Devices))
	for _, p := range s.Devices {
		path := filepath.Join(t.TempDir(), "token.json")
		stderr, err := subscriptionCLIStderr(t, func() error { return a.subscription([]string{"issue", "--device", p.ID, "--out", path}) })
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var m tokenMaterial
		if err = json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if len(m.Token) != 64 || m.DeviceID != p.ID || strings.Contains(stderr, m.Token) {
			t.Fatal("token issue leaked or mismatched device")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("token material must be a new private file", err)
		}
		if len(m.Links) != 0 {
			t.Fatal("local token pretended HTTPS subscription was deployed")
		}
		materials = append(materials, m)
	}
	backend.checks = 0
	backend.activeCalls = 0
	backend.starts = 0
	backend.stops = 0
	return a, s, backend, dir, materials
}

func subscriptionCLIGet(t *testing.T, dir, token string) (int, string) {
	t.Helper()
	h, err := subscription.NewHandler(func() (subscription.Snapshot, error) { return subscription.Read(dir) }, subscription.HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+token+"/sing-box", nil))
	return w.Code, w.Body.String()
}

func TestSubscriptionCLIIssueKeepsTokenOutOfStateAndOtherDevice(t *testing.T) {
	a, s, backend, dir, materials := subscriptionCLIFixture(t)
	beforeGeneration, before := savedBatchState(t, a)
	if err := filepath.WalkDir(a.store.Root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			for _, m := range materials {
				if bytes.Contains(b, []byte(m.Token)) {
					t.Errorf("raw subscription token persisted inside State tree %s", filepath.Base(path))
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	publication, err := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range materials {
		if bytes.Contains(publication, []byte(m.Token)) {
			t.Fatal("raw subscription token in service registry")
		}
	}
	for i, m := range materials {
		code, body := subscriptionCLIGet(t, dir, m.Token)
		if code != 200 {
			t.Fatal("published download", code)
		}
		own, other := s.Nodes[0].Users[i], s.Nodes[0].Users[1-i]
		if !strings.Contains(body, own.Password) || strings.Contains(body, other.Password) {
			t.Fatal("subscription leaked another device authentication")
		}
	}
	for _, cmd := range [][]string{{"status"}, {"publish"}} {
		out, err := wizardOutput(t, func() error { return a.subscription(cmd) })
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range materials {
			if strings.Contains(out, m.Token) {
				t.Fatal("query printed raw token")
			}
		}
	}
	generation, after := savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("publication/query touched proxy State or service")
	}
}

func TestSubscriptionHTTPReadsWithoutManagementLock(t *testing.T) {
	a, _, backend, dir, materials := subscriptionCLIFixture(t)
	beforeGeneration, before := savedBatchState(t, a)
	h, err := subscription.NewHandler(func() (subscription.Snapshot, error) { return subscription.Read(dir) }, subscription.HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { done <- a.store.InspectExisting(func() error { close(held); <-release; return nil }) }()
	<-held
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(server.URL + "/s/" + materials[0].Token + "/sing-box")
	if err != nil {
		t.Fatal("HTTP reader waited on management lock", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	client.CloseIdleConnections()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	generation, after := savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("subscription request changed State/service")
	}
}

func TestSubscriptionCLIRevokeRotateExpiryPreserveProxyAuthentication(t *testing.T) {
	a, s, backend, dir, materials := subscriptionCLIFixture(t)
	beforeGeneration, before := savedBatchState(t, a)
	if _, err := subscriptionCLIStderr(t, func() error { return a.subscription([]string{"revoke", "--device", s.Devices[0].ID, "--yes"}) }); err != nil {
		t.Fatal(err)
	}
	badCode, badBody := subscriptionCLIGet(t, dir, strings.Repeat("0", 64))
	revokedCode, revokedBody := subscriptionCLIGet(t, dir, materials[0].Token)
	if badCode != 404 || revokedCode != badCode || revokedBody != badBody {
		t.Fatal("revoked token is distinguishable or accepted")
	}
	path := filepath.Join(t.TempDir(), "rotated.json")
	if _, err := subscriptionCLIStderr(t, func() error {
		return a.subscription([]string{"rotate", "--device", s.Devices[0].ID, "--out", path, "--yes"})
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rotated tokenMaterial
	if json.Unmarshal(b, &rotated) != nil || rotated.Token == materials[0].Token {
		t.Fatal("token did not rotate")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
		t.Fatal("old token survived rotation")
	}
	if code, _ := subscriptionCLIGet(t, dir, rotated.Token); code != 200 {
		t.Fatal("new token rejected")
	}
	publication, err := subscription.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range publication.Records {
		if publication.Records[i].DeviceID == s.Devices[0].ID {
			publication.Records[i].IssuedAt = time.Now().Add(-time.Hour)
			publication.Records[i].ExpiresAt = time.Now().Add(-time.Second)
		}
	}
	if err = subscription.Publish(dir, publication, -1); err != nil {
		t.Fatal(err)
	}
	code, body := subscriptionCLIGet(t, dir, rotated.Token)
	if code != 404 || body != badBody {
		t.Fatal("expired token accepted or identifiable")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[1].Token); code != 200 {
		t.Fatal("unrelated token revoked")
	}
	generation, after := savedBatchState(t, a)
	afterState, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if generation != beforeGeneration || !bytes.Equal(before, after) || !reflect.DeepEqual(s.Nodes, afterState.Nodes) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("download authorization changed proxy credentials/service")
	}
}

func TestSubscriptionFailedRefreshKeepsCommittedStateAndOldPublication(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "running"}[active], func(t *testing.T) {
			a, s, backend, dir, _ := subscriptionCLIFixture(t)
			backend.active = active
			beforeGeneration, _ := savedBatchState(t, a)
			before, err := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
			if err != nil {
				t.Fatal(err)
			}
			// Inject an external permission change after the State transaction's
			// preflight, at the post-commit publication boundary. An already-bad
			// snapshot must instead fail the new authorization preflight.
			a.store.AfterCommit = func(st node.State) error {
				if e := os.Chmod(filepath.Join(dir, subscription.SnapshotName), 0644); e != nil {
					return e
				}
				return a.refreshPublished(st)
			}
			err = a.device([]string{"tags", "--id", s.Nodes[0].ID, "--tags", "new-tag"})
			if err == nil || !strings.Contains(err.Error(), "已提交") || !strings.Contains(err.Error(), "旧快照保留") {
				t.Fatal("post-commit publication failure was hidden", err)
			}
			generation, _ := savedBatchState(t, a)
			afterState, err := a.store.Load()
			if err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(dir, subscription.SnapshotName))
			if generation == beforeGeneration || len(afterState.Nodes[0].Tags) != 1 || afterState.Nodes[0].Tags[0] != "new-tag" || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 || backend.active != active {
				t.Fatal("failed refresh rolled back committed State, modified publication, or changed proxy lifecycle")
			}
			if err = os.Chmod(filepath.Join(dir, subscription.SnapshotName), 0640); err != nil {
				t.Fatal(err)
			}
			a.store.AfterCommit = a.refreshPublished
			if err = a.subscription([]string{"publish"}); err != nil {
				t.Fatal("explicit publication retry failed", err)
			}
			if _, err = subscription.Read(dir); err != nil {
				t.Fatal(err)
			}
			if backend.starts != 0 || backend.stops != 0 || backend.active != active {
				t.Fatal("publication retry restarted service")
			}
		})
	}
}

func TestSubscriptionStateRollbackDoesNotReviveDownloadToken(t *testing.T) {
	a, s, backend, dir, materials := subscriptionCLIFixture(t)
	if _, err := subscriptionCLIStderr(t, func() error { return a.device([]string{"disable", "--id", s.Devices[0].ID, "--yes"}) }); err != nil {
		t.Fatal(err)
	}
	if err := a.store.WithLock(func() error { return a.store.Rollback() }); err != nil {
		t.Fatal(err)
	}
	after, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Devices[0].Disabled {
		t.Fatal("State rollback did not restore prior device selection")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
		t.Fatal("State rollback revived revoked download token")
	}
	if !reflect.DeepEqual(s.Nodes, after.Nodes) || backend.starts != 0 || backend.stops != 0 || backend.active {
		t.Fatal("metadata rollback changed credentials or started stopped service")
	}
}

func TestSubscriptionRemovedDeviceTokenCannotFollowDisplayName(t *testing.T) {
	a, s, backend, dir, materials := subscriptionCLIFixture(t)
	candidate := s.Clone()
	survivor := candidate.Devices[1]
	survivor.Name = candidate.Devices[0].ID
	candidate.Devices = []node.DeviceProfile{survivor}
	// Exercise the publisher independently as well: the pre-commit revocation
	// hook must not hide a name-fallback bug in the renderer's credential lookup.
	old, err := subscription.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	config, ok, err := a.publisherConfig()
	if err != nil || !ok {
		t.Fatal("publisher config", err)
	}
	next, err := publicationForState(candidate, config, old)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range next.Records {
		if record.DeviceID == s.Devices[0].ID && (!record.Revoked || len(record.Outputs) != 0) {
			t.Fatal("publisher followed a display name instead of exact device ID")
		}
	}
	if err := a.store.WithLock(func() error { return a.store.Apply(candidate) }); err != nil {
		t.Fatal(err)
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
		t.Fatal("removed device token followed another device's display name")
	}
	if code, body := subscriptionCLIGet(t, dir, materials[1].Token); code != 200 || !strings.Contains(body, s.Nodes[0].Users[1].Password) || strings.Contains(body, s.Nodes[0].Users[0].Password) {
		t.Fatal("survivor lost its precise credential binding", code)
	}
	if backend.starts != 0 || backend.stops != 0 || backend.active {
		t.Fatal("publication identity repair restarted stopped service")
	}
}

func TestSubscriptionPrecommitRevocationSurvivesOtherDeviceExportFailure(t *testing.T) {
	for _, mode := range []string{"disabled-batch", "removed-state"} {
		t.Run(mode, func(t *testing.T) {
			a, s, backend, dir, materials := subscriptionCLIFixture(t)
			beforeGeneration, _ := savedBatchState(t, a)
			beforePublication, err := subscription.Read(dir)
			if err != nil {
				t.Fatal(err)
			}
			candidate := s.Clone()
			candidate.Devices[1].Strategy = "fallback"
			candidate.Devices[1].TestURL = "https://health.example.test/controlled"
			candidate.Devices[1].IntervalSeconds = 300
			if mode == "disabled-batch" {
				candidate.Devices[0].Disabled = true
				err = a.device([]string{"apply", "--file", deviceProfilesFile(t, candidate.Devices)})
			} else {
				candidate.Devices = candidate.Devices[1:]
				err = a.store.WithLock(func() error { return a.store.Apply(candidate) })
			}
			if err == nil || !strings.Contains(err.Error(), "已提交") || !strings.Contains(err.Error(), "旧快照保留") {
				t.Fatal("expected committed State plus unsupported sing-box fallback publication", err)
			}
			generation, _ := savedBatchState(t, a)
			afterState, loadErr := a.store.Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if generation == beforeGeneration {
				t.Fatal("State commit incorrectly undone by publication failure")
			}
			if mode == "disabled-batch" && !afterState.Devices[0].Disabled || mode == "removed-state" && len(afterState.Devices) != 1 {
				t.Fatal("device deactivation did not commit")
			}
			if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
				t.Fatal("previously authorized removed/disabled device survived failed publication")
			}
			if code, body := subscriptionCLIGet(t, dir, materials[1].Token); code != 200 || !strings.Contains(body, s.Nodes[0].Users[1].Password) {
				t.Fatal("unrelated previous valid publication was lost", code)
			}
			afterPublication, err := subscription.Read(dir)
			if err != nil {
				t.Fatal(err)
			}
			var oldOther, newOther map[string]subscription.Payload
			for _, r := range beforePublication.Records {
				if r.DeviceID == s.Devices[1].ID {
					oldOther = r.Outputs
				}
			}
			for _, r := range afterPublication.Records {
				if r.DeviceID == s.Devices[1].ID {
					newOther = r.Outputs
				}
			}
			if !reflect.DeepEqual(oldOther, newOther) || backend.starts != 0 || backend.stops != 0 || backend.active {
				t.Fatal("failed publication changed unrelated payload or proxy lifecycle")
			}
		})
	}
}
