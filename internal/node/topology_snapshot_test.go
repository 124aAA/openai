package node

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTopologySnapshotBackupAndRollbackRetainIndependentRemoteSecrets(t *testing.T) {
	store, backend := newStore(t)
	st := topologyFixture(t)
	st.Egresses = append(st.Egresses, topologyWG(t))
	st.Forwards = []PortForward{{ID: "6666666666666666", Name: "relay", Listen: "127.0.0.1", Port: 23456, Network: "tcp+udp", TargetHost: "192.0.2.20", TargetPort: 443, EgressID: st.Egresses[0].ID, Enabled: true}}
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	original, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := store.current()
	statePath := filepath.Join(store.Root, generation, "state.json")
	originalBytes, _ := os.ReadFile(statePath)
	snapshot, err := Capture(store.Root, original, "batch05-test", ServiceUnit)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := BackupSnapshot(snapshot, "topology test recovery phrase")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{original.Nodes[0].Reality.PrivateKey, original.Egresses[0].Socks.Password, original.Egresses[2].WireGuard.PrivateKey} {
		if bytes.Contains(sealed, []byte(secret)) {
			t.Fatal("encrypted topology backup contains plaintext credentials")
		}
	}
	restored, err := RestoreSnapshot(sealed, "topology test recovery phrase")
	if err != nil || !equalJSON(snapshot, restored) || !equalJSON(original, restored.State) {
		t.Fatal("topology snapshot changed IDs, remote secrets, received routes, or forward mapping", err)
	}
	changed := restored.State.Clone()
	changed.Egresses[0].Socks.Password = "changed-remote-secret"
	if err = store.WithLock(func() error { return store.Apply(changed) }); err != nil {
		t.Fatal(err)
	}
	if backend.activations != 2 {
		t.Fatal("used topology change did not activate once")
	}
	if err = store.WithLock(store.Rollback); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || !equalJSON(original, got) || backend.activations != 3 {
		t.Fatal("topology rollback lost original runtime selection or local/remote authentication", err)
	}
	after, _ := os.ReadFile(statePath)
	if !bytes.Equal(originalBytes, after) {
		t.Fatal("backup/edit/rollback overwrote original generation recovery bytes")
	}
}

func TestTopologyUnusedRemoteCredentialSaveAndRollbackKeepStoppedState(t *testing.T) {
	store, backend, st := impactStore(t)
	if err := backend.Stop(); err != nil {
		t.Fatal(err)
	}
	starts, stops, activeReads := backend.activations, backend.stops, backend.activeReads
	st.Egresses = []Egress{topologySOCKS("3333333333333333", "unused")}
	if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || len(got.Egresses) != 1 || got.Egresses[0].Socks.Password != st.Egresses[0].Socks.Password {
		t.Fatal("unused remote definition was not persisted", err)
	}
	if backend.active || backend.activations != starts || backend.stops != stops || backend.activeReads != activeReads {
		t.Fatal("unused remote edit touched stopped service")
	}
	if err := store.WithLock(store.Rollback); err != nil {
		t.Fatal(err)
	}
	got, err = store.Load()
	if err != nil || len(got.Egresses) != 0 || backend.active || backend.activations != starts || backend.stops != stops || backend.activeReads != activeReads {
		t.Fatal("unused remote rollback changed service state", err)
	}
}
