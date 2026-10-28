//go:build linux

package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOfficialCoreCertificateMigrationPEMRestoresIdentityAndHY2(t *testing.T) {
	core := os.Getenv("SING_BOX_BIN")
	if core == "" {
		t.Skip("requires verified official core; encrypted PEM migration and HY2 data fixture")
	}
	cert, key := makeCert(t)
	resource := CertificateResource{ID: Token(8), Name: "shared PEM migration resource", Certificate: Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}
	state := NewState()
	state.CoreVersion = acmeFixtureCoreVersion(t, core)
	state.Certificates = []CertificateResource{resource}
	state.Nodes = []Node{{ID: Token(8), Name: "restored entry", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true, CertificateID: resource.ID,
		Users: []User{{ID: Token(8), Name: "original device", Password: "fixture-auth-preserved"}}}}
	makeStore := func() (*Store, *certificateMigrationBackend) {
		backend := &certificateMigrationBackend{hy2ContinuityBackend: &hy2ContinuityBackend{processBackend: processBackend{root: t.TempDir(), bin: core}}, stoppedConfirmed: true}
		store := &Store{Root: backend.root, Backend: backend, GID: -1}
		t.Cleanup(func() {
			if err := backend.Stop(); err != nil {
				t.Error(err)
			}
			if t.Failed() {
				for _, path := range backend.logs {
					b, _ := os.ReadFile(path)
					t.Logf("owned migration core: %s", b)
				}
			}
		})
		return store, backend
	}
	source, sourceBackend := makeStore()
	if err := source.WithLock(func() error { return source.Apply(state) }); err != nil {
		t.Fatal(err)
	}
	saved, err := source.Load()
	if err != nil {
		t.Fatal(err)
	}
	acmeFixtureHY2(t, core, saved.Nodes[0].Port, "localhost", []byte(cert))
	if err := sourceBackend.Stop(); err != nil {
		t.Fatal(err)
	}
	// Preserve a damaged derived file as source evidence. A new host must render
	// from the authenticated State, not execute the archived service material.
	damaged := []byte("{damaged-owned-derived-config")
	if err := os.WriteFile(filepath.Join(source.Root, "current", "server.json"), damaged, 0600); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err := source.WithLock(func() error {
		snapshot, err := Capture(source.Root, saved, "owned-integration-fixture", "[Service]\nExecStart=/untrusted/archived-evidence-only\n")
		if err != nil {
			return err
		}
		migration, err := CaptureMigration(snapshot, nil, nil, false)
		if err != nil {
			return err
		}
		if migration.Mode != "complete" || migration.Consistency != "no-runtime-assets" {
			t.Fatal("embedded PEM-only migration unexpectedly needs external runtime assets")
		}
		encrypted, err = BackupMigration(migration, "fixture-password-not-a-cli-argument")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !IsMigrationBackup(encrypted) || bytes.Contains(encrypted, []byte(key)) || bytes.Contains(encrypted, []byte(saved.Nodes[0].Users[0].Password)) {
		t.Fatal("complete migration envelope did not protect secrets")
	}
	restored, err := RestoreMigration(encrypted, "fixture-password-not-a-cli-argument")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Snapshot.ServerRaw, damaged) {
		t.Fatal("damaged source configuration evidence lost")
	}
	target, targetBackend := makeStore()
	if err := target.WithLock(func() error { return target.RestoreMigrationAssets(restored, MigrationTargets{}, false) }); err != nil {
		t.Fatal(err)
	}
	loaded, err := target.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Nodes[0].Users, saved.Nodes[0].Users) || loaded.Nodes[0].ID != saved.Nodes[0].ID || loaded.Nodes[0].CertificateID != saved.Nodes[0].CertificateID {
		t.Fatal("migration changed entry or device identity")
	}
	if !reflect.DeepEqual(loaded.Certificates, saved.Certificates) {
		t.Fatal("migration changed certificate resource or PEM private key")
	}
	rendered, err := os.ReadFile(filepath.Join(target.Root, "current", "server.json"))
	if err != nil || !json.Valid(rendered) || bytes.Contains(rendered, damaged) {
		t.Fatal("target did not regenerate valid derived configuration", err)
	}
	if !targetBackend.Active() {
		t.Fatal("target official core is not running")
	}
	acmeFixtureHY2(t, core, loaded.Nodes[0].Port, "localhost", []byte(cert))
	t.Log("encrypted complete PEM migration restored the same entry ID, credential ID/password, certificate resource ID and private key; regenerated damaged derived configuration and carried real HY2 HTTPS and UDP in a clean target directory; archived service text was not executed")
}

// A process test backend has no systemd cgroup. Its confirmation is based on
// never having started a child, or its own Stop waiting for cmd.Wait completion.
// Merely observing Active()==false is not treated as this confirmation.
type certificateMigrationBackend struct {
	*hy2ContinuityBackend
	stoppedConfirmed bool
}

func (b *certificateMigrationBackend) Activate(state State) error {
	b.stoppedConfirmed = false
	return b.hy2ContinuityBackend.Activate(state)
}
func (b *certificateMigrationBackend) Stop() error {
	err := b.hy2ContinuityBackend.Stop()
	if err == nil && b.cmd == nil {
		b.stoppedConfirmed = true
	}
	return err
}
func (b *certificateMigrationBackend) ConfirmStopped() error {
	if !b.stoppedConfirmed || b.cmd != nil {
		return errors.New("owned test core cmd.Wait completion not confirmed")
	}
	return nil
}
