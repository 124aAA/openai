//go:build linux

package node

// The historical CLI is built from the fixed research snapshot, transported as
// a hash-bound test input, and executed only in a private offline directory.
// This is real old-format generation, not JSON manufactured by the new model.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLegacyV028RealBinaryMigrationAndBackup(t *testing.T) {
	if os.Getenv("QINGNODE_LEGACY_V028_TEST") != "1" {
		t.Skip("explicit hash-bound historical v0.2.8 binary acceptance not requested")
	}
	bin, expected := os.Getenv("QINGNODE_LEGACY_V028_BIN"), os.Getenv("QINGNODE_LEGACY_V028_SHA256")
	info, err := os.Lstat(bin)
	if !filepath.IsAbs(bin) || err != nil || !info.Mode().IsRegular() || len(expected) != 64 || info.Size() > 64<<20 {
		t.Fatal("explicit regular historical CLI and SHA256 required")
	}
	data, err := os.ReadFile(bin)
	digest := sha256.Sum256(data)
	if err != nil || hex.EncodeToString(digest[:]) != expected {
		t.Fatal("historical CLI digest mismatch")
	}
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, bin, args...)
		// Never copy this output to a failure log: explicit export can contain
		// authentication, and all generated material belongs to this fixture.
		out, err := command.Output()
		if err != nil || len(out) > 8<<20 {
			t.Fatalf("historical offline CLI operation failed (operation=%s)", args[0])
		}
		return out
	}
	const source = "70c0c277aa8703a4bd2cf8268b6bdad09ae13fc2"
	version := "QingNode 0.2.8 (" + source + ")"
	// The official published archive embeds the 12-character revision; its
	// pinned binary digest and RELEASE.json bind that revision to the full SHA.
	switch expected {
	case "e1634d5bc24123c3c522e2904e8d9bc51fdf7501db778b64d84b5ca43bb99b75":
	case "ca87b8ad0f11796225676c3cb1d90eb530be861bc920ddbbaa397a6b05735d77":
		version = "QingNode 0.2.8 (" + source[:12] + ")"
	default:
		t.Fatal("historical CLI is not one of the pinned official or source-rebuilt artifacts")
	}
	if !bytes.Equal(bytes.TrimSpace(run("version")), []byte(version)) {
		t.Fatal("historical CLI source revision is not the fixed v0.2.8 snapshot")
	}
	root, materials := filepath.Join(t.TempDir(), "legacy"), t.TempDir()
	old := func(args ...string) []byte { return run(append([]string{"--offline", "--root", root}, args...)...) }
	old("init", "--protocol", "reality", "--name", "legacy-reality", "--server", "2001:db8::8", "--listen", "::", "--port", "24443", "--sni", "example.com", "--quiet")
	old("add", "--protocol", "ss2022", "--name", "legacy-ss", "--server", "127.0.0.1", "--listen", "127.0.0.1", "--port", "24444", "--quiet")
	cert, key := makeCert(t)
	certPath, keyPath := filepath.Join(materials, "cert.pem"), filepath.Join(materials, "key.pem")
	if err := os.WriteFile(certPath, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	old("add", "--protocol", "hysteria2", "--name", "legacy-hy2", "--server", "127.0.0.1", "--listen", "127.0.0.1", "--port", "24445", "--sni", "localhost", "--cert", certPath, "--key", keyPath, "--quiet")
	statePath := filepath.Join(root, "current", "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var original State
	if err := json.Unmarshal(raw, &original); err != nil || original.Schema != 1 || len(original.Nodes) != 3 {
		t.Fatal("old CLI did not generate the expected original schema and three nodes", err)
	}
	oldGeneration, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[string]string)
	for _, n := range original.Nodes {
		shares[n.ID] = strings.TrimSpace(string(old("export", "--id", n.ID, "--user", n.Users[0].ID, "--format", "uri")))
	}
	pass := "bounded-historical-fixture-password"
	passPath, backupPath := filepath.Join(materials, "password"), filepath.Join(materials, "legacy.qnbak")
	if err := os.WriteFile(passPath, []byte(pass), 0600); err != nil {
		t.Fatal(err)
	}
	old("backup", "--file", backupPath, "--password-file", passPath)
	encrypted, err := os.ReadFile(backupPath)
	if err != nil || !bytes.HasPrefix(encrypted, []byte("QNBK2\x00")) {
		t.Fatal("historical CLI did not produce QNBK2", err)
	}
	assertIdentity := func(got State) {
		t.Helper()
		if got.Schema != Schema || len(got.Nodes) != len(original.Nodes) {
			t.Fatal("old-format migration changed node count or current schema")
		}
		for _, before := range original.Nodes {
			after, err := got.Find(before.ID)
			if err != nil || after.ID != before.ID || !reflect.DeepEqual(before.Users, after.Users) || !reflect.DeepEqual(before.Reality, after.Reality) || !reflect.DeepEqual(before.Shadowsocks, after.Shadowsocks) || !reflect.DeepEqual(before.Certificate, after.Certificate) || before.Host != after.Host || before.Listen != after.Listen || before.Port != after.Port || EffectiveConnectPort(*after) != before.Port {
				t.Fatal("migration changed an existing identity, credential, certificate or endpoint", err)
			}
			if URI(*after, after.Users[0]) != shares[before.ID] {
				t.Fatal("migration changed bytes of an actual old CLI share URI")
			}
		}
	}
	loaded, err := ReadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	assertIdentity(loaded)
	if now, err := os.ReadFile(statePath); err != nil || !bytes.Equal(now, raw) {
		t.Fatal("read-only migration rewrote historical recovery bytes", err)
	}
	snapshot, err := RestoreSnapshot(encrypted, pass)
	if err != nil {
		t.Fatal(err)
	}
	assertIdentity(snapshot.State)
	if _, err := RestoreSnapshot(encrypted, "incorrect-password"); err == nil {
		t.Fatal("old encrypted backup accepted a wrong password")
	}
	restored := &Store{Root: filepath.Join(t.TempDir(), "restored"), Backend: OfflineBackend{}, GID: -1}
	if err := restored.WithLock(func() error { return restored.Apply(snapshot.State) }); err != nil {
		t.Fatal(err)
	}
	got, err := restored.Load()
	if err != nil {
		t.Fatal(err)
	}
	assertIdentity(got)
	store := &Store{Root: root, Backend: OfflineBackend{}, GID: -1}
	if err := store.WithLock(func() error {
		current, err := store.Load()
		if err != nil {
			return err
		}
		return store.Apply(current)
	}); err != nil {
		t.Fatal(err)
	}
	// Loading and reapplying equivalent data must retain the original format.
	// Only a meaningful management write may create a current-schema generation.
	if noOpGeneration, err := os.Readlink(filepath.Join(root, "current")); err != nil || noOpGeneration != oldGeneration {
		t.Fatal("no-op migration changed the historical generation pointer", err)
	}
	if noOpBytes, err := os.ReadFile(statePath); err != nil || !bytes.Equal(noOpBytes, raw) {
		t.Fatal("no-op migration rewrote historical recovery bytes", err)
	}
	if err := store.WithLock(func() error {
		current, err := store.Load()
		if err != nil {
			return err
		}
		// A display tag exercises persistence without changing any old share
		// URI, endpoint, credential, REALITY key or certificate.
		current.Nodes[0].Tags = append(current.Nodes[0].Tags, "legacy-migration-proof")
		return store.Apply(current)
	}); err != nil {
		t.Fatal(err)
	}
	if newGeneration, err := os.Readlink(filepath.Join(root, "current")); err != nil || newGeneration == oldGeneration {
		t.Fatal("meaningful migration write did not create a new generation", err)
	}
	newRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(newRaw, &persisted); err != nil || persisted.Schema != Schema {
		t.Fatal("meaningful migration write did not persist the current explicit schema", err)
	}
	if retained, err := os.ReadFile(filepath.Join(root, oldGeneration, "state.json")); err != nil || !bytes.Equal(retained, raw) {
		t.Fatal("write migration discarded the exact historical recovery generation", err)
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	assertIdentity(current)
	if len(current.Nodes[0].Tags) != 1 || current.Nodes[0].Tags[0] != "legacy-migration-proof" {
		t.Fatal("meaningful migration write did not retain the explicit display tag")
	}
	// The old binary must not interpret the new format by dropping unknown data.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, bin, "validate-state", "--file", filepath.Join(root, "current", "state.json")).Run(); err == nil {
		t.Fatal("historical binary accepted a State version it cannot understand")
	}
	future := current.Clone()
	future.Schema = Schema + 1
	futureBytes, _ := json.Marshal(future)
	if _, err := DecodeState(futureBytes); err == nil {
		t.Fatal("future State format accepted")
	}
}
