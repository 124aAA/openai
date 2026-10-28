package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var deviceLegacyFixtures = []string{"state-v1.json", "state-v2-hy2-performance.json", "state-v3-endpoints.json", "state-v4-topology.json"}

func TestDeviceMigrationPreservesAllLegacyFieldsAndRecoveryBytes(t *testing.T) {
	for _, file := range deviceLegacyFixtures {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			var old State
			if err = json.Unmarshal(raw, &old); err != nil {
				t.Fatal(err)
			}
			want := old.Clone()
			if old.Schema < 3 {
				for i := range want.Nodes {
					port := want.Nodes[i].Port
					want.Nodes[i].ConnectPort = &port
				}
			}
			want.Schema = Schema
			want, err = CanonicalCertificates(want)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := ReadState(path)
			if err != nil || !reflect.DeepEqual(got, want) || got.Schema != Schema || got.Devices != nil {
				t.Fatal("migration changed saved identity, topology, performance, or endpoints", err)
			}
			if err = got.Validate(); err != nil {
				t.Fatal(err)
			}
			for i, n := range old.Nodes {
				for j, u := range n.Users {
					if URI(n, u) != URI(got.Nodes[i], got.Nodes[i].Users[j]) {
						t.Fatal("migration changed an existing share URI")
					}
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("read-only migration rewrote original recovery bytes", err)
			}
			plain := append(append([]byte(`{"format":2,"state":`), raw...), '}')
			snapshot, err := RestorePlainSnapshot(plain)
			if err != nil || snapshot.Format != 2 || !reflect.DeepEqual(snapshot.State, want) {
				t.Fatal("old snapshot did not restore the same migrated identity", err)
			}
			legacy, err := decodeSnapshot(raw, true)
			if err != nil || legacy.Format != 1 || !reflect.DeepEqual(legacy.State, want) {
				t.Fatal("legacy backup State entry lost its identity", err)
			}
		})
	}
}

func TestDeviceMigrationRejectsOldSchemaExtensionsIncludingNullAndUnicodeAliases(t *testing.T) {
	for schema := 1; schema <= 4; schema++ {
		for _, key := range []string{"devices", "Devices", "DEVICEſ"} {
			for _, value := range []string{"null", "[]"} {
				raw := fmt.Sprintf(`{"schema":%d,"core_version":"1.14.0","nodes":[],%q:%s}`, schema, key, value)
				if _, err := DecodeState([]byte(raw)); err == nil || !strings.Contains(err.Error(), "设备扩展") {
					t.Fatalf("old schema %d accepted hidden device field %s=%s: %v", schema, key, value, err)
				}
			}
		}
		for _, key := range []string{"tags", "TAGS", "tagſ"} {
			for _, value := range []string{"null", "[]"} {
				raw := fmt.Sprintf(`{"schema":%d,"core_version":"1.14.0","nodes":[{%q:%s}]}`, schema, key, value)
				if _, err := DecodeState([]byte(raw)); err == nil || !strings.Contains(err.Error(), "节点标签") {
					t.Fatalf("old schema %d accepted hidden node tags %s=%s: %v", schema, key, value, err)
				}
			}
		}
		if _, err := MigrateState(State{Schema: schema, Devices: []DeviceProfile{}}); err == nil {
			t.Fatal("typed migration discarded device declarations", schema)
		}
		if _, err := MigrateState(State{Schema: schema, Nodes: []Node{{Tags: []string{}}}}); err == nil {
			t.Fatal("typed migration discarded node tags", schema)
		}
	}
	for _, raw := range []string{
		`{"schema":5,"core_version":"1.14.0","nodes":[],"devices":[],"DEVICEſ":[]}`,
		`{"schema":5,"core_version":"1.14.0","nodes":[{"tags":[],"tagſ":[]}]}`,
		fmt.Sprintf(`{"schema":%d,"core_version":"1.14.0","nodes":[]}`, Schema+1),
	} {
		if _, err := DecodeState([]byte(raw)); err == nil {
			t.Fatal("ambiguous or unsupported device State was accepted")
		}
	}
}

func TestDeviceMigrationEncryptedV4BackupKeepsEntranceAndRemoteIdentities(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "state-v4-topology.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := DecodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := "batch 06 legacy backup fixture"
	for _, format := range []int{1, 2} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			plain, magic := raw, backupMagic
			if format == 2 {
				plain = append(append([]byte(`{"format":2,"state":`), raw...), '}')
				magic = []byte("QNBK2\x00")
			}
			sealed, err := sealBackup(plain, passphrase, magic)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]byte{}, sealed...)
			got, err := RestoreSnapshot(sealed, passphrase)
			if err != nil || got.Format != format || !reflect.DeepEqual(got.State, want) {
				t.Fatal("authenticated legacy backup changed local or remote credentials", err)
			}
			if !bytes.Equal(sealed, original) || !bytes.Contains(raw, []byte(`"schema": 4`)) {
				t.Fatal("migration rewrote authenticated recovery material")
			}
		})
	}
}

func TestDeviceMigrationWritesNewGenerationAndRollbackPreservesOldBytes(t *testing.T) {
	for _, file := range deviceLegacyFixtures {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			migrated, err := DecodeState(raw)
			if err != nil {
				t.Fatal(err)
			}
			store, backend := newStore(t)
			if err = store.WithLock(func() error { return store.Apply(migrated) }); err != nil {
				t.Fatal(err)
			}
			original, _ := store.current()
			path := filepath.Join(store.Root, original, "state.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if err = store.WithLock(func() error { return store.Apply(loaded) }); err != nil {
				t.Fatal(err)
			}
			if current, _ := store.current(); current != original {
				t.Fatal("read/no-op migration created a new generation")
			}
			loaded.Nodes[0].Name += " renamed"
			if err = store.WithLock(func() error { return store.Apply(loaded) }); err != nil {
				t.Fatal(err)
			}
			current, _ := store.current()
			if current == original || backend.activations != 1 {
				t.Fatal("metadata write did not preserve generation or running service")
			}
			newRaw, err := os.ReadFile(filepath.Join(store.Root, current, "state.json"))
			if err != nil || !bytes.Contains(newRaw, []byte(fmt.Sprintf(`"schema":%d`, Schema))) {
				t.Fatal("meaningful write did not explicitly use current schema", err)
			}
			if err = store.WithLock(func() error { return store.Rollback() }); err != nil {
				t.Fatal(err)
			}
			restored, err := store.Load()
			// Rollback is a new management write, so UpdatedAt may record that
			// operation. All identities, original creation times and settings stay.
			comparison := restored.Clone()
			for i := range comparison.Nodes {
				comparison.Nodes[i].UpdatedAt = migrated.Nodes[i].UpdatedAt
			}
			if err != nil || !reflect.DeepEqual(comparison, migrated) || backend.activations != 1 {
				t.Fatal("rollback changed identities/topology or restarted unchanged runtime", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("write/rollback destroyed original recovery bytes", err)
			}
		})
	}
}
