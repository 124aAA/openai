package node

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestStateVersionEntryPreservesLegacyIdentityAndBytes(t *testing.T) {
	data, err := os.ReadFile("testdata/state-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := ReadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Validate(); err != nil {
		t.Fatal(err)
	}
	if st.Schema != Schema || st.Nodes[0].ID != "1111111111111111" || st.Nodes[0].Users[0].ID != "2222222222222222" || st.Nodes[0].CreatedAt != "" || st.Nodes[0].UpdatedAt != "" {
		t.Fatal("legacy identity or unknown timestamps changed")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, data) {
		t.Fatal("read migrated the file on disk")
	}
	for _, replacement := range []string{`"schema": ` + strconv.Itoa(Schema+1), `"schema": 999`} {
		newer := bytes.Replace(data, []byte(`"schema": 1`), []byte(replacement), 1)
		if _, err = DecodeState(newer); err == nil || !strings.Contains(err.Error(), "不支持状态版本") {
			t.Fatal("future schema was accepted", err)
		}
	}
	unknown := bytes.Replace(data, []byte(`"schema": 1,`), []byte(`"schema": 1, "future_policy": {"secret": "keep"},`), 1)
	if _, err = DecodeState(unknown); err == nil {
		t.Fatal("unknown field was discarded")
	}
	if err = os.WriteFile(path, unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadState(path); err == nil {
		t.Fatal("unknown field accepted on disk")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(after, unknown) {
		t.Fatal("rejected state lost original recovery data")
	}
}

func TestLegacySnapshotFixturesRestoreThroughVersionEntry(t *testing.T) {
	data, err := os.ReadFile("testdata/state-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := DecodeState(data)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed legacy State bytes are sealed with the existing v1 backup envelope.
	backup, err := sealBackup(data, "fixture passphrase 2026", backupMagic)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RestoreSnapshot(backup, "fixture passphrase 2026")
	if err != nil || got.Format != 1 || !reflect.DeepEqual(got.State, want) {
		t.Fatal("v1 snapshot identity changed", err)
	}
	encoded, err := json.Marshal(Snapshot{Format: 2, State: want, Service: "historical unit is data", ManagerVersion: "0.2.8"})
	if err != nil {
		t.Fatal(err)
	}
	got, err = RestorePlainSnapshot(encoded)
	if err != nil || got.Format != 2 || !reflect.DeepEqual(got.State, want) {
		t.Fatal("v2 snapshot identity changed", err)
	}
	newer := bytes.Replace(encoded, []byte(`"schema":`+strconv.Itoa(Schema)), []byte(`"schema":`+strconv.Itoa(Schema+1)), 1)
	if bytes.Equal(newer, encoded) {
		t.Fatal("future-state snapshot test did not change the current schema")
	}
	if _, err = RestorePlainSnapshot(newer); err == nil {
		t.Fatal("future state inside snapshot accepted")
	}
	newer = bytes.Replace(encoded, []byte(`"format":2`), []byte(`"format":3`), 1)
	if _, err = RestorePlainSnapshot(newer); err == nil {
		t.Fatal("future snapshot format accepted")
	}
}

func TestSchema6MigrationPreservesSavedIdentityWithoutWritingOrEnablingObservation(t *testing.T) {
	s := fixture(t)
	s.Schema = 6
	s.Nodes[0].CreatedAt, s.Nodes[0].UpdatedAt = "2026-10-01T01:02:03Z", "2026-10-02T03:04:05Z"
	s.Nodes[0].Tags = []string{"owned"}
	s.Devices = []DeviceProfile{{ID: "3333333333333333", Name: "legacy bound device", Bindings: []DeviceBinding{{NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[0].ID}}}}
	legacy, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "schema6.json")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(path)
	if err != nil || got.Schema != Schema || got.Observability != nil || got.CredentialExpirations != nil {
		t.Fatal("legacy read enabled a new feature or failed migration", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	comparable := got.Clone()
	comparable.Schema = 6
	if !reflect.DeepEqual(comparable, s) {
		t.Fatal("schema6 migration changed stable identities, secrets, timestamps or device bindings")
	}
	retained, _ := os.ReadFile(path)
	if !bytes.Equal(retained, legacy) {
		t.Fatal("schema6 query wrote upgraded bytes to the original file")
	}
	newBytes, err := json.Marshal(got)
	if err != nil || !bytes.Contains(newBytes, []byte(`"schema":`+strconv.Itoa(Schema))) || bytes.Contains(newBytes, []byte(`"observability"`)) || bytes.Contains(newBytes, []byte(`"credential_expirations"`)) {
		t.Fatal("upgraded serialization created an enabled endpoint or a deadline", err)
	}
	for _, field := range []string{"observability", "Observability", "obſervability", "credential_expirations", "Credential_Expirations", "credential_expirationſ"} {
		invalid := append([]byte(`{"`+field+`":null,`), legacy[1:]...)
		if _, err := DecodeState(invalid); err == nil {
			t.Fatalf("schema6 accepted version7 field %q, including null", field)
		}
	}
}

func TestSchema7RoundTripAndNestedUnknownOrDuplicateFieldsAreRejected(t *testing.T) {
	s := fixture(t)
	s.Observability = &CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: 19090, Secret: strings.Repeat("a", 48)}
	s.CredentialExpirations = []CredentialExpiration{{ID: "4444444444444444", NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[0].ID, ExpiresAt: "2030-01-02T03:04:05Z"}}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeState(encoded)
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("schema7 changed observation authentication or expiry stable identity", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(encoded, []byte(`"enabled":true,"listen":"127.0.0.1"`), []byte(`"enabled":true,"future_setting":1,"listen":"127.0.0.1"`), 1),
		bytes.Replace(encoded, []byte(`"expires_at":"2030-01-02T03:04:05Z"`), []byte(`"expires_at":"2030-01-02T03:04:05Z","future_quota":100`), 1),
		bytes.Replace(encoded, []byte(`"expires_at":"2030-01-02T03:04:05Z"`), []byte(`"expires_at":"2030-01-02T03:04:05Z","EXPIRES_AT":"2040-01-01T00:00:00Z"`), 1),
	} {
		if bytes.Equal(invalid, encoded) {
			t.Fatal("unknown/duplicate field fixture did not alter serialized State")
		}
		if _, err := DecodeState(invalid); err == nil {
			t.Fatal("nested future or duplicate field was silently discarded")
		}
	}
}
