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

func TestSnapshotEnvelopeRejectsEveryDuplicateMetadataField(t *testing.T) {
	snapshot := Snapshot{Format: 2, State: topologyFixture(t), Server: json.RawMessage(`{"log":{"level":"warn"}}`), ServerRaw: []byte("damaged original"), Service: "owned unit", ManagerVersion: "0.2.8", CreatedAt: "2026-10-18T00:00:00Z"}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	aliases := map[string]string{"state": "ſtate", "server_config": "ſerver_config", "invalid_server_config": "invalid_ſerver_config", "systemd_unit": "ſystemd_unit", "manager_version": "manager_verſion"}
	for name, value := range fields {
		spellings := []string{name, strings.ToUpper(name)}
		if alias := aliases[name]; alias != "" {
			spellings = append(spellings, alias)
		}
		for _, spelling := range spellings {
			t.Run(name+"/"+spelling, func(t *testing.T) {
				key, _ := json.Marshal(spelling)
				duplicate := append(append(append(append([]byte{}, raw[:len(raw)-1]...), ','), key...), ':')
				duplicate = append(duplicate, value...)
				duplicate = append(duplicate, '}')
				if _, err := RestorePlainSnapshot(duplicate); err == nil || !strings.Contains(err.Error(), "重复字段") {
					t.Fatal("duplicate snapshot metadata was accepted or misclassified", err)
				}
			})
		}
	}
}

func TestSnapshotEnvelopeCannotHideFutureFormatOrDiscardEarlierTopology(t *testing.T) {
	state, err := json.Marshal(topologyFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"schema":3,"core_version":"1.14.0","nodes":[]}`
	futureSchema := strconv.Itoa(Schema + 1)
	for name, raw := range map[string]string{
		"future envelope overwritten": `{"format":3,"format":2,"state":` + legacy + `}`,
		"future envelope case alias":  `{"format":3,"Format":2,"state":` + legacy + `}`,
		"future state overwritten":    `{"format":2,"state":{"schema":` + futureSchema + `},"state":` + legacy + `}`,
		"future state Unicode alias":  `{"format":2,"state":{"schema":` + futureSchema + `},"ſtate":` + legacy + `}`,
		"topology overwritten":        `{"format":2,"state":` + string(state) + `,"state":` + legacy + `}`,
		"hidden old-schema extension": `{"format":2,"state":{"schema":3,"egresses":[]},"state":` + legacy + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RestorePlainSnapshot([]byte(raw))
			if err == nil {
				t.Fatalf("ENVELOPE_DUPLICATE_WITNESS case=%q accepted=true decoded_format=%d decoded_schema=%d decoded_egresses=%d", name, got.Format, got.State.Schema, len(got.State.Egresses))
			}
			if !strings.Contains(err.Error(), "重复字段") {
				t.Fatal("ambiguous recovery input bypassed version or topology protection", err)
			}
		})
	}
	for name, raw := range map[string]string{
		"unknown envelope field": `{"format":2,"state":` + legacy + `,"future_metadata":{"secret":"retain"}}`,
		"unknown State field":    `{"format":2,"state":{"schema":4,"core_version":"1.14.0","nodes":[],"future_policy":{"secret":"retain"}}}`,
		"future format":          `{"format":3,"state":` + legacy + `}`,
		"future State":           `{"format":2,"state":{"schema":` + futureSchema + `,"core_version":"1.14.0","nodes":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RestorePlainSnapshot([]byte(raw)); err == nil {
				t.Fatal("unsupported recovery input was accepted")
			}
		})
	}
	// The authenticated QNBK2 path must reject the same ambiguity after decryption,
	// not merely the explicit local plaintext recovery entry point.
	ambiguous := []byte(`{"format":2,"state":{"schema":` + futureSchema + `},"State":` + legacy + `}`)
	sealed, err := sealBackup(ambiguous, "snapshot envelope duplicate test", []byte("QNBK2\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreSnapshot(sealed, "snapshot envelope duplicate test"); err == nil || !strings.Contains(err.Error(), "重复字段") {
		t.Fatal("authenticated snapshot bypassed duplicate State protection", err)
	}
}

func TestSnapshotEnvelopeKeepsLegacyIdentityAndOriginalServerEvidence(t *testing.T) {
	// Duplicate fields in the captured core configuration are original evidence,
	// not manager metadata. Do not normalize or reject those saved bytes here.
	server := []byte(`{ "schema":5, "schema":4, "outbounds":[{"type":"direct","tag":"first","tag":"last"}] }`)
	for _, file := range []string{"state-v1.json", "state-v2-hy2-performance.json", "state-v3-endpoints.json"} {
		t.Run(file, func(t *testing.T) {
			original, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte{}, original...)
			want, err := DecodeState(original)
			if err != nil {
				t.Fatal(err)
			}
			plain := append([]byte(`{"format":2,"state":`), original...)
			plain = append(plain, []byte(`,"server_config":`)...)
			plain = append(plain, server...)
			plain = append(plain, '}')
			got, err := RestorePlainSnapshot(plain)
			if err != nil || got.Format != 2 || !reflect.DeepEqual(got.State, want) || !bytes.Equal(got.Server, server) {
				t.Fatal("legacy identity or original core evidence changed", err)
			}
			if !bytes.Equal(original, before) {
				t.Fatal("restore mutated original State bytes")
			}
			legacy, err := decodeSnapshot(original, true)
			if err != nil || legacy.Format != 1 || !reflect.DeepEqual(legacy.State, want) {
				t.Fatal("legacy envelope migration changed identity", err)
			}
		})
	}
	current := topologyFixture(t)
	snapshot := Snapshot{Format: 2, State: current, Server: server, Service: "original unit"}
	sealed, err := BackupSnapshot(snapshot, "snapshot envelope recovery test")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreSnapshot(sealed, "snapshot envelope recovery test")
	if err != nil || !reflect.DeepEqual(restored.State, current) || !equalJSON(restored, snapshot) {
		t.Fatal("authenticated v2 recovery changed topology, identities, or evidence", err)
	}
	plain, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Case-folded single keys remain readable, as before; only ambiguous aliases
	// are rejected. State itself keeps using its stricter independent decoder.
	plain = bytes.Replace(plain, []byte(`"state":`), []byte(`"ſtate":`), 1)
	if got, err := RestorePlainSnapshot(plain); err != nil || !reflect.DeepEqual(got.State, current) {
		t.Fatal("single case-folded envelope key lost existing compatibility", err)
	}
}
