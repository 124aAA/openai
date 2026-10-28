package node

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func certificateEd25519Fixture(t *testing.T) State {
	t.Helper()
	s := hyFixture(t)
	cert, key := certificateTestPair(t, time.Now(), false, true)
	s.Nodes[0].Certificate = &Certificate{Mode: "pem", ServerName: "hy2.example.test", CertPEM: cert, KeyPEM: key}
	s.Nodes[0].HY2 = &HY2Performance{Client: &HY2Transport{DisableChromeParrot: hyBool(true)}}
	return s
}

func TestCertificateEd25519LegacyStateBackupsAndMetadataPreserveExplicitClientChoice(t *testing.T) {
	legacy := certificateEd25519Fixture(t)
	legacy.Schema = 5
	before := legacy.Clone()
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, err := ReadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrated.Validate(); err != nil {
		t.Fatal("legacy explicit native QUIC state rejected", err)
	}
	if err = migrated.ValidateForRestore(); err != nil {
		t.Fatal("legacy Ed25519 recovery asset rejected", err)
	}
	if !reflect.DeepEqual(legacy, before) {
		t.Fatal("legacy source memory changed")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("read-only migration rewrote Ed25519 recovery bytes", err)
	}
	oldNode, node := legacy.Nodes[0], migrated.Nodes[0]
	if oldNode.ID != node.ID || !reflect.DeepEqual(oldNode.Users, node.Users) || !reflect.DeepEqual(oldNode.Certificate, node.Certificate) || !reflect.DeepEqual(oldNode.HY2, node.HY2) || URI(oldNode, oldNode.Users[0]) != URI(node, node.Users[0]) || !equalJSON(Outbound(oldNode, oldNode.Users[0]), Outbound(node, node.Users[0])) {
		t.Fatal("legacy Ed25519 identity or explicit client choice changed")
	}
	for _, magic := range [][]byte{backupMagic, []byte("QNBK2\x00")} {
		plain := raw
		if bytes.Equal(magic, []byte("QNBK2\x00")) {
			plain = append(append([]byte(`{"format":2,"state":`), raw...), '}')
		}
		encrypted, err := sealBackup(plain, "Ed25519 legacy recovery passphrase", magic)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := RestoreSnapshot(encrypted, "Ed25519 legacy recovery passphrase")
		if err != nil || !reflect.DeepEqual(restored.State, migrated) {
			t.Fatal("legacy encrypted Ed25519 backup did not restore identity", string(magic), err)
		}
	}
	for _, active := range []bool{true, false} {
		store, backend := newStore(t)
		if err = store.WithLock(func() error { return store.Apply(migrated) }); err != nil {
			t.Fatal(err)
		}
		if !active {
			if err = backend.Stop(); err != nil {
				t.Fatal(err)
			}
		}
		activations := backend.activations
		loaded, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		loaded.Nodes[0].Name += " renamed"
		impact, err := store.Preview(loaded)
		if err != nil || impact.NeedsRestart {
			t.Fatal("Ed25519 metadata edit changed server runtime", err)
		}
		if err = store.WithLock(func() error { return store.Apply(loaded) }); err != nil {
			t.Fatal("Ed25519 metadata edit rejected", err)
		}
		if backend.activations != activations || backend.active != active {
			t.Fatal("metadata edit changed prior running state")
		}
		restored, err := store.Load()
		if err != nil || restored.Nodes[0].Certificate.KeyPEM != oldNode.Certificate.KeyPEM || !reflect.DeepEqual(restored.Nodes[0].Users, oldNode.Users) || !reflect.DeepEqual(restored.Nodes[0].HY2, oldNode.HY2) {
			t.Fatal("metadata edit changed Ed25519 material or proxy identity", err)
		}
	}
}

func TestCertificateEd25519ClientRestrictionIsSpecificAndCannotBeLossyBypassed(t *testing.T) {
	s := certificateEd25519Fixture(t)
	n := s.Nodes[0]
	u := n.Users[0]
	p := DeviceProfile{ID: "7777777777777777", Name: "Ed25519 device", Bindings: []DeviceBinding{{NodeID: n.ID, UserID: u.ID}}}
	for _, choice := range []string{"default", "explicit-false", "explicit-true"} {
		t.Run(choice, func(t *testing.T) {
			selected := s.Clone()
			switch choice {
			case "default":
				selected.Nodes[0].HY2 = nil
			case "explicit-false":
				selected.Nodes[0].HY2.Client.DisableChromeParrot = hyBool(false)
			}
			node := selected.Nodes[0]
			before := selected.Clone()
			if err := selected.Validate(); err != nil {
				t.Fatal("server validation applied client fingerprint restriction", err)
			}
			if err := selected.ValidateForRestore(); err != nil {
				t.Fatal("recovery validation applied client restriction", err)
			}
			if _, err := Server(selected, "/owned/root"); err != nil {
				t.Fatal("server config rejected valid Ed25519 certificate", err)
			}
			expectedFailure := choice != "explicit-true"
			for _, lossy := range []bool{false, true} {
				single, err := ExportWithCapabilities(node, u, "sing-box", "1.14.3", nil, lossy)
				if (err != nil) != expectedFailure {
					t.Fatal("sing-box certificate/fingerprint compatibility gate wrong", choice, lossy, err)
				}
				if expectedFailure && (!strings.Contains(err.Error(), "Ed25519") || len(single.Data) != 0) {
					t.Fatal("incompatible config escaped exact error boundary")
				}
				for _, format := range []string{"sing-box", "sing-box-outbounds"} {
					result, err := ExportDeviceProfile(selected, p, format, "1.14.3", lossy)
					if (err != nil) != expectedFailure {
						t.Fatal("device export bypassed client certificate gate", format, choice, lossy, err)
					}
					if expectedFailure && len(result.Content) != 0 {
						t.Fatal("failed device emitted partial private config")
					}
				}
			}
			if _, err := Export(node, u, "sing-box"); (err != nil) != expectedFailure {
				t.Fatal("ordinary complete export bypassed certificate gate", choice, err)
			}
			if choice != "explicit-false" {
				for _, format := range []string{"mihomo", "provider"} {
					if _, err := ExportWithCapabilities(node, u, format, "1.19.30", nil, false); err != nil {
						t.Fatal("Mihomo native QUIC incorrectly inherited Chrome restriction", format, choice, err)
					}
				}
			}
			if choice == "explicit-true" {
				if _, err := Export(node, u, "uri"); err == nil || !strings.Contains(err.Error(), "性能选择") {
					t.Fatal("URI silently lost required explicit native QUIC choice", err)
				}
			}
			if !reflect.DeepEqual(selected, before) {
				t.Fatal("validation/export silently changed fingerprint choice")
			}
		})
	}
}
