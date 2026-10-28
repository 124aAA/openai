package node

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceChangesKeepRunningAndStoppedBackend(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "stopped"}[stopped], func(t *testing.T) {
			s, b, st := impactStore(t)
			if stopped {
				if err := b.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			starts, stops := b.activations, b.stops
			key := st.Nodes[0].Users[0].UUID
			st.Nodes[0].Tags = []string{"personal"}
			st.Devices = []DeviceProfile{{ID: "eeeeeeeeeeeeeeee", Name: "phone", Bindings: []DeviceBinding{{NodeID: st.Nodes[0].ID, UserID: st.Nodes[0].Users[0].ID}}, NodeTags: []string{"personal"}}}
			if err := s.WithLock(func() error {
				impact, e := s.Preview(st)
				if e != nil {
					return e
				}
				if !impact.ClientExport || impact.NeedsRestart || impact.ServerRuntime || impact.HostEffects {
					t.Fatalf("device impact %+v", impact)
				}
				return s.Apply(st)
			}); err != nil {
				t.Fatal(err)
			}
			if b.activations != starts || b.stops != stops || b.active == stopped {
				t.Fatal("device edit changed service state")
			}
			got, _ := s.Load()
			if got.Nodes[0].Users[0].UUID != key || len(got.Devices) != 1 {
				t.Fatal("device edit changed credential or lost profile")
			}
		})
	}
}

func TestDevicePublicationFailureDoesNotUndoCommittedProxyState(t *testing.T) {
	s, b, st := impactStore(t)
	starts := b.activations
	s.AfterCommit = func(State) error { return errors.New("injected publication disk failure") }
	st.Nodes[0].Tags = []string{"persist-even-if-publication-fails"}
	err := s.WithLock(func() error { return s.Apply(st) })
	if err == nil || !strings.Contains(err.Error(), "已提交") {
		t.Fatal("committed vs failed output not distinguished", err)
	}
	got, _ := s.Load()
	if len(got.Nodes[0].Tags) != 1 || b.activations != starts {
		t.Fatal("publication failure undid State or restarted core")
	}
	if _, e := os.Lstat(filepath.Join(s.Root, "transaction.json")); !os.IsNotExist(e) {
		t.Fatal("committed state retained misleading transaction", e)
	}
	called := 0
	s.AfterCommit = func(State) error { called++; return nil }
	if e := s.WithLock(func() error { return s.Apply(got) }); e != nil || called != 1 {
		t.Fatal("explicit repeated apply did not retry publication", e)
	}
	if e := s.Inspect(func() error { _, e := s.Load(); return e }); e != nil || called != 1 {
		t.Fatal("query published or repaired", e)
	}
}

func TestDeviceDisableIsExactAndRejectsSharedCredentialsAtomically(t *testing.T) {
	st := fixture(t)
	n := &st.Nodes[0]
	n.Users = append(n.Users, NewUser("unrelated", n.Protocol))
	first := n.Users[0]
	other := n.Users[1]
	p := DeviceProfile{ID: "dddddddddddddddd", Name: "phone", Bindings: []DeviceBinding{{NodeID: n.ID, UserID: first.ID}}}
	st.Devices = []DeviceProfile{p, {ID: "cccccccccccccccc", Name: "shared", Bindings: p.Bindings}}
	before := st.Clone()
	if e := DisableDeviceCredentials(&st, p.ID); e == nil || !equalJSON(before, st) {
		t.Fatal("shared disable partly changed State")
	}
	st.Devices = st.Devices[:1]
	if e := DisableDeviceCredentials(&st, p.ID); e != nil {
		t.Fatal(e)
	}
	if len(st.Nodes[0].Users) != 1 || st.Nodes[0].Users[0] != other || !st.Nodes[0].Enabled || !st.Devices[0].Disabled {
		t.Fatal("exclusive disable touched unrelated user")
	}
	st.Devices[0].Bindings = []DeviceBinding{{NodeID: st.Nodes[0].ID, UserID: other.ID}}
	st.Devices[0].Disabled = false
	if e := DisableDeviceCredentials(&st, p.ID); e != nil {
		t.Fatal(e)
	}
	if st.Nodes[0].Enabled || st.Nodes[0].Users[0] != other {
		t.Fatal("last credential not preserved behind disabled listener")
	}
}

func TestDeviceDownloadDisabledStillProtectsSharedCredentials(t *testing.T) {
	for _, multipleUsers := range []bool{false, true} {
		t.Run(fmt.Sprintf("multiple_users=%t", multipleUsers), func(t *testing.T) {
			st := fixture(t)
			n := &st.Nodes[0]
			if multipleUsers {
				n.Users = append(n.Users, NewUser("unrelated", n.Protocol))
			}
			binding := []DeviceBinding{{NodeID: n.ID, UserID: n.Users[0].ID}}
			st.Devices = []DeviceProfile{
				{ID: "dddddddddddddddd", Name: "phone", Bindings: binding},
				{ID: "cccccccccccccccc", Name: "download-revoked", Disabled: true, Bindings: binding},
			}
			before := st.Clone()
			if err := DisableDeviceCredentials(&st, st.Devices[0].ID); err == nil {
				t.Fatal("download revocation was mistaken for proxy credential revocation")
			}
			if !equalJSON(before, st) {
				t.Fatal("shared credential rejection changed another device, user or listener")
			}
		})
	}
}

func TestDeviceTokenAndAuthorizationRedaction(t *testing.T) {
	secret := strings.Repeat("a", 64)
	input := `https://sub.example/s/` + secret + `/mihomo` + "\nAuthorization: Bearer " + secret + "\nsubscription_token=" + secret + "\n" + `{"api_key":"` + secret + `","token":"` + secret + `"}`
	if out := Redact(input); bytes.Contains([]byte(out), []byte(secret)) {
		t.Fatal("subscription or DNS credential leaked")
	}
}

func TestDeviceDisabledHistoricalNodeIDDoesNotMatchAnotherNodeName(t *testing.T) {
	st := fixture(t)
	missingID := "babebabebabebabe"
	st.Nodes[0].Name = missingID
	st.Devices = []DeviceProfile{{ID: "dddddddddddddddd", Name: "old-device", Disabled: true, Bindings: []DeviceBinding{{NodeID: missingID, UserID: st.Nodes[0].Users[0].ID}}}}
	before := st.Clone()
	if e := DisableDeviceCredentials(&st, st.Devices[0].ID); e != nil {
		t.Fatal(e)
	}
	if !equalJSON(before.Nodes, st.Nodes) {
		t.Fatal("historical stable ID resolved through another node's display name")
	}
}
