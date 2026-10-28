package node

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func expiryFixture(t *testing.T) (State, time.Time) {
	t.Helper()
	s := NewState()
	n := ssFixture()
	n.ID, n.Name = "1000000000000001", "expiry source"
	n.Users[0].ID, n.Users[1].ID = "2000000000000001", "2000000000000002"
	s.Nodes = []Node{n}
	s.Devices = []DeviceProfile{{ID: "3000000000000001", Name: "multi", Bindings: []DeviceBinding{{NodeID: n.ID, UserID: n.Users[0].ID}, {NodeID: n.ID, UserID: n.Users[1].ID}}}}
	now, _ := time.Parse(time.RFC3339, "2030-01-02T03:04:05Z")
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s, now
}

func expiryEntry(s State, at time.Time) CredentialExpiration {
	return CredentialExpiration{ID: "4000000000000001", NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[0].ID, ExpiresAt: at.UTC().Format(time.RFC3339Nano)}
}

func TestCredentialExpirationRequiresStableReferencesAndUTC(t *testing.T) {
	for _, invalid := range []string{"2030-01-02", "2030-01-02T03:04:05", "2030-01-02T03:04:05+00:00", "2030-01-02T11:04:05+08:00", "2019-01-02T03:04:05Z", "2030-01-02T03:04:05,123Z", "never"} {
		if _, err := ParseExpirationTime(invalid); err == nil {
			t.Fatalf("accepted ambiguous/noncanonical timestamp %q", invalid)
		}
	}
	if _, err := ParseExpirationTime("2030-01-02T03:04:05.000Z"); err != nil {
		t.Fatal("RFC3339 fractional seconds rejected", err)
	}
	for _, kind := range []string{"node-name", "user-name", "device-name", "orphan-node", "orphan-user", "orphan-device", "unbound-device", "duplicate-id", "duplicate-target", "completed-in-future", "completed-live-user"} {
		t.Run(kind, func(t *testing.T) {
			s, now := expiryFixture(t)
			e := expiryEntry(s, now)
			s.CredentialExpirations = []CredentialExpiration{e}
			switch kind {
			case "node-name":
				s.CredentialExpirations[0].NodeID = s.Nodes[0].Name
			case "user-name":
				s.CredentialExpirations[0].UserID = s.Nodes[0].Users[0].Name
			case "device-name":
				s.CredentialExpirations[0].DeviceID = s.Devices[0].Name
			case "orphan-node":
				s.CredentialExpirations[0].NodeID = "ffffffffffffffff"
			case "orphan-user":
				s.CredentialExpirations[0].UserID = "ffffffffffffffff"
			case "orphan-device":
				s.CredentialExpirations[0].DeviceID = "ffffffffffffffff"
			case "unbound-device":
				s.Devices[0].Bindings = s.Devices[0].Bindings[1:]
				s.CredentialExpirations[0].DeviceID = s.Devices[0].ID
			case "duplicate-id":
				other := e
				other.UserID = s.Nodes[0].Users[1].ID
				s.CredentialExpirations = append(s.CredentialExpirations, other)
			case "duplicate-target":
				other := e
				other.ID, other.DeviceID = "4000000000000002", s.Devices[0].ID
				s.CredentialExpirations = append(s.CredentialExpirations, other)
			case "completed-in-future":
				s.CredentialExpirations[0].DisabledAt = now.Add(-time.Second).Format(time.RFC3339)
			case "completed-live-user":
				s.CredentialExpirations[0].DisabledAt = e.ExpiresAt
			}
			if err := s.Validate(); err == nil {
				t.Fatal("invalid deadline/reference accepted")
			}
		})
	}
}

func TestCredentialExpirationBoundaryAndReadOnlyPlan(t *testing.T) {
	s, now := expiryFixture(t)
	e := expiryEntry(s, now)
	if err := SetCredentialExpiration(&s, e); err != nil {
		t.Fatal(err)
	}
	before := s.Clone()
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		plan, err := PlanExpirations(s, now.Add(delta))
		if err != nil || len(plan.Items) != 1 || plan.Items[0].Due != (delta >= 0) {
			t.Fatal("deadline boundary", plan, err)
		}
	}
	if !reflect.DeepEqual(s, before) {
		t.Fatal("planning modified proxy credentials, bindings or deadlines")
	}
	for _, clock := range []time.Time{time.Time{}, time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, _, err := ApplyDueExpirations(s, clock); err == nil {
			t.Fatal("untrusted old/zero clock accepted")
		}
	}
	if _, _, err := ApplyDueExpirationsSince(s, now, now.Add(time.Nanosecond)); err == nil {
		t.Fatal("clock earlier than last observation accepted")
	}
}

func TestCredentialExpirationPreservesOtherCredentialsBindingsAndDownloadAccess(t *testing.T) {
	s, now := expiryFixture(t)
	e := expiryEntry(s, now)
	e.DeviceID = s.Devices[0].ID
	if err := SetCredentialExpiration(&s, e); err != nil {
		t.Fatal(err)
	}
	before := s.Clone()
	c, p, err := ApplyDueExpirations(s, now)
	if err != nil || p.Ready != 1 || p.Blocked != 0 {
		t.Fatal(p, err)
	}
	if !reflect.DeepEqual(before, s) {
		t.Fatal("candidate construction modified input")
	}
	if len(c.Nodes[0].Users) != 1 || !reflect.DeepEqual(c.Nodes[0].Users[0], before.Nodes[0].Users[1]) || !c.Nodes[0].Enabled || !reflect.DeepEqual(c.Nodes[0].Shadowsocks, before.Nodes[0].Shadowsocks) {
		t.Fatal("unrelated credential/server secret/listener changed")
	}
	if c.Devices[0].Disabled || len(c.Devices[0].Bindings) != 1 || c.Devices[0].Bindings[0] != before.Devices[0].Bindings[1] {
		t.Fatal("expiration disabled unrelated device bindings or download access")
	}
	if c.CredentialExpirations[0].DisabledAt != now.Format(time.RFC3339) {
		t.Fatal("missing authoritative stop record")
	}
	again, plan, err := ApplyDueExpirations(c, now.Add(time.Hour))
	if err != nil || plan.Ready != 0 || !reflect.DeepEqual(c, again) {
		t.Fatal("completed record was applied a second time", err)
	}
	if err := SetCredentialExpiration(&c, e); err == nil {
		t.Fatal("quietly renewed completed deadline")
	}
	if err := RemoveCredentialExpiration(&c, e.ID); err != nil || len(c.Nodes[0].Users) != 1 || len(c.Devices[0].Bindings) != 1 {
		t.Fatal("unscheduling restored deleted credential/binding", err)
	}
}

func TestCredentialExpirationSharedDeviceBlocksWholeBatchIncludingDisabledSharers(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "active-sharer", true: "disabled-sharer"}[disabled], func(t *testing.T) {
			s, now := expiryFixture(t)
			s.Devices = append(s.Devices, DeviceProfile{ID: "3000000000000002", Name: "sharer", Disabled: disabled, Bindings: []DeviceBinding{s.Devices[0].Bindings[0]}})
			e := expiryEntry(s, now)
			e.DeviceID = s.Devices[0].ID
			other := e
			other.ID, other.UserID, other.DeviceID = "4000000000000002", s.Nodes[0].Users[1].ID, ""
			s.CredentialExpirations = []CredentialExpiration{other, e}
			before := s.Clone()
			c, p, err := ApplyDueExpirations(s, now)
			if err == nil || p.Due != 2 || p.Ready != 1 || p.Blocked != 1 || len(p.Items) != 2 || !reflect.DeepEqual(before, s) || !reflect.DeepEqual(c, s) {
				t.Fatal("shared credential batch was partially applied", p, err)
			}
			if len(p.Items[0].AffectedDeviceIDs) != 2 || !strings.Contains(p.Items[0].Reason, "下载") {
				t.Fatal("shared-credential refusal concealed affected devices/token distinction")
			}
		})
	}
}

func TestCredentialExpirationUserScopeRemovesOnlySharedCredential(t *testing.T) {
	s, now := expiryFixture(t)
	s.Devices = append(s.Devices, DeviceProfile{ID: "3000000000000002", Name: "last-binding", Bindings: []DeviceBinding{s.Devices[0].Bindings[0]}})
	s.CredentialExpirations = []CredentialExpiration{expiryEntry(s, now)}
	c, p, err := ApplyDueExpirations(s, now)
	if err != nil || p.Blocked != 0 || len(p.Items[0].AffectedDeviceIDs) != 2 {
		t.Fatal(p, err)
	}
	if c.Devices[0].Disabled || len(c.Devices[0].Bindings) != 1 || !c.Devices[1].Disabled || len(c.Devices[1].Bindings) != 1 || len(c.Nodes[0].Users) != 1 {
		t.Fatal("user expiry lost unrelated binding or last-binding historical identity")
	}
}

func TestCredentialExpirationAllUsersStopsListenerAndExplicitEnableIsRejected(t *testing.T) {
	s, now := expiryFixture(t)
	e := expiryEntry(s, now)
	other := e
	other.ID, other.UserID = "4000000000000002", s.Nodes[0].Users[1].ID
	s.CredentialExpirations = []CredentialExpiration{other, e}
	c, p, err := ApplyDueExpirations(s, now)
	if err != nil || p.Ready != 2 || c.Nodes[0].Enabled || len(c.Nodes[0].Users) != 1 || !c.Devices[0].Disabled {
		t.Fatal("last credential stop failed", p, err)
	}
	if !p.Items[0].StopsNode || !p.Items[1].StopsNode {
		t.Fatal("preview did not disclose cumulative all-user listener stop")
	}
	c.Nodes[0].Enabled = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "显式移除") {
		t.Fatal("ordinary enable silently revived expired last credential", err)
	}
	c.Nodes[0].Enabled = false
	if _, _, err := ApplyDueExpirations(c, now.Add(-time.Nanosecond)); err == nil {
		t.Fatal("clock before existing stop record accepted")
	}
	c.Nodes = nil
	if err := c.Validate(); err == nil {
		t.Fatal("deleted node concealed completed expiry history reference")
	}
}

func TestCredentialExpirationOrdinaryEditsDoNotRenewOrApply(t *testing.T) {
	s, now := expiryFixture(t)
	e := expiryEntry(s, now.Add(-time.Hour))
	s.CredentialExpirations = []CredentialExpiration{e}
	s.Nodes[0].Name, s.Nodes[0].Host = "display edit", "203.0.113.8"
	s.Devices[0].Name = "device display edit"
	if err := s.Validate(); err != nil || s.CredentialExpirations[0] != e || len(s.Nodes[0].Users) != 2 || s.Devices[0].Disabled {
		t.Fatal("ordinary validation edited an expired credential or deadline", err)
	}
	s.Nodes[0].Users = s.Nodes[0].Users[1:]
	s.Devices[0].Disabled = true
	if err := s.Validate(); err == nil {
		t.Fatal("disabled device allowed pending plan's user deletion")
	}
}
