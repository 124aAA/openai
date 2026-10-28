package node

import (
	"strings"
	"testing"
)

func TestTopologyWireGuardReceiveChecksDormantPolicyCandidates(t *testing.T) {
	st := NewState()
	a := topologySOCKS("3333333333333333", "receive-primary")
	b := topologySOCKS("4444444444444444", "receive-backup")
	b.Server = "192.0.2.20"
	wg := topologyWG(t)
	policy := EgressPolicy{ID: "5555555555555555", Name: "receive-policy", Mode: "failover", Primary: a.ID, Backup: b.ID, Health: &EgressHealth{URL: "https://health.example/status", UDPAddress: "192.0.2.30:7000", FailureThreshold: 2, RecoveryThreshold: 2, CooldownSeconds: 30, TimeoutSeconds: 2}}
	wg.WireGuard.ReceiveEgressID = policy.ID
	st.Egresses, st.EgressPolicies = []Egress{a, b, wg}, []EgressPolicy{policy}
	if err := st.Validate(); err != nil {
		t.Fatal("independent receive primary/backup candidates rejected", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*State)
	}{
		{"dormant backup is receiver", func(st *State) { st.EgressPolicies[0].Backup = wg.ID }},
		{"dormant backup detours through receiver", func(st *State) { st.Egresses[1].Detour = wg.ID }},
		{"dormant primary is receiver", func(st *State) {
			st.EgressPolicies[0].Primary, st.EgressPolicies[0].Selected = wg.ID, "backup"
		}},
		{"dormant primary detours through receiver", func(st *State) {
			st.Egresses[0].Detour, st.EgressPolicies[0].Selected = wg.ID, "backup"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := st.Clone()
			tc.edit(&next)
			if err := next.Validate(); err == nil || !strings.Contains(err.Error(), "自身隧道") {
				t.Fatal("unselected self-receive path accepted or misclassified", err)
			}
		})
	}
	st.Egresses[1].Detour = a.ID
	if err := st.Validate(); err != nil {
		t.Fatal("valid explicitly shared detour was mistaken for unknown cross-host mesh cycle", err)
	}
	st.EgressPolicies[0].Selected = "backup"
	if err := st.Validate(); err != nil {
		t.Fatal("valid backup selection rejected", err)
	}
	st.EgressPolicies[0].Mode, st.EgressPolicies[0].Backup, st.EgressPolicies[0].Selected, st.EgressPolicies[0].Health = "fixed", "", "", nil
	if err := st.Validate(); err != nil {
		t.Fatal("valid fixed receive policy rejected", err)
	}
}
