package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func TestProbeProfileBindsActualInternalPathWithoutLandingCredentials(t *testing.T) {
	a, initial := batchFixture(t)
	legacy, err := a.probeProfile(initial.Nodes[0].ID, "")
	if err != nil || legacy.Version != 1 || legacy.ServerPathSHA256 != "" {
		t.Fatal("old direct entry did not retain profile v1", err)
	}
	first, upstream := topologyRemoteSS("3333333333333333"), topologyRemoteSS("4444444444444444")
	first.Detour = upstream.ID
	file := topologyFile(t, topologyOperation{Action: "egress-put", Egress: &first}, topologyOperation{Action: "egress-put", Egress: &upstream}, topologyOperation{Action: "route-set", NodeID: initial.Nodes[0].ID, EgressID: &first.ID})
	topologyCommand(t, a, "topology", "apply", "--file", file)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	gen, raw := savedBatchState(t, a)
	p, err := a.probeProfile(initial.Nodes[0].ID, "")
	if err != nil || p.Version != 2 || p.ServerPathSHA256 == "" || p.ConfigSHA256 != legacy.ConfigSHA256 || !bytes.Equal(p.Outbound, legacy.Outbound) {
		t.Fatal("internal path binding changed entrance outbound or lost explicit v2 identity", err)
	}
	encoded, _ := json.Marshal(p)
	for _, secret := range []string{first.Shadowsocks.Password, upstream.Shadowsocks.Password, first.Server} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("portable entry profile leaked an internal landing credential or address")
		}
	}
	unchanged, err := a.probeProfile(initial.Nodes[1].ID, "")
	if err != nil || unchanged.Version != 1 || unchanged.ServerPathSHA256 != "" {
		t.Fatal("unrelated direct entry changed portable format", err)
	}
	afterGen, after := savedBatchState(t, a)
	if gen != afterGen || !bytes.Equal(raw, after) || backend.checks+backend.starts+backend.stops+backend.activeCalls != 0 {
		t.Fatal("profile query changed runtime, state or recovery material")
	}
}

func TestPublicFingerprintScopesActualTopologyAndPreservesLegacyBytes(t *testing.T) {
	_, s := batchFixture(t)
	n := s.Nodes[0]
	legacy := s
	legacy.Nodes = []node.Node{n}
	want := stateFingerprint(legacy)
	if publicFingerprint(s, n) != want {
		t.Fatal("historical no-topology fingerprint bytes changed")
	}
	primary, upstream, backup := topologyRemoteSS("3333333333333333"), topologyRemoteSS("4444444444444444"), topologyRemoteSS("5555555555555555")
	primary.Detour = upstream.ID
	s.Egresses = []node.Egress{primary, upstream, backup}
	s.Forwards = []node.PortForward{{ID: "6666666666666666", Name: "unrelated", Listen: "127.0.0.1", Port: 35555, Network: "tcp", TargetHost: "203.0.113.40", TargetPort: 443, Enabled: true}}
	if publicFingerprint(s, n) != want {
		t.Fatal("unused topology invalidated an existing direct entry check")
	}
	p := node.EgressPolicy{ID: "7777777777777777", Name: "explicit-primary-backup", Mode: "failover", Primary: primary.ID, Backup: backup.ID, Health: &node.EgressHealth{URL: "https://controlled.example.test/health", UDPAddress: "203.0.113.40:35557", FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 30, TimeoutSeconds: 2}}
	s.EgressPolicies, s.Nodes[0].EgressID = []node.EgressPolicy{p}, p.ID
	n = s.Nodes[0]
	before := publicFingerprint(s, n)
	other := s.Clone()
	other.Egresses[2].Server = "203.0.113.99" // Dormant backup settings.
	other.Forwards[0].TargetPort = 8443
	other.Nodes[1].Port++
	if publicFingerprint(other, n) != before {
		t.Fatal("unrelated forward, entry or dormant backup invalidated the chosen path")
	}
	for _, change := range []func(*node.State){
		func(s *node.State) { s.Egresses[0].Server = "203.0.113.99" },
		func(s *node.State) { s.Egresses[1].Port++ },
		func(s *node.State) { s.EgressPolicies[0].Selected = "backup" },
	} {
		changed := s.Clone()
		change(&changed)
		if publicFingerprint(changed, n) == before {
			t.Fatal("changed selected path did not invalidate the old manual check")
		}
	}
}
