package node

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The four new listeners use the same stable-ID route graph as the original
// protocols. Their client profiles contain only entry credentials; the remote
// egress credentials belong exclusively to the server configuration.
func TestProtocolExpansionTopologyRoutesUseStableIDsAndKeepEgressSecrets(t *testing.T) {
	s, profile := protocolExpansionDeviceFixture(t)
	const egressID = "3333333333333333"
	s.Egresses = []Egress{
		topologySOCKS(egressID, "selected remote"),
		topologySOCKS("4444444444444444", "unused remote"),
	}
	s.Egresses[1].Socks.Password = "UNUSED-EGRESS-PASSWORD"
	want := make(map[string]string)
	for i := 0; i < 4; i++ {
		s.Nodes[i].EgressID = egressID
		want[s.Nodes[i].ID] = EgressTag(egressID)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	server, err := Server(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
		Route struct {
			Rules []struct {
				Inbound  []string `json:"inbound"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(server, &rendered); err != nil {
		t.Fatal(err)
	}
	if len(rendered.Inbounds) != len(s.Nodes) || len(rendered.Outbounds) != 2 ||
		rendered.Outbounds[0].Tag != "direct" || rendered.Outbounds[1].Tag != EgressTag(egressID) ||
		len(rendered.Route.Rules) != len(want) {
		t.Fatalf("selected route graph differs from four bound nodes: %s", server)
	}
	for i, inbound := range rendered.Inbounds {
		if inbound.Tag != s.Nodes[i].ID {
			t.Fatalf("node %s lost its stable inbound ID: %q", s.Nodes[i].Protocol, inbound.Tag)
		}
	}
	for _, rule := range rendered.Route.Rules {
		if len(rule.Inbound) != 1 || want[rule.Inbound[0]] != rule.Outbound {
			t.Fatalf("a new protocol lost its explicit remote route: %+v", rule)
		}
		delete(want, rule.Inbound[0])
	}
	if len(want) != 0 || bytes.Contains(server, []byte(s.Egresses[1].Socks.Password)) {
		t.Fatal("unused remote rendered or an entry had no route", want)
	}
	client, err := ExportDeviceProfile(s, profile, "sing-box", "1.14.3", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range s.Egresses {
		if bytes.Contains(client.Content, []byte(e.Socks.Username)) || bytes.Contains(client.Content, []byte(e.Socks.Password)) {
			t.Fatal("server-side remote credential leaked into the client profile")
		}
	}
}

func TestProtocolExpansionTopologyRejectsTCPOnlyExitForUDPBusiness(t *testing.T) {
	for _, protocol := range []string{"anytls", "trojan", "ss-aead", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			s, _ := protocolExpansionDeviceFixture(t)
			e := topologySOCKS("3333333333333333", "TCP-only remote")
			e.UDP = false
			s.Egresses = []Egress{e}
			for i := range s.Nodes {
				if s.Nodes[i].Protocol == protocol {
					s.Nodes[i].EgressID = e.ID
				}
			}
			if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "UDP") {
				t.Fatal("TCP-only exit accepted for UDP-capable business traffic", err)
			}
			if _, err := Server(s, t.TempDir()); err == nil {
				t.Fatal("invalid exit rendered and could fall through to direct")
			}
			s.Egresses[0].UDP = true
			if err := s.Validate(); err != nil {
				t.Fatal("UDP-capable exit rejected", err)
			}
			// Removing a referenced exit must fail instead of silently sending
			// this new protocol's traffic to the historical direct final route.
			s.Egresses = nil
			if err := s.Validate(); err == nil {
				t.Fatal("deleting a referenced exit was accepted")
			}
			if _, err := Server(s, t.TempDir()); err == nil {
				t.Fatal("missing exit rendered as an implicit direct route")
			}
		})
	}
}
