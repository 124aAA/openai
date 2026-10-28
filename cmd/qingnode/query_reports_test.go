package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func decodePublicQuery(t *testing.T, text string, kind string) json.RawMessage {
	t.Helper()
	var report struct {
		Version  int             `json:"version"`
		Kind     string          `json:"kind"`
		At       time.Time       `json:"observed_at"`
		Location string          `json:"observation_location"`
		Data     json.RawMessage `json:"data"`
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if err := d.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("extra output after query JSON", err)
	}
	if report.Version != 1 || report.Kind != kind || report.At.IsZero() || report.Location != "manager-configuration" {
		t.Fatal("wrong query version, identity or observation scope")
	}
	return report.Data
}

func TestPublicQueryJSONKeepsNATEndpointsIdentityAndSecretsPrivate(t *testing.T) {
	a, state := batchFixture(t)
	remote := topologyRemoteSS("3333333333333333")
	state.Egresses = []node.Egress{remote}
	state.Forwards = []node.PortForward{{ID: "4444444444444444", Name: "转发 中文", Listen: "127.0.0.1", Port: 35555, Network: "tcp+udp", TargetHost: "203.0.113.40", TargetPort: 443, EgressID: remote.ID, Enabled: true}}
	connectPort := 30000
	state.Nodes[0].ConnectPort = &connectPort
	state.Nodes[0].AdditionalEndpoints = []node.ConnectionEndpoint{{ID: "6666666666666666", Host: "2001:db8::8", Port: 30001}}
	state.Devices = []node.DeviceProfile{{ID: "5555555555555555", Name: "手机 " + state.Nodes[0].Users[0].Password, Strategy: "manual", Routing: "global", Bindings: []node.DeviceBinding{{NodeID: state.Nodes[0].ID, UserID: state.Nodes[0].Users[0].ID, EndpointID: "default"}}}}
	state.CredentialExpirations = []node.CredentialExpiration{{ID: "7777777777777777", NodeID: state.Nodes[0].ID, UserID: state.Nodes[0].Users[0].ID, ExpiresAt: "2090-01-02T03:04:05Z"}}
	if err := a.store.WithLock(func() error { return a.store.Apply(state) }); err != nil {
		t.Fatal(err)
	}
	beforeGeneration, before := savedBatchState(t, a)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	cases := []struct {
		args []string
		kind string
	}{
		{[]string{"dns", "show", "--json"}, "qingnode-project-dns"},
		{[]string{"endpoint", "list", "--id", state.Nodes[0].ID, "--json"}, "qingnode-endpoint-declarations"},
		{[]string{"egress", "list", "--json"}, "qingnode-egress-declarations"},
		{[]string{"egress", "show", "--id", remote.ID, "--json"}, "qingnode-egress-declarations"},
		{[]string{"egress", "policy", "list", "--json"}, "qingnode-egress-policy-declarations"},
		{[]string{"forward", "list", "--json"}, "qingnode-forward-declarations"},
		{[]string{"device", "list", "--json"}, "qingnode-device-bindings"},
		{[]string{"device", "show", "--id", state.Devices[0].ID, "--json"}, "qingnode-device-bindings"},
		{[]string{"expiration", "list", "--json"}, "qingnode-credential-expiration-plan"},
		{[]string{"subscription", "status", "--json"}, "qingnode-subscription-authorization"},
	}
	for _, item := range cases {
		t.Run(strings.Join(item.args[:2], "-"), func(t *testing.T) {
			text, err := wizardOutput(t, func() error { return a.command(item.args) })
			if err != nil {
				t.Fatal(err)
			}
			data := decodePublicQuery(t, text, item.kind)
			for _, secret := range []string{remote.Shadowsocks.Password, state.Nodes[0].Shadowsocks.ServerKey, state.Nodes[0].Users[0].Password} {
				if strings.Contains(text, secret) {
					t.Fatal("public query exposed a proxy credential")
				}
			}
			if item.kind == "qingnode-endpoint-declarations" {
				var endpoints struct {
					ListenPort      int                       `json:"listen_port"`
					Endpoints       []node.ConnectionEndpoint `json:"connection_endpoints"`
					PublicIngress   string                    `json:"public_ingress"`
					CloudNATChanged bool                      `json:"cloud_nat_changed"`
				}
				if err := json.Unmarshal(data, &endpoints); err != nil {
					t.Fatal(err)
				}
				if endpoints.ListenPort != state.Nodes[0].Port || len(endpoints.Endpoints) != 2 || endpoints.Endpoints[0].Port != 30000 || endpoints.Endpoints[1].Host != "2001:db8::8" || endpoints.PublicIngress != "unknown" || endpoints.CloudNATChanged {
					t.Fatal("NAT and IPv6 declarations were conflated with local listening or real ingress")
				}
			}
		})
	}
	afterGeneration, after := savedBatchState(t, a)
	if beforeGeneration != afterGeneration || !bytes.Equal(before, after) || backend.activeCalls+backend.checks+backend.starts+backend.stops != 0 {
		t.Fatal("public queries modified configuration or operated the backend")
	}
}

func TestPublicQueryJSONFlagsCannotSneakIntoWritesOrRecoverTransactions(t *testing.T) {
	a, state := batchFixture(t)
	generation, before := savedBatchState(t, a)
	for _, args := range [][]string{
		{"endpoint", "edit", "--id", state.Nodes[0].ID, "--connect-port", "30000", "--json"},
		{"egress", "add", "--json"}, {"forward", "add", "--json"}, {"egress", "policy", "add", "--json"},
		{"device", "create", "--name", "invalid", "--json"}, {"expiration", "apply", "--yes", "--json"}, {"subscription", "init", "--json"},
	} {
		if _, err := wizardOutput(t, func() error { return a.command(args) }); err == nil {
			t.Fatal("unsupported JSON write accepted", args)
		}
	}
	journal := filepath.Join(a.store.Root, "transaction.json")
	pending := []byte("preserve interrupted transaction verbatim")
	if err := os.WriteFile(journal, pending, 0600); err != nil {
		t.Fatal(err)
	}
	text, err := wizardOutput(t, func() error { return a.command([]string{"dns", "show", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	decodePublicQuery(t, text, "qingnode-project-dns")
	retained, _ := os.ReadFile(journal)
	afterGeneration, after := savedBatchState(t, a)
	if !bytes.Equal(pending, retained) || generation != afterGeneration || !bytes.Equal(before, after) {
		t.Fatal("query repaired pending transaction or changed State")
	}
}

func TestHY2JSONReportsDefaultsAndSavedPlanWithoutTextSuffix(t *testing.T) {
	a, backend, state := hy2CLIState(t)
	state.Nodes[0].Name = "旧HY2\u2066" + state.Nodes[0].Users[0].Password
	if err := a.store.WithLock(func() error { return a.store.Apply(state) }); err != nil {
		t.Fatal(err)
	}
	generation, before := savedBatchState(t, a)
	checks, starts := backend.checks, backend.starts
	text, err := wizardOutput(t, func() error { return a.hy2([]string{"show", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	data := decodePublicQuery(t, text, "qingnode-hy2-settings")
	if strings.ContainsAny(string(data), "\u2066\u2069\u202e") {
		t.Fatal("legacy direction control leaked into query name")
	}
	if !bytes.Contains(data, []byte(`"performance":null`)) || !bytes.Contains(data, []byte(`"server_upload_direction":"VPS-to-client"`)) || strings.Contains(text, state.Nodes[0].Users[0].Password) {
		t.Fatal("default or bandwidth direction misreported, or credentials exposed")
	}
	path := filepath.Join(t.TempDir(), "new-plan.json")
	text, err = wizardOutput(t, func() error {
		return a.hy2([]string{"plan", "--id", state.Nodes[0].ID, "--preset", "core-default", "--out", path, "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var output hy2Plan
	if err = json.Unmarshal([]byte(text), &output); err != nil {
		t.Fatal(err)
	}
	saved, err := readHY2Plan(path)
	if err != nil || saved.NodeID != output.NodeID || saved.GlobalSHA != output.GlobalSHA {
		t.Fatal("printed plan differs from saved plan", err)
	}
	afterGeneration, after := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(before, after) || backend.checks != checks || backend.starts != starts {
		t.Fatal("query or plan modified runtime")
	}
}
