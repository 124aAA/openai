package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func endpointCommand(t *testing.T, a *app, args ...string) string {
	t.Helper()
	out, err := wizardOutput(t, func() error { return a.command(args) })
	if err != nil {
		t.Fatal(args, err)
	}
	return out
}

func TestEndpointCLIIndependentPortsAndExports(t *testing.T) {
	a := wizardApp(t, "")
	endpointCommand(t, a, "add", "--protocol", "ss2022", "--server", "[2001:db8::9]", "--listen", "127.0.0.1", "--port", "24443", "--connect-port", "30000", "--quiet")
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	old := s.Nodes[0]
	b := &batchBackend{active: true}
	a.store.Backend = b
	beforeServer, err := node.Server(s, a.store.Root)
	if err != nil {
		t.Fatal(err)
	}
	p0, err := a.probeProfile(old.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := publicFingerprint(s, old)
	endpointCommand(t, a, "endpoint", "add", "--id", old.ID, "--endpoint", "relay", "--server", "relay.example.test", "--connect-port", "31000")
	endpointCommand(t, a, "endpoint", "edit", "--id", old.ID, "--connect-port", "30001")
	s, err = a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	n := s.Nodes[0]
	afterServer, err := node.Server(s, a.store.Root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeServer, afterServer) || b.starts != 0 || b.stops != 0 || !b.active {
		t.Fatal("client endpoint edit changed server/service")
	}
	if n.Port != 24443 || node.EffectiveConnectPort(n) != 30001 || !reflect.DeepEqual(n.Users, old.Users) || !reflect.DeepEqual(n.Shadowsocks, old.Shadowsocks) {
		t.Fatal("listener or credentials changed")
	}
	if publicFingerprint(s, n) == fingerprint {
		t.Fatal("manual client test history remained current after endpoint change")
	}
	p1, err := a.probeProfile(n.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := a.probeEndpointProfile(n.ID, "", "relay")
	if err != nil {
		t.Fatal(err)
	}
	if p0.ConfigSHA256 == p1.ConfigSHA256 || p1.ConfigSHA256 == p2.ConfigSHA256 {
		t.Fatal("selected proxy report fingerprint did not change")
	}
	for _, id := range []string{"default", "relay"} {
		selected, err := node.WithEndpoint(n, id)
		if err != nil {
			t.Fatal(err)
		}
		out := endpointCommand(t, a, "export", "--id", n.ID, "--endpoint", id, "--format", "uri")
		if strings.TrimSpace(out) != node.URI(selected, n.Users[0]) {
			t.Fatal("export ignored endpoint", id, out)
		}
	}
	out := endpointCommand(t, a, "info", "--id", n.ID)
	for _, want := range []string{"127.0.0.1:24443", "客户端端口：30001", "relay.example.test:31000", "[2001:db8::9]:30001"} {
		if !strings.Contains(out, want) {
			t.Fatal("info omitted endpoint/listener", want, out)
		}
	}
	endpointCommand(t, a, "edit", "--id", n.ID, "--port", "24445")
	s, err = a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if node.EffectiveConnectPort(s.Nodes[0]) != 30001 || s.Nodes[0].Port != 24445 || b.starts != 1 {
		t.Fatal("local port edit changed connection port or did not apply once")
	}
}

func TestEndpointPreviewBadBatchAndStoppedService(t *testing.T) {
	a, s := batchFixture(t)
	id := s.Nodes[0].ID
	b := &batchBackend{}
	a.store.Backend = b
	generation, before := savedBatchState(t, a)
	out := endpointCommand(t, a, "endpoint", "add", "--id", id, "--endpoint", "v6", "--server", "[2001:db8::1]", "--connect-port", "30000", "--preview")
	afterGeneration, after := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(before, after) || b.starts != 0 || !strings.Contains(out, "只读端点预览") {
		t.Fatal("preview mutated state")
	}
	for _, args := range [][]string{
		{"endpoint", "add", "--id", id, "--endpoint", "bad", "--server", "https://wrong.test", "--connect-port", "30000"},
		{"endpoint", "add", "--id", id, "--endpoint", "bad", "--server", "name.test", "--connect-port", "0"},
		{"endpoint", "add", "--id", id, "--endpoint", "default", "--server", "name.test", "--connect-port", "30000"},
		{"endpoint", "remove", "--id", id, "--endpoint", "missing"},
	} {
		if err := a.command(args); err == nil {
			t.Fatal("accepted invalid endpoint", args)
		}
	}
	port := 30000
	bad := []node.ConnectionEndpoint{{ID: "x", Host: "bad:443", Port: 30001}}
	request := batchFile(t, []nodeEdit{{ID: id, ConnectPort: &port}, {ID: s.Nodes[1].ID, AdditionalEndpoints: &bad}})
	if err := a.command([]string{"batch", "--file", request}); err == nil {
		t.Fatal("invalid batch partially accepted")
	}
	afterGeneration, after = savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(before, after) || b.starts != 0 || b.stops != 0 {
		t.Fatal("invalid input had effects")
	}
	endpointCommand(t, a, "endpoint", "edit", "--id", id, "--connect-port", "30000")
	if b.active || b.starts != 0 || b.stops != 0 {
		t.Fatal("endpoint edit started stopped service")
	}
	if err := os.WriteFile(filepath.Join(a.store.Root, "transaction.json"), []byte(`{"evidence":"retain"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.command([]string{"endpoint", "edit", "--id", id, "--server", "next.example.test", "--preview"}); err == nil {
		t.Fatal("preview accepted pending transaction")
	}
	raw, err := os.ReadFile(filepath.Join(a.store.Root, "transaction.json"))
	if err != nil || string(raw) != `{"evidence":"retain"}` {
		t.Fatal("preview repaired pending transaction")
	}
}

func TestEndpointMaterialIsDeclarationWithoutCredentials(t *testing.T) {
	a, s := batchFixture(t)
	n := s.Nodes[0]
	endpointCommand(t, a, "endpoint", "edit", "--id", n.ID, "--connect-port", "30000")
	path := filepath.Join(t.TempDir(), "material.json")
	endpointCommand(t, a, "endpoint", "material", "--id", n.ID, "--out", path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report["version"] != float64(1) || report["cloud_nat_changed"] != false || report["dns_aaaa"] != "unknown" || report["inbound_udp"] != "unknown" {
		t.Fatal("material claimed external success")
	}
	mappings := report["required_mappings"].([]any)
	if len(mappings) != 2 {
		t.Fatal("SS TCP/UDP mappings not separate")
	}
	for _, item := range mappings {
		m := item.(map[string]any)
		if m["external_port"] != float64(30000) || m["local_port"] != float64(n.Port) || m["status"] != "unverified" {
			t.Fatal("wrong mapping", m)
		}
	}
	for _, secret := range []string{n.Shadowsocks.ServerKey, n.Users[0].Password, node.URI(n, n.Users[0])} {
		if secret != "" && bytes.Contains(raw, []byte(secret)) {
			t.Fatal("material leaked secret")
		}
	}
	if err = a.command([]string{"endpoint", "material", "--id", n.ID, "--out", path}); err == nil {
		t.Fatal("material overwrote prior output")
	}
	if err = a.command([]string{"endpoint", "material", "--id", n.ID, "--out", filepath.Join(a.store.Root, "material.json")}); err == nil {
		t.Fatal("material wrote into managed state")
	}
}

func TestNATWizardCancelInvalidAndExplicitMapping(t *testing.T) {
	for _, input := range []string{"name\n:cancel\n", "name\nhttps://bad.test\n", "name\n203.0.113.9\n0.0.0.0\n443\n:cancel\n", "name\n203.0.113.9\n0.0.0.0\n443\n0\n"} {
		a := wizardApp(t, input)
		_, err := wizardOutput(t, func() error { return a.installWizardOptions(true, "ss2022", true, true) })
		if err == nil {
			t.Fatal("cancel/invalid wizard accepted")
		}
		if _, err = os.Stat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cancel/invalid wizard created state", err)
		}
	}
	a := wizardApp(t, "nat-node\n[2001:db8::1]\n127.0.0.1\n443\n30000\n")
	out, err := wizardOutput(t, func() error { return a.installWizardOptions(true, "ss2022", false, true) })
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	n := s.Nodes[0]
	if n.Host != "2001:db8::1" || n.Listen != "127.0.0.1" || n.Port != 443 || node.EffectiveConnectPort(n) != 30000 || !strings.Contains(out, "客户端端口：30000") {
		t.Fatal("NAT input replaced/conflated", n, out)
	}
}

func TestCapabilitiesBeforeInstallDoesNotInitializeState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	out, err := wizardOutput(t, func() error { return run([]string{"--root", root, "capabilities", "--json", "--skip-loopback"}) })
	if err != nil {
		t.Fatal(err)
	}
	var r node.RuntimeCapabilities
	if err = json.Unmarshal([]byte(out), &r); err != nil || r.Version != 1 || r.RemotePath.Available != nil {
		t.Fatal("capability report invalid", err)
	}
	if _, err = os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capabilities initialized state", err)
	}
}

func TestConnectionPortFlagsAreDecimalAcrossCreateEditAndEndpoint(t *testing.T) {
	a := wizardApp(t, "")
	endpointCommand(t, a, "add", "--protocol", "ss2022", "--server", "203.0.113.8", "--port", "24443", "--connect-port", "03000", "--quiet")
	s, err := a.store.Load()
	if err != nil || node.EffectiveConnectPort(s.Nodes[0]) != 3000 {
		t.Fatal("create connection port treated as octal", err)
	}
	endpointCommand(t, a, "edit", "--id", "main", "--connect-port", "08443")
	s, err = a.store.Load()
	if err != nil || node.EffectiveConnectPort(s.Nodes[0]) != 8443 {
		t.Fatal("edit connection port not decimal", err)
	}
	endpointCommand(t, a, "endpoint", "edit", "--id", "main", "--connect-port", "09443")
	s, err = a.store.Load()
	if err != nil || node.EffectiveConnectPort(s.Nodes[0]) != 9443 {
		t.Fatal("endpoint port not decimal", err)
	}
	generation, before := savedBatchState(t, a)
	if err = a.command([]string{"endpoint", "edit", "--id", "main", "--connect-port", "0x20"}); err == nil {
		t.Fatal("hexadecimal connection port accepted")
	}
	afterGeneration, after := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(before, after) {
		t.Fatal("invalid port changed state")
	}
}
