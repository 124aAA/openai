package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func topologyCommand(t *testing.T, a *app, args ...string) string {
	t.Helper()
	out, err := wizardOutput(t, func() error { return a.command(args) })
	if err != nil {
		t.Fatal(args, err)
	}
	return out
}

func topologyFile(t *testing.T, ops ...topologyOperation) string {
	t.Helper()
	raw, err := json.Marshal(topologyBatch{Version: 1, Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "topology.json")
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func topologyRemoteSS(id string) node.Egress {
	server := node.NewShadowsocks()
	u := node.NewUser("remote-user", "ss2022")
	return node.Egress{ID: id, Name: "remote-" + id, Protocol: "ss2022", Server: "203.0.113.20", Port: 35443, UDP: true, Shadowsocks: &node.RemoteSS{Method: node.SS2022Method, Password: server.ServerKey + ":" + u.Password}}
}

func TestTopologyBatchRejectsAmbiguousAndInjectedFields(t *testing.T) {
	for _, raw := range []string{
		`{"version":2,"operations":[{"action":"egress-remove","id":"a"}]}`,
		`{"version":2,"verſion":1,"operations":[{"action":"egress-remove","id":"a"}]}`,
		`{"version":1,"operations":[{"action":"egress-put","egress":{"id":"a","socks":{"password":"first","paſſword":"second"}}}]}`,
		`{"version":1,"operations":[]}`,
		`{"version":1,"operations":[{"action":"unknown","id":"a"}]}`,
		`{"version":1,"operations":[{"action":"egress-remove","id":"a","id":"b"}]}`,
		`{"version":1,"operations":[{"action":"egress-remove","ID":"a"}]}`,
		`{"version":1,"operations":[{"action":"egress-remove","id":"a","egress":null}]}`,
		`{"version":1,"operations":[{"action":"egress-remove","id":"a","node_id":"b"}]}`,
		`{"version":1,"operations":[{"action":"egress-remove","id":"a"},{"action":"egress-remove","id":"a"}]}`,
		`{"version":1,"operations":[{"action":"route-set","node_id":"a"}]}`,
		`{"version":1,"operations":[{"action":"route-set","node_id":"a","egress_id":""}]}`,
		`{"version":1,"operations":[{"action":"egress-put","egress":{"id":"a","outbounds":[{"type":"direct"}]}}]}`,
		`{"version":1,"operations":[{"action":"egress-put","egress":{"id":"a","socks":{"Password":"secret-that-must-not-be-echoed"}}}]}`,
		`{"version":1,"operations":[{"action":"egress-put","egress":{"id":"a","socks":{"password":"secret-that-must-not-be-echoed","exec":"anything"}}}]}`,
		`{"version":1,"operations":[{"action":"egress-remove","id":"a"}]} {}`,
	} {
		if _, err := decodeTopologyBatch([]byte(raw)); err == nil {
			t.Fatal("accepted ambiguous or injected topology", raw)
		} else if strings.Contains(err.Error(), "secret-that-must-not-be-echoed") {
			t.Fatal("decoder echoed a remote credential")
		}
	}
	if _, err := decodeTopologyBatch(bytes.Repeat([]byte(" "), maxBatchBytes+1)); err == nil {
		t.Fatal("accepted oversized topology")
	}
	ops := make([]topologyOperation, maxBatchEdits+1)
	for i := range ops {
		ops[i] = topologyOperation{Action: "egress-remove", ID: node.Token(8)}
	}
	raw, _ := json.Marshal(topologyBatch{Version: 1, Operations: ops})
	if _, err := decodeTopologyBatch(raw); err == nil {
		t.Fatal("accepted unbounded topology operations")
	}
}

func TestTopologyCLIExportsOnlyEntranceCredentialsAndRejectsReferencedRemoval(t *testing.T) {
	a, before := batchFixture(t)
	remote := topologyRemoteSS("3333333333333333")
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	topologyCommand(t, a, "egress", "add", "--id", remote.ID, "--name", remote.Name, "--protocol", "ss2022", "--server", remote.Server, "--port", "035443", "--password", remote.Shadowsocks.Password)
	topologyCommand(t, a, "route", "set", "--id", before.Nodes[0].ID, "--egress", remote.ID)
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Egresses[0].Port != 35443 || s.Nodes[0].EgressID != remote.ID || s.Nodes[1].EgressID != "" || !reflect.DeepEqual(s.Nodes[0].Users, before.Nodes[0].Users) {
		t.Fatal("route changed unrelated node, credentials, or decimal port", s)
	}
	for _, command := range [][]string{{"egress", "list"}, {"egress", "show", "--id", remote.ID}, {"info", "--id", before.Nodes[0].ID}, {"export", "--id", before.Nodes[0].ID, "--format", "sing-box"}, {"export", "--id", before.Nodes[0].ID, "--format", "uri"}} {
		out := topologyCommand(t, a, command...)
		if strings.Contains(out, remote.Shadowsocks.Password) {
			t.Fatal("entrance export or query leaked internal landing credential", command)
		}
	}
	if out := topologyCommand(t, a, "export", "--id", before.Nodes[0].ID, "--format", "uri"); strings.TrimSpace(out) != node.URI(before.Nodes[0], before.Nodes[0].Users[0]) {
		t.Fatal("remote route changed existing entrance URI")
	}
	gen, raw := savedBatchState(t, a)
	starts := backend.starts
	if err = a.command([]string{"egress", "remove", "--id", remote.ID, "--yes"}); err == nil {
		t.Fatal("removed a referenced remote exit")
	}
	nextGen, nextRaw := savedBatchState(t, a)
	if gen != nextGen || !bytes.Equal(raw, nextRaw) || starts != backend.starts {
		t.Fatal("referenced removal changed committed configuration")
	}
	// A complete typed batch can remove the old reference and the exit together,
	// independent of operation order, while keeping other entrances untouched.
	direct := "direct"
	file := topologyFile(t, topologyOperation{Action: "egress-remove", ID: remote.ID}, topologyOperation{Action: "route-set", NodeID: before.Nodes[0].Name, EgressID: &direct})
	topologyCommand(t, a, "topology", "batch", "--file", file)
	s, err = a.store.Load()
	if err != nil || len(s.Egresses) != 0 || s.Nodes[0].EgressID != "" {
		t.Fatal("atomic explicit reference migration failed", err)
	}
	for i := range s.Nodes {
		s.Nodes[i].CreatedAt, s.Nodes[i].UpdatedAt = "", ""
		before.Nodes[i].CreatedAt, before.Nodes[i].UpdatedAt = "", ""
	}
	if !reflect.DeepEqual(s.Nodes, before.Nodes) {
		t.Fatal("explicit route migration changed unrelated node choices or identity")
	}
	if backend.starts != starts+1 {
		t.Fatal("topology batch did not apply exactly once", backend.starts, starts)
	}
}

func TestTopologyBatchInvalidRowAndPreviewLeaveStateServiceAndJournal(t *testing.T) {
	a, s := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	e := topologyRemoteSS("3333333333333333")
	file := topologyFile(t, topologyOperation{Action: "egress-put", Egress: &e}, topologyOperation{Action: "route-set", NodeID: s.Nodes[0].ID, EgressID: &e.ID})
	gen, raw := savedBatchState(t, a)
	out := topologyCommand(t, a, "topology", "apply", "--file", file, "--preview")
	nextGen, nextRaw := savedBatchState(t, a)
	if gen != nextGen || !bytes.Equal(raw, nextRaw) || backend.checks != 0 || backend.starts != 0 || !strings.Contains(out, "只读拓扑预览") || !strings.Contains(out, s.Nodes[0].ID) {
		t.Fatal("preview changed state or omitted affected entrance")
	}
	bad := "missing-exit"
	invalid := topologyFile(t, topologyOperation{Action: "egress-put", Egress: &e}, topologyOperation{Action: "route-set", NodeID: s.Nodes[0].ID, EgressID: &bad})
	if err := a.command([]string{"topology", "batch", "--file", invalid}); err == nil {
		t.Fatal("invalid route partially accepted")
	}
	nextGen, nextRaw = savedBatchState(t, a)
	if gen != nextGen || !bytes.Equal(raw, nextRaw) || backend.checks != 0 || backend.starts != 0 {
		t.Fatal("invalid batch had partial effects")
	}
	journal := filepath.Join(a.store.Root, "transaction.json")
	if err := os.WriteFile(journal, []byte(`{"evidence":"keep"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.command([]string{"topology", "batch", "--file", file, "--preview"}); err == nil {
		t.Fatal("preview silently recovered interrupted transaction")
	}
	kept, err := os.ReadFile(journal)
	if err != nil || string(kept) != `{"evidence":"keep"}` || backend.starts != 0 {
		t.Fatal("read-only preview changed interruption material")
	}
}

func TestForwardCLITransportAndSOCKSCapability(t *testing.T) {
	a := wizardApp(t, "")
	topologyCommand(t, a, "egress", "add", "--id", "4444444444444444", "--protocol", "socks5", "--server", "127.0.0.1", "--port", "1080")
	topologyCommand(t, a, "forward", "add", "--id", "5555555555555555", "--listen", "127.0.0.1", "--port", "34443", "--network", "tcp", "--target-host", "203.0.113.30", "--target-port", "443", "--egress", "4444444444444444")
	topologyCommand(t, a, "forward", "add", "--id", "6666666666666666", "--listen", "127.0.0.1", "--port", "34443", "--network", "udp", "--target-host", "203.0.113.30", "--target-port", "443")
	gen, raw := savedBatchState(t, a)
	for _, command := range [][]string{
		{"forward", "edit", "--id", "5555555555555555", "--network", "tcp+udp"},
		{"forward", "edit", "--id", "6666666666666666", "--egress", "4444444444444444"},
		{"forward", "add", "--id", "7777777777777777", "--listen", "127.0.0.1", "--port", "34443", "--network", "tcp", "--target-host", "203.0.113.30", "--target-port", "443"},
		{"forward", "remove", "--id", "5555555555555555"},
		{"egress", "list", "--password", "must-not-be-consumed"},
		{"egress", "edit", "--id", "4444444444444444", "--sni", "irrelevant.test"},
		{"egress", "edit", "--id", "4444444444444444", "--via", ""},
		{"forward", "edit", "--id", "5555555555555555", "--egress", ""},
	} {
		if err := a.command(command); err == nil {
			t.Fatal("accepted unsupported transport, conflict or irrelevant flags", command)
		}
	}
	nextGen, nextRaw := savedBatchState(t, a)
	if gen != nextGen || !bytes.Equal(raw, nextRaw) {
		t.Fatal("invalid topology request changed committed state")
	}
	topologyCommand(t, a, "forward", "remove", "--id", "6666666666666666", "--yes")
	topologyCommand(t, a, "forward", "edit", "--id", "5555555555555555", "--enabled=false")
	s, err := a.store.Load()
	if err != nil || len(s.Nodes) != 0 || len(s.Forwards) != 1 || s.Forwards[0].Enabled || s.Egresses[0].UDP {
		t.Fatal("pure-forward operations changed capability or created proxy user", err)
	}
}

func TestTopologyBatchActivationFailureRestoresAllReferences(t *testing.T) {
	a, initial := batchFixture(t)
	e := topologyRemoteSS("3333333333333333")
	forward := node.PortForward{ID: "4444444444444444", Name: "atomic-forward", Listen: "127.0.0.1", Port: 35555, Network: "tcp+udp", TargetHost: "203.0.113.40", TargetPort: 443, EgressID: e.ID, Enabled: true}
	file := topologyFile(t, topologyOperation{Action: "egress-put", Egress: &e}, topologyOperation{Action: "forward-put", Forward: &forward}, topologyOperation{Action: "route-set", NodeID: initial.Nodes[0].ID, EgressID: &e.ID})
	gen, raw := savedBatchState(t, a)
	server, err := os.ReadFile(filepath.Join(a.store.Root, "current", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &batchBackend{active: true, failStarts: 1}
	a.store.Backend = backend
	if err = a.command([]string{"topology", "apply", "--file", file}); err == nil {
		t.Fatal("expected activation failure")
	}
	nextGen, nextRaw := savedBatchState(t, a)
	nextServer, err := os.ReadFile(filepath.Join(a.store.Root, "current", "server.json"))
	if err != nil || gen != nextGen || !bytes.Equal(raw, nextRaw) || !bytes.Equal(server, nextServer) || backend.starts != 2 || !backend.active {
		t.Fatal("failed batch did not restore the complete prior generation and running state", err)
	}
	if _, err = os.Lstat(filepath.Join(a.store.Root, "transaction.json")); !os.IsNotExist(err) {
		t.Fatal("completed recovery retained an ambiguous journal", err)
	}
	topologyCommand(t, a, "topology", "apply", "--file", file)
	committed, err := a.store.Load()
	if err != nil || len(committed.Forwards) != 1 || len(committed.Egresses) != 1 || committed.Nodes[0].EgressID != e.ID || committed.Nodes[1].EgressID != "" || backend.starts != 3 {
		t.Fatal("retry was not a single complete application", err)
	}
	if !reflect.DeepEqual(committed.Nodes[0].Users, initial.Nodes[0].Users) || !reflect.DeepEqual(committed.Nodes[1].Users, initial.Nodes[1].Users) {
		t.Fatal("failed batch or retry changed local credentials")
	}
	topologyCommand(t, a, "rollback")
	restored, err := a.store.Load()
	if err != nil || len(restored.Forwards) != 0 || len(restored.Egresses) != 0 || restored.Nodes[0].EgressID != "" || backend.starts != 4 || !backend.active {
		t.Fatal("topology rollback did not restore the prior direct path", err)
	}
}

func TestTopologyOnlyListenersKeepOrdinaryLifecycleAndStoppedMetadata(t *testing.T) {
	for _, kind := range []string{"forward", "wireguard-landing"} {
		t.Run(kind, func(t *testing.T) {
			a := wizardApp(t, "")
			var edit func(string, bool)
			if kind == "forward" {
				topologyCommand(t, a, "forward", "add", "--id", "3333333333333333", "--listen", "127.0.0.1", "--port", "35555", "--network", "tcp+udp", "--target-host", "203.0.113.40", "--target-port", "443")
				edit = func(name string, runtime bool) {
					args := []string{"forward", "edit", "--id", "3333333333333333", "--name", name}
					if runtime {
						args = append(args, "--port", "35556")
					}
					topologyCommand(t, a, args...)
				}
			} else {
				pair, err := node.NewWireGuardPair(node.WireGuardPairOptions{ID: "lifecycle", EntryTunnel: "10.77.0.1/32", LandingTunnel: "10.77.0.2/32", LandingHost: "203.0.113.40", ConnectPort: 35555, ListenPort: 35555, AllowedIPs: []string{"0.0.0.0/0"}})
				if err != nil {
					t.Fatal(err)
				}
				topologyCommand(t, a, "topology", "apply", "--file", topologyFile(t, topologyOperation{Action: "egress-put", Egress: &pair.Landing}))
				edit = func(name string, runtime bool) {
					s, err := a.store.Load()
					if err != nil {
						t.Fatal(err)
					}
					e := s.Egresses[0]
					e.Name = name
					if runtime {
						e.WireGuard.ListenPort = 35556
					}
					topologyCommand(t, a, "topology", "apply", "--file", topologyFile(t, topologyOperation{Action: "egress-put", Egress: &e}))
				}
			}
			backend := &batchBackend{}
			a.store.Backend, a.offline = backend, false
			s, err := a.store.Load()
			if err != nil || len(s.Nodes) != 0 || !node.HasEnabled(s) {
				t.Fatal("standalone listener was not recognized", err)
			}
			topologyCommand(t, a, "start")
			topologyCommand(t, a, "stop")
			if backend.starts != 1 || backend.stops != 1 || backend.active {
				t.Fatal("ordinary start/stop failed")
			}
			edit("stopped-display-change", false)
			if backend.starts != 1 || backend.stops != 1 || backend.active {
				t.Fatal("metadata edit started a stopped topology")
			}
			topologyCommand(t, a, "start")
			topologyCommand(t, a, "apply")
			if backend.starts != 2 || !backend.active {
				t.Fatal("repeat apply changed running topology")
			}
			edit("runtime-change", true)
			if backend.starts != 3 || !backend.active {
				t.Fatal("listener runtime edit did not activate exactly once")
			}
			topologyCommand(t, a, "rollback")
			if backend.starts != 4 || !backend.active {
				t.Fatal("listener rollback did not activate exactly once")
			}
		})
	}
}

func TestTopologyValidationErrorDoesNotEchoRemoteCredentialName(t *testing.T) {
	a, _ := batchFixture(t)
	secret := "remote-secret-hidden-in-name"
	e := node.Egress{ID: "3333333333333333", Name: secret, Protocol: "socks5", Server: "invalid host", Port: 1080, Socks: &node.RemoteSOCKS{Username: "remote-user", Password: secret}}
	// An invalid server causes a named validation error. The name is user
	// controlled and can repeat the private password.
	file := topologyFile(t, topologyOperation{Action: "egress-put", Egress: &e})
	err := a.command([]string{"topology", "apply", "--file", file})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("invalid topology leaked the remote credential", err)
	}
}

func TestEgressEditPreservesRemoteSecretsAndDefaultNodeCredentials(t *testing.T) {
	a, initial := batchFixture(t)
	remote := topologyRemoteSS("3333333333333333")
	topologyCommand(t, a, "egress", "add", "--id", remote.ID, "--protocol", "ss2022", "--server", remote.Server, "--port", "35443", "--password", remote.Shadowsocks.Password)
	topologyCommand(t, a, "egress", "edit", "--id", remote.ID, "--name", "renamed")
	s, err := a.store.Load()
	if err != nil || s.Egresses[0].Shadowsocks.Password != remote.Shadowsocks.Password || !reflect.DeepEqual(s.Nodes[0].Users, initial.Nodes[0].Users) {
		t.Fatal("ordinary egress metadata edit rotated credentials", err)
	}
	file := batchFile(t, []nodeEdit{{ID: s.Nodes[0].ID, EgressID: &remote.ID}, {ID: s.Nodes[1].ID, EgressID: &remote.ID}})
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	topologyCommand(t, a, "batch", "--file", file)
	s, err = a.store.Load()
	if err != nil || s.Nodes[0].EgressID != remote.ID || s.Nodes[1].EgressID != remote.ID || backend.starts != 1 {
		t.Fatal("existing batch egress binding did not apply once", err)
	}
	topologyCommand(t, a, "edit", "--id", s.Nodes[0].ID, "--egress", "direct")
	if backend.starts != 2 {
		t.Fatal("explicit return to direct not applied")
	}
}

func TestEgressPolicyCLIRequiresExplicitFailoverAndPreservesSelection(t *testing.T) {
	a, original := batchFixture(t)
	primary, backup := topologyRemoteSS("3333333333333333"), topologyRemoteSS("4444444444444444")
	file := topologyFile(t, topologyOperation{Action: "egress-put", Egress: &primary}, topologyOperation{Action: "egress-put", Egress: &backup})
	topologyCommand(t, a, "topology", "batch", "--file", file)
	gen, raw := savedBatchState(t, a)
	if err := a.command([]string{"egress", "policy", "add", "--id", "5555555555555555", "--mode", "failover", "--primary", primary.ID, "--backup", backup.ID}); err == nil {
		t.Fatal("accepted failover without explicit health thresholds")
	}
	nextGen, nextRaw := savedBatchState(t, a)
	if gen != nextGen || !bytes.Equal(raw, nextRaw) {
		t.Fatal("invalid policy changed state")
	}
	topologyCommand(t, a, "egress", "policy", "add", "--id", "5555555555555555", "--mode", "failover", "--primary", primary.ID, "--backup", backup.ID, "--target", "https://controlled.example.test/health", "--udp-target", "203.0.113.30:34567", "--failure-threshold", "3", "--recovery-threshold", "4", "--cooldown-seconds", "60", "--timeout-seconds", "3")
	topologyCommand(t, a, "route", "set", "--id", original.Nodes[0].ID, "--egress", "5555555555555555")
	topologyCommand(t, a, "egress", "policy", "edit", "--id", "5555555555555555", "--name", "stable-policy")
	s, err := a.store.Load()
	if err != nil || s.EgressPolicies[0].Selected != "" || s.EgressPolicies[0].Health.RecoveryThreshold != 4 {
		t.Fatal("metadata edit silently changed selection or explicit thresholds", err)
	}
	if err = a.command([]string{"egress", "policy", "remove", "--id", "5555555555555555", "--yes"}); err == nil {
		t.Fatal("removed referenced policy")
	}
	out := topologyCommand(t, a, "egress", "policy", "list")
	if !strings.Contains(out, "当前:primary") || !strings.Contains(out, "查询不发起探测") {
		t.Fatal("policy query implies automatic health or hides current branch", out)
	}
}

func TestTopologyRouteAliasesAndBatchNodeAliasesCannotTargetTwice(t *testing.T) {
	a, s := batchFixture(t)
	direct := "direct"
	b := topologyBatch{Version: 1, Operations: []topologyOperation{{Action: "route-set", NodeID: s.Nodes[0].ID, EgressID: &direct}, {Action: "route-set", NodeID: s.Nodes[0].Name, EgressID: &direct}}}
	before := s.Clone()
	if err := applyTopologyBatch(&s, b); err == nil || !reflect.DeepEqual(s, before) {
		t.Fatal("duplicate old ID/name modified candidate")
	}
	if err := a.command([]string{"route", "set", "--id", s.Nodes[0].ID, "--egress", ""}); err == nil {
		t.Fatal("implicit empty route accepted")
	}
}

func TestTopologyInputPrivateRegularFileAndHelpDoNotCreateState(t *testing.T) {
	a := wizardApp(t, "")
	for _, args := range [][]string{{"topology", "batch", "--help"}, {"egress", "add", "--help"}, {"forward", "add", "--help"}, {"route", "set", "--help"}, {"egress", "policy", "add", "--help"}} {
		if err := a.command(args); err != nil {
			t.Fatal("help failed", args, err)
		}
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("help created managed root", err)
	}
	path := filepath.Join(t.TempDir(), "topology.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"operations":[{"action":"egress-remove","id":"3333333333333333"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTopologyFile(path); err == nil {
		t.Fatal("accepted world-readable remote credential input")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTopologyFile(path); err != nil {
		t.Fatal("rejected private regular input", err)
	}
	alias := filepath.Join(t.TempDir(), "alias.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readTopologyFile(alias); err == nil {
		t.Fatal("accepted symlink credential input")
	}
}
