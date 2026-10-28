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

func phase2CLIState(t *testing.T, a *app) node.State {
	t.Helper()
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func phase2CLIFind(t *testing.T, s node.State, id string) node.Node {
	t.Helper()
	n, err := s.Find(id)
	if err != nil {
		t.Fatal(err)
	}
	return *n
}

func phase2CLIOriginalNodesUnchanged(t *testing.T, a *app, original node.State) {
	t.Helper()
	s := phase2CLIState(t, a)
	for _, n := range original.Nodes {
		if !reflect.DeepEqual(phase2CLIFind(t, s, n.ID), n) {
			t.Fatal("phase2 operation changed an unrelated node or its credentials")
		}
	}
}

func TestProtocolExpansionCLIPhase2ShadowsocksAEADLifecycle(t *testing.T) {
	a, base := batchFixture(t)
	// This backend records requested actions; it is not a real service process.
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	if err := a.add("add", []string{"--protocol", "ss-aead", "--name", "classic-ss", "--server", "203.0.113.8", "--listen", "127.0.0.1", "--port", "33445", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	n := phase2CLIFind(t, phase2CLIState(t, a), "classic-ss")
	if n.Shadowsocks == nil || n.Shadowsocks.Method != node.DefaultSSAEADMethod || n.Shadowsocks.ServerKey != "" {
		t.Fatal("classic SS creation did not select the explicit default method without a service key")
	}
	first := n.Users[0]
	if err := a.users("user-add", []string{"--id", n.ID, "--name", "second-device"}); err != nil {
		t.Fatal(err)
	}
	n = phase2CLIFind(t, phase2CLIState(t, a), n.ID)
	if len(n.Users) != 2 || n.Users[0] != first || n.Users[1].Password == first.Password || n.Users[1].UUID != "" {
		t.Fatal("adding a classic SS user rotated the first user or reused its credentials")
	}
	users := append([]node.User(nil), n.Users...)
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		if err := a.edit([]string{"--id", n.ID, "--method", method}); err != nil {
			t.Fatal(err)
		}
		n = phase2CLIFind(t, phase2CLIState(t, a), n.ID)
		if n.Shadowsocks.Method != method || n.Shadowsocks.ServerKey != "" || !reflect.DeepEqual(n.Users, users) {
			t.Fatal("method edit changed independent user passwords or added a service key")
		}
	}
	generation, saved := savedBatchState(t, a)
	checks, starts, stops := backend.checks, backend.starts, backend.stops
	if err := a.users("rotate", []string{"--id", n.ID, "--server-key", "--yes"}); err == nil || !strings.Contains(err.Error(), "SS2022") {
		t.Fatal("classic SS did not explicitly reject SS2022 service-key rotation")
	}
	afterGeneration, after := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(saved, after) || checks != backend.checks || starts != backend.starts || stops != backend.stops {
		t.Fatal("rejected service-key rotation changed State, generation, or requested service actions")
	}
	if err := a.users("user-delete", []string{"--id", n.ID, "--user", users[1].ID, "--yes"}); err != nil {
		t.Fatal(err)
	}
	n = phase2CLIFind(t, phase2CLIState(t, a), n.ID)
	if len(n.Users) != 1 || n.Users[0] != first {
		t.Fatal("revoking the selected user removed or rotated the other password")
	}
	phase2CLIOriginalNodesUnchanged(t, a, base)
}

func TestProtocolExpansionCLIPhase2TUICSharedCertificateAndAtomicLifecycle(t *testing.T) {
	a, base := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	if err := a.add("add", []string{"--protocol", "trojan", "--name", "certificate-owner", "--server", "203.0.113.8", "--listen", "127.0.0.1", "--port", "33446", "--sni", "shared.example.test", "--acme-email", "owner@example.test", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	holder := phase2CLIFind(t, phase2CLIState(t, a), "certificate-owner")
	if holder.CertificateID == "" {
		t.Fatal("certificate fixture did not receive a managed resource identity")
	}
	if err := a.add("add", []string{"--protocol", "tuic", "--name", "tuic-node", "--server", "203.0.113.8", "--listen", "127.0.0.1", "--port", "33447", "--certificate-id", holder.CertificateID, "--quiet"}); err != nil {
		t.Fatal(err)
	}
	n := phase2CLIFind(t, phase2CLIState(t, a), "tuic-node")
	if n.CertificateID != holder.CertificateID || n.Certificate == nil || n.Certificate.ServerName != holder.Certificate.ServerName || n.Users[0].UUID == "" || n.Users[0].Password == "" {
		t.Fatal("TUIC creation lost the shared certificate or UUID/password authentication")
	}
	users := append([]node.User(nil), n.Users...)
	input := filepath.Join(t.TempDir(), "tuic-options.json")
	writeOptions := func(zeroRTT bool) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"version": 1, "node_id": n.ID, "tuic": map[string]any{"server_congestion_control": "bbr", "client_congestion_control": "new_reno", "auth_timeout": "3s", "server_heartbeat": "2s", "client_heartbeat": "1500ms", "udp_relay_mode": "quic", "zero_rtt_handshake": zeroRTT}})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(input, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeOptions(false)
	generation, saved := savedBatchState(t, a)
	checks, starts, stops := backend.checks, backend.starts, backend.stops
	if err := a.protocols([]string{"options", "--file", input, "--preview"}); err != nil {
		t.Fatal(err)
	}
	afterGeneration, after := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(saved, after) || checks != backend.checks || starts != backend.starts || stops != backend.stops {
		t.Fatal("TUIC options preview wrote State, changed generation, or requested a service action")
	}
	if err := a.protocols([]string{"options", "--file", input, "--yes"}); err != nil {
		t.Fatal(err)
	}
	n = phase2CLIFind(t, phase2CLIState(t, a), n.ID)
	if n.TUIC == nil || n.TUIC.ServerCongestionControl != "bbr" || n.TUIC.ClientCongestionControl != "new_reno" || n.TUIC.ClientHeartbeat != "1500ms" || n.TUIC.ZeroRTTHandshake == nil || *n.TUIC.ZeroRTTHandshake || !reflect.DeepEqual(n.Users, users) {
		t.Fatal("TUIC option application mixed directions or rotated authentication")
	}
	generation, saved = savedBatchState(t, a)
	checks, starts, stops = backend.checks, backend.starts, backend.stops
	writeOptions(true)
	if err := a.protocols([]string{"options", "--file", input, "--yes"}); err == nil || !strings.Contains(err.Error(), "0-RTT") {
		t.Fatal("TUIC did not reject enabling replay-prone 0-RTT")
	}
	afterGeneration, after = savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(saved, after) || checks != backend.checks || starts != backend.starts || stops != backend.stops {
		t.Fatal("rejected 0-RTT request partially changed State or requested service actions")
	}
	for _, cmd := range []string{"disable", "enable"} {
		if err := a.toggle(cmd, []string{"--id", n.ID}); err != nil {
			t.Fatal(err)
		}
		current := phase2CLIFind(t, phase2CLIState(t, a), n.ID)
		if current.Enabled != (cmd == "enable") || !reflect.DeepEqual(current.Users, users) || current.CertificateID != holder.CertificateID {
			t.Fatal("TUIC stop/start declaration changed authentication or certificate ownership")
		}
	}
	if err := a.toggle("delete", []string{"--id", n.ID, "--yes"}); err != nil {
		t.Fatal(err)
	}
	final := phase2CLIState(t, a)
	if _, err := final.Find(n.ID); err == nil || len(final.Nodes) != len(base.Nodes)+1 || !reflect.DeepEqual(phase2CLIFind(t, final, holder.ID), holder) {
		t.Fatal("TUIC deletion damaged the sharing node or left the selected node behind")
	}
	if _, err := final.FindCertificate(holder.CertificateID); err != nil {
		t.Fatal("deleting TUIC removed a certificate still used by another node", err)
	}
	phase2CLIOriginalNodesUnchanged(t, a, base)
}
