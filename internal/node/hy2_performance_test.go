package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func hyInt(v int) *int       { return &v }
func hyBytes(v int64) *int64 { return &v }
func hyBool(v bool) *bool    { return &v }
func hyFixture(t *testing.T) State {
	t.Helper()
	cert, key := makeCert(t)
	s := NewState()
	s.Nodes = []Node{{ID: "1111111111111111", Name: "hy2", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 1443, Enabled: true, Users: []User{{ID: "2222222222222222", Name: "client", Password: "preserved-password-123456"}}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
	return s
}

func TestHY2DefaultRenderingAndExplicitValues(t *testing.T) {
	s := hyFixture(t)
	n := s.Nodes[0]
	u := n.Users[0]
	want := M{"type": "hysteria2", "password": u.Password, "tls": M{"enabled": true, "server_name": "localhost"}}
	if !equalJSON(hysteriaOutbound(n, u), want) {
		t.Fatal("new defaults changed legacy outbound")
	}
	before, _ := Server(s, "/private/root")
	s.Nodes[0].HY2 = &HY2Performance{}
	after, _ := Server(s, "/private/root")
	if !bytes.Equal(before, after) {
		t.Fatal("empty performance settings changed default server bytes")
	}
	p := &HY2Performance{ServerUpMbps: hyInt(31), ServerDownMbps: hyInt(47), ClientUpMbps: hyInt(53), ClientDownMbps: hyInt(61), IgnoreClientBandwidth: hyBool(false), ClientMode: "brutal", Client: &HY2Transport{DisableChromeParrot: hyBool(false), BrutalDebug: hyBool(false)}}
	n.HY2 = p
	in, out, mihomo := hysteriaInbound(n, "/private/root"), hysteriaOutbound(n, u), hysteriaMihomo(n, u)
	if in["up_mbps"] != 31 || in["down_mbps"] != 47 || out["up_mbps"] != 53 || out["down_mbps"] != 61 || mihomo["up"] != "53 Mbps" || mihomo["down"] != "61 Mbps" {
		t.Fatal("server/client directions or units were mixed")
	}
	if v, exists := out["disable_chrome_parrot"]; !exists || v != false {
		t.Fatal("explicit false disappeared")
	}
	if _, exists := in["disable_chrome_parrot"]; exists {
		t.Fatal("client option leaked into server")
	}
	if p.ClientUpMbps == nil || *p.ClientUpMbps != 53 {
		t.Fatal("render mutated original settings")
	}
}

func TestHY2BoundsModesVersionsAndClientLoss(t *testing.T) {
	n := hyFixture(t).Nodes[0]
	u := n.Users[0]
	if validateHY2Performance(&HY2Performance{IgnoreClientBandwidth: hyBool(true), ClientMode: "brutal", ClientUpMbps: hyInt(10), ClientDownMbps: hyInt(20)}) == nil {
		t.Fatal("fixed client rates accepted while the same server ignores their negotiation")
	}
	for _, p := range []*HY2Performance{{ServerUpMbps: hyInt(0)}, {ClientUpMbps: hyInt(10)}, {ClientUpMbps: hyInt(10), ClientDownMbps: hyInt(20), ClientMode: "bbr"}, {ClientMode: "brutal"}, {ServerUpMbps: hyInt(10), IgnoreClientBandwidth: hyBool(true)}, {Server: &HY2Transport{DisableChromeParrot: hyBool(false)}}, {Client: &HY2Transport{BBRProfile: "magic"}}, {Client: &HY2Transport{QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1)}}}, {Client: &HY2Transport{QUIC: &HY2QUIC{IdleTimeout: "1s", KeepAlivePeriod: "2s"}}}, {Client: &HY2Transport{QUIC: &HY2QUIC{InitialPacketSize: hyInt(9000)}}}} {
		n.HY2 = p
		if validateHY2Performance(p) == nil {
			t.Fatalf("invalid performance settings accepted: %+v", p)
		}
	}
	n.HY2 = &HY2Performance{ClientMode: "bbr", Client: &HY2Transport{BBRProfile: "conservative", QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(2 << 20), IdleTimeout: "45s"}}}
	for _, version := range []string{"1.14.0", "1.14.3"} {
		if err := ValidateHY2Capabilities(n, version, []string{"with_quic"}); err != nil {
			t.Fatal(version, err)
		}
	}
	if ValidateHY2Capabilities(n, "1.15.0", []string{"with_quic"}) == nil || ValidateHY2Capabilities(n, "1.14.3", []string{"with_utls"}) == nil {
		t.Fatal("unsupported version or missing QUIC capability accepted")
	}
	for _, format := range []string{"uri", "qr", "base64", "mihomo", "provider"} {
		if _, err := Export(n, u, format); err == nil {
			t.Fatal("silently lost client settings", format)
		}
	}
	r, err := ExportWithCapabilities(n, u, "mihomo", "1.19.30", nil, true)
	if err != nil || len(r.Warnings) == 0 || !bytes.Contains(r.Data, []byte("max-stream-receive-window")) {
		t.Fatal("explicit loss-bearing downgrade failed", err)
	}
	if _, err = ExportWithCapabilities(n, u, "mihomo", "1.19.29", nil, true); err == nil {
		t.Fatal("guessed support for an unchecked client version")
	}
	r, err = ExportWithCapabilities(n, u, "sing-box", "1.14.3", []string{"with_quic"}, false)
	if err != nil || len(r.Warnings) == 0 {
		t.Fatal("Chrome overriding local choices was not disclosed", err)
	}
	n.HY2.Client.DisableChromeParrot = hyBool(true)
	if warnings := HY2ExportWarnings(n, "sing-box"); len(warnings) != 0 {
		t.Fatal("warned of disabled Chrome override", warnings)
	}
	n.HY2.Client = &HY2Transport{BBRProfile: "standard"}
	if _, err = ExportWithCapabilities(n, u, "mihomo", "1.19.30", nil, false); err != nil {
		t.Fatal("supported client mapping rejected", err)
	}
	n.HY2.Client.QUIC = &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(2 << 20)}
	m := hysteriaMihomo(n, u)
	if m["initial-stream-receive-window"] != m["max-stream-receive-window"] || m["initial-connection-receive-window"] != m["max-connection-receive-window"] {
		t.Fatal("Mihomo initial and max windows disagree")
	}
	n.HY2.Client.DisableChromeParrot = hyBool(true)
	if _, err = ExportWithCapabilities(n, u, "mihomo", "1.19.30", nil, false); err != nil {
		t.Fatal("known native QUIC/window equivalence was rejected", err)
	}
}

func TestSchemaOneExtensionsRejectedAndMigrationPure(t *testing.T) {
	data, err := os.ReadFile("testdata/state-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, newData := range [][]byte{
		bytes.Replace(data, []byte(`"schema": 1,`), []byte(`"schema": 1,"dns":null,`), 1),
		bytes.Replace(data, []byte(`"schema": 1,`), []byte(`"schema": 1,"DNS":null,`), 1),
		bytes.Replace(data, []byte(`"nodes": [`), []byte(`"nodes": [{"hysteria2":null},`), 1),
		bytes.Replace(data, []byte(`"nodes": [`), []byte(`"nodes": [{"HYSTERIA2":null},`), 1),
		bytes.Replace(data, []byte(`"nodes": [`), []byte(`"Nodes": [{"hysteria2":null},`), 1),
	} {
		if _, err = DecodeState(newData); err == nil {
			t.Fatal("schema1 accepted extension fields")
		}
	}
	legacy := hyFixture(t)
	legacy.Schema = 1
	before := legacy.Clone()
	migrated, err := MigrateState(legacy)
	if err != nil || migrated.Schema != Schema {
		t.Fatal(err)
	}
	want := before.Clone()
	for i := range want.Nodes {
		want.Nodes[i].ConnectPort = hyInt(want.Nodes[i].Port)
	}
	want.Schema = Schema
	want, err = CanonicalCertificates(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy, before) || !reflect.DeepEqual(migrated, want) {
		t.Fatal("migration changed identity or source memory")
	}
	modern, err := os.ReadFile("testdata/state-v2-hy2-performance.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := DecodeState(modern)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Validate(); err != nil {
		t.Fatal(err)
	}
	if st.Nodes[0].HY2.Client.BrutalDebug == nil || *st.Nodes[0].HY2.Client.BrutalDebug {
		t.Fatal("version2 lost explicit false")
	}
	unsupported := bytes.Replace(modern, []byte(`"quic": {`), []byte(`"quic": {"http2_multiplex":true,`), 1)
	if _, err = DecodeState(unsupported); err == nil {
		t.Fatal("unknown HTTP2 setting accepted as a HY2 QUIC option")
	}
}

func TestLegacyGenerationWriteAndRollbackRetainOriginal(t *testing.T) {
	store, backend := newStore(t)
	s := hyFixture(t)
	if err := store.WithLock(func() error { return store.Apply(s) }); err != nil {
		t.Fatal(err)
	}
	old, _ := store.current()
	path := filepath.Join(store.Root, old, "state.json")
	legacy := s.Clone()
	legacy.Schema = 1
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded.Schema != Schema {
		t.Fatal(err)
	}
	if err = store.WithLock(func() error { return store.Apply(loaded) }); err != nil {
		t.Fatal(err)
	}
	noOp, _ := store.current()
	if noOp != old {
		t.Fatal("read/no-op wrote migration generation")
	}
	loaded.Nodes[0].Name = "renamed"
	if err = store.WithLock(func() error { return store.Apply(loaded) }); err != nil {
		t.Fatal(err)
	}
	current, _ := store.current()
	if current == old || backend.activations != 1 {
		t.Fatal("metadata migration restarted service or lost history")
	}
	saved, _ := os.ReadFile(path)
	if !bytes.Equal(saved, raw) {
		t.Fatal("migration overwrote original recovery bytes")
	}
	newRaw, _ := os.ReadFile(filepath.Join(store.Root, current, "state.json"))
	if !bytes.Contains(newRaw, []byte(fmt.Sprintf(`"schema":%d`, Schema))) {
		t.Fatal("new generation not explicitly versioned")
	}
	if err = store.WithLock(func() error { return store.Rollback() }); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got.Nodes[0].Name != "hy2" || !reflect.DeepEqual(got.Nodes[0].Users, s.Nodes[0].Users) || got.Nodes[0].Certificate.KeyPEM != s.Nodes[0].Certificate.KeyPEM {
		t.Fatal("legacy rollback changed identity", err)
	}
	if backend.activations != 1 {
		t.Fatal("metadata rollback restarted the service")
	}
	if !strings.Contains(string(newRaw), "preserved-password") {
		t.Fatal("credential unexpectedly rotated")
	}
}

func TestHY2EndpointImpactAndFailedApplyPreserveIdentity(t *testing.T) {
	store, backend := newStore(t)
	s := hyFixture(t)
	if err := store.WithLock(func() error { return store.Apply(s) }); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	credential := st.Nodes[0].Users[0]
	cert := *st.Nodes[0].Certificate
	st.Nodes[0].HY2 = &HY2Performance{ClientMode: "bbr"}
	if err = store.Inspect(func() error {
		impact, e := store.Preview(st)
		if e == nil && (!impact.ClientExport || impact.NeedsRestart || impact.HostEffects) {
			t.Fatalf("client-only export-policy change was misclassified: %+v", impact)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.WithLock(func() error { return store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if backend.activations != 1 {
		t.Fatal("client-only profile restarted server")
	}
	current, _ := store.current()
	st.Nodes[0].HY2.ServerUpMbps = hyInt(73)
	if err = store.Inspect(func() error {
		impact, e := store.Preview(st)
		if e == nil && (!impact.ServerRuntime || !impact.NeedsRestart || impact.HostEffects) {
			t.Fatalf("server policy change was misclassified: %+v", impact)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	backend.failNext = true
	if err = store.WithLock(func() error { return store.Apply(st) }); err == nil {
		t.Fatal("injected runtime failure passed")
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := store.current()
	if current != after || got.Nodes[0].HY2.ServerUpMbps != nil || got.Nodes[0].Users[0] != credential || *got.Nodes[0].Certificate != cert {
		t.Fatal("failed profile change lost committed configuration or identity")
	}
}
