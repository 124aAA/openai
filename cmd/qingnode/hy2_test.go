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
	"time"

	"qingnode/internal/node"
)

func hy2CLIState(t *testing.T) (*app, *batchBackend, node.State) {
	t.Helper()
	a := wizardApp(t, "")
	b := &batchBackend{}
	a.store.Backend = b
	s := node.NewState()
	s.Nodes = []node.Node{{ID: "1111111111111111", Name: "hy2-cli", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 24443, Enabled: true, Users: []node.User{{ID: "2222222222222222", Name: "client", Password: "preserved-private-hy2-password-123456"}}, Certificate: &node.Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "owner@example.test"}}}
	if e := a.store.WithLock(func() error { return a.store.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	saved, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	return a, b, saved
}
func hy2CLISettings(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if e := os.WriteFile(path, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}
func hy2CLIPlan(t *testing.T, a *app, preset string, extra ...string) (string, hy2Plan) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	args := []string{"plan", "--id", "1111111111111111", "--preset", preset, "--out", path}
	args = append(args, extra...)
	if e := a.hy2(args); e != nil {
		t.Fatal(e)
	}
	p, e := readHY2Plan(path)
	if e != nil {
		t.Fatal(e)
	}
	return path, p
}

func TestHY2CLIPlanApplyRevertAndDerivedRepair(t *testing.T) {
	a, b, before := hy2CLIState(t)
	generation, raw := savedBatchState(t, a)
	path, p := hy2CLIPlan(t, a, "custom", "--settings", hy2CLISettings(t, `{"client_mode":"bbr","client":{"bbr_profile":"conservative"}}`))
	afterGeneration, afterRaw := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(raw, afterRaw) || b.starts != 1 {
		t.Fatal("plan modified production state or service")
	}
	if !p.Impact.ClientExport || p.Impact.NeedsRestart || p.BeforeClientSHA == p.AfterClientSHA || p.BeforeServerSHA != p.AfterServerSHA {
		t.Fatalf("wrong actual change boundaries: %+v", p)
	}
	planRaw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{before.Nodes[0].Users[0].Password, "certificate_pem", "key_pem", "users", "password"} {
		if bytes.Contains(planRaw, []byte(secret)) {
			t.Fatal("plan exposed private material", secret)
		}
	}
	if p.RenderedAfter.Client["bbr_profile"] != "conservative" || len(p.RenderedAfter.Server) != 0 {
		t.Fatal("plan did not show actual flattened fields")
	}
	if e = a.hy2([]string{"apply", "--file", path}); e != nil {
		t.Fatal(e)
	}
	if b.starts != 1 {
		t.Fatal("client-only performance changed server lifecycle")
	}
	if e = a.hy2([]string{"apply", "--file", path}); e != nil {
		t.Fatal("repeat apply failed", e)
	}
	current, _ := os.Readlink(filepath.Join(a.store.Root, "current"))
	broken := filepath.Join(a.store.Root, current, "server.json")
	if e = os.WriteFile(broken, []byte(`{"damaged":`), 0640); e != nil {
		t.Fatal(e)
	}
	checks := b.checks
	if e = a.hy2([]string{"apply", "--file", path}); e != nil {
		t.Fatal("repeat plan skipped derived repair", e)
	}
	repaired, _ := os.Readlink(filepath.Join(a.store.Root, "current"))
	if repaired == current || b.checks <= checks || b.starts != 1 {
		t.Fatal("derived repair did not validate/save without restart")
	}
	original, _ := os.ReadFile(broken)
	if string(original) != `{"damaged":` {
		t.Fatal("repair removed original recovery bytes")
	}
	if e = a.hy2([]string{"revert", "--file", path}); e != nil {
		t.Fatal(e)
	}
	restored, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	if restored.Nodes[0].HY2 != nil || !reflect.DeepEqual(restored.Nodes[0].Users, before.Nodes[0].Users) || *restored.Nodes[0].Certificate != *before.Nodes[0].Certificate || b.starts != 1 {
		t.Fatal("performance revert changed identity or restarted metadata-only state")
	}
}

func TestHY2CLIStaleCoreGlobalNodeAndTamperedTargetRejected(t *testing.T) {
	for _, scenario := range []string{"node", "core", "global", "target", "rendered", "pending"} {
		t.Run(scenario, func(t *testing.T) {
			a, b, _ := hy2CLIState(t)
			_, p := hy2CLIPlan(t, a, "custom", "--settings", hy2CLISettings(t, `{"client":{"bbr_profile":"conservative"}}`))
			s, e := a.store.Load()
			if e != nil {
				t.Fatal(e)
			}
			switch scenario {
			case "node":
				s.Nodes[0].Host = "192.0.2.90"
			case "core":
				s.CoreVersion = "1.14.3"
			case "global":
				s.Firewall = "ufw"
			case "target":
				p.After.Client.BBRProfile = "aggressive"
			case "rendered":
				p.RenderedAfter.Client["bbr_profile"] = "aggressive"
			case "pending":
				if e = os.WriteFile(filepath.Join(a.store.Root, "transaction.json"), []byte(`{"unknown":true}`), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "node" || scenario == "core" || scenario == "global" {
				if e = a.store.WithLock(func() error { return a.store.Apply(s) }); e != nil {
					t.Fatal(e)
				}
			}
			generation, raw := savedBatchState(t, a)
			starts, checks := b.starts, b.checks
			if e = a.applyHY2Plan(p, false); e == nil {
				t.Fatal("stale/tampered plan accepted", scenario)
			}
			afterGeneration, afterRaw := savedBatchState(t, a)
			if generation != afterGeneration || !bytes.Equal(raw, afterRaw) || b.starts != starts || b.checks != checks {
				t.Fatal("rejected plan partially applied or recovered transaction", scenario)
			}
		})
	}
}

func TestHY2CLIPlanFileStrictPrivateAndAtomic(t *testing.T) {
	a, _, _ := hy2CLIState(t)
	path, p := hy2CLIPlan(t, a, "automatic")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = atomicHY2Plan(path, p); e == nil {
		t.Fatal("overwrote an existing plan")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing plan was changed")
	}
	if e = a.hy2([]string{"plan", "--id", p.NodeID, "--preset", "automatic", "--out", filepath.Join(a.store.Root, "new-private.json")}); e == nil {
		t.Fatal("plan written in production state directory")
	}
	for _, raw := range [][]byte{[]byte(`{"version":1,"version":1}`), []byte(`{"version":2}`), append([]byte(`{"password":"private",`), before[1:]...), append(before, []byte(`{}`)...), []byte(strings.Repeat(" ", maxHY2PlanBytes+1))} {
		file := filepath.Join(t.TempDir(), "invalid.json")
		if e = os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = readHY2Plan(file); e == nil {
			t.Fatal("unknown/ambiguous/oversized plan accepted")
		}
	}
	p.RenderedAfter.Client["password"] = "private"
	if validateHY2Plan(p) == nil {
		t.Fatal("private actual-rendered field was accepted")
	}
	delete(p.RenderedAfter.Client, "password")
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = readHY2Plan(path); e == nil {
		t.Fatal("publicly readable plan accepted")
	}
	if _, e = readHY2Plan(t.TempDir()); e == nil {
		t.Fatal("directory accepted as a plan")
	}
}

func TestHY2CLIFixedRequiresIndependentDirectionalEvidence(t *testing.T) {
	a, _, _ := hy2CLIState(t)
	out := filepath.Join(t.TempDir(), "plan.json")
	base := []string{"plan", "--id", "1111111111111111", "--preset", "fixed", "--up-mbps", "17", "--down-mbps", "29", "--measured-at", time.Now().UTC().Format(time.RFC3339), "--initiator", "controlled-client", "--out", out}
	if e := a.hy2(base); e == nil {
		t.Fatal("fixed inferred both directions without evidence")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("invalid plan left a result")
	}
	for _, sensitive := range []string{"hy2://secret@example.test:443", "https://example.test/result?token=private", "password=private-123", "11111111-2222-4333-8444-555555555555"} {
		e := validateHY2Evidence(hy2Evidence{time.Now().UTC(), "controlled-client", sensitive, "download-result.json"})
		if e == nil {
			t.Fatal("sensitive evidence accepted", sensitive)
		}
	}
	_, p := hy2CLIPlan(t, a, "fixed", "--up-mbps", "17", "--down-mbps", "29", "--measured-at", time.Now().UTC().Format(time.RFC3339), "--initiator", "controlled-client", "--upload-basis", "iperf3 reverse-upload-2026.json", "--download-basis", "iperf3 forward-download-2026.json")
	if *p.After.ClientUpMbps != 17 || *p.After.ClientDownMbps != 29 || p.Evidence == nil || p.RenderedAfter.Client["up_mbps"] != float64(17) {
		t.Fatal("client direction/evidence lost in plan")
	}
	if e := a.applyHY2Plan(p, false); e != nil {
		t.Fatal(e)
	}
}

func TestHY2CLIEvidenceRejectsSecretsFromOtherNodes(t *testing.T) {
	a, b, s := hy2CLIState(t)
	otherHY2 := s.Nodes[0]
	otherHY2.ID, otherHY2.Name, otherHY2.Port = "3333333333333333", "other-hy2", 24444
	otherHY2.Users = []node.User{{ID: "4444444444444444", Name: "other-client", Password: "bare-other-node-private-secret-123456"}}
	r, e := node.NewReality("reality.example.test", "reality.example.test:443")
	if e != nil {
		t.Fatal(e)
	}
	ss := node.NewShadowsocks()
	s.Nodes = append(s.Nodes, otherHY2,
		node.Node{ID: "5555555555555555", Name: "other-reality", Protocol: "reality", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 24445, Users: []node.User{node.NewUser("other-reality-client", "reality")}, Reality: r},
		node.Node{ID: "6666666666666666", Name: "other-ss", Protocol: "ss2022", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 24446, Users: []node.User{node.NewUser("other-ss-client", "ss2022")}, Shadowsocks: ss})
	if e = a.store.WithLock(func() error { return a.store.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	generation, raw := savedBatchState(t, a)
	starts, checks := b.starts, b.checks
	for _, secret := range []struct{ name, value string }{{"password", otherHY2.Users[0].Password}, {"ss-server-key", ss.ServerKey}, {"reality-private-key", r.PrivateKey}} {
		for _, field := range []string{"--initiator", "--upload-basis", "--download-basis"} {
			t.Run(secret.name+field, func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "plan.json")
				values := map[string]string{"--initiator": "controlled-client", "--upload-basis": "upload-result.json", "--download-basis": "download-result.json"}
				values[field] = secret.value
				args := []string{"plan", "--id", "1111111111111111", "--preset", "fixed", "--up-mbps", "17", "--down-mbps", "29", "--measured-at", time.Now().UTC().Format(time.RFC3339), "--out", out}
				for _, flag := range []string{"--initiator", "--upload-basis", "--download-basis"} {
					args = append(args, flag, values[flag])
				}
				e := a.hy2(args)
				if e == nil || strings.Contains(e.Error(), secret.value) {
					t.Fatal("another node's bare secret accepted or exposed in error")
				}
				if _, e = os.Stat(out); !os.IsNotExist(e) {
					t.Fatal("secret-containing evidence left a plan")
				}
			})
		}
	}
	afterGeneration, afterRaw := savedBatchState(t, a)
	if generation != afterGeneration || !bytes.Equal(raw, afterRaw) || b.starts != starts || b.checks != checks {
		t.Fatal("rejected evidence changed production state or service")
	}
}

func TestHY2CLIConservativeResourceAndServerScope(t *testing.T) {
	old := readHY2MemAvailable
	defer func() { readHY2MemAvailable = old }()
	available := uint64(512 << 20)
	readHY2MemAvailable = func() (*uint64, error) { v := available; return &v, nil }
	a, b, before := hy2CLIState(t)
	_, p := hy2CLIPlan(t, a, "conservative")
	if p.After.Client != nil || p.After.ClientUpMbps != nil || p.After.ClientMode != "" || p.Resources.MemAvailableBytes == nil || p.Resources.ServerWindowBytes != 4<<20 || p.Resources.RequiredAvailableBytes != 128<<20 || !p.Impact.NeedsRestart {
		t.Fatal("conservative guessed client resources or wrong local bounds")
	}
	available = 64 << 20
	if e := a.applyHY2Plan(p, false); e == nil {
		t.Fatal("applied windows after available memory dropped")
	}
	if b.starts != 1 {
		t.Fatal("low-memory rejection restarted service")
	}
	available = 512 << 20
	if e := a.applyHY2Plan(p, false); e != nil {
		t.Fatal(e)
	}
	if b.starts != 2 {
		t.Fatal("server QUIC change did not apply once")
	}
	got, e := a.store.Load()
	if e != nil || !reflect.DeepEqual(got.Nodes[0].Users, before.Nodes[0].Users) {
		t.Fatal("server profile rotated identity", e)
	}
	if e = a.applyHY2Plan(p, true); e != nil {
		t.Fatal(e)
	}
	if b.starts != 3 {
		t.Fatal("server profile revert did not apply once")
	}
	readHY2MemAvailable = func() (*uint64, error) { return nil, errors.New("container limit unknown") }
	if _, e = hy2ResourceEvidence(p.After); e == nil {
		t.Fatal("unknown memory accepted for server window preset")
	}
}

func TestHY2CLIRevertRefusesLaterRelevantChanges(t *testing.T) {
	a, b, _ := hy2CLIState(t)
	_, p := hy2CLIPlan(t, a, "automatic")
	if e := a.applyHY2Plan(p, false); e != nil {
		t.Fatal(e)
	}
	s, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	s.Nodes[0].Users[0].Password = "explicitly-rotated-other-operation-123"
	if e = a.store.WithLock(func() error { return a.store.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	starts := b.starts
	generation, raw := savedBatchState(t, a)
	if e = a.applyHY2Plan(p, true); e == nil {
		t.Fatal("revert overwrote later credential change")
	}
	newGeneration, newRaw := savedBatchState(t, a)
	if generation != newGeneration || !bytes.Equal(raw, newRaw) || b.starts != starts {
		t.Fatal("stale revert partially changed state")
	}
}

func TestHY2CLISettingsRejectsUnknownCoreFields(t *testing.T) {
	a, _, _ := hy2CLIState(t)
	for _, raw := range []string{`{"client":{"http2":true}}`, `{"password":"private"}`, `{"client":{"quic":{"stream_receive_window":0}}}`, `{"client":{"bbr_profile":"standard","bbr_profile":"aggressive"}}`} {
		path := filepath.Join(t.TempDir(), "out.json")
		if e := a.hy2([]string{"plan", "--id", "1111111111111111", "--preset", "custom", "--settings", hy2CLISettings(t, raw), "--out", path}); e == nil {
			t.Fatal("invalid typed settings were accepted")
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("invalid custom plan left a file")
		}
	}
}

func TestHY2CLIPlanHashesAreCanonicalPrivateProfileHashes(t *testing.T) {
	a, _, s := hy2CLIState(t)
	_, p := hy2CLIPlan(t, a, "automatic")
	profile, e := a.probeProfile(s.Nodes[0].ID, s.Nodes[0].Users[0].ID)
	if e != nil || profile.ConfigSHA256 != p.BeforeClientSHA {
		t.Fatal("plan hash differs from actual private probe profile", e)
	}
	bytes, _ := json.Marshal(p)
	if !json.Valid(bytes) {
		t.Fatal("invalid plan JSON")
	}
}
