package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWireGuardPairCLIPrivatePerHostMaterialsAndCancellationBoundaries(t *testing.T) {
	a, _ := batchFixture(t)
	before, raw := savedBatchState(t, a)
	dir := filepath.Join(t.TempDir(), "pair")
	args := []string{"pair", "--id", "pair1", "--entry-tunnel", "10.66.0.1/32", "--landing-tunnel", "10.66.0.2/32", "--landing-server", "198.51.100.8", "--connect-port", "30001", "--listen-port", "51820", "--allowed-ips", "0.0.0.0/0", "--keepalive", "25", "--out-dir", dir}
	output, err := wizardOutput(t, func() error { return a.wireguardPair(args) })
	if err != nil {
		t.Fatal(err)
	}
	var entry, landing topologyBatch
	for name, target := range map[string]*topologyBatch{"entry.json": &entry, "landing.json": &landing} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, target); e != nil {
			t.Fatal(e)
		}
		info, e := os.Stat(filepath.Join(dir, name))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private pair material permissions", e)
		}
		if _, e = decodeTopologyBatch(b); e != nil {
			t.Fatal("generated material cannot use the actual import interface", e)
		}
	}
	keyA := entry.Operations[0].Egress.WireGuard.PrivateKey
	keyB := landing.Operations[0].Egress.WireGuard.PrivateKey
	if keyA == keyB || strings.Contains(output, keyA) || strings.Contains(output, keyB) {
		t.Fatal("private keys reused or leaked")
	}
	entryRaw, _ := os.ReadFile(filepath.Join(dir, "entry.json"))
	landingRaw, _ := os.ReadFile(filepath.Join(dir, "landing.json"))
	if strings.Contains(string(entryRaw), keyB) || strings.Contains(string(landingRaw), keyA) {
		t.Fatal("opposite host private key leaked into per-host material")
	}
	if err = a.wireguardPair(args); err == nil {
		t.Fatal("existing pair directory overwritten")
	}
	after, next := savedBatchState(t, a)
	if before != after || string(raw) != string(next) {
		t.Fatal("pair generation changed production State")
	}
	badDir := filepath.Join(t.TempDir(), "invalid")
	bad := append([]string{}, args...)
	bad[len(bad)-1] = badDir
	for i := range bad {
		if bad[i] == "0.0.0.0/0" {
			bad[i] = "invalid"
		}
	}
	if err = a.wireguardPair(bad); err == nil {
		t.Fatal("invalid allowed IP accepted")
	}
	if _, err = os.Lstat(badDir); !os.IsNotExist(err) {
		t.Fatal("invalid input created output")
	}
}

func TestWireGuardPairRefusesOwnedOutputAndUnknownCleanup(t *testing.T) {
	a, _ := batchFixture(t)
	if err := a.wireguardPair([]string{"pair", "--id", "pair1", "--entry-tunnel", "10.66.0.1/32", "--landing-tunnel", "10.66.0.2/32", "--landing-server", "198.51.100.8", "--connect-port", "30001", "--listen-port", "51820", "--allowed-ips", "0.0.0.0/0", "--out-dir", filepath.Join(a.store.Root, "pair")}); err == nil {
		t.Fatal("managed output accepted")
	}
	dir := filepath.Join(t.TempDir(), "new")
	if err := writeNewPairDirectory(dir, map[string][]byte{"../escape": []byte("bad")}); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("own empty output not cleaned")
	}
}
