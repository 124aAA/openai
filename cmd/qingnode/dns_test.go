package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func TestDNSCLIResolverParsingAndPreviewAreStrictAndReadOnly(t *testing.T) {
	for _, raw := range []string{"system", "udp://127.0.0.1:53", "udp://[::1]:5353"} {
		if _, e := parseProjectResolver(raw); e != nil {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{"", "project", "https://resolver.example/dns-query", "tcp://127.0.0.1:53", "udp://resolver.example:53", "udp://127.0.0.1", "udp://[::1]:0", "udp://127.0.0.1:65536", "udp://user:private@127.0.0.1:53"} {
		if _, e := parseProjectResolver(raw); e == nil {
			t.Fatal("ambiguous resolver accepted", raw)
		}
	}
	a, _ := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	generation, before := savedBatchState(t, a)
	history := filepath.Join(a.store.Root, "observations.json")
	sentinel := []byte("manual-public-result-history")
	os.WriteFile(history, sentinel, 0600)
	for _, args := range [][]string{{"show"}, {"set", "--resolver", "udp://127.0.0.1:5353", "--preview"}, {"set", "--resolver", "system", "--preview"}, {"reset", "--preview"}} {
		out, e := wizardOutput(t, func() error { return a.dns(args) })
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(out, "system") {
			t.Fatal("DNS command omitted actual resolver", out)
		}
	}
	afterGeneration, after := savedBatchState(t, a)
	historyAfter, _ := os.ReadFile(history)
	if generation != afterGeneration || !bytes.Equal(before, after) || !bytes.Equal(sentinel, historyAfter) || backend.activeCalls+backend.checks+backend.starts+backend.stops != 0 {
		t.Fatal("DNS show/preview modified node state, service or manual history")
	}
	for _, journal := range []string{"transaction.json", "uninstall.json"} {
		path := filepath.Join(a.store.Root, journal)
		pending := []byte("pending-dns-sentinel")
		os.WriteFile(path, pending, 0600)
		if _, e := wizardOutput(t, func() error { return a.dns([]string{"set", "--resolver", "system", "--preview"}) }); e == nil {
			t.Fatal("DNS preview ignored pending transaction")
		}
		data, _ := os.ReadFile(path)
		if !bytes.Equal(data, pending) {
			t.Fatal("DNS preview recovered a node transaction")
		}
		os.Remove(path)
	}
}

func TestDNSCLIInvalidDiagnosisAndOutputDoNotCreateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent-state")
	a := &app{store: &node.Store{Root: root, GID: -1, Backend: node.OfflineBackend{}}, offline: false}
	for _, args := range [][]string{{"diagnose", "--name", "https://not-a-domain", "--resolver", "system"}, {"diagnose", "--name", "controlled.invalid", "--resolver", "udp://not-a-literal:53"}, {"diagnose", "--name", "controlled.invalid", "--samples", "99"}, {"set", "--resolver", "system", "--preview"}, {"reset", "--resolver", "system", "--preview"}, {"show", "extra"}} {
		if _, e := wizardOutput(t, func() error { return a.dns(args) }); e == nil {
			t.Fatalf("invalid DNS command accepted: %v", args)
		}
	}
	if _, e := os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("DNS errors initialized State", e)
	}
	a, _ = batchFixture(t)
	a.offline = false
	g, before := savedBatchState(t, a)
	if _, e := wizardOutput(t, func() error {
		return a.dns([]string{"diagnose", "--name", "controlled.invalid", "--out", filepath.Join(a.store.Root, "new-result.json")})
	}); e == nil {
		t.Fatal("DNS report allowed a production State output path")
	}
	afterG, after := savedBatchState(t, a)
	if g != afterG || !bytes.Equal(before, after) {
		t.Fatal("invalid output changed State")
	}
}
