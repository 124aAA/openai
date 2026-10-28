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

type batchBackend struct {
	active                             bool
	checks, activeCalls, starts, stops int
	failStarts                         int
}

func (b *batchBackend) Check(node.State, string) error { b.checks++; return nil }
func (b *batchBackend) Active() bool                   { b.activeCalls++; return b.active }
func (b *batchBackend) Activate(node.State) error {
	b.starts++
	if b.failStarts > 0 {
		b.failStarts--
		b.active = false
		return errors.New("test activation failure")
	}
	b.active = true
	return nil
}
func (b *batchBackend) Stop() error { b.stops++; b.active = false; return nil }

func batchFixture(t *testing.T) (*app, node.State) {
	t.Helper()
	a := wizardApp(t, "")
	for _, args := range [][]string{
		{"--name", "one", "--protocol", "ss2022", "--server", "203.0.113.8", "--port", "24443", "--quiet"},
		{"--name", "two", "--protocol", "ss2022", "--server", "203.0.113.8", "--port", "24444", "--quiet"},
	} {
		if err := a.add("add", args); err != nil {
			t.Fatal(err)
		}
	}
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return a, s
}

func batchFile(t *testing.T, edits []nodeEdit) string {
	t.Helper()
	b, err := json.Marshal(editBatch{Version: 1, Edits: edits})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "edits.json")
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func savedBatchState(t *testing.T, a *app) (string, []byte) {
	t.Helper()
	g, err := os.Readlink(filepath.Join(a.store.Root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(a.store.Root, "current", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return g, b
}

func TestBatchDecodeRejectsAmbiguousOrUnsupportedRequests(t *testing.T) {
	for _, raw := range []string{
		`{"version":2,"edits":[{"id":"one","name":"new"}]}`,
		`{"version":1,"edits":[]}`,
		`{"version":1,"edits":[{"id":"one"}]}`,
		`{"version":1,"edits":[{"id":"one","name":""}]}`,
		`{"version":1,"edits":[{"id":"one","name":"new","password":"secret"}]}`,
		`{"version":1,"edits":[{"id":"one","name":"new","name":"other"}]}`,
		`{"version":1,"edits":[{"id":"one","name":"new","port":null}]}`,
		`{"version":1,"edits":[{"id":"one","port":1.5}]}`,
		`{"version":1,"edits":[{"id":"one","name":"new"}]} {}`,
		`[]`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := decodeEditBatch([]byte(raw)); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if _, err := decodeEditBatch(bytes.Repeat([]byte(" "), maxBatchBytes+1)); err == nil {
		t.Fatal("oversized request accepted")
	}
	edits := make([]nodeEdit, maxBatchEdits+1)
	for i := range edits {
		edits[i] = nodeEdit{ID: "one", Name: editString("new")}
	}
	b, _ := json.Marshal(editBatch{Version: 1, Edits: edits})
	if _, err := decodeEditBatch(b); err == nil {
		t.Fatal("unbounded edit list accepted")
	}
}

func TestBatchHelpDocumentsTheImplementedJSONFieldsWithoutCreatingState(t *testing.T) {
	a := wizardApp(t, "")
	f, err := os.CreateTemp(t.TempDir(), "help")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = oldStderr; f.Close() }()
	if err = a.command([]string{"batch", "--help"}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--file", "--preview", `"version":1`, "id", "name", "server", "listen", "port", "fingerprint", "sni", "target", "cert", "key", "acme_email", "enabled", "256", "1 MiB", "null"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("batch help omitted %q", want)
		}
	}
	if _, err = os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("help initialized management state", err)
	}
}

func TestBatchInvalidRowNeverPartiallyApplies(t *testing.T) {
	for _, kind := range []string{"invalid-port", "name-conflict", "duplicate-target", "missing-target", "wrong-protocol"} {
		t.Run(kind, func(t *testing.T) {
			a, old := batchFixture(t)
			backend := &batchBackend{active: true}
			a.store.Backend = backend
			beforeGeneration, before := savedBatchState(t, a)
			edits := []nodeEdit{{ID: old.Nodes[0].ID, Name: editString("renamed")}, {ID: old.Nodes[1].ID, Server: editString("new.example.com")}}
			switch kind {
			case "invalid-port":
				badPort := 0
				edits[1].Port = &badPort
			case "name-conflict":
				edits[1].Name = editString("renamed")
			case "duplicate-target":
				edits[1].ID = old.Nodes[0].Name // ID and old name select the same object.
			case "missing-target":
				edits[1].ID = "missing"
			case "wrong-protocol":
				edits[1].Fingerprint = editString("firefox")
			}
			_, err := wizardOutput(t, func() error { return a.command([]string{"batch", "--file", batchFile(t, edits)}) })
			if err == nil {
				t.Fatal("invalid row accepted")
			}
			afterGeneration, after := savedBatchState(t, a)
			if beforeGeneration != afterGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 {
				t.Fatal("failed batch changed State, generation, or service")
			}
		})
	}
}

func TestBatchNameAndPortSwapsApplyOnceAndKeepIdentity(t *testing.T) {
	a, old := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	edits := []nodeEdit{
		{ID: "one", Name: editString("two"), Port: &old.Nodes[1].Port},
		{ID: "two", Name: editString("one"), Port: &old.Nodes[0].Port},
	}
	if _, err := wizardOutput(t, func() error { return a.batch([]string{"--file", batchFile(t, edits)}) }); err != nil {
		t.Fatal(err)
	}
	st, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if backend.starts != 1 || backend.stops != 0 || st.Nodes[0].Name != "two" || st.Nodes[1].Name != "one" || st.Nodes[0].Port != old.Nodes[1].Port || st.Nodes[1].Port != old.Nodes[0].Port {
		t.Fatal("batch was order-dependent or activated more than once")
	}
	for i := range old.Nodes {
		if st.Nodes[i].ID != old.Nodes[i].ID || !reflect.DeepEqual(st.Nodes[i].Users, old.Nodes[i].Users) || !reflect.DeepEqual(st.Nodes[i].Shadowsocks, old.Nodes[i].Shadowsocks) {
			t.Fatal("ordinary edit changed stable identity or authentication")
		}
	}
}

func TestBatchPreviewLeavesDamagedFilesAndServiceUntouched(t *testing.T) {
	a, old := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	beforeGeneration, before := savedBatchState(t, a)
	path := filepath.Join(a.store.Root, "current", "server.json")
	damaged := []byte("broken derived JSON")
	if err := os.WriteFile(path, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	edits := []nodeEdit{{ID: old.Nodes[0].ID, Name: editString("renamed")}}
	out, err := wizardOutput(t, func() error { return a.batch([]string{"--file", batchFile(t, edits), "--preview"}) })
	if err != nil || !strings.Contains(out, "派生文件修复 有") || !strings.Contains(out, old.Nodes[0].ID) {
		t.Fatal("preview missed repair or affected node", out, err)
	}
	afterGeneration, after := savedBatchState(t, a)
	actual, _ := os.ReadFile(path)
	if beforeGeneration != afterGeneration || !bytes.Equal(before, after) || !bytes.Equal(actual, damaged) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("preview changed files or queried/changed service")
	}
	journal := filepath.Join(a.store.Root, "transaction.json")
	if err = os.WriteFile(journal, []byte("pending transaction"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.batch([]string{"--file", batchFile(t, edits), "--preview"}); err == nil || !strings.Contains(err.Error(), "recover") {
		t.Fatal("preview did not reject pending transaction", err)
	}
	if b, _ := os.ReadFile(journal); string(b) != "pending transaction" || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("preview recovered pending operation")
	}
}

func TestPreviewMissingRootAndRandomPortCreateNothing(t *testing.T) {
	a := wizardApp(t, "")
	edits := []nodeEdit{{ID: "one", Name: editString("new")}}
	if err := a.batch([]string{"--file", batchFile(t, edits), "--preview"}); err == nil {
		t.Fatal("preview accepted missing root")
	}
	if err := a.edit([]string{"--id", "one", "--preview", "--random-port"}); err == nil {
		t.Fatal("preview selected random port")
	}
	if _, err := os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created management directory", err)
	}
}

func TestBatchMetadataAndRepeatedApplyDoNotActivate(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "running"}[active], func(t *testing.T) {
			a := wizardApp(t, "")
			if err := a.add("add", []string{"--name", "real", "--server", "203.0.113.8", "--sni", "example.com", "--quiet"}); err != nil {
				t.Fatal(err)
			}
			old, _ := a.store.Load()
			backend := &batchBackend{active: active}
			a.store.Backend = backend
			edits := []nodeEdit{{ID: "real", Name: editString("renamed"), Server: editString("new.example.com"), Fingerprint: editString("firefox")}}
			file := batchFile(t, edits)
			out, err := wizardOutput(t, func() error { return a.batch([]string{"--file", file, "--preview"}) })
			if err != nil || !strings.Contains(out, "无需重新启动") || !strings.Contains(out, "客户端导出 有") {
				t.Fatal(out, err)
			}
			if _, err = wizardOutput(t, func() error { return a.batch([]string{"--file", file}) }); err != nil {
				t.Fatal(err)
			}
			generation, _ := savedBatchState(t, a)
			if err = a.command([]string{"apply"}); err != nil {
				t.Fatal(err)
			}
			repeated, _ := savedBatchState(t, a)
			st, _ := a.store.Load()
			if backend.starts != 0 || backend.stops != 0 || backend.active != active || generation != repeated || st.Nodes[0].ID != old.Nodes[0].ID || !reflect.DeepEqual(st.Nodes[0].Users, old.Nodes[0].Users) || st.Nodes[0].Reality.PrivateKey != old.Nodes[0].Reality.PrivateKey || st.Nodes[0].Reality.ShortID != old.Nodes[0].Reality.ShortID {
				t.Fatal("metadata edit or apply changed service/identity/history")
			}
		})
	}
}

func TestBatchActivationFailureRestoresEveryNode(t *testing.T) {
	a, old := batchFixture(t)
	backend := &batchBackend{active: true, failStarts: 1}
	a.store.Backend = backend
	beforeGeneration, before := savedBatchState(t, a)
	port := 24445
	edits := []nodeEdit{{ID: old.Nodes[0].ID, Name: editString("renamed")}, {ID: old.Nodes[1].ID, Port: &port}}
	_, err := wizardOutput(t, func() error { return a.batch([]string{"--file", batchFile(t, edits)}) })
	if err == nil || !strings.Contains(err.Error(), "已恢复原状态") {
		t.Fatal("failed activation not reported as recovered", err)
	}
	afterGeneration, after := savedBatchState(t, a)
	if beforeGeneration != afterGeneration || !bytes.Equal(before, after) || !backend.active || backend.starts != 2 {
		t.Fatal("failed batch did not completely restore saved nodes and service")
	}
	if _, err = os.Lstat(filepath.Join(a.store.Root, "transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful recovery left an unresolved journal", err)
	}
}
