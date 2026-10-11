package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"qingnode/internal/node"
)

type inspectionBackend struct{ effects int }

func (b *inspectionBackend) Check(node.State, string) error { return nil }
func (b *inspectionBackend) Active() bool                   { return true }
func (b *inspectionBackend) Activate(node.State) error      { b.effects++; return nil }
func (b *inspectionBackend) Stop() error                    { b.effects++; return nil }
func (b *inspectionBackend) RecoverRemoval() error          { b.effects++; return nil }

func TestQueriesLeavePendingRecoveryAndServiceUntouched(t *testing.T) {
	for _, cmd := range []string{"list", "info", "export", "render", "check", "core", "firewall"} {
		t.Run(cmd, func(t *testing.T) {
			a := wizardApp(t, "")
			if e := a.add("init", []string{"--protocol", "ss2022", "--server", "203.0.113.8", "--quiet"}); e != nil {
				t.Fatal(e)
			}
			backend := &inspectionBackend{}
			a.store.Backend = backend
			current := filepath.Join(a.store.Root, "current")
			generation, _ := os.Readlink(current)
			statePath := filepath.Join(current, "state.json")
			before, _ := os.ReadFile(statePath)
			journal, _ := json.Marshal(map[string]any{"previous": generation, "next": generation, "was_active": true})
			path := filepath.Join(a.store.Root, "transaction.json")
			if e := os.WriteFile(path, journal, 0600); e != nil {
				t.Fatal(e)
			}
			uninstall := filepath.Join(a.store.Root, "uninstall.json")
			if e := os.WriteFile(uninstall, []byte("pending-removal"), 0600); e != nil {
				t.Fatal(e)
			}
			args := []string{cmd}
			switch cmd {
			case "export", "render":
				args = append(args, "--id", "main", "--out", filepath.Join(t.TempDir(), "output"))
			case "core":
				args = append(args, "check") // Missing core may fail; inspection must still have no effects.
			case "firewall":
				args = append(args, "status")
				a.offline = false
				t.Setenv("PATH", t.TempDir()) // No host firewall tools are executed.
			}
			_, e := wizardOutput(t, func() error { return a.command(args) })
			if e != nil && cmd != "core" && cmd != "check" {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(statePath)
			pending, _ := os.ReadFile(path)
			pointer, _ := os.Readlink(current)
			if backend.effects != 0 || !bytes.Equal(before, after) || !bytes.Equal(journal, pending) || pointer != generation {
				t.Fatal("query recovered a transaction, changed state, or touched the service")
			}
			if b, e := os.ReadFile(uninstall); e != nil || string(b) != "pending-removal" {
				t.Fatal("query changed pending uninstall")
			}
		})
	}
}

func TestQueriesDoNotInitializeMissingStore(t *testing.T) {
	for _, cmd := range []string{"list", "info", "export", "render", "check", "core"} {
		root := filepath.Join(t.TempDir(), "absent")
		a := &app{store: &node.Store{Root: root, Backend: node.OfflineBackend{}, GID: -1}, offline: true}
		args := []string{cmd}
		if cmd == "core" {
			args = append(args, "check")
		}
		_, _ = wizardOutput(t, func() error { return a.command(args) })
		if _, e := os.Lstat(root); !os.IsNotExist(e) {
			t.Fatalf("%s initialized the missing store", cmd)
		}
	}
}
