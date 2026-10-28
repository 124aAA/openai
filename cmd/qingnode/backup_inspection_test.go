package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"qingnode/internal/node"
)

type backupInspectionBackend struct {
	recoveries, activations, stops, checks int
	lastChecked, lastActivated             node.State
	lastCheckPath                          string
	order                                  []string
}

func (b *backupInspectionBackend) Check(st node.State, path string) error {
	b.checks++
	b.lastChecked, b.lastCheckPath = st.Clone(), path
	b.order = append(b.order, "check")
	return nil
}
func (b *backupInspectionBackend) Active() bool { return true }
func (b *backupInspectionBackend) Activate(st node.State) error {
	b.activations++
	b.lastActivated = st.Clone()
	b.order = append(b.order, "activate")
	return nil
}
func (b *backupInspectionBackend) Stop() error { b.stops++; return nil }
func (b *backupInspectionBackend) RecoverRemoval() error {
	b.recoveries++
	b.order = append(b.order, "recover-removal")
	return nil
}

const backupTestPassword = "backup-test-password"

func backupPasswordFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if e := os.WriteFile(path, []byte(backupTestPassword+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

func backupReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestBackupRefusesPendingRecoveryWithoutEffects(t *testing.T) {
	for _, journals := range [][]string{{"transaction.json"}, {"uninstall.json"}, {"transaction.json", "uninstall.json"}} {
		for _, automatic := range []bool{false, true} {
			name := strings.Join(journals, "+")
			if automatic {
				name += "/automatic-path"
			}
			t.Run(name, func(t *testing.T) {
				a, n := menuFixture(t, "")
				current := filepath.Join(a.store.Root, "current")
				committed, e := os.Readlink(current)
				if e != nil {
					t.Fatal(e)
				}
				if journals[0] == "transaction.json" {
					if e = a.command([]string{"edit", "--id", n.ID, "--name", "uncommitted-candidate"}); e != nil {
						t.Fatal(e)
					}
				}
				pointer, e := os.Readlink(current)
				if e != nil {
					t.Fatal(e)
				}
				state := backupReadFile(t, filepath.Join(current, "state.json"))
				server := backupReadFile(t, filepath.Join(current, "server.json"))
				records := map[string][]byte{}
				for _, journal := range journals {
					data := []byte("pending-removal\n")
					if journal == "transaction.json" {
						data, e = json.Marshal(map[string]any{"previous": committed, "next": pointer, "was_active": true})
						if e != nil {
							t.Fatal(e)
						}
					}
					records[journal] = data
					if e = os.WriteFile(filepath.Join(a.store.Root, journal), data, 0600); e != nil {
						t.Fatal(e)
					}
				}
				backend := &backupInspectionBackend{}
				a.store.Backend = backend
				output := filepath.Join(t.TempDir(), "backup.qnbak")
				args := []string{"--password-file", backupPasswordFile(t)}
				if !automatic {
					args = append(args, "--file", output)
				}
				out, e := wizardOutput(t, func() error { return a.backup("backup", args) })
				if e == nil || !strings.Contains(e.Error(), "doctor") || !strings.Contains(e.Error(), "recover") {
					t.Errorf("pending backup was not refused with recovery guidance: %v", e)
				}
				if out != "" || backend.recoveries != 0 || backend.activations != 0 || backend.stops != 0 {
					t.Error("backup produced output or touched recovery/service")
				}
				afterPointer, e := os.Readlink(current)
				if e != nil || afterPointer != pointer || !bytes.Equal(state, backupReadFile(t, filepath.Join(current, "state.json"))) || !bytes.Equal(server, backupReadFile(t, filepath.Join(current, "server.json"))) {
					t.Error("backup changed current, State, or server configuration", e)
				}
				for journal, data := range records {
					b, e := os.ReadFile(filepath.Join(a.store.Root, journal))
					if e != nil || !bytes.Equal(b, data) {
						t.Errorf("backup changed %s: %v", journal, e)
					}
				}
				for _, path := range []string{output, filepath.Join(a.store.Root, "backups"), filepath.Join(a.store.Root, "observations.json")} {
					if _, e := os.Lstat(path); !os.IsNotExist(e) {
						t.Errorf("refused backup created %s", path)
					}
				}
			})
		}
	}
}

func TestBackupRejectsPendingSymlinks(t *testing.T) {
	for _, journal := range []string{"transaction.json", "uninstall.json"} {
		t.Run(journal, func(t *testing.T) {
			a, _ := menuFixture(t, "")
			path := filepath.Join(a.store.Root, journal)
			target := filepath.Join(t.TempDir(), "missing-record")
			if e := os.Symlink(target, path); e != nil {
				t.Fatal(e)
			}
			backend := &backupInspectionBackend{}
			a.store.Backend = backend
			file := filepath.Join(t.TempDir(), "backup.qnbak")
			out, e := wizardOutput(t, func() error {
				return a.backup("backup", []string{"--file", file, "--password-file", backupPasswordFile(t)})
			})
			if e == nil || out != "" || backend.recoveries != 0 || backend.activations != 0 || backend.stops != 0 {
				t.Fatal("symbolic pending record was ignored", e)
			}
			if link, e := os.Readlink(path); e != nil || link != target {
				t.Fatal("backup changed pending symbolic link", e)
			}
			if _, e := os.Lstat(file); !os.IsNotExist(e) {
				t.Fatal("backup was created for symbolic pending record")
			}
		})
	}
}

func TestBackupDoesNotInitializeMissingStore(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		a := wizardApp(t, "")
		file := filepath.Join(t.TempDir(), "backup.qnbak")
		args := []string{"--password-file", backupPasswordFile(t)}
		if !automatic {
			args = append(args, "--file", file)
		}
		out, e := wizardOutput(t, func() error { return a.backup("backup", args) })
		if e == nil || out != "" {
			t.Error("missing store was backed up", e)
		}
		for _, path := range []string{a.store.Root, file} {
			if _, e := os.Lstat(path); !os.IsNotExist(e) {
				t.Errorf("backup initialized missing path %s", path)
			}
		}
	}
}

func TestBackupPreservesV2AndRestoreStillRecoversV1V2(t *testing.T) {
	for _, format := range []int{1, 2} {
		t.Run("v"+strconv.Itoa(format), func(t *testing.T) {
			a, n := menuFixture(t, "")
			original, e := a.store.Load()
			if e != nil {
				t.Fatal(e)
			}
			backend := &backupInspectionBackend{}
			a.store.Backend = backend
			file := filepath.Join(t.TempDir(), "backup.qnbak")
			pass := backupPasswordFile(t)
			if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--file", file, "--password-file", pass}) }); e != nil {
				t.Fatal(e)
			}
			snapshot, e := node.RestoreSnapshot(backupReadFile(t, file), backupTestPassword)
			var server bytes.Buffer
			if e := json.Compact(&server, backupReadFile(t, filepath.Join(a.store.Root, "current", "server.json"))); e != nil {
				t.Fatal(e)
			}
			if e != nil || snapshot.Format != 2 || !reflect.DeepEqual(snapshot.State, original) || !bytes.Equal(snapshot.Server, server.Bytes()) {
				t.Fatal("ordinary backup changed v2 snapshot contents", e)
			}
			unchanged, e := a.store.Load()
			if e != nil || !reflect.DeepEqual(unchanged, original) {
				t.Fatal("ordinary backup changed its source state", e)
			}
			if backend.recoveries != 0 || backend.activations != 0 || backend.stops != 0 || backend.checks != 0 {
				t.Error("ordinary backup invoked recovery/service")
			}
			if _, e := os.Stat(filepath.Join(a.store.Root, "observations.json")); e != nil {
				t.Fatal("ordinary backup did not record its observation", e)
			}
			if format == 1 {
				legacy, e := node.Backup(original, backupTestPassword)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(file, legacy, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e = a.command([]string{"edit", "--id", n.ID, "--name", "changed"}); e != nil {
				t.Fatal(e)
			}
			current, e := os.Readlink(filepath.Join(a.store.Root, "current"))
			if e != nil {
				t.Fatal(e)
			}
			journal, _ := json.Marshal(map[string]any{"previous": current, "next": current, "was_active": true})
			if e = os.WriteFile(filepath.Join(a.store.Root, "transaction.json"), journal, 0600); e != nil {
				t.Fatal(e)
			}
			*backend = backupInspectionBackend{}
			if _, e = wizardOutput(t, func() error { return a.backup("restore", []string{"--file", file, "--password-file", pass, "--yes"}) }); e != nil {
				t.Fatal(e)
			}
			restored, e := a.store.Load()
			if e != nil {
				t.Fatal(e)
			}
			restoredGeneration, e := os.Readlink(filepath.Join(a.store.Root, "current"))
			if e != nil {
				t.Fatal(e)
			}
			parent := backupReadFile(t, filepath.Join(a.store.Root, restoredGeneration, "parent"))
			if restoredGeneration == current || string(parent) != current || backend.checks != 1 ||
				!reflect.DeepEqual(backend.lastChecked, restored) ||
				backend.lastCheckPath != filepath.Join(a.store.Root, restoredGeneration, "server.json") {
				t.Fatal("metadata restore did not validate and save exactly one complete candidate with the replaced generation as parent")
			}
			if backend.recoveries != 1 || backend.activations != 1 || backend.stops != 0 ||
				backend.lastActivated.Nodes[0].Name != "changed" ||
				backend.lastActivated.Nodes[0].ID != n.ID ||
				!reflect.DeepEqual(backend.lastActivated.Nodes[0].Users, original.Nodes[0].Users) ||
				!reflect.DeepEqual(backend.order, []string{"recover-removal", "activate", "check"}) {
				t.Fatal("legacy pending transaction must recover once before candidate validation; metadata restore must not activate again")
			}
			restored.Nodes[0].UpdatedAt, original.Nodes[0].UpdatedAt = "", ""
			if !reflect.DeepEqual(restored, original) {
				t.Fatal("restore did not retain write-path recovery or original identities")
			}
			if _, e = os.Lstat(filepath.Join(a.store.Root, "transaction.json")); !os.IsNotExist(e) {
				t.Fatal("restore left pending transaction", e)
			}
			files, e := filepath.Glob(filepath.Join(a.store.Root, "backups", "before-restore-*.qnbak"))
			if e != nil || len(files) != 1 {
				t.Fatal("restore lost its automatic pre-restore backup", e)
			}
			before, e := node.RestoreSnapshot(backupReadFile(t, files[0]), backupTestPassword)
			if e != nil || before.State.Nodes[0].Name != "changed" {
				t.Fatal("pre-restore backup did not retain replaced state", e)
			}
		})
	}
}
