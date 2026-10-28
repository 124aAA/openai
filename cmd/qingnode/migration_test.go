package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
)

type migrationCLIBackend struct {
	*batchBackend
	confirmErr error
}

func (b *migrationCLIBackend) ConfirmStopped() error {
	if b.active {
		return errors.New("owned fixture active")
	}
	return b.confirmErr
}

func TestMigrationCLICleanTargetPreviewAndRestore(t *testing.T) {
	source, s := batchFixture(t)
	pass := backupPasswordFile(t)
	file := filepath.Join(t.TempDir(), "full.qnbak")
	before, raw := savedBatchState(t, source)
	if _, e := wizardOutput(t, func() error {
		return source.backup("backup", []string{"--full", "--file", file, "--password-file", pass})
	}); e != nil {
		t.Fatal(e)
	}
	if after, b := savedBatchState(t, source); after != before || !bytes.Equal(raw, b) {
		t.Fatal("full backup changed production State")
	}
	target := wizardApp(t, "")
	output, e := wizardOutput(t, func() error {
		return target.backup("restore", []string{"--file", file, "--password-file", pass, "--preview"})
	})
	if e != nil || !strings.Contains(output, "QNBK3") || !strings.Contains(output, "核心") {
		t.Fatal("clean target preview failed", e, output)
	}
	if _, e = os.Lstat(target.store.Root); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("read-only clean preview initialized State")
	}
	if _, e = wizardOutput(t, func() error {
		return target.backup("restore", []string{"--file", file, "--password-file", pass, "--yes"})
	}); e != nil {
		t.Fatal(e)
	}
	got, e := target.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Nodes) != len(s.Nodes) {
		t.Fatal("nodes lost during CLI clean restore")
	}
	for i := range s.Nodes {
		if got.Nodes[i].ID != s.Nodes[i].ID || !reflect.DeepEqual(got.Nodes[i].Users, s.Nodes[i].Users) {
			t.Fatal("clean restore rotated identity")
		}
	}
	backups, e := filepath.Glob(filepath.Join(target.store.Root, "backups", "before-restore-*.qnbak"))
	if e != nil || len(backups) != 1 {
		t.Fatal("clean restore did not retain initial recovery point", e)
	}
}

func TestMigrationCLISubscriptionPermissionMappingAndQuiescence(t *testing.T) {
	source, state, backend, sourceDir, materials := subscriptionCLIFixture(t)
	wrapped := &migrationCLIBackend{batchBackend: backend}
	source.store.Backend = wrapped
	wrapped.active = true
	pass := backupPasswordFile(t)
	file := filepath.Join(t.TempDir(), "full.qnbak")
	preview, e := wizardOutput(t, func() error { return source.backup("backup", []string{"--full", "--preview"}) })
	if e != nil || !strings.Contains(preview, "短停") {
		t.Fatal("preview omitted lifecycle impact", e)
	}
	if wrapped.stops != 0 || wrapped.starts != 0 {
		t.Fatal("preview changed service")
	}
	if _, e = wizardOutput(t, func() error {
		return source.backup("backup", []string{"--full", "--file", file, "--password-file", pass})
	}); e == nil {
		t.Fatal("running runtime storage copied without explicit quiesce")
	}
	if wrapped.stops != 0 || wrapped.starts != 0 {
		t.Fatal("refused snapshot changed service")
	}
	if _, e = wizardOutput(t, func() error {
		return source.backup("backup", []string{"--full", "--file", file, "--password-file", pass, "--quiesce"})
	}); e != nil {
		t.Fatal(e)
	}
	if wrapped.stops != 1 || wrapped.starts != 1 || !wrapped.active {
		t.Fatal("full snapshot did not restore original running state")
	}
	target := wizardApp(t, "")
	dir := filepath.Join(t.TempDir(), "restored-publication")
	args := []string{"--file", file, "--password-file", pass, "--yes", "--subscription-directory", dir}
	if _, e = wizardOutput(t, func() error { return target.backup("restore", args) }); e == nil || !strings.Contains(e.Error(), "--restore-subscriptions") {
		t.Fatal("download permissions restored without explicit selection", e)
	}
	if _, e = os.Lstat(target.store.Root); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("rejected permissions restore initialized State")
	}
	args = append(args, "--restore-subscriptions")
	if _, e = wizardOutput(t, func() error { return target.backup("restore", args) }); e != nil {
		t.Fatal(e)
	}
	c, ok, e := target.publisherConfig()
	if e != nil || !ok || c.Directory != dir || c.Directory == sourceDir {
		t.Fatal("archived publisher path was not mapped", e)
	}
	got, e := target.store.Load()
	if e != nil || len(got.Devices) != len(state.Devices) {
		t.Fatal("device permissions lost", e)
	}
	for _, m := range materials {
		status, _ := subscriptionCLIGet(t, dir, m.Token)
		if status != 200 {
			t.Fatal("explicit permission migration failed", status)
		}
	}
}

func TestMigrationCLIUnconfirmedStopAndPendingPreviewAreReadOnly(t *testing.T) {
	a, _, backend, _, _ := subscriptionCLIFixture(t)
	wrapped := &migrationCLIBackend{batchBackend: backend, confirmErr: errors.New("cannot confirm owned cgroup")}
	a.store.Backend = wrapped
	file := filepath.Join(t.TempDir(), "refused.qnbak")
	pass := backupPasswordFile(t)
	if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--full", "--file", file, "--password-file", pass}) }); e == nil || !strings.Contains(e.Error(), "cgroup") {
		t.Fatal("unknown stopped state was accepted", e)
	}
	if _, e := os.Lstat(file); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("failed confirmation created a backup")
	}
	journal := filepath.Join(a.store.Root, node.MigrationJournalName)
	_ = os.WriteFile(journal, []byte("interrupted migration evidence"), 0600)
	_, before := savedBatchState(t, a)
	if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--full", "--preview"}) }); e == nil {
		t.Fatal("pending asset migration preview ignored unresolved transaction")
	}
	_, after := savedBatchState(t, a)
	if !bytes.Equal(before, after) {
		t.Fatal("failed preview repaired State")
	}
	data, _ := os.ReadFile(journal)
	if string(data) != "interrupted migration evidence" {
		t.Fatal("read-only preview changed recovery material")
	}
}

func TestMigrationCLIBackupRetentionDoesNotDeleteExplicitOutputs(t *testing.T) {
	a, _ := batchFixture(t)
	pass := backupPasswordFile(t)
	for i := 0; i < 3; i++ {
		if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--password-file", pass}) }); e != nil {
			t.Fatal(e)
		}
	}
	explicit := filepath.Join(t.TempDir(), "user.qnbak")
	if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--file", explicit, "--password-file", pass}) }); e != nil {
		t.Fatal(e)
	}
	if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--prune", "--retain-count", "1"}) }); e != nil {
		t.Fatal(e)
	}
	all, _ := filepath.Glob(filepath.Join(a.store.Root, "backups", "backup-*.qnbak"))
	if len(all) != 3 {
		t.Fatal("retention preview deleted backups")
	}
	if _, e := wizardOutput(t, func() error { return a.backup("backup", []string{"--prune", "--retain-count", "1", "--yes"}) }); e != nil {
		t.Fatal(e)
	}
	all, _ = filepath.Glob(filepath.Join(a.store.Root, "backups", "backup-*.qnbak"))
	if len(all) != 1 {
		t.Fatal("retention did not apply count limit")
	}
	if _, e := os.Stat(explicit); e != nil {
		t.Fatal("retention deleted a user-selected output", e)
	}
}

func TestMigrationCLIIncompleteRollbackKeepsOwnedServiceStopped(t *testing.T) {
	for _, name := range []string{node.MigrationJournalName, "transaction.json"} {
		t.Run(name, func(t *testing.T) {
			a, state := batchFixture(t)
			backend := &migrationCLIBackend{batchBackend: &batchBackend{active: true}}
			a.store.Backend = backend
			path := filepath.Join(a.store.Root, name)
			evidence := []byte("pending recovery material")
			err := a.withStoppedMigration(state, true, func() error {
				if err := os.WriteFile(path, evidence, 0600); err != nil {
					return err
				}
				return errors.New("injected rollback disk failure")
			})
			if err == nil || !strings.Contains(err.Error(), "保持停止") {
				t.Fatal("failed rollback omitted stopped recovery guidance", err)
			}
			if backend.active || backend.stops != 1 || backend.starts != 0 {
				t.Fatal("failed asset or State rollback restarted an unconfirmed configuration")
			}
			got, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(got, evidence) {
				t.Fatal("failed rollback lost its recovery material", e)
			}
		})
	}
}

func TestMigrationCLIOfflineACMEStorageCannotClaimConsistentFullSnapshot(t *testing.T) {
	a := wizardApp(t, "")
	if e := a.add("add", []string{"--name", "offline-acme", "--protocol", "hysteria2", "--server", "127.0.0.1", "--port", "15443", "--sni", "acme.example.test", "--acme-email", "owner@example.test", "--quiet"}); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(a.store.Root, "acme")
	if e := os.Mkdir(dir, 0750); e != nil {
		t.Fatal(e)
	}
	secret := []byte("account-being-written-by-an-unmanaged-core")
	if e := os.WriteFile(filepath.Join(dir, "account.key"), secret, 0600); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(t.TempDir(), "offline.qnbak")
	pass := backupPasswordFile(t)
	if _, e := wizardOutput(t, func() error {
		return a.backup("backup", []string{"--full", "--file", file, "--password-file", pass, "--quiesce"})
	}); e == nil || !strings.Contains(e.Error(), "不能证明") {
		t.Fatal("offline backend claimed a stopped ACME writer", e)
	}
	if _, e := os.Lstat(file); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refused snapshot wrote an output")
	}
	if _, e := wizardOutput(t, func() error {
		return a.backup("backup", []string{"--full", "--file", file, "--password-file", pass, "--allow-incomplete"})
	}); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	m, e := node.RestoreMigration(raw, backupTestPassword)
	if e != nil {
		t.Fatal(e)
	}
	if m.Mode != "limited" || len(m.External) == 0 {
		t.Fatal("offline storage exclusion was hidden")
	}
	for _, r := range m.Roots {
		if r.ID == "acme" {
			t.Fatal("unconfirmed offline writer's ACME root was copied")
		}
	}
	for _, f := range m.Files {
		if bytes.Contains(f.Data, secret) {
			t.Fatal("excluded ACME runtime material leaked into limited package")
		}
	}
	got, e := os.ReadFile(filepath.Join(dir, "account.key"))
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal("offline backup changed user's storage", e)
	}
}

func TestMigrationCLIPreRestoreCompletePointSurvivesLaterConfigurationRetention(t *testing.T) {
	a, _, backend, _, _ := subscriptionCLIFixture(t)
	a.store.Backend = &migrationCLIBackend{batchBackend: backend}
	state, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := a.snapshot(state)
	if e != nil {
		t.Fatal(e)
	}
	input, e := node.BackupSnapshot(snapshot, backupTestPassword)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(t.TempDir(), "configuration-to-restore.qnbak")
	if e = os.WriteFile(file, input, 0600); e != nil {
		t.Fatal(e)
	}
	pass := backupPasswordFile(t)
	if _, e = wizardOutput(t, func() error { return a.backup("restore", []string{"--file", file, "--password-file", pass, "--yes"}) }); e != nil {
		t.Fatal(e)
	}
	before, e := filepath.Glob(filepath.Join(a.store.Root, "backups", "before-restore-*.qnbak"))
	if e != nil || len(before) != 1 {
		t.Fatal("missing automatic complete recovery point", e)
	}
	material, e := os.ReadFile(before[0])
	if e != nil {
		t.Fatal(e)
	}
	migration, e := node.RestoreMigration(material, backupTestPassword)
	if e != nil || migration.Mode != "complete" {
		t.Fatal("automatic original-asset recovery point was not complete", e)
	}
	if _, e = wizardOutput(t, func() error { return a.backup("backup", []string{"--password-file", pass}) }); e != nil {
		t.Fatal(e)
	}
	if _, e = wizardOutput(t, func() error {
		return a.backup("backup", []string{"--prune", "--retain-count", "1", "--retain-age", "1ns", "--retain-bytes", "1", "--yes"})
	}); e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(before[0])
	if e != nil || !bytes.Equal(after, material) {
		t.Fatal("later configuration-only backup allowed retention to delete the sole complete pre-restore recovery point", e)
	}
	current, _ := filepath.Glob(filepath.Join(a.store.Root, "backups", "backup-*.qnbak"))
	if len(current) != 1 {
		t.Fatal("current configuration recovery point was deleted")
	}
}
