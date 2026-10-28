package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func migrationFixture(t *testing.T) MigrationPackage {
	t.Helper()
	s, e := CanonicalCertificates(hyFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	m, e := CaptureMigration(Snapshot{Format: 2, State: s, ServerRaw: []byte("{damaged derived"), Service: "[Service]\nExecStart=/never/execute\n"}, nil, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func migrationAsset(id, p string, b []byte, mode uint32) MigrationFile {
	h := sha256.Sum256(b)
	return MigrationFile{RootID: id, Path: p, Mode: mode, SHA256: hex.EncodeToString(h[:]), Data: append([]byte{}, b...)}
}
func migrationClone(m MigrationPackage) MigrationPackage {
	b, _ := json.Marshal(m)
	var c MigrationPackage
	_ = json.Unmarshal(b, &c)
	return c
}

func TestMigrationEncryptedRoundTripAndOldFormats(t *testing.T) {
	m := migrationFixture(t)
	pass := "migration-strong-password"
	b, e := BackupMigration(m, pass)
	if e != nil {
		t.Fatal(e)
	}
	if !IsMigrationBackup(b) || bytes.Contains(b, []byte(m.Snapshot.State.Certificates[0].Certificate.KeyPEM)) {
		t.Fatal("private material was not encrypted")
	}
	got, e := RestoreMigration(b, pass)
	if e != nil || !reflect.DeepEqual(got, m) {
		t.Fatal("migration changed identities, certificate material or original evidence", e)
	}
	if _, e = RestoreSnapshot(b, pass); e == nil {
		t.Fatal("old configuration restore accepted unknown migration format")
	}
	if _, e = RestoreMigration(b, "incorrect-password"); e == nil || !strings.Contains(e.Error(), "口令") {
		t.Fatal("wrong password accepted", e)
	}
	b[len(b)-1] ^= 1
	if _, e = RestoreMigration(b, pass); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	for _, format := range []int{1, 2} {
		var old []byte
		if format == 1 {
			old, e = Backup(m.Snapshot.State, pass)
		} else {
			old, e = BackupSnapshot(m.Snapshot, pass)
		}
		if e != nil {
			t.Fatal(e)
		}
		oldState, e := Restore(old, pass)
		if e != nil || !reflect.DeepEqual(oldState, m.Snapshot.State) {
			t.Fatal("legacy encrypted format lost identity", format, e)
		}
	}
}

func TestMigrationRejectsAuthenticatedFutureUnknownDuplicateAndNull(t *testing.T) {
	m := migrationFixture(t)
	raw, _ := json.Marshal(m)
	cases := map[string][]byte{}
	future := migrationClone(m)
	future.Version++
	cases["future package"], _ = json.Marshal(future)
	futureManifest := migrationClone(m)
	futureManifest.Manifest.Version++
	cases["future manifest"], _ = json.Marshal(futureManifest)
	cases["unknown manifest field"] = []byte(strings.Replace(string(raw), "\"manifest\":{", "\"manifest\":{\"future\":true,", 1))
	cases["future State"] = bytes.Replace(raw, []byte(`"schema":`+strconv.Itoa(Schema)), []byte(`"schema":`+strconv.Itoa(Schema+1)), 1)
	if bytes.Equal(cases["future State"], raw) {
		t.Fatal("future State migration fixture did not change current schema")
	}
	cases["unknown envelope"] = append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"unexpected\":\"preserve\"}")...)
	cases["duplicate"] = append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"version\":1}")...)
	cases["Unicode alias"] = append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"verſion\":1}")...)
	cases["null"] = []byte(strings.Replace(string(raw), "\"files\":[]", "\"files\":null", 1))
	cases["trailing"] = append(append([]byte{}, raw...), []byte("{}")...)
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			sealed, e := sealBackup(b, "authenticated-invalid-fixture", []byte("QNBK3\x00"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = RestoreMigration(sealed, "authenticated-invalid-fixture"); e == nil {
				t.Fatal("invalid authenticated migration was accepted")
			}
		})
	}
}

func TestMigrationRejectsMaliciousEntriesAndFalseCompleteness(t *testing.T) {
	base := migrationFixture(t)
	root := MigrationRoot{ID: "acme", Kind: "acme-storage", Source: "/source/acme", OwnerID: os.Geteuid(), GroupID: -1}
	if validMigrationPath("..") {
		t.Fatal("parent directory was accepted as a migration path")
	}
	for _, name := range []string{"../escape", "/absolute", "a/../../escape", "a//b", "a/./b", "C:/host", "a\\host", ".", "..", "bad\nname"} {
		t.Run(name, func(t *testing.T) {
			m := migrationClone(base)
			m.Roots = []MigrationRoot{root}
			m.Consistency = "stopped-owned-core"
			m.Files = []MigrationFile{migrationAsset("acme", name, []byte("x"), 0600)}
			if m.Validate() == nil {
				t.Fatal("unsafe entry was accepted")
			}
		})
	}
	acme := base.Snapshot.State.Clone()
	r := &acme.Certificates[0]
	r.Certificate = Certificate{Mode: "acme", ServerName: "localhost", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01"}}
	for i := range acme.Nodes {
		acme.Nodes[i].Certificate = nil
	}
	acme, e := CanonicalCertificates(acme)
	if e != nil {
		t.Fatal(e)
	}
	m := migrationClone(base)
	m.Snapshot.State = acme
	m.Roots = []MigrationRoot{root}
	m.Files = []MigrationFile{}
	m.Consistency = "stopped-owned-core"
	if m.Validate() == nil {
		t.Fatal("empty ACME directory was called a complete migration")
	}
	m.Mode = "limited"
	m.External = []string{"ACME account and certificate not issued"}
	if e = m.Validate(); e != nil {
		t.Fatal("explicit limited migration rejected", e)
	}
	parentDirectory := migrationClone(m)
	parentDirectory.Files = []MigrationFile{{RootID: "acme", Path: "..", Directory: true, Mode: 0700}}
	if parentDirectory.Validate() == nil {
		t.Fatal("parent directory entry would escape the staging directory")
	}
	for name, change := range map[string]func(*MigrationPackage){
		"future asset root": func(m *MigrationPackage) { m.Roots[0].ID = "untrusted" },
		"duplicate path": func(m *MigrationPackage) {
			f := migrationAsset("acme", "duplicate", []byte("x"), 0600)
			m.Files = []MigrationFile{f, f}
		},
		"executable mode": func(m *MigrationPackage) {
			m.Files = []MigrationFile{migrationAsset("acme", "binary", []byte("x"), 0755)}
		},
		"wrong digest": func(m *MigrationPackage) {
			f := migrationAsset("acme", "bad", []byte("x"), 0600)
			f.SHA256 = strings.Repeat("0", 64)
			m.Files = []MigrationFile{f}
		},
		"parent file": func(m *MigrationPackage) {
			m.Files = []MigrationFile{migrationAsset("acme", "parent", []byte("x"), 0600), migrationAsset("acme", "parent/child", []byte("y"), 0600)}
		},
		"directory payload": func(m *MigrationPackage) {
			f := migrationAsset("acme", "dir", []byte("x"), 0700)
			f.Directory = true
			m.Files = []MigrationFile{f}
		},
		"false no-runtime claim": func(m *MigrationPackage) { m.Consistency = "no-runtime-assets" },
	} {
		t.Run(name, func(t *testing.T) {
			c := migrationClone(m)
			change(&c)
			if c.Validate() == nil {
				t.Fatal("malformed typed archive was accepted")
			}
		})
	}
	tooMany := migrationClone(m)
	tooMany.Files = make([]MigrationFile, MaxMigrationFiles+1)
	if tooMany.Validate() == nil {
		t.Fatal("unbounded count accepted")
	}
	large := migrationClone(m)
	large.Files = []MigrationFile{migrationAsset("acme", "large", make([]byte, MaxMigrationFileBytes+1), 0600)}
	if large.Validate() == nil {
		t.Fatal("unbounded file accepted")
	}
}

func TestMigrationCaptureRejectsLinksSpecialPermissionsAndConcurrentWriterClaim(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "writable", "executable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0750); e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(dir, "asset")
			switch kind {
			case "symlink":
				if e := os.Symlink("missing", p); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				original := filepath.Join(dir, "original")
				_ = os.WriteFile(original, []byte("secret"), 0600)
				if e := os.Link(original, p); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := syscall.Mkfifo(p, 0600); e != nil {
					t.Fatal(e)
				}
			case "writable":
				_ = os.WriteFile(p, []byte("secret"), 0666)
				_ = os.Chmod(p, 0666)
			case "executable":
				_ = os.WriteFile(p, []byte("payload"), 0755)
				_ = os.Chmod(p, 0755)
			}
			_, e := captureMigrationRoot(MigrationRoot{ID: "acme", Kind: "acme-storage", Source: dir, OwnerID: os.Geteuid(), GroupID: -1})
			if e == nil {
				t.Fatal("unsafe filesystem object captured")
			}
		})
	}
	m := migrationFixture(t)
	dir := t.TempDir()
	_, e := CaptureMigration(m.Snapshot, []MigrationRoot{{ID: "acme", Kind: "acme-storage", Source: dir, OwnerID: os.Geteuid(), GroupID: -1}}, nil, false)
	if e == nil {
		t.Fatal("active runtime storage copied without quiescence")
	}
}

type migrationBackend struct {
	fakeBackend
	confirmErr error
}

func (b *migrationBackend) ConfirmStopped() error {
	if b.active {
		return errors.New("fixture still active")
	}
	return b.confirmErr
}

func TestMigrationRestoreFailureAndCommittedPublicationError(t *testing.T) {
	for _, kind := range []string{"check failure", "activation failure", "publication failure", "stopped proof failure"} {
		t.Run(kind, func(t *testing.T) {
			m := migrationFixture(t)
			b := &migrationBackend{}
			s := &Store{Root: filepath.Join(t.TempDir(), "state"), Backend: b, GID: -1}
			old := m.Snapshot.State.Clone()
			old.Nodes[0].Name = "old"
			if e := s.WithLock(func() error { return s.Apply(old) }); e != nil {
				t.Fatal(e)
			}
			_ = b.Stop()
			if kind == "check failure" {
				b.failCheck = true
			}
			if kind == "activation failure" {
				b.failNext = true
				m.Snapshot.State.Nodes[0].Port++
			}
			if kind == "publication failure" {
				s.AfterCommit = func(State) error { return errors.New("private publish disk failure") }
			}
			if kind == "stopped proof failure" {
				b.confirmErr = errors.New("unknown owned process")
			}
			e := s.InspectExisting(func() error { return s.RestoreMigrationAssets(m, MigrationTargets{}, false) })
			if e == nil {
				t.Fatal("injected failure disappeared")
			}
			got, ge := s.Load()
			if ge != nil {
				t.Fatal(ge)
			}
			if kind == "publication failure" {
				if got.Nodes[0].Name != m.Snapshot.State.Nodes[0].Name {
					t.Fatal("committed State was incorrectly rolled back after publication error")
				}
			} else if got.Nodes[0].Name != "old" {
				t.Fatal("failed migration changed State")
			}
			if _, e = os.Lstat(filepath.Join(s.Root, MigrationJournalName)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("completed rollback retained asset journal", e)
			}
		})
	}
}

func TestMigrationRecoverySameStateBeforeCommitRollsBackAssets(t *testing.T) {
	m := migrationFixture(t)
	b := &migrationBackend{}
	s := &Store{Root: filepath.Join(t.TempDir(), "state"), Backend: b, GID: -1}
	if e := s.WithLock(func() error { return s.Apply(m.Snapshot.State) }); e != nil {
		t.Fatal(e)
	}
	_ = b.Stop()
	generation, _ := s.current()
	id := Token(16)
	target := filepath.Join(s.Root, "acme")
	x := migrationSwitch{ID: "acme", Target: target, Staged: target + ".qingnode-stage-" + id, Previous: target + ".qingnode-previous-" + id, HadPrevious: true}
	for dir, value := range map[string]string{x.Previous: "old", target: "candidate"} {
		_ = os.Mkdir(dir, 0750)
		_ = os.WriteFile(filepath.Join(dir, "asset"), []byte(value), 0600)
	}
	j := migrationRestoreJournal{Version: 1, ID: id, PreviousGeneration: generation, NextState: m.Snapshot.State, Switches: []migrationSwitch{x}}
	if e := writeMigrationJournal(s.Root, j); e != nil {
		t.Fatal(e)
	}
	if e := s.WithLock(func() error { return nil }); e == nil {
		t.Fatal("ordinary write crossed interrupted migration")
	}
	if e := s.InspectExisting(func() error { return s.RecoverMigrationAssets() }); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(filepath.Join(target, "asset"))
	if string(data) != "old" {
		t.Fatal("same State was mistaken for a committed asset switch")
	}
	if b.Active() {
		t.Fatal("recovery started a previously stopped service")
	}
}

func TestMigrationRecoveryRejectsForeignTargetAndUnconfirmedStop(t *testing.T) {
	for _, kind := range []string{"foreign subscription", "symlink", "unconfirmed"} {
		t.Run(kind, func(t *testing.T) {
			m := migrationFixture(t)
			b := &migrationBackend{}
			s := &Store{Root: filepath.Join(t.TempDir(), "state"), Backend: b, GID: -1}
			if e := s.WithLock(func() error { return s.Apply(m.Snapshot.State) }); e != nil {
				t.Fatal(e)
			}
			_ = b.Stop()
			id := Token(16)
			target := filepath.Join(t.TempDir(), "foreign")
			_ = os.Mkdir(target, 0750)
			_ = os.WriteFile(filepath.Join(target, "owned-by-user"), []byte("keep"), 0600)
			x := migrationSwitch{ID: "subscription", Target: target, Staged: target + ".qingnode-stage-" + id, Previous: target + ".qingnode-previous-" + id, HadPrevious: true}
			if kind == "symlink" {
				x.ID = "acme"
				x.Target = filepath.Join(s.Root, "acme")
				x.Staged = x.Target + ".qingnode-stage-" + id
				x.Previous = x.Target + ".qingnode-previous-" + id
				_ = os.Symlink(target, x.Target)
			}
			if kind == "unconfirmed" {
				x.ID = "acme"
				x.Target = filepath.Join(s.Root, "acme")
				x.Staged = x.Target + ".qingnode-stage-" + id
				x.Previous = x.Target + ".qingnode-previous-" + id
				_ = os.Mkdir(x.Target, 0750)
				b.confirmErr = errors.New("service query denied")
			}
			j := migrationRestoreJournal{Version: 1, ID: id, NextState: m.Snapshot.State, Switches: []migrationSwitch{x}}
			if e := writeMigrationJournal(s.Root, j); e != nil {
				t.Fatal(e)
			}
			if e := s.InspectExisting(func() error { return s.RecoverMigrationAssets() }); e == nil {
				t.Fatal("unsafe recovery was allowed")
			}
			data, _ := os.ReadFile(filepath.Join(target, "owned-by-user"))
			if string(data) != "keep" {
				t.Fatal("recovery changed another user's directory")
			}
		})
	}
}

func TestManagedBackupRetentionProtectsCurrentAndLatestComplete(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	for _, name := range []string{"first.qnbak", "complete.qnbak", "latest.qnbak"} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, bytes.Repeat([]byte(name), 8), 0600)
		if e := RegisterManagedBackup(dir, p, name == "complete.qnbak"); e != nil {
			t.Fatal(e)
		}
	}
	unmanaged := filepath.Join(dir, "manual.qnbak")
	_ = os.WriteFile(unmanaged, []byte("unindexed user backup"), 0600)
	p := BackupRetention{Count: 1, MaxAge: time.Nanosecond, Bytes: 1}
	names, e := PruneManagedBackups(dir, p, false)
	if e != nil || len(names) != 1 || names[0] != "first.qnbak" {
		t.Fatal("retention preview did not protect both restoration points", names, e)
	}
	if _, e = os.Stat(filepath.Join(dir, "first.qnbak")); e != nil {
		t.Fatal("preview deleted a file")
	}
	if _, e = PruneManagedBackups(dir, p, true); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"complete.qnbak", "latest.qnbak", "manual.qnbak"} {
		if _, e = os.Stat(filepath.Join(dir, name)); e != nil {
			t.Fatal("protected or unowned backup deleted", name, e)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "complete.qnbak"), []byte("external edit"), 0600)
	if _, e = PruneManagedBackups(dir, p, true); e == nil {
		t.Fatal("external modification was silently pruned")
	}
}

func TestMigrationManifestRejectsSourceMismatchAndKeepsUnknownDigests(t *testing.T) {
	m := migrationFixture(t)
	if m.Manifest.CoreBinarySHA256 != "" || m.Manifest.CoreArchiveSHA256 != "" {
		t.Fatal("absent installed-core evidence was invented")
	}
	upper := migrationClone(m)
	upper.Snapshot.State.CoreArchiveSHA256 = strings.Repeat("AB", 32)
	upper.Manifest.CoreArchiveSHA256 = upper.Snapshot.State.CoreArchiveSHA256
	if err := upper.Validate(); err != nil || upper.Snapshot.State.CoreArchiveSHA256 != strings.Repeat("AB", 32) {
		t.Fatal("existing uppercase archive digest was rejected or rewritten", err)
	}
	for name, change := range map[string]func(*MigrationPackage){
		"wrong core": func(m *MigrationPackage) { m.Manifest.CoreVersion = "1.14.3" },
		"wrong manager": func(m *MigrationPackage) {
			m.Snapshot.ManagerVersion = "recorded-manager"
			m.Manifest.ManagerVersion = "other-manager"
		},
		"unknown platform":     func(m *MigrationPackage) { m.Manifest.OS = "future-os" },
		"unknown architecture": func(m *MigrationPackage) { m.Manifest.Architecture = "future-arch" },
		"invalid digest":       func(m *MigrationPackage) { m.Manifest.CoreBinarySHA256 = "not-a-sha256" },
		"mismatched archive":   func(m *MigrationPackage) { m.Manifest.CoreArchiveSHA256 = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			c := migrationClone(m)
			change(&c)
			if c.Validate() == nil {
				t.Fatal("untrusted version manifest accepted")
			}
		})
	}
}
