package node

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSocketOwnershipRejectsUnrelatedListener(t *testing.T) {
	s := fixture(t)
	n := s.Nodes[0]
	n.Listen = "0.0.0.0"
	s.Nodes[0] = n
	sockets := []Socket{{Network: "tcp", Address: n.Listen, Port: n.Port}}
	if SocketsReady(s, sockets) {
		t.Fatal("unrelated socket counted as service")
	}
	sockets[0].Owned = true
	if !SocketsReady(s, sockets) {
		t.Fatal("owned socket not detected")
	}
	sockets[0].Address = "127.0.0.1"
	if SocketsReady(s, sockets) {
		t.Fatal("wrong bind address accepted")
	}
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "42/fd"), 0700)
	os.MkdirAll(filepath.Join(proc, "net"), 0700)
	os.Symlink("socket:[777]", filepath.Join(proc, "42/fd/3"))
	os.WriteFile(filepath.Join(proc, "net/tcp"), []byte("0: 00000000:01BB 00000000:0000 0A 0 0 0 0 0 777\n"), 0600)
	got := ReadSockets(proc, 42)
	if len(got) != 1 || !got[0].Owned || got[0].Port != 443 {
		t.Fatalf("socket inode parsing failed: %+v", got)
	}
}
func TestRestartDoesNotEnableAutostart(t *testing.T) {
	var commands []string
	b := SystemBackend{Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil, errors.New("injected restart failure")
	}}
	if b.Activate(fixture(t)) == nil {
		t.Fatal("restart failure ignored")
	}
	if len(commands) != 1 || strings.Contains(commands[0], " enable ") {
		t.Fatal(commands)
	}
}
func TestReadOnlyInspectionLeavesPendingTransaction(t *testing.T) {
	st, b := newStore(t)
	if e := st.WithLock(func() error { return st.Apply(fixture(t)) }); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(st.Root, "transaction.json"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	before := b.activations
	if e := st.Inspect(func() error { _, e := st.Load(); return e }); e != nil {
		t.Fatal(e)
	}
	if b.activations != before {
		t.Fatal("inspection restarted service")
	}
	if st.WithLock(func() error { return nil }) == nil {
		t.Fatal("invalid recovery record ignored")
	}
}
func TestRejectedCandidateIsCleaned(t *testing.T) {
	st, b := newStore(t)
	s := fixture(t)
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadDir(filepath.Join(st.Root, "generations"))
	b.failCheck = true
	s.Nodes[0].Port++
	if st.WithLock(func() error { return st.Apply(s) }) == nil {
		t.Fatal("expected error")
	}
	after, _ := os.ReadDir(filepath.Join(st.Root, "generations"))
	if len(before) != len(after) {
		t.Fatal("failed generation leaked")
	}
}
func TestRemovalFailureRestoresOnlyOwnedFiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "state")
	os.MkdirAll(filepath.Join(root, "cores"), 0700)
	unit := filepath.Join(dir, "qingnode.service")
	bin := filepath.Join(dir, "qingnode")
	lib := filepath.Join(dir, "lib")
	os.Mkdir(lib, 0700)
	os.WriteFile(filepath.Join(lib, ".qingnode-owner"), []byte(OwnerMarker), 0600)
	os.WriteFile(unit, []byte(ServiceUnit), 0600)
	os.WriteFile(bin, []byte("binary"), 0700)
	other := filepath.Join(dir, "ssh-config")
	os.WriteFile(other, []byte("keep"), 0600)
	failed := false
	r := Removal{Root: root, Unit: unit, Binary: bin, Library: lib, Execute: func(_ time.Duration, _ string, args ...string) ([]byte, error) {
		if args[0] == "daemon-reload" && !failed {
			failed = true
			return nil, errors.New("injected reload failure")
		}
		return nil, nil
	}}
	if r.Remove(true) == nil {
		t.Fatal("expected uninstall failure")
	}
	for _, p := range []string{unit, bin, lib, filepath.Join(root, "cores"), other} {
		if _, e := os.Stat(p); e != nil {
			t.Fatal("not restored", p, e)
		}
	}
	if _, e := os.Stat(filepath.Join(root, "uninstall.json")); !os.IsNotExist(e) {
		t.Fatal("journal not cleared")
	}
	if e := r.Remove(false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(bin); e != nil {
		t.Fatal("core-only uninstall deleted manager")
	}
}
func TestRedactionCoversURIJSONPEMAndOldSecrets(t *testing.T) {
	s := fixture(t)
	text := s.Nodes[0].Users[0].UUID + " vless://secret@host:443 " + `{"password":"unknown-secret"}` + "\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\x1b[31m"
	got := Redact(text, s)
	for _, secret := range []string{s.Nodes[0].Users[0].UUID, "vless://", "unknown-secret", "abc", "\x1b"} {
		if strings.Contains(got, secret) {
			t.Fatal("secret leaked", secret)
		}
	}
}

func TestStoreRecoversInterruptedCoreRemovalBeforeCreatingDirectories(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".qingnode-owner"), []byte(OwnerMarker), 0600)
	os.Mkdir(filepath.Join(root, "cores"), 0700)
	os.WriteFile(filepath.Join(root, "cores", "original-core"), []byte("keep"), 0600)
	if e := os.Rename(filepath.Join(root, "cores"), filepath.Join(root, ".uninstall-cores")); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "uninstall.json"), []byte(`{"full":false,"active":false,"enabled":false}`), 0600)
	b := SystemBackend{Root: root, Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("unexpected command %s", name)
		}
		return nil, nil
	}}
	s := &Store{Root: root, Backend: b, GID: -1}
	if e := s.WithLock(func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(root, "cores", "original-core"))
	if e != nil || string(data) != "keep" {
		t.Fatal("original core not recovered", e)
	}
	if _, e = os.Stat(filepath.Join(root, "uninstall.json")); !os.IsNotExist(e) {
		t.Fatal("removal journal not cleared")
	}
}

func TestRetainedAccountRecordDoesNotAdoptForeignFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".qingnode-account")
	r := Removal{Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name != "getent" || len(args) != 2 || args[1] != "qingnode" {
			t.Fatal(name, args)
		}
		if args[0] == "passwd" {
			return []byte("qingnode:x:999:999::/var/lib/qingnode/acme:/usr/sbin/nologin\n"), nil
		}
		return []byte("qingnode:x:999:\n"), nil
	}}
	os.WriteFile(path, []byte("foreign file"), 0600)
	if r.RecordAccount(path) == nil {
		t.Fatal("foreign file overwritten")
	}
	os.Remove(path)
	if e := r.RecordAccount(path); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	i, _ := os.Stat(path)
	if !strings.Contains(string(b), "qingnode:x:999:999:") || i.Mode().Perm() != 0600 {
		t.Fatal("identity/permissions missing")
	}
}
