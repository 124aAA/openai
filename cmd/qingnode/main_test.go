package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"qingnode/internal/node"
)

func TestCLICompleteOfflineLifecycle(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	call := func(args ...string) {
		t.Helper()
		a := append([]string{"--offline", "--root", root}, args...)
		if e := run(a); e != nil {
			t.Fatal(args, e)
		}
	}
	load := func() node.State {
		t.Helper()
		s, e := node.ReadState(filepath.Join(root, "current", "state.json"))
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	call("init", "--server", "2001:db8::10", "--sni", "example.com")
	first := load()
	call("init")
	second := load()
	if first.Nodes[0].Reality.PrivateKey != second.Nodes[0].Reality.PrivateKey || first.Nodes[0].Users[0].UUID != second.Nodes[0].Users[0].UUID {
		t.Fatal("repeated install changed keys")
	}
	call("edit", "--id", "main", "--port", "8443", "--name", "香港 # 测试")
	call("user-add", "--id", first.Nodes[0].ID, "--name", "laptop")
	s := load()
	if len(s.Nodes[0].Users) != 2 || s.Nodes[0].Users[0].UUID != first.Nodes[0].Users[0].UUID {
		t.Fatal("adding user changed existing credentials")
	}
	export := filepath.Join(t.TempDir(), "client.json")
	call("export", "--id", first.Nodes[0].ID, "--user", "default", "--format", "sing-box", "--out", export)
	b, e := os.ReadFile(export)
	if e != nil {
		t.Fatal(e)
	}
	var c map[string]any
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	if c["outbounds"].([]any)[0].(map[string]any)["server_port"].(float64) != 8443 {
		t.Fatal("export not synchronized")
	}
	i, _ := os.Stat(export)
	if i.Mode().Perm() != 0600 {
		t.Fatal("secret export permissions")
	}
	call("disable", "--id", first.Nodes[0].ID)
	if load().Nodes[0].Enabled {
		t.Fatal("disable failed")
	}
	call("rollback")
	if !load().Nodes[0].Enabled {
		t.Fatal("rollback failed")
	}
	call("user-delete", "--id", first.Nodes[0].ID, "--user", "laptop", "--yes")
	call("delete", "--id", first.Nodes[0].ID, "--yes")
	if len(load().Nodes) != 0 {
		t.Fatal("delete failed")
	}
}
func TestCLIRejectsMissingInputInsteadOfInventingEndpoint(t *testing.T) {
	e := run([]string{"--offline", "--root", filepath.Join(t.TempDir(), "state"), "init"})
	if e == nil {
		t.Fatal("missing endpoint accepted")
	}
}
func TestOfflineModeCannotTouchSystemState(t *testing.T) {
	if run([]string{"--offline", "list"}) == nil {
		t.Fatal("offline mode used production directory")
	}
}

func TestExplicitPortsUseDecimalAndRejectInvalidValues(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	call := func(args ...string) error {
		return run(append([]string{"--offline", "--root", root}, args...))
	}
	if e := call("init", "--protocol", "ss2022", "--server", "203.0.113.8", "--port", "0443", "--quiet"); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "current", "state.json")
	s, e := node.ReadState(path)
	if e != nil || s.Nodes[0].Port != 443 {
		t.Fatal("leading-zero init port was not decimal", e)
	}
	if e = call("edit", "--id", "main", "--port", "08443"); e != nil {
		t.Fatal(e)
	}
	s, e = node.ReadState(path)
	if e != nil || s.Nodes[0].Port != 8443 {
		t.Fatal("leading-zero edit port was not decimal", e)
	}
	for _, raw := range []string{"0", "-1", "65536", "0x1bb", "invalid"} {
		if e = call("edit", "--id", "main", "--port", raw); e == nil {
			t.Fatalf("invalid explicit port accepted: %s", raw)
		}
	}
	s, e = node.ReadState(path)
	if e != nil || s.Nodes[0].Port != 8443 {
		t.Fatal("rejected edit changed port", e)
	}
}

func TestParameterEditsAndIndependentRotations(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	call := func(args ...string) {
		t.Helper()
		if e := run(append([]string{"--offline", "--root", root}, args...)); e != nil {
			t.Fatal(args, e)
		}
	}
	load := func() node.Node {
		s, e := node.ReadState(filepath.Join(root, "current", "state.json"))
		if e != nil {
			t.Fatal(e)
		}
		return s.Nodes[0]
	}
	call("init", "--server", "203.0.113.8", "--sni", "example.com", "--target", "custom.example.com:443", "--quiet")
	first := load()
	call("init", "--quiet")
	same := load()
	if first.CreatedAt == "" || same.UpdatedAt != first.UpdatedAt {
		t.Fatal("repeat init touched timestamps")
	}
	call("edit", "--id", first.ID, "--sni", "new.example.com", "--fingerprint", "firefox", "--random-port")
	edited := load()
	if edited.Reality.Target != first.Reality.Target || edited.Users[0].UUID != first.Users[0].UUID || edited.CreatedAt != first.CreatedAt {
		t.Fatal("edit changed unrelated parameters")
	}
	if edited.Reality.Fingerprint != "firefox" || edited.Port == first.Port {
		t.Fatal("parameter update lost")
	}
	call("rotate", "--id", first.ID, "--short-id", "--yes")
	short := load()
	if short.Reality.ShortID == first.Reality.ShortID || short.Reality.PrivateKey != first.Reality.PrivateKey || short.Users[0].UUID != first.Users[0].UUID {
		t.Fatal("short-ID rotation changed keys")
	}
	call("rotate", "--id", first.ID, "--keys", "--yes")
	keys := load()
	if keys.Reality.ShortID != short.Reality.ShortID || keys.Reality.PrivateKey == short.Reality.PrivateKey || keys.Reality.Fingerprint != "firefox" {
		t.Fatal("key rotation lost metadata")
	}
	if e := run([]string{"--offline", "--root", root, "edit", "--id", first.ID, "--port", "0"}); e == nil {
		t.Fatal("invalid explicit port ignored")
	}
}
func TestRestoreCreatesEncryptedPreRestoreSnapshot(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "state")
	pass := filepath.Join(dir, "password")
	os.WriteFile(pass, []byte("test long passphrase 2026"), 0600)
	call := func(args ...string) {
		t.Helper()
		if e := run(append([]string{"--offline", "--root", root}, args...)); e != nil {
			t.Fatal(args, e)
		}
	}
	call("init", "--server", "203.0.113.8", "--sni", "example.com", "--quiet")
	file := filepath.Join(dir, "backup.qnbak")
	call("backup", "--file", file, "--password-file", pass)
	call("edit", "--id", "main", "--port", "8443")
	call("restore", "--file", file, "--password-file", pass, "--yes")
	s, e := node.ReadState(filepath.Join(root, "current", "state.json"))
	if e != nil || s.Nodes[0].Port != 443 {
		t.Fatal("restore failed", e)
	}
	files, _ := filepath.Glob(filepath.Join(root, "backups", "before-restore-*.qnbak"))
	if len(files) != 1 {
		t.Fatal("missing pre-restore backup")
	}
	b, _ := os.ReadFile(files[0])
	snap, e := node.RestoreSnapshot(b, "test long passphrase 2026")
	if e != nil || snap.State.Nodes[0].Port != 8443 {
		t.Fatal("wrong pre-restore state", e)
	}
}

func TestSS2022CLILifecycleKeepsOtherNodesAndKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	call := func(args ...string) {
		t.Helper()
		if e := run(append([]string{"--offline", "--root", root}, args...)); e != nil {
			t.Fatal(args, e)
		}
	}
	load := func() node.State {
		s, e := node.ReadState(filepath.Join(root, "current", "state.json"))
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	call("init", "--server", "203.0.113.8", "--sni", "example.com", "--quiet")
	reality := load().Nodes[0]
	call("add", "--name", "SS-01", "--protocol", "ss2022", "--server", "203.0.113.8", "--port", "24567", "--quiet")
	ss := load().Nodes[1]
	call("user-add", "--id", "SS-01", "--name", "laptop")
	call("edit", "--id", "SS-01", "--port", "25678")
	changed := load()
	if changed.Nodes[0].Reality.PrivateKey != reality.Reality.PrivateKey || changed.Nodes[1].Shadowsocks.ServerKey != ss.Shadowsocks.ServerKey || changed.Nodes[1].Users[0].Password != ss.Users[0].Password {
		t.Fatal("SS management rotated existing identities")
	}
	call("rotate", "--id", "SS-01", "--user", "laptop", "--yes")
	if load().Nodes[1].Users[0].Password != ss.Users[0].Password {
		t.Fatal("wrong SS user rotated")
	}
	call("delete", "--id", "SS-01", "--yes")
	if len(load().Nodes) != 1 || load().Nodes[0].ID != reality.ID {
		t.Fatal("SS delete damaged other node")
	}
}

func TestPlainSnapshotRestoresDamagedConfigWithoutRotatingKeys(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "state")
	call := func(args ...string) error { return run(append([]string{"--offline", "--root", root}, args...)) }
	if e := call("init", "--protocol", "ss2022", "--server", "203.0.113.8", "--quiet"); e != nil {
		t.Fatal(e)
	}
	st, e := node.ReadState(filepath.Join(root, "current", "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(root, "current", "server.json")
	if e = os.WriteFile(config, []byte("broken JSON"), 0600); e != nil {
		t.Fatal(e)
	}
	snap, e := node.Capture(root, st, version, node.ServiceUnit)
	if e != nil || string(snap.ServerRaw) != "broken JSON" {
		t.Fatal("damaged config not backed up", e)
	}
	snap.Service = "[Service]\nExecStart=/usr/bin/false\n"
	data, e := json.Marshal(snap)
	if e != nil {
		t.Fatal(e)
	}
	file, pass := filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "pass")
	os.WriteFile(file, data, 0644)
	os.WriteFile(pass, []byte("test long passphrase 2026"), 0600)
	args := []string{"restore", "--snapshot", "--file", file, "--password-file", pass, "--yes"}
	if call(args...) == nil {
		t.Fatal("world-readable snapshot accepted")
	}
	os.Chmod(file, 0600)
	if e = call(args...); e != nil {
		t.Fatal(e)
	}
	after, e := node.ReadState(filepath.Join(root, "current", "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	beforeJSON, _ := json.Marshal(st)
	afterJSON, _ := json.Marshal(after)
	if string(beforeJSON) != string(afterJSON) {
		t.Fatal("repair changed saved identities or timestamps")
	}
	b, e := os.ReadFile(config)
	if e != nil || !json.Valid(b) {
		t.Fatal("derived config not repaired", e)
	}
	files, _ := filepath.Glob(filepath.Join(root, "backups", "before-restore-*.qnbak"))
	if len(files) != 1 {
		t.Fatal("missing pre-restore backup")
	}
	b, _ = os.ReadFile(files[0])
	old, e := node.RestoreSnapshot(b, "test long passphrase 2026")
	if e != nil || string(old.ServerRaw) != "broken JSON" {
		t.Fatal("damaged original evidence lost", e)
	}
}
