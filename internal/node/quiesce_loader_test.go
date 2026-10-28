package node

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"qingnode/internal/platform"
)

func TestOpenRCStopProofFindsOwnedCoreBehindMuslLoader(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	process := filepath.Join(proc, "1234")
	if e := os.Mkdir(process, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/lib/ld-musl-x86_64.so.1", filepath.Join(process, "exe")); e != nil {
		t.Fatal(e)
	}
	b := SystemBackend{Root: root, ProcRoot: proc, OpenRCPIDFile: filepath.Join(t.TempDir(), "missing"), ManagerKind: platform.InitOpenRC, Execute: func(_ time.Duration, _ string, _ ...string) ([]byte, error) {
		return []byte("status: stopped\n"), errors.New("exit status 3")
	}}
	for _, tc := range []struct {
		name, args string
		pass       bool
	}{
		{"owned", "/lib/ld-musl-x86_64.so.1\x00" + CorePath(root, DefaultCore) + "\x00run\x00-c\x00config.json\x00", false},
		{"foreign", "/lib/ld-musl-x86_64.so.1\x00/opt/foreign/sing-box\x00run\x00", true},
		{"prefix sibling", "/lib/ld-musl-x86_64.so.1\x00" + root + "/cores-foreign/v/sing-box\x00", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := os.WriteFile(filepath.Join(process, "cmdline"), []byte(tc.args), 0600); e != nil {
				t.Fatal(e)
			}
			if e := b.ConfirmStopped(); (e == nil) != tc.pass {
				t.Fatal(e)
			}
		})
	}
	if e := os.Remove(filepath.Join(process, "cmdline")); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(process, "cmdline"), 0700); e != nil {
		t.Fatal(e)
	}
	if b.ConfirmStopped() == nil {
		t.Fatal("unreadable loader arguments accepted as stopped")
	}
}
