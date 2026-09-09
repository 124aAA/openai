package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStorePermissionsUnderRestrictiveUmask(t *testing.T) {
	const helper = "QINGNODE_TEST_RESTRICTIVE_UMASK"
	if os.Getenv(helper) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStorePermissionsUnderRestrictiveUmask$", "-test.v")
		cmd.Env = append(os.Environ(), helper+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated permission regression failed: %v\n%s", err, out)
		} else {
			t.Logf("%s", out)
		}
		return
	}
	// umask is process-wide; only the isolated test process changes it.
	syscall.Umask(0077)
	base, err := os.MkdirTemp("", "qingnode-permissions-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	gid := -1
	if os.Geteuid() == 0 {
		gid = 65534
	}
	st := &Store{Root: filepath.Join(base, "state"), Backend: OfflineBackend{}, GID: gid}
	s := fixture(t)
	for _, stage := range []string{"initial", "changed"} {
		if stage == "changed" {
			s.Nodes[0].Port++
			// Already owned directories also need repair on the next mutation.
			for _, p := range []string{st.Root, filepath.Join(st.Root, "generations"), filepath.Join(st.Root, "cores")} {
				if err := os.Chmod(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := st.WithLock(func() error { return st.Apply(s) }); err != nil {
			t.Fatal(stage, err)
		}
		g, err := st.current()
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(st.Root, g)
		for _, p := range []string{st.Root, filepath.Join(st.Root, "generations"), filepath.Join(st.Root, "cores"), dir} {
			assertStorePermissions(t, p, 0750, gid)
		}
		for _, name := range []string{"core-version", "server.json"} {
			assertStorePermissions(t, filepath.Join(dir, name), 0640, gid)
		}
		for _, name := range []string{"state.json", "parent"} {
			assertStorePermissions(t, filepath.Join(dir, name), 0600, -1)
		}
		if gid >= 0 {
			cmd := exec.Command("/bin/sh", "-c", `
for name in core-version server.json; do
  cat "$1/$name" >/dev/null || exit 11
done
for name in state.json parent; do
  if cat "$1/$name" >/dev/null 2>&1; then exit 12; fi
done
`, "qingnode-permissions", dir)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: uint32(gid)}}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: service-group read contract failed: %v\n%s", stage, err, out)
			}
		} else {
			t.Log("non-root run checks modes; root is required for the service-group read check")
		}
	}
}

func assertStorePermissions(t *testing.T, path string, mode os.FileMode, gid int) {
	t.Helper()
	i, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if i.Mode().Perm() != mode {
		t.Errorf("%s: mode %04o, want %04o", path, i.Mode().Perm(), mode)
	}
	if gid >= 0 {
		owner := i.Sys().(*syscall.Stat_t)
		if owner.Uid != 0 || owner.Gid != uint32(gid) {
			t.Errorf("%s: owner %d:%d, want 0:%d", path, owner.Uid, owner.Gid, gid)
		}
	}
}
