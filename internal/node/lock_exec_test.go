package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStateManagementLockDoesNotEscapeIntoServiceChild(t *testing.T) {
	const helper = "QINGNODE_TEST_LOCK_EXEC_PATH"
	if target := os.Getenv(helper); target != "" {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			value, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil && value == target {
				t.Fatal("service child inherited the parent's private management lock")
			}
		}
		return
	}
	store, _ := newStore(t)
	if err := store.WithLock(func() error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStateManagementLockDoesNotEscapeIntoServiceChild$")
		cmd.Env = append(os.Environ(), helper+"="+filepath.Join(store.Root, ".lock"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("actual child descriptor check failed: %v\n%s", err, output)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
