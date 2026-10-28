package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuxiliaryControlLeaseSerializesOnlyItsOwnService(t *testing.T) {
	root := t.TempDir()
	release, err := AuxiliaryControlLease(root, "qingnode-monitor")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if duplicate, err := AuxiliaryControlLease(root, "qingnode-monitor"); err == nil {
		duplicate()
		t.Fatal("same service controlled concurrently")
	}
	other, err := AuxiliaryControlLease(root, "qingnode-subscription")
	if err != nil {
		t.Fatal("unrelated service lease was blocked", err)
	}
	other()
	if lease, err := AuxiliaryControlLease(root, "../external"); err == nil {
		lease()
		t.Fatal("unowned service accepted")
	}
}

func TestAuxiliaryControlLeaseRejectsExternalLockFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".service-qingnode-monitor.lock")
			external := filepath.Join(t.TempDir(), "external")
			if err := os.WriteFile(external, []byte("external bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(external, path)
			case "hardlink":
				err = os.Link(external, path)
			case "public":
				err = os.WriteFile(path, nil, 0600)
				if err == nil {
					err = os.Chmod(path, 0644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if lease, err := AuxiliaryControlLease(root, "qingnode-monitor"); err == nil {
				lease()
				t.Fatal("untrusted lock file accepted")
			}
			data, err := os.ReadFile(external)
			if err != nil || string(data) != "external bytes" {
				t.Fatal("external file changed", err)
			}
		})
	}
}
