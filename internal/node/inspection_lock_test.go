package node

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectExistingRejectsMissingRootWithoutCallback(t *testing.T) {
	s := &Store{Root: filepath.Join(t.TempDir(), "missing"), Backend: OfflineBackend{}, GID: -1}
	called := false
	e := s.InspectExisting(func() error { called = true; return nil })
	if !errors.Is(e, os.ErrNotExist) || called {
		t.Fatal("missing root entered existing-store callback", e)
	}
	if _, e := os.Lstat(s.Root); !os.IsNotExist(e) {
		t.Fatal("inspection initialized missing root", e)
	}
	e = s.Inspect(func() error { called = true; return nil })
	if e != nil || !called {
		t.Fatal("ordinary Inspect lost its missing-root callback behavior", e)
	}
	if _, e := os.Lstat(s.Root); !os.IsNotExist(e) {
		t.Fatal("ordinary inspection initialized missing root", e)
	}
}

func TestInspectExistingKeepsOwnershipAndExclusiveLock(t *testing.T) {
	s := &Store{Root: filepath.Join(t.TempDir(), "state"), Backend: OfflineBackend{}, GID: -1}
	if e := s.WithLock(func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	other := &Store{Root: s.Root, Backend: OfflineBackend{}, GID: -1}
	if e := s.InspectExisting(func() error {
		for _, inspect := range []func(func() error) error{other.InspectExisting, other.Inspect, other.WithLock} {
			called := false
			e := inspect(func() error { called = true; return nil })
			if e == nil || !strings.Contains(e.Error(), "另一个") || called {
				t.Fatal("existing inspection did not exclude another operation", e)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(s.Root, ".qingnode-owner"), []byte("unmanaged"), 0600); e != nil {
		t.Fatal(e)
	}
	called := false
	if e := s.InspectExisting(func() error { called = true; return nil }); e == nil || called {
		t.Fatal("existing inspection bypassed ownership")
	}
}
