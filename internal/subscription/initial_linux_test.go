//go:build linux

package subscription

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestInitialPublicationExclusivelyCreatesCompletePrivateSnapshot(t *testing.T) {
	for _, markerOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-directory", true: "existing-marker"}[markerOnly], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "publication")
			if markerOnly {
				if err := Initialize(dir, -1); err != nil {
					t.Fatal(err)
				}
			}
			if err := CreateInitial(dir, -1); err != nil {
				t.Fatal(err)
			}
			initial, err := Read(dir)
			if err != nil || initial.Version != Version || initial.GeneratedAt.IsZero() || len(initial.Records) != 0 {
				t.Fatal("initial publication is not complete", err)
			}
			path := filepath.Join(dir, SnapshotName)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			uid, gid, links, err := owner(info)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 || uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) || links != 1 {
				t.Fatal("initial snapshot ownership, permissions, or candidate cleanup is wrong", err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := CreateInitial(dir, -1); err == nil {
				t.Fatal("existing empty snapshot was replaced")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("initial snapshot original bytes changed", err)
			}
		})
	}
}

func TestInitialPublicationRejectsExistingAuthorizationAndUnsafeTargets(t *testing.T) {
	for _, kind := range []string{"active", "revoked", "unknown-format", "partial", "symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := publicationDir(t)
			path := filepath.Join(dir, SnapshotName)
			contents := []byte(`{"version":99,"retain_unknown":true}`)
			switch kind {
			case "active", "revoked":
				s, _ := fixture()
				if kind == "revoked" {
					s.Records[0].Revoked = true
					s.Records[0].Outputs = map[string]Payload{}
				}
				var err error
				contents, err = Encode(s)
				if err != nil {
					t.Fatal(err)
				}
			case "partial":
				contents = []byte(`{"version":`)
			}
			other := filepath.Join(dir, "original")
			if err := os.WriteFile(other, contents, 0640); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink("original", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(other, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0640); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, contents, 0640); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := CreateInitial(dir, -1); err == nil {
				t.Fatal("existing initial target was adopted", kind)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("existing target identity or mode changed", err)
			}
			if after.Mode().IsRegular() {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, contents) {
					t.Fatal("existing target evidence was overwritten", err)
				}
			}
			original, err := os.ReadFile(other)
			if err != nil || !bytes.Equal(original, contents) {
				t.Fatal("source or linked target was modified", err)
			}
		})
	}
}

func TestInitialPublicationConcurrentCreatorsCannotReplaceWinner(t *testing.T) {
	dir := publicationDir(t)
	const workers = 8
	errors := make([]error, workers)
	start := make(chan struct{})
	var done sync.WaitGroup
	for i := range errors {
		done.Add(1)
		go func(i int) { defer done.Done(); <-start; errors[i] = CreateInitial(dir, -1) }(i)
	}
	close(start)
	done.Wait()
	winners := 0
	for _, err := range errors {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("initial publication must have exactly one creator", winners)
	}
	if _, err := Read(dir); err != nil {
		t.Fatal("winner's snapshot is incomplete or has linked candidates", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("initial candidate files were not cleaned", err)
	}
}
