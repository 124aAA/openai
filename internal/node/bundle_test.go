package node

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBundleNewDocsAndSymlink(t *testing.T) {
	for _, invalid := range []string{"", "symlink", "monitoring-tampered", "batch08-missing"} {
		t.Run(invalid, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Mkdir(filepath.Join(dir, "docs"), 0700); e != nil {
				t.Fatal(e)
			}
			names := []string{"qingnode", "install.sh", "docs/GETTING_STARTED.md", "docs/FAQ.md", "docs/DEVELOPMENT.md", "docs/SUBSCRIPTIONS.md", "docs/BATCH06.md", "docs/CERTIFICATES.md", "docs/MIGRATION.md", "docs/BATCH07.md", "docs/MONITORING.md", "docs/BATCH08.md", "docs/PROTOCOLS.md", "docs/BATCH09.md"}
			var manifest strings.Builder
			for _, name := range names {
				data := []byte("fixture: " + name)
				path := filepath.Join(dir, name)
				if invalid == "symlink" && name == "docs/FAQ.md" {
					target := filepath.Join(t.TempDir(), "original")
					if e := os.WriteFile(target, data, 0600); e != nil {
						t.Fatal(e)
					}
					if e := os.Symlink(target, path); e != nil {
						t.Fatal(e)
					}
				} else if e := os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
				fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(data), name)
			}
			if e := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest.String()), 0600); e != nil {
				t.Fatal(e)
			}
			if invalid == "monitoring-tampered" {
				if e := os.WriteFile(filepath.Join(dir, "docs", "MONITORING.md"), []byte("changed after checksum"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if invalid == "batch08-missing" {
				if e := os.Remove(filepath.Join(dir, "docs", "BATCH08.md")); e != nil {
					t.Fatal(e)
				}
			}
			if e := VerifyBundle(dir); (e == nil) != (invalid == "") {
				t.Fatalf("VerifyBundle result: %v", e)
			}
		})
	}
}
