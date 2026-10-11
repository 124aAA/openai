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
	for _, invalid := range []string{"", "symlink"} {
		t.Run(invalid, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Mkdir(filepath.Join(dir, "docs"), 0700); e != nil {
				t.Fatal(e)
			}
			names := []string{"qingnode", "install.sh", "docs/GETTING_STARTED.md", "docs/FAQ.md", "docs/DEVELOPMENT.md"}
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
			if e := VerifyBundle(dir); (e == nil) != (invalid == "") {
				t.Fatalf("VerifyBundle result: %v", e)
			}
		})
	}
}
