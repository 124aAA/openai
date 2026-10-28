package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateOutputPinsDirectoryAndRefusesReplacement(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "private")
	foreign := filepath.Join(base, "foreign")
	for _, dir := range []string{parent, foreign} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p, err := pinNewOutput(filepath.Join(parent, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.root.Close()
	if err = os.Rename(parent, parent+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(foreign, parent); err != nil {
		t.Fatal(err)
	}
	if err = p.write([]byte("private")); err == nil {
		t.Fatal("followed a replaced output parent")
	}
	for _, dir := range []string{foreign, parent + "-moved"} {
		if _, err = os.Lstat(filepath.Join(dir, "result.json")); !os.IsNotExist(err) {
			t.Fatal("wrote through a changed directory")
		}
	}
}

func TestPrivateOutputNewFileAndUnsafeParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")
	p, err := pinNewOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.root.Close()
	if err = p.write([]byte("result")); err != nil {
		t.Fatal(err)
	}
	i, err := os.Stat(path)
	if err != nil || i.Mode().Perm() != 0600 {
		t.Fatal("result not private", err)
	}
	if err = p.write([]byte("overwrite")); err == nil {
		t.Fatal("existing result overwritten")
	}
	if _, err = pinNewOutput(path); err == nil {
		t.Fatal("existing output accepted")
	}
	if err = os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if _, err = pinNewOutput(filepath.Join(dir, "other.json")); err == nil {
		t.Fatal("untrusted writable output parent accepted")
	}
}
