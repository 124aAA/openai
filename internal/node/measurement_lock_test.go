package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMeasurementLeaseSingleInstanceReleaseAndForeignFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".measurement.lock")
	release, e := MeasurementLease(root)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := MeasurementLease(root); e == nil {
		second()
		t.Fatal("concurrent measurements multiplied traffic")
	}
	release()
	second, e := MeasurementLease(root)
	if e != nil {
		t.Fatal(e)
	}
	second()
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	victim := filepath.Join(root, "foreign")
	if e = os.WriteFile(victim, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(victim, path); e != nil {
		t.Fatal(e)
	}
	if f, e := MeasurementLease(root); e == nil {
		f()
		t.Fatal("symlink accepted")
	}
	got, _ := os.ReadFile(victim)
	if string(got) != "preserve" {
		t.Fatal("foreign file changed")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(victim, path); e != nil {
		t.Fatal(e)
	}
	if f, e := MeasurementLease(root); e == nil {
		f()
		t.Fatal("hardlink accepted")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, original, 0644); e != nil {
		t.Fatal(e)
	}
	if f, e := MeasurementLease(root); e == nil {
		f()
		t.Fatal("world-readable lock adopted")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal("unowned permissions repaired")
	}
}
