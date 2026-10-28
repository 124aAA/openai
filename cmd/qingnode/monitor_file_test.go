package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMonitorBoundedFileRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "damaged.sha256")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := readMonitorBounded(fifo, 128); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("damaged derived file blocked bounded recovery")
	}
	original := filepath.Join(root, "original")
	if e := os.WriteFile(original, []byte("trusted"), 0600); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(root, "alias")
	if e := os.Symlink(original, alias); e != nil {
		t.Fatal(e)
	}
	if _, e := readMonitorBounded(alias, 128); e == nil {
		t.Fatal("followed symlink")
	}
	if e := os.Remove(alias); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(original, alias); e != nil {
		t.Fatal(e)
	}
	if _, e := readMonitorBounded(alias, 128); e == nil {
		t.Fatal("accepted hardlink")
	}
	if _, e := readMonitorBounded(original, 2); e == nil {
		t.Fatal("oversized material accepted")
	}
	b, _ := os.ReadFile(original)
	if string(b) != "trusted" {
		t.Fatal("foreign file repaired or overwritten")
	}
}
