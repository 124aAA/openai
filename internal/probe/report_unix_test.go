//go:build !windows

package probe

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadReportRefusesFIFOWithoutWaitingForAWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report-pipe")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadReport(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("named pipe accepted as a result file")
		}
	case <-time.After(time.Second):
		t.Fatal("report reader blocked waiting for a named-pipe writer")
	}
}
