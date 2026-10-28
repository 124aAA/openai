package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestDiagnosticRunOwnedChild(t *testing.T) {
	mode := os.Getenv("QINGNODE_DIAGNOSTIC_RUN_CHILD")
	if mode == "" {
		return
	}
	if err := os.WriteFile(os.Getenv("QINGNODE_DIAGNOSTIC_RUN_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(2)
	}
	if mode == "oversized" {
		block := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 96; i++ {
			if _, err := os.Stdout.Write(block); err != nil {
				os.Exit(3)
			}
		}
	} else {
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func TestDiagnosticRunBoundsOutputDeadlineAndReapsItsProcess(t *testing.T) {
	for _, mode := range []string{"oversized", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "owned-child-pid")
			t.Setenv("QINGNODE_DIAGNOSTIC_RUN_CHILD", mode)
			t.Setenv("QINGNODE_DIAGNOSTIC_RUN_PID", pidFile)
			output, err := runBoundedDiagnostic(3*time.Second, os.Args[0], "-test.run=^TestDiagnosticRunOwnedChild$")
			if mode == "oversized" {
				if !errors.Is(err, errDiagnosticOutputLimit) || len(output) != 4<<20 {
					t.Fatal("output exceeded budget or limit not reported", len(output), err)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("timeout was not independently enforced", err)
			}
			pidBytes, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal("owned child did not start before the deadline", err)
			}
			pid, err := strconv.Atoi(string(pidBytes))
			if err != nil || pid <= 0 {
				t.Fatal("invalid child identity")
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatal("owned diagnostic process remained after bounded command returned", err)
			}
		})
	}
}

func TestDiagnosticRunCancellationReapsItsProcess(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "owned-child-pid")
	t.Setenv("QINGNODE_DIAGNOSTIC_RUN_CHILD", "deadline")
	t.Setenv("QINGNODE_DIAGNOSTIC_RUN_PID", pidFile)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := os.Stat(pidFile); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	_, err := runBoundedDiagnosticContext(ctx, 5*time.Second, os.Args[0], "-test.run=^TestDiagnosticRunOwnedChild$")
	<-finished
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not distinguished from timeout or success", err)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil || pid <= 0 {
		t.Fatal("invalid owned child PID")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("canceled owned child remains", err)
	}
}
