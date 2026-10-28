package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var errDiagnosticOutputLimit = errors.New("diagnostic output exceeded 4MiB")

type diagnosticOutput struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
	cancel   context.CancelFunc
}

func (b *diagnosticOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := (4 << 20) - len(b.data)
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		b.overflow = true
		b.cancel()
		return remaining, errDiagnosticOutputLimit
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// A result size check after CombinedOutput would already have allocated the
// unbounded output. Cancel this owned command while collecting at the limit.
func runBoundedDiagnostic(timeout time.Duration, name string, args ...string) ([]byte, error) {
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runBoundedDiagnosticContext(parent, timeout, name, args...)
}

func runBoundedDiagnosticContext(parent context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	output := &diagnosticOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.overflow {
		return output.data, errDiagnosticOutputLimit
	}
	if ctx.Err() != nil {
		return output.data, ctx.Err()
	}
	return output.data, err
}
