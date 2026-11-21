//go:build darwin

package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"time"
)

var darwinLsofRunner = runDarwinLsof

func runDarwinLsof(ctx context.Context, pid int) ([]byte, error) {
	bin := "/usr/sbin/lsof"
	if p, err := exec.LookPath("lsof"); err == nil {
		bin = p
	}
	cmd := exec.CommandContext(ctx, bin, "-Pan", "-p", strconv.Itoa(pid), "-iTCP", "-sTCP:LISTEN", "-F", "pfnT")
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, limit: (256 << 10) + 1}
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if out.Len() > 256<<10 {
		return nil, errors.New("lsof listener output exceeded safety limit")
	}
	if err != nil {
		// lsof exits with code 1 when no matching open files exist yet (e.g. still starting).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return out.Bytes(), nil
		}
		return nil, err
	}
	return out.Bytes(), nil
}

type limitedWriter struct {
	w     io.Writer
	limit int
	n     int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	orig := len(p)
	rem := l.limit - l.n
	if rem > 0 {
		if len(p) > rem {
			p = p[:rem]
		}
		_, _ = l.w.Write(p)
	}
	l.n += orig
	return orig, nil
}

func ownedListener(pid, port int) (bool, error) {
	if pid <= 0 || port <= 0 || port > 65535 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := darwinLsofRunner(ctx, pid)
	if err != nil {
		return false, err
	}
	return parseDarwinLsofListener(raw, pid, port)
}
