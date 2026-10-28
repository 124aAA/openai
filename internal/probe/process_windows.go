package probe

import (
	"os/exec"
	"syscall"
)

// The accepted official client protocols cannot spawn external helpers (no
// ACME, script or command config is accepted). Only this owned process is killed.
func prepareProcess(c *exec.Cmd)          { c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
func stopProcess(c *exec.Cmd, force bool) { _ = c.Process.Kill() }
