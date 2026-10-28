//go:build !windows

package probe

import (
	"os/exec"
	"syscall"
)

func prepareProcess(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func stopProcess(c *exec.Cmd, force bool) {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	_ = syscall.Kill(-c.Process.Pid, sig)
}
