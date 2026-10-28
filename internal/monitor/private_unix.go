//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package monitor

import (
	"errors"
	"os"
	"syscall"
)

func protectPrivate(path string, directory bool) error {
	m := os.FileMode(0600)
	if directory {
		m = 0700
	}
	return os.Chmod(path, m)
}
func checkPrivate(path string) error {
	i, e := os.Stat(path)
	if e != nil {
		return e
	}
	if i.Mode().Perm()&0077 != 0 {
		return errors.New("private mode required")
	}
	return nil
}
func singleLink(f *os.File) error {
	i, e := f.Stat()
	if e != nil {
		return e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Nlink != 1 {
		return errors.New("监控文件不能是硬链接")
	}
	return nil
}
func lockFile(f *os.File) error {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if e == syscall.EWOULDBLOCK || e == syscall.EAGAIN {
		return ErrBusy
	}
	return e
}

func openOwned(path string, flags int, mode os.FileMode) (*os.File, error) {
	fd, e := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
