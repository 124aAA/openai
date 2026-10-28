//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package monitor

import (
	"errors"
	"os"
)

func protectPrivate(string, bool) error { return errors.New("本平台尚未实现监控私有权限") }
func checkPrivate(string) error         { return errors.New("本平台尚未实现监控私有权限校验") }
func singleLink(*os.File) error         { return errors.New("本平台尚未实现监控路径校验") }
func lockFile(*os.File) error           { return errors.New("本平台尚未实现监控单实例锁") }
func openOwned(string, int, os.FileMode) (*os.File, error) {
	return nil, errors.New("本平台尚未实现监控文件安全读取")
}
