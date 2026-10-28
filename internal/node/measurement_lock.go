package node

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// MeasurementLease prevents this manager's periodic and active probes from
// multiplying the configured traffic budget. It never waits or recovers State.
// The caller must already have verified the managed root with InspectExisting.
func MeasurementLease(root string) (func(), error) {
	fd, err := unix.Open(filepath.Join(root, ".measurement.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("无法取得测试锁")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, errors.New("测试锁不是本用户的私有普通文件")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(fd)
		return nil, errors.New("已有主动或周期测试运行；本次不排队、不叠加流量")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}
