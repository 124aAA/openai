package node

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// AuxiliaryControlLease serializes lifecycle commands for one owned auxiliary
// service without holding the State lock while that service starts. The caller
// must first verify the managed root under InspectExisting. A oneshot monitor
// itself reads State, so holding that lock across its startup would deadlock.
func AuxiliaryControlLease(root, name string) (func(), error) {
	if name != "qingnode-monitor" && name != "qingnode-subscription" {
		return nil, errors.New("未知附属服务，未取得控制锁")
	}
	fd, err := unix.Open(filepath.Join(root, ".service-"+name+".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("无法取得附属服务控制锁")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, errors.New("附属服务控制锁不是本用户的私有普通文件")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(fd)
		return nil, errors.New("另一个附属服务控制操作正在运行；本次不排队")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}
