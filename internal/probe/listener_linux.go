package probe

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Check the actual loopback LISTEN socket inode against this child's open fds.
// A successful connect alone could hit another process after port reservation.
func ownedListener(pid, port int) (bool, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return false, err
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	f.Close()
	if err != nil {
		return false, err
	}
	if len(b) > 1<<20 {
		return false, fmt.Errorf("TCP listener table exceeds 1 MiB")
	}
	address := fmt.Sprintf("0100007F:%04X", port)
	inodes := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 9 && fields[1] == address && fields[3] == "0A" {
			inodes["socket:["+fields[9]+"]"] = true
		}
	}
	if len(inodes) == 0 {
		return false, nil
	}
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(dir, fd.Name()))
		if err == nil && inodes[target] {
			return true, nil
		}
	}
	return false, nil
}
