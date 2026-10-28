//go:build !linux && !windows

package probe

import "errors"

func ownedListener(pid, port int) (bool, error) {
	return false, errors.New("listener ownership verification supports Linux and Windows")
}
