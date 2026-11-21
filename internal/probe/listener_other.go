//go:build !linux && !windows && !darwin

package probe

import "errors"

func ownedListener(pid, port int) (bool, error) {
	return false, errors.New("listener ownership verification supports Linux, macOS and Windows")
}
