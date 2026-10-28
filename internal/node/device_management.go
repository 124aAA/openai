package node

import (
	"errors"
	"fmt"
	"strings"
)

// Tags select only explicitly bound credentials; they never select a user.
func ValidateNodeTags(tags []string) error {
	if len(tags) > 16 {
		return errors.New("每个节点最多16个标签")
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		if !cleanName(tag) || len(tag) > 64 || strings.TrimSpace(tag) != tag || seen[tag] {
			return errors.New("标签须为1–64字节、无控制字符且不重复；不能含首尾空白")
		}
		seen[tag] = true
	}
	return nil
}

func FindDevice(st *State, id string) (*DeviceProfile, error) {
	for i := range st.Devices {
		if st.Devices[i].ID == id {
			return &st.Devices[i], nil
		}
	}
	for i := range st.Devices {
		if st.Devices[i].Name == id {
			return &st.Devices[i], nil
		}
	}
	return nil, errors.New("设备不存在；请用 device list 查看稳定ID")
}

// DisableDeviceCredentials preflights the complete operation on a clone.
// Shared credentials cannot be silently removed or rotated. A disabled
// profile only loses download access; its previously exported credential
// can remain valid and must still be protected.
// A last user is preserved in a disabled listener; an explicit node enable
// would restore that credential, which the CLI must disclose.
func DisableDeviceCredentials(st *State, id string) error {
	candidate := st.Clone()
	p, err := FindDevice(&candidate, id)
	if err != nil {
		return err
	}
	for _, binding := range p.Bindings {
		for _, other := range candidate.Devices {
			if other.ID == p.ID {
				continue
			}
			for _, used := range other.Bindings {
				if binding.NodeID == used.NodeID && binding.UserID == used.UserID {
					return fmt.Errorf("凭据由另一设备 %s 共享；仅撤销本设备下载权限，或先为设备分配独立凭据", other.ID)
				}
			}
		}
	}
	for _, binding := range p.Bindings {
		var n *Node
		for i := range candidate.Nodes {
			if candidate.Nodes[i].ID == binding.NodeID {
				n = &candidate.Nodes[i]
				break
			}
		}
		if n == nil {
			continue
		} // A previously disabled device can retain history.
		for i := range n.Users {
			if n.Users[i].ID != binding.UserID {
				continue
			}
			if len(n.Users) == 1 {
				n.Enabled = false
			} else {
				n.Users = append(n.Users[:i], n.Users[i+1:]...)
			}
			break
		}
	}
	p.Disabled = true
	if err := candidate.Validate(); err != nil {
		return err
	}
	*st = candidate
	return nil
}
