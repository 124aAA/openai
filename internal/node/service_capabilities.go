package node

import (
	"errors"
	"qingnode/internal/platform"
	"strings"
	"time"
)

// OpenRC delegates the bind capability through its actual supervisor. A file
// capability would clear that ambient set on exec; a compatibility loader can
// then exec again and lose the file grant. Queries never change an xattr.
func installedCoreReady(root, version string) bool {
	if VerifyCore(root, version) != nil {
		return false
	}
	if platform.DetectServiceManager() != platform.InitOpenRC {
		return true
	}
	legacy, err := openRCCoreFileCapabilityWithRunner(CorePath(root, version), Run)
	return err == nil && !legacy
}

// Only this project's exact old bind grant is recognized for explicit install
// migration. Other grants are never erased or silently adopted. InstallCore
// keeps the old directory/inode/xattrs and stages a fresh verified plain file.
func openRCCoreFileCapabilityWithRunner(path string, run Runner) (legacy bool, err error) {
	out, e := run(10*time.Second, "getcap", path)
	if e != nil {
		return false, errors.New("无法只读检查OpenRC核心文件权限；保留旧核心")
	}
	switch strings.TrimSpace(string(out)) {
	case "":
		return false, nil
	case path + " cap_net_bind_service=ep":
		return true, nil
	default:
		return false, errors.New("OpenRC核心有未知文件权限；拒绝覆盖或删除，保留旧核心")
	}
}

func verifyOpenRCCoreFileCapability(path string) error {
	return verifyOpenRCCoreFileCapabilityWithRunner(path, Run)
}

func verifyOpenRCCoreFileCapabilityWithRunner(path string, run Runner) error {
	legacy, err := openRCCoreFileCapabilityWithRunner(path, run)
	if err != nil {
		return err
	}
	if legacy {
		return errors.New("候选OpenRC核心不能带文件权限；由受管监督进程授予低端口权限")
	}
	return nil
}
