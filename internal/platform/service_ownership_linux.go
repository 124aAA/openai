package platform

import (
	"errors"
	"os"
	"syscall"
)

func verifyDefinitionFileOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return errors.New("服务定义必须为root或当前管理者的单链接文件")
	}
	return nil
}
