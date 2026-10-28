package monitor

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectPrivate(path string, directory bool) error {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer t.Close()
	u, err := t.GetTokenUser()
	if err != nil {
		return err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + inherit + ";FA;;;" + u.User.Sid.String() + ")(A;" + inherit + ";FA;;;SY)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func checkPrivate(path string) error {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer t.Close()
	u, err := t.GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("private ACL required")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != u.User.Sid.String() && sid != "S-1-5-18" {
			return errors.New("private ACL required")
		}
	}
	return nil
}

func singleLink(f *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 {
		return errors.New("监控文件不能是硬链接")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("监控文件不能是重解析链接")
	}
	return nil
}

func openOwned(path string, flags int, _ os.FileMode) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	access := uint32(windows.GENERIC_READ)
	if flags&os.O_RDWR != 0 {
		access |= windows.GENERIC_WRITE
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if flags&os.O_CREATE != 0 {
		disposition = windows.OPEN_ALWAYS
	}
	h, e := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disposition, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}

func lockFile(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err == windows.ERROR_LOCK_VIOLATION {
		return ErrBusy
	}
	return err
}
