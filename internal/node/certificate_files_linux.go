//go:build linux

package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func openCertificateReference(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("证书引用路径无效")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

type CertificateFileIdentity struct {
	ResourceID string `json:"resource_id"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
}

func certificateFileOwner(st os.FileInfo) (uint32, uint32, error) {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return 0, 0, errors.New("证书引用文件属主不可验证或存在硬链接")
	}
	return stat.Uid, stat.Gid, nil
}

func CertificateFileIdentities(s State) ([]CertificateFileIdentity, error) {
	s, e := CanonicalCertificates(s)
	if e != nil {
		return nil, e
	}
	var result []CertificateFileIdentity
	active := map[string]bool{}
	for _, n := range s.Nodes {
		if n.Enabled && n.CertificateID != "" && n.Certificate != nil && n.Certificate.Mode == "file" {
			active[n.CertificateID] = true
		}
	}
	for _, r := range s.Certificates {
		if r.Certificate.Mode != "file" || !active[r.ID] {
			continue
		}
		for i, path := range []string{r.Certificate.CertificatePath, r.Certificate.KeyPath} {
			data, st, e := readCertificateFileStat(path, i == 1)
			if e != nil {
				return nil, e
			}
			uid, gid, e := certificateFileOwner(st)
			if e != nil {
				return nil, e
			}
			h := sha256.Sum256(data)
			result = append(result, CertificateFileIdentity{r.ID, path, hex.EncodeToString(h[:]), uint32(st.Mode().Perm()), uid, gid})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ResourceID != result[j].ResourceID {
			return result[i].ResourceID < result[j].ResourceID
		}
		return result[i].Path < result[j].Path
	})
	return result, nil
}

func CheckCertificateFilePermissions(s State) error {
	var paths []string
	for _, n := range s.Nodes {
		if n.Enabled && n.Certificate != nil && n.Certificate.Mode == "file" {
			paths = append(paths, n.Certificate.CertificatePath, n.Certificate.KeyPath)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	service, e := user.Lookup("qingnode")
	if e != nil {
		return errors.New("文件引用需要已安装qingnode服务用户，无法确认实际读取权限")
	}
	uid, e := strconv.ParseUint(service.Uid, 10, 32)
	if e != nil {
		return errors.New("服务用户UID无效")
	}
	groupIDs, e := service.GroupIds()
	if e != nil {
		return errors.New("无法读取服务用户组")
	}
	groups := map[uint32]bool{}
	for _, id := range groupIDs {
		v, e := strconv.ParseUint(id, 10, 32)
		if e == nil {
			groups[uint32(v)] = true
		}
	}
	for _, path := range paths {
		for _, hidden := range []string{"/root", "/home", "/run/user", "/tmp", "/var/tmp"} {
			if path == hidden || strings.HasPrefix(path, hidden+"/") {
				return errors.New("文件引用位于受管服务ProtectHome/PrivateTmp隔离路径；请选择服务可见路径或显式导入PEM")
			}
		}
		for p := path; ; p = filepath.Dir(p) {
			st, e := os.Lstat(p)
			if e != nil || st.Mode()&os.ModeSymlink != 0 {
				return errors.New("证书引用路径不可访问或含符号链接")
			}
			stat, ok := st.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("无法验证证书引用属主")
			}
			need := os.FileMode(4)
			if p != path {
				need = 1
			}
			perm := st.Mode().Perm()
			if stat.Uid == uint32(uid) {
				perm >>= 6
			} else if groups[stat.Gid] {
				perm >>= 3
			}
			if perm&need == 0 {
				return errors.New("qingnode服务用户缺少证书文件读取或父目录遍历权限")
			}
			if filepath.Dir(p) == p {
				break
			}
		}
	}
	return nil
}
