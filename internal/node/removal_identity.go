package node

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// These fingerprints live only for one authorized operation. Old uninstall
// journals retain their format; an explicit recovery verifies existing local
// material first, then watches that same material throughout its native waits.
type removalFileIdentity struct {
	Present bool
	Mode    uint32
	UID     uint32
	GID     uint32
	Links   uint64
	Size    int64
	SHA256  [32]byte
}
type removalIdentityPath struct{ Live, Stored string }
type removalOwnershipGuard struct {
	r                               Removal
	allowMoved, allowUnloaded, full bool
	files                           map[removalIdentityPath]removalFileIdentity
}

func removalReadIdentity(path string) (removalFileIdentity, error) {
	var identity removalFileIdentity
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return identity, nil
	}
	if err != nil {
		return identity, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) || st.Size < 0 || st.Size > 256<<20 {
		return identity, errors.New("卸载文件的类型、权限、属主、链接数或大小不可安全核对")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	var after unix.Stat_t
	if err != nil || n != st.Size || unix.Fstat(fd, &after) != nil || after.Mode != st.Mode || after.Uid != st.Uid || after.Gid != st.Gid || after.Nlink != st.Nlink || after.Size != st.Size {
		return identity, errors.New("卸载文件在读取指纹期间变化，未继续")
	}
	identity = removalFileIdentity{Present: true, Mode: st.Mode, UID: st.Uid, GID: st.Gid, Links: uint64(st.Nlink), Size: st.Size}
	copy(identity.SHA256[:], h.Sum(nil))
	return identity, nil
}

func (p removalIdentityPath) read() (removalFileIdentity, error) {
	live, err := removalReadIdentity(p.Live)
	if err != nil {
		return live, err
	}
	stored, err := removalReadIdentity(p.Stored)
	if err != nil {
		return stored, err
	}
	if live.Present && stored.Present {
		return live, errors.New("卸载文件原件和恢复件同时存在，未接管")
	}
	if stored.Present {
		return stored, nil
	}
	return live, nil
}

func (g *removalOwnershipGuard) identities(allowMissing bool) error {
	if g.files == nil {
		paths := []removalIdentityPath{{g.r.Unit, g.r.Unit + ".qingnode-uninstall"}}
		if g.r.Binary != "" {
			paths = append(paths, removalIdentityPath{g.r.Binary, g.r.Binary + ".qingnode-uninstall"})
		}
		if g.full {
			for _, name := range []string{".qingnode-owner", "install.sh"} {
				paths = append(paths, removalIdentityPath{filepath.Join(g.r.Library, name), filepath.Join(g.r.Library+".qingnode-uninstall", name)})
			}
			if g.r.Logrotate != "" && (ownedLogrotate(g.r.Logrotate) || ownedLogrotate(g.r.Logrotate+".qingnode-uninstall")) {
				paths = append(paths, removalIdentityPath{g.r.Logrotate, g.r.Logrotate + ".qingnode-uninstall"})
			}
		}
		g.files = map[removalIdentityPath]removalFileIdentity{}
		for _, path := range paths {
			identity, err := path.read()
			if err != nil {
				return err
			}
			g.files[path] = identity
		}
		return nil
	}
	for path, before := range g.files {
		after, err := path.read()
		if err != nil {
			return err
		}
		if allowMissing && !after.Present {
			continue
		}
		if before != after {
			return errors.New("卸载文件内容、权限或属组已由外部修改；保留原件与恢复材料，未覆盖或删除")
		}
	}
	return nil
}

func (g *removalOwnershipGuard) verify(allowMissing bool) error {
	// Snapshot local bytes before the first controller query, then compare them
	// again afterwards; even a source query can contain an administrator hook.
	if err := g.identities(allowMissing); err != nil {
		return err
	}
	if err := g.r.serviceMaterialSafe(g.allowMoved, g.allowUnloaded); err != nil {
		return err
	}
	if g.full {
		if err := g.r.libraryMaterialSafe(g.allowMoved); err != nil {
			return err
		}
	}
	return g.identities(allowMissing)
}
func (g *removalOwnershipGuard) check() error        { return g.verify(false) }
func (g *removalOwnershipGuard) cleanupCheck() error { return g.verify(true) }
