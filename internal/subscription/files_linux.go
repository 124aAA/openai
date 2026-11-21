//go:build linux

package subscription

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	unmappedOverflowOnce sync.Once
	unmappedOverflowUID  uint32
	unmappedOverflowOK   bool
)

func parseUnmappedOverflowUID(overflowRaw, uidMapRaw string) (uint32, bool) {
	overflowStr := strings.TrimSpace(overflowRaw)
	if overflowStr == "" {
		return 0, false
	}
	overflow, err := strconv.ParseUint(overflowStr, 10, 32)
	if err != nil {
		return 0, false
	}
	lines := strings.Split(strings.TrimSpace(uidMapRaw), "\n")
	parsed := 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return 0, false
		}
		inside, e1 := strconv.ParseUint(fields[0], 10, 64)
		_, e2 := strconv.ParseUint(fields[1], 10, 64)
		length, e3 := strconv.ParseUint(fields[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || length == 0 {
			return 0, false
		}
		end := inside + length
		if end < inside || 0 >= inside && 0 < end || overflow >= inside && overflow < end {
			return 0, false
		}
		parsed++
	}
	if parsed == 0 {
		return 0, false
	}
	return uint32(overflow), true
}

func unmappedHostAncestorUID(uid uint32) bool {
	unmappedOverflowOnce.Do(func() {
		ob, e1 := os.ReadFile("/proc/sys/kernel/overflowuid")
		mb, e2 := os.ReadFile("/proc/self/uid_map")
		if e1 == nil && e2 == nil {
			unmappedOverflowUID, unmappedOverflowOK = parseUnmappedOverflowUID(string(ob), string(mb))
		}
	})
	return unmappedOverflowOK && uid == unmappedOverflowUID
}

func owner(info os.FileInfo) (uint32, uint32, uint64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, errors.New("cannot inspect publication ownership")
	}
	return s.Uid, s.Gid, uint64(s.Nlink), nil
}

// Every path ancestor must already be a real directory. A root-owned sticky
// temporary directory is the only writable ancestor exception (including host
// root surfaced as unmapped overflowuid in a rootless user namespace). The
// directory descriptor is then pinned; a later pathname replacement cannot redirect I/O.
func trustedRoot(dir string, allowSticky bool) (*os.Root, os.FileInfo, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, errors.New("publication path must be absolute")
	}
	clean := filepath.Clean(dir)
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	p := "/"
	for _, part := range parts {
		p = filepath.Join(p, part)
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("publication path must contain real directories")
		}
		uid, _, _, err := owner(info)
		ancestor := p != clean || allowSticky
		rootOwned := uid == 0 || (ancestor && unmappedHostAncestorUID(uid))
		if err != nil || !rootOwned && uid != uint32(os.Geteuid()) {
			return nil, nil, errors.New("publication path has an untrusted owner")
		}
		if info.Mode().Perm()&0022 != 0 && !(ancestor && rootOwned && info.Mode()&os.ModeSticky != 0) {
			return nil, nil, errors.New("publication path is writable by another user")
		}
	}
	i, err := os.Lstat(clean)
	if err != nil {
		return nil, nil, errors.New("publication directory is unavailable")
	}
	r, err := os.OpenRoot(clean)
	if err != nil {
		return nil, nil, errors.New("cannot open publication directory")
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(i, opened) {
		r.Close()
		return nil, nil, errors.New("publication directory changed while opening")
	}
	return r, opened, nil
}

func openDirectory(dir string, write bool) (*os.Root, os.FileInfo, error) {
	if filepath.Clean(dir) == "/" {
		return nil, nil, errors.New("publication directory must be dedicated")
	}
	r, i, err := trustedRoot(dir, false)
	if err != nil {
		return nil, nil, err
	}
	uid, _, _, err := owner(i)
	if err != nil || i.Mode().Perm() != 0750 || write && uid != uint32(os.Geteuid()) {
		r.Close()
		return nil, nil, errors.New("publication directory permissions or owner are invalid")
	}
	return r, i, nil
}

func readFile(r *os.Root, dirInfo os.FileInfo, name string, limit int) ([]byte, error) {
	// Open first: a legitimate atomic publication may replace the pathname at
	// any instant. Inspect the pinned file, never compare it to a later pathname.
	f, err := openNoFollow(r, name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open publication file")
	}
	defer f.Close()
	return readOpenedFile(f, dirInfo, limit)
}

// Root.OpenFile confines symlinks to its tree, but resolves internal symlinks
// even when O_NOFOLLOW is passed. These owned publication names are single path
// components: openat on the pinned directory descriptor supplies the stronger
// rule that no final-component symlink may be followed at all.
func openNoFollow(r *os.Root, name string, flags int, mode uint32) (*os.File, error) {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("publication filename must be a single component")
	}
	dir, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("cannot wrap publication descriptor")
	}
	return f, nil
}

func readOpenedFile(f *os.File, dirInfo os.FileInfo, limit int) ([]byte, error) {
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() {
		return nil, errors.New("publication file is not regular")
	}
	uid, gid, links, err := owner(i)
	duid, dgid, _, de := owner(dirInfo)
	// An opened previous publication can already be unlinked (nlink=0) by a
	// successful rename. It remains immutable and safe to complete this read.
	// nlink>1 is forbidden, including a hard link introduced before this check.
	if err != nil || de != nil || uid != duid || gid != dgid || links > 1 || i.Mode().Perm() != 0640 {
		return nil, errors.New("publication file permissions or ownership are invalid")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, errors.New("publication file exceeds its limit or cannot be read")
	}
	return b, nil
}

func checkMarker(r *os.Root, i os.FileInfo) error {
	b, err := readFile(r, i, MarkerName, len(OwnerMarker))
	if err != nil || string(b) != OwnerMarker {
		return errors.New("subscription directory ownership marker is invalid")
	}
	return nil
}

// Initialize marks a new or empty directory. It never adopts an unmarked
// non-empty directory, changes an existing publication's owner, or creates any
// parent directories. gid=-1 preserves the creating user's current group.
func Initialize(dir string, gid int) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) == "/" || gid < -1 {
		return errors.New("invalid publication directory or group")
	}
	// Pin the parent before making anything; never follow an ancestor symlink
	// while creating or applying permissions to the new directory.
	parent := filepath.Dir(filepath.Clean(dir))
	p, _, e := trustedRoot(parent, true)
	if e != nil {
		return e
	}
	defer p.Close()
	base := filepath.Base(filepath.Clean(dir))
	created := false
	if e = p.Mkdir(base, 0750); e == nil {
		created = true
	} else if !errors.Is(e, os.ErrExist) {
		return errors.New("cannot create publication directory")
	}
	if created {
		f, err := openNoFollow(p, base, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return errors.New("cannot open created publication directory")
		}
		if gid >= 0 {
			e = f.Chown(os.Geteuid(), gid)
		}
		if e == nil {
			e = f.Chmod(0750)
		}
		_ = f.Close()
		if e != nil {
			return errors.New("cannot set publication directory permissions")
		}
	}
	r, i, e := openDirectory(dir, true)
	if e != nil {
		return e
	}
	defer r.Close()
	_, actualGID, _, e := owner(i)
	if e != nil || gid >= 0 && actualGID != uint32(gid) {
		return errors.New("publication service group does not match")
	}
	if e = checkMarker(r, i); e == nil {
		if _, e = r.Lstat(SnapshotName); errors.Is(e, os.ErrNotExist) {
			return nil
		} else if e != nil {
			return errors.New("cannot inspect existing publication")
		}
		b, err := readFile(r, i, SnapshotName, MaxSnapshotBytes)
		if err != nil {
			return err
		}
		_, err = Decode(b)
		return err
	}
	f, e := r.Open(".")
	if e != nil {
		return errors.New("cannot inspect publication directory")
	}
	entries, e := f.ReadDir(-1)
	_ = f.Close()
	if e != nil || len(entries) != 0 {
		return errors.New("refusing an unmarked or damaged publication directory")
	}
	return atomicFile(r, i, MarkerName, []byte(OwnerMarker))
}

func atomicFile(r *os.Root, dirInfo os.FileInfo, name string, b []byte) error {
	// Never replace a symlink, hard link, or unrelated permissive file.
	if _, e := r.Lstat(name); e == nil {
		if _, e = readFile(r, dirInfo, name, MaxSnapshotBytes); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return errors.New("cannot inspect publication destination")
	}
	var f *os.File
	var temp string
	for attempt := 0; attempt < 8; attempt++ {
		raw, _, e := NewToken()
		if e != nil {
			return e
		}
		temp = ".publication-" + raw[:24]
		f, e = openNoFollow(r, temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			break
		}
		if !errors.Is(e, os.ErrExist) {
			return errors.New("cannot create publication candidate")
		}
	}
	if f == nil {
		return errors.New("cannot allocate publication candidate")
	}
	defer r.Remove(temp)
	uid, gid, _, e := owner(dirInfo)
	if e == nil {
		e = f.Chown(int(uid), int(gid))
	}
	if e == nil {
		e = f.Chmod(0640)
	}
	if e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return errors.New("cannot write publication candidate")
	}
	if e = r.Rename(temp, name); e != nil {
		return errors.New("cannot replace publication atomically")
	}
	d, e := r.Open(".")
	if e != nil {
		return errors.New("cannot synchronize publication directory")
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return errors.New("publication replaced but directory synchronization failed")
	}
	return nil
}

func Publish(dir string, s Snapshot, gid int) error {
	if gid < -1 {
		return errors.New("invalid publication group")
	}
	b, e := Encode(s)
	if e != nil {
		return e
	}
	r, i, e := openDirectory(dir, true)
	if e != nil {
		return e
	}
	defer r.Close()
	_, actualGID, _, e := owner(i)
	if e != nil || gid >= 0 && actualGID != uint32(gid) {
		return errors.New("publication service group does not match")
	}
	if e = checkMarker(r, i); e != nil {
		return e
	}
	return atomicFile(r, i, SnapshotName, b)
}

func Read(dir string) (Snapshot, error) {
	r, i, e := openDirectory(dir, false)
	if e != nil {
		return Snapshot{}, e
	}
	defer r.Close()
	if e = checkMarker(r, i); e != nil {
		return Snapshot{}, e
	}
	b, e := readFile(r, i, SnapshotName, MaxSnapshotBytes)
	if e != nil {
		return Snapshot{}, e
	}
	return Decode(b)
}

type snapshotFileKey struct {
	dev       uint64
	ino       uint64
	size      int64
	mtimeSec  int64
	mtimeNsec int64
}

type SnapshotCache struct {
	dir     string
	mu      sync.RWMutex
	valid   bool
	key     snapshotFileKey
	cached  IndexedSnapshot
	decodes uint64
}

func NewSnapshotCache(dir string) *SnapshotCache {
	return &SnapshotCache{dir: dir}
}

func (c *SnapshotCache) Decodes() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.decodes
}

func (c *SnapshotCache) Read() (IndexedSnapshot, error) {
	r, dirInfo, e := openDirectory(c.dir, false)
	if e != nil {
		return IndexedSnapshot{}, e
	}
	defer r.Close()
	if e = checkMarker(r, dirInfo); e != nil {
		return IndexedSnapshot{}, e
	}
	f, e := openNoFollow(r, SnapshotName, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return IndexedSnapshot{}, errors.New("cannot open publication file")
	}
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() {
		return IndexedSnapshot{}, errors.New("publication file is not regular")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return IndexedSnapshot{}, errors.New("cannot inspect publication ownership")
	}
	duid, dgid, _, de := owner(dirInfo)
	links := uint64(st.Nlink)
	if de != nil || st.Uid != duid || st.Gid != dgid || links > 1 || fi.Mode().Perm() != 0640 {
		return IndexedSnapshot{}, errors.New("publication file permissions or ownership are invalid")
	}
	k := snapshotFileKey{
		dev:       uint64(st.Dev),
		ino:       uint64(st.Ino),
		size:      st.Size,
		mtimeSec:  int64(st.Mtim.Sec),
		mtimeNsec: int64(st.Mtim.Nsec),
	}
	if links == 1 {
		c.mu.RLock()
		if c.valid && c.key == k {
			hit := c.cached
			c.mu.RUnlock()
			return hit, nil
		}
		c.mu.RUnlock()
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(MaxSnapshotBytes)+1))
	if e != nil || len(b) > MaxSnapshotBytes {
		return IndexedSnapshot{}, errors.New("publication file exceeds its limit or cannot be read")
	}
	snap, e := Decode(b)
	if e != nil {
		return IndexedSnapshot{}, e
	}
	idx, e := BuildIndex(snap)
	if e != nil {
		return IndexedSnapshot{}, e
	}
	if links == 1 {
		c.mu.Lock()
		c.key = k
		c.cached = idx
		c.valid = true
		c.decodes++
		c.mu.Unlock()
	}
	return idx, nil
}

