//go:build linux

package subscription

import (
	"errors"
	"io"
	"os"
	"time"
)

// CreateInitial creates the first empty publication without replacing any
// existing snapshot. A fully written/synchronized candidate is hard-linked to
// the destination: Link fails atomically if another manager has already won.
// A reader can briefly see nlink=2 until candidate cleanup and must fail closed.
// A crash in that interval leaves both owned names as recovery evidence; never
// reinitialize or silently remove an existing snapshot to hide that condition.
func CreateInitial(dir string, gid int) error {
	if err := Initialize(dir, gid); err != nil {
		return err
	}
	r, info, err := openDirectory(dir, true)
	if err != nil {
		return err
	}
	defer r.Close()
	uid, actualGID, _, err := owner(info)
	if err != nil || gid >= 0 && actualGID != uint32(gid) {
		return errors.New("publication service group does not match")
	}
	if err := checkMarker(r, info); err != nil {
		return err
	}
	if _, err := r.Lstat(SnapshotName); !errors.Is(err, os.ErrNotExist) {
		return errors.New("initial publication already exists or cannot be inspected; preserve it and choose a new directory")
	}
	contents, err := Encode(Snapshot{Version: Version, GeneratedAt: time.Now().UTC(), Records: []Record{}})
	if err != nil {
		return err
	}
	var candidate *os.File
	var name string
	for attempt := 0; attempt < 8; attempt++ {
		raw, _, err := NewToken()
		if err != nil {
			return err
		}
		name = ".publication-initial-" + raw[:24]
		candidate, err = openNoFollow(r, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return errors.New("cannot create initial publication candidate")
		}
	}
	if candidate == nil {
		return errors.New("cannot allocate initial publication candidate")
	}
	defer r.Remove(name)
	defer candidate.Close()
	if n, err := candidate.Write(contents); err != nil || n != len(contents) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := candidate.Chown(int(uid), int(actualGID)); err != nil {
		return errors.New("cannot set initial publication owner")
	}
	if err := candidate.Chmod(0640); err != nil {
		return errors.New("cannot set initial publication permissions")
	}
	if err := candidate.Sync(); err != nil {
		return errors.New("cannot synchronize initial publication candidate")
	}
	if err := candidate.Close(); err != nil {
		return errors.New("cannot close initial publication candidate")
	}
	if err := r.Link(name, SnapshotName); err != nil {
		return errors.New("initial publication was not installed; preserve any existing snapshot and choose a new directory")
	}
	if err := r.Remove(name); err != nil {
		return errors.New("initial publication linked but candidate cleanup failed; preserve both owned names for recovery")
	}
	directory, err := r.Open(".")
	if err != nil {
		return errors.New("initial publication installed but directory synchronization could not begin")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("initial publication installed but directory synchronization failed")
	}
	return nil
}
