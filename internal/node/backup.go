package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

var backupMagic = []byte("QNBK1\x00")

type Snapshot struct {
	Format         int             `json:"format"`
	State          State           `json:"state"`
	Server         json.RawMessage `json:"server_config,omitempty"`
	ServerRaw      []byte          `json:"invalid_server_config,omitempty"`
	Service        string          `json:"systemd_unit,omitempty"`
	ManagerVersion string          `json:"manager_version,omitempty"`
	CreatedAt      string          `json:"created_at,omitempty"`
}

func Capture(root string, s State, manager, unit string) (Snapshot, error) {
	snap := Snapshot{Format: 2, State: s, Service: unit, ManagerVersion: manager, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if e := s.Validate(); e != nil {
		return snap, e
	}
	b, e := os.ReadFile(filepath.Join(root, "current", "server.json"))
	if e != nil && !os.IsNotExist(e) {
		return snap, e
	}
	if len(b) > 0 && !json.Valid(b) {
		snap.ServerRaw = b // Preserve damaged configuration as evidence without blocking a backup.
	} else {
		snap.Server = b
	}
	return snap, nil
}
func BackupSnapshot(s Snapshot, password string) ([]byte, error) {
	b, e := json.Marshal(s)
	if e != nil {
		return nil, e
	}
	return sealBackup(b, password, []byte("QNBK2\x00"))
}
func Backup(s State, password string) ([]byte, error) {
	b, e := json.Marshal(s)
	if e != nil {
		return nil, e
	}
	return sealBackup(b, password, backupMagic)
}
func sealBackup(plain []byte, password string, magic []byte) ([]byte, error) {
	if len(password) < 12 {
		return nil, errors.New("备份口令至少 12 字节")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key, e := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	header := append(append(append([]byte{}, magic...), salt...), nonce...)
	return append(header, g.Seal(nil, nonce, plain, header)...), nil
}
func Restore(data []byte, password string) (State, error) {
	snap, e := RestoreSnapshot(data, password)
	return snap.State, e
}
func RestoreSnapshot(data []byte, password string) (Snapshot, error) {
	var snap Snapshot
	if len(data) < 50 || len(data) > 32<<20 || (!bytes.Equal(data[:6], backupMagic) && !bytes.Equal(data[:6], []byte("QNBK2\x00"))) {
		return snap, errors.New("无效的加密备份")
	}
	key, e := pbkdf2.Key(sha256.New, password, data[6:22], 600000, 32)
	if e != nil {
		return snap, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return snap, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return snap, e
	}
	plain, e := g.Open(nil, data[22:34], data[34:], data[:34])
	if e != nil {
		return snap, errors.New("口令错误或备份已被修改")
	}
	return decodeSnapshot(plain, bytes.Equal(data[:6], backupMagic))
}

// RestorePlainSnapshot is only used for explicitly selected, root-private local recovery snapshots.
func RestorePlainSnapshot(data []byte) (Snapshot, error) {
	if len(data) > 32<<20 {
		return Snapshot{}, errors.New("快照过大")
	}
	return decodeSnapshot(data, false)
}
func decodeSnapshot(plain []byte, legacy bool) (Snapshot, error) {
	var snap Snapshot
	var e error
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if legacy {
		snap.Format = 1
		e = d.Decode(&snap.State)
	} else {
		e = d.Decode(&snap)
		if e == nil && snap.Format != 2 {
			e = errors.New("不支持该快照版本")
		}
	}
	if e != nil {
		return snap, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return snap, errors.New("备份包含多余数据")
	}
	return snap, snap.State.Validate()
}
