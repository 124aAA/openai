package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	MigrationVersion       = 1
	MaxMigrationBytes      = 96 << 20
	MaxMigrationFileBytes  = 16 << 20
	MaxMigrationAssetBytes = 64 << 20
	MaxMigrationFiles      = 1024
)

// MigrationPackage uses typed, uncompressed entries rather than executable
// archives. There are no tar links, arbitrary entry types or decompression step.
// Snapshot.Service is evidence only; restore renders the local service definition.
type MigrationPackage struct {
	Version     int               `json:"version"`
	Mode        string            `json:"mode"`
	Snapshot    Snapshot          `json:"snapshot"`
	Roots       []MigrationRoot   `json:"roots"`
	Files       []MigrationFile   `json:"files"`
	External    []string          `json:"external"`
	Consistency string            `json:"consistency"`
	Manifest    MigrationManifest `json:"manifest"`
}

// Empty digests mean unavailable source evidence, never a checksum of zero.
// The target still obtains and verifies its own architecture's trusted core.
type MigrationManifest struct {
	Version           int    `json:"version"`
	OS                string `json:"os"`
	Architecture      string `json:"architecture"`
	ManagerVersion    string `json:"manager_version"`
	ManagerRevision   string `json:"manager_revision"`
	CoreVersion       string `json:"core_version"`
	CoreArchiveSHA256 string `json:"core_archive_sha256"`
	CoreBinarySHA256  string `json:"core_binary_sha256"`
	ServiceManager    string `json:"service_manager"`
}

type MigrationRoot struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	GroupID int    `json:"group_id"`
	OwnerID int    `json:"owner_id"`
}

type MigrationFile struct {
	RootID    string `json:"root_id"`
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Mode      uint32 `json:"mode"`
	SHA256    string `json:"sha256"`
	Data      []byte `json:"data"`
}

func validMigrationPath(p string) bool {
	return p != "" && len(p) <= 1024 && p != "." && p != ".." && path.Clean(p) == p && !strings.ContainsAny(p, "\\:\x00\r\n") && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "../")
}

func validMigrationRoot(r MigrationRoot) bool {
	return (r.ID == "acme" && r.Kind == "acme-storage" || r.ID == "subscription" && r.Kind == "subscription-publication" || r.ID == "publisher" && r.Kind == "subscription-config") && filepath.IsAbs(r.Source) && filepath.Clean(r.Source) != string(os.PathSeparator) && r.GroupID >= -1 && r.OwnerID >= 0
}

func (m MigrationPackage) Validate() error {
	if m.Version != MigrationVersion || m.Mode != "complete" && m.Mode != "limited" || len(m.Roots) > 3 || len(m.Files) > MaxMigrationFiles || len(m.External) > 256 {
		return errors.New("不支持的迁移包版本、模式或条目数量")
	}
	if m.Consistency != "stopped-owned-core" && m.Consistency != "no-runtime-assets" {
		return errors.New("迁移包没有可识别的一致性证明")
	}
	if len(m.Roots) > 0 && m.Consistency != "stopped-owned-core" {
		return errors.New("运行资产不能声明为无运行资产快照")
	}
	if m.Mode == "complete" && len(m.External) != 0 || m.Mode == "limited" && len(m.External) == 0 {
		return errors.New("迁移包完整性声明与外部资产清单不一致")
	}
	if m.Snapshot.Format != 2 {
		return errors.New("迁移包快照版本无效")
	}
	if e := m.Manifest.validate(m.Snapshot); e != nil {
		return e
	}
	if err := m.Snapshot.State.ValidateForRestore(); err != nil {
		return err
	}
	if len(m.Snapshot.Service) > 128<<10 || len(m.Snapshot.Server)+len(m.Snapshot.ServerRaw) > 16<<20 {
		return errors.New("迁移包来源材料过大")
	}
	roots := map[string]bool{}
	for _, r := range m.Roots {
		if !validMigrationRoot(r) || roots[r.ID] {
			return errors.New("迁移资产根目录未知或重复")
		}
		roots[r.ID] = true
	}
	seen := map[string]bool{}
	var size int64
	for _, f := range m.Files {
		name := f.RootID + "/" + f.Path
		if !roots[f.RootID] || !validMigrationPath(f.Path) || seen[name] {
			return errors.New("迁移资产路径非法、未知或重复")
		}
		seen[name] = true
		if f.Directory {
			if f.Mode != 0700 && f.Mode != 0750 && f.Mode != 0755 || len(f.Data) != 0 || f.SHA256 != "" {
				return errors.New("迁移目录模式或内容非法")
			}
		} else {
			if f.Mode != 0600 && f.Mode != 0640 && f.Mode != 0644 || len(f.Data) > MaxMigrationFileBytes {
				return errors.New("迁移文件权限或大小非法")
			}
			h := sha256.Sum256(f.Data)
			if f.SHA256 != hex.EncodeToString(h[:]) {
				return errors.New("迁移资产摘要不匹配")
			}
			size += int64(len(f.Data))
		}
	}
	if size > MaxMigrationAssetBytes {
		return errors.New("迁移资产总大小超过64MiB")
	}
	for _, f := range m.Files {
		for p := path.Dir(f.Path); p != "."; p = path.Dir(p) {
			for _, parent := range m.Files {
				if parent.RootID == f.RootID && parent.Path == p && !parent.Directory {
					return errors.New("迁移文件与父目录冲突")
				}
			}
		}
	}
	for _, ref := range m.External {
		if ref == "" || len(ref) > 2048 || strings.ContainsAny(ref, "\x00\r\n") {
			return errors.New("外部资产说明非法")
		}
	}
	return validateMigrationCoverage(m)
}

func BackupMigration(m MigrationPackage, password string) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxMigrationBytes-64 {
		return nil, errors.New("迁移包过大")
	}
	return sealBackup(b, password, []byte("QNBK3\x00"))
}

func IsMigrationBackup(data []byte) bool {
	return len(data) >= 6 && bytes.Equal(data[:6], []byte("QNBK3\x00"))
}

func RestoreMigration(data []byte, password string) (MigrationPackage, error) {
	var m MigrationPackage
	if len(data) < 50 || len(data) > MaxMigrationBytes || !IsMigrationBackup(data) {
		return m, errors.New("无效的QNBK3完整迁移包")
	}
	b, err := openBackup(data, password)
	if err != nil {
		return m, err
	}
	if err = rejectMigrationJSON(b); err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return m, errors.New("迁移包结构无效")
	}
	// DecodeState is authoritative for legacy migration and unsupported versions.
	var raw struct {
		Snapshot struct {
			State json.RawMessage `json:"state"`
		} `json:"snapshot"`
	}
	if err = json.Unmarshal(b, &raw); err != nil {
		return m, err
	}
	if m.Snapshot.State, err = DecodeState(raw.Snapshot.State); err != nil {
		return m, err
	}
	return m, m.Validate()
}

// All typed envelope objects reject aliases, duplicates and null. Saved server
// JSON is original evidence and is delegated to Snapshot's existing decoder.
func rejectMigrationJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int, string) error
	walk = func(depth int, key string) error {
		if depth > 48 {
			return errors.New("迁移包嵌套过深")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if t == nil {
			return errors.New("迁移包不接受null")
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				t, e = d.Token()
				if e != nil {
					return e
				}
				name, ok := t.(string)
				if !ok {
					return errors.New("迁移字段无效")
				}
				fold := stateFieldKey(name)
				if seen[fold] {
					return errors.New("迁移包对象含重复字段")
				}
				seen[fold] = true
				if name != strings.ToLower(name) {
					return errors.New("迁移包字段拼写无效")
				}
				if name == "server_config" {
					var raw json.RawMessage
					if e = d.Decode(&raw); e != nil {
						return e
					}
					continue
				}
				if e = walk(depth+1, name); e != nil {
					return e
				}
			}
		} else if delim == '[' {
			for d.More() {
				if e = walk(depth+1, key); e != nil {
					return e
				}
			}
		} else {
			return errors.New("迁移包JSON无效")
		}
		_, e = d.Token()
		return e
	}
	if err := walk(0, ""); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("迁移包包含额外JSON")
	}
	return nil
}

// CaptureMigration must run under the management lock. quiesced means the
// caller confirmed the owned core is stopped and no external writer is allowed
// in these dedicated roots. A double inventory catches accidental concurrent edits.
func CaptureMigration(snap Snapshot, roots []MigrationRoot, external []string, quiesced bool) (MigrationPackage, error) {
	m := MigrationPackage{Version: MigrationVersion, Mode: "complete", Snapshot: snap, Roots: append([]MigrationRoot{}, roots...), Files: []MigrationFile{}, External: append([]string{}, external...), Consistency: "no-runtime-assets"}
	manager := snap.ManagerVersion
	if manager == "" {
		manager = "unknown"
	}
	m.Manifest = MigrationManifest{Version: 1, OS: runtime.GOOS, Architecture: runtime.GOARCH, ManagerVersion: manager, ManagerRevision: "unknown", CoreVersion: snap.State.CoreVersion, CoreArchiveSHA256: snap.State.CoreArchiveSHA256, ServiceManager: "unknown"}
	if len(external) > 0 {
		m.Mode = "limited"
	}
	if len(roots) > 0 {
		if !quiesced {
			return m, errors.New("迁移运行资产需要先确认受管核心已停止；普通配置备份不会暂停服务")
		}
		m.Consistency = "stopped-owned-core"
	}
	for _, r := range roots {
		if !validMigrationRoot(r) {
			return m, errors.New("迁移来源根目录无效")
		}
		files, err := captureMigrationRoot(r)
		if err != nil {
			return m, err
		}
		m.Files = append(m.Files, files...)
	}
	sort.Slice(m.Files, func(i, j int) bool {
		return m.Files[i].RootID+"/"+m.Files[i].Path < m.Files[j].RootID+"/"+m.Files[j].Path
	})
	missing, err := MigrationMissingAssets(m)
	if err != nil {
		return m, err
	}
	if len(missing) > 0 {
		m.Mode = "limited"
		seen := map[string]bool{}
		for _, ref := range m.External {
			seen[ref] = true
		}
		for _, ref := range missing {
			if !seen[ref] {
				m.External = append(m.External, ref)
				seen[ref] = true
			}
		}
	}
	return m, m.Validate()
}

func captureMigrationRoot(r MigrationRoot) ([]MigrationFile, error) {
	base := filepath.Clean(r.Source)
	if err := migrationSafeAncestors(base); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var files []MigrationFile
	var total int64
	var walk func(string) error
	walk = func(rel string) error {
		d, err := migrationOpen(root, rel, syscall.O_RDONLY|syscall.O_DIRECTORY)
		if err != nil {
			return err
		}
		entries, err := d.ReadDir(-1)
		_ = d.Close()
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if r.ID == "publisher" && entry.Name() != "subscription-publisher.json" {
				continue
			}
			if r.ID == "subscription" && (rel != "." || entry.Name() != "snapshot.json" && entry.Name() != ".qingnode-subscription-owner") {
				return errors.New("订阅目录含未知资产或未完成发布文件，未创建完整迁移包")
			}
			p := path.Join(rel, entry.Name())
			if !validMigrationPath(p) {
				return errors.New("迁移来源含非法路径")
			}
			info, err := root.Lstat(p)
			if err != nil {
				return err
			}
			if len(files) >= MaxMigrationFiles {
				return errors.New("迁移文件数量超过上限")
			}
			mode := info.Mode().Perm()
			f := MigrationFile{RootID: r.ID, Path: p, Directory: info.IsDir(), Mode: uint32(mode), Data: []byte{}}
			if info.IsDir() {
				if mode != 0700 && mode != 0750 && mode != 0755 {
					return errors.New("迁移目录权限异常")
				}
				files = append(files, f)
				if err = walk(p); err != nil {
					return err
				}
				continue
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || !ok || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) && st.Uid != 0 && st.Uid != uint32(r.OwnerID) || mode != 0600 && mode != 0640 && mode != 0644 {
				return errors.New("迁移来源含链接、特殊文件或不可信权限/属主")
			}
			if info.Size() > MaxMigrationFileBytes {
				return errors.New("迁移单文件超过16MiB")
			}
			opened, err := migrationOpen(root, p, syscall.O_RDONLY|syscall.O_NONBLOCK)
			if err != nil {
				return err
			}
			openedInfo, err := opened.Stat()
			if err != nil || !os.SameFile(info, openedInfo) {
				opened.Close()
				return errors.New("迁移来源在读取时变化")
			}
			f.Data, err = io.ReadAll(io.LimitReader(opened, MaxMigrationFileBytes+1))
			after, ae := opened.Stat()
			_ = opened.Close()
			if err != nil || ae != nil || len(f.Data) > MaxMigrationFileBytes || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
				return errors.New("迁移来源在读取期间变化")
			}
			total += int64(len(f.Data))
			if total > MaxMigrationAssetBytes {
				return errors.New("迁移资产超过64MiB")
			}
			h := sha256.Sum256(f.Data)
			f.SHA256 = hex.EncodeToString(h[:])
			files = append(files, f)
		}
		return nil
	}
	if err = walk("."); err != nil {
		return nil, err
	}
	// Check every pathname again, including directories, before accepting the snapshot.
	for _, f := range files {
		i, e := root.Lstat(f.Path)
		if e != nil || i.IsDir() != f.Directory || i.Mode().Perm() != fs.FileMode(f.Mode) {
			return nil, errors.New("迁移来源清单在读取后变化")
		}
		if !f.Directory {
			o, e := migrationOpen(root, f.Path, syscall.O_RDONLY|syscall.O_NONBLOCK)
			if e != nil {
				return nil, e
			}
			b, e := io.ReadAll(io.LimitReader(o, MaxMigrationFileBytes+1))
			_ = o.Close()
			h := sha256.Sum256(b)
			if e != nil || hex.EncodeToString(h[:]) != f.SHA256 {
				return nil, errors.New("迁移来源内容在读取后变化")
			}
		}
	}
	var actual []string
	var list func(string) error
	list = func(rel string) error {
		d, e := migrationOpen(root, rel, syscall.O_RDONLY|syscall.O_DIRECTORY)
		if e != nil {
			return e
		}
		entries, e := d.ReadDir(-1)
		_ = d.Close()
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if r.ID == "publisher" && entry.Name() != "subscription-publisher.json" {
				continue
			}
			p := path.Join(rel, entry.Name())
			actual = append(actual, p)
			if len(actual) > MaxMigrationFiles {
				return errors.New("迁移来源清单超过上限")
			}
			if entry.IsDir() {
				if e = list(p); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if err = list("."); err != nil {
		return nil, err
	}
	if len(actual) != len(files) {
		return nil, errors.New("迁移来源清单在读取期间变化")
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.Path] = true
	}
	for _, p := range actual {
		if !seen[p] {
			return nil, errors.New("迁移来源出现新条目")
		}
	}
	return files, nil
}

func migrationOpen(root *os.Root, rel string, flags int) (*os.File, error) {
	dir, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	if rel == "." {
		return dir, nil
	}
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			dir.Close()
			return nil, errors.New("迁移打开路径无效")
		}
		f := syscall.O_RDONLY | syscall.O_DIRECTORY
		if i == len(parts)-1 {
			f = flags
		}
		fd, err := syscall.Openat(int(dir.Fd()), part, f|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = dir.Close()
		if err != nil {
			return nil, err
		}
		dir = os.NewFile(uintptr(fd), part)
		if dir == nil {
			_ = syscall.Close(fd)
			return nil, errors.New("迁移文件描述符无效")
		}
	}
	return dir, nil
}

func migrationSafeAncestors(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) == string(os.PathSeparator) {
		return errors.New("迁移目录必须为独立绝对路径")
	}
	for current := filepath.Clean(p); ; current = filepath.Dir(current) {
		i, e := os.Lstat(current)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("迁移目录祖先不能是链接或非目录")
		}
		if i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
			return errors.New("迁移目录祖先可被其他用户修改")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func MigrationSummary(m MigrationPackage) string {
	var total int
	for _, f := range m.Files {
		total += len(f.Data)
	}
	return fmt.Sprintf("迁移格式 QNBK3/v%d；模式 %s；State %d；核心 %s；资产 %d 条/%d 字节；外部资产 %d 项；来源服务仅作证据", m.Version, m.Mode, m.Snapshot.State.Schema, m.Snapshot.State.CoreVersion, len(m.Files), total, len(m.External))
}

func (m MigrationManifest) validate(s Snapshot) error {
	if m.Version != 1 || m.OS != "linux" || m.Architecture != "amd64" && m.Architecture != "arm64" || m.CoreVersion != s.State.CoreVersion || m.CoreArchiveSHA256 != s.State.CoreArchiveSHA256 || m.ServiceManager != "unknown" && m.ServiceManager != "systemd" && m.ServiceManager != "openrc" && m.ServiceManager != "offline" {
		return errors.New("迁移版本清单未来版本、平台或核心来源不一致")
	}
	for _, v := range []string{m.ManagerVersion, m.ManagerRevision} {
		if !cleanName(v) || len(v) > 160 {
			return errors.New("迁移管理器版本证据无效")
		}
	}
	if s.ManagerVersion != "" && m.ManagerVersion != s.ManagerVersion {
		return errors.New("迁移管理器版本与来源快照不一致")
	}
	for _, sum := range []string{m.CoreArchiveSHA256, m.CoreBinarySHA256} {
		if sum != "" {
			b, e := hex.DecodeString(sum)
			if e != nil || len(b) != 32 {
				return errors.New("迁移核心摘要无效")
			}
		}
	}
	return nil
}

// A retention index only ever names random, manager-created regular files.
// It is deliberately separate from manually selected output paths.
type BackupRetention struct {
	Count  int
	MaxAge time.Duration
	Bytes  int64
}
type managedBackup struct {
	Name      string    `json:"name"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	Complete  bool      `json:"complete"`
}
type backupIndex struct {
	Version           int             `json:"version"`
	Current           string          `json:"current"`
	ProtectedComplete string          `json:"protected_complete"`
	Files             []managedBackup `json:"files"`
}

const backupIndexName = ".qingnode-backups.json"

func RegisterManagedBackup(dir, file string, complete ...bool) error {
	i, err := loadBackupIndex(dir)
	if err != nil {
		return err
	}
	if filepath.Dir(file) != filepath.Clean(dir) || !strings.HasSuffix(filepath.Base(file), ".qnbak") {
		return errors.New("只能登记本项目备份目录中的备份")
	}
	b, err := readManagedBackup(file)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	for _, r := range i.Files {
		if r.Name == filepath.Base(file) {
			return errors.New("备份已登记")
		}
	}
	i.Current = filepath.Base(file)
	isComplete := len(complete) == 1 && complete[0]
	if len(complete) > 1 {
		return errors.New("备份完整性登记参数无效")
	}
	i.Files = append(i.Files, managedBackup{Name: i.Current, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b)), CreatedAt: time.Now().UTC(), Complete: isComplete})
	if isComplete {
		i.ProtectedComplete = i.Current
	}
	return saveBackupIndex(dir, i)
}

func loadBackupIndex(dir string) (backupIndex, error) {
	i := backupIndex{Version: 1, Files: []managedBackup{}}
	if err := migrationSafeAncestors(dir); err != nil {
		return i, err
	}
	indexPath := filepath.Join(dir, backupIndexName)
	info, err := os.Lstat(indexPath)
	if errors.Is(err, os.ErrNotExist) {
		return i, nil
	}
	if err != nil {
		return i, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return i, errors.New("受管备份索引所有权或权限无效")
	}
	b, err := os.ReadFile(indexPath)
	if err != nil {
		return i, err
	}
	if len(b) > 1<<20 {
		return i, errors.New("备份索引过大")
	}
	if err = rejectMigrationJSON(b); err != nil {
		return i, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&i); err != nil || i.Version != 1 || len(i.Files) > 4096 {
		return i, errors.New("备份索引无效")
	}
	seen := map[string]bool{}
	current := false
	protected := i.ProtectedComplete == ""
	for _, r := range i.Files {
		if !validMigrationPath(r.Name) || filepath.Base(r.Name) != r.Name || !strings.HasSuffix(r.Name, ".qnbak") || seen[r.Name] || r.Size < 50 || r.Size > MaxMigrationBytes || len(r.SHA256) != 64 || r.CreatedAt.IsZero() {
			return i, errors.New("备份索引条目无效")
		}
		seen[r.Name] = true
		current = current || r.Name == i.Current
		protected = protected || r.Name == i.ProtectedComplete && r.Complete
	}
	if len(i.Files) > 0 && !current || !protected {
		return i, errors.New("备份索引缺少当前恢复点")
	}
	return i, nil
}
func saveBackupIndex(dir string, i backupIndex) error {
	b, e := json.MarshalIndent(i, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(dir, backupIndexName), b, 0600)
}
func readManagedBackup(p string) ([]byte, error) {
	i, e := os.Lstat(p)
	if e != nil {
		return nil, e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("受管备份须为当前用户私有、无链接普通文件")
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) {
		return nil, errors.New("受管备份在读取时变化")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxMigrationBytes+1))
	if e != nil || len(b) > MaxMigrationBytes {
		return nil, errors.New("受管备份过大")
	}
	return b, nil
}

func PruneManagedBackups(dir string, p BackupRetention, apply bool) ([]string, error) {
	if p.Count < 1 || p.Count > 4096 || p.MaxAge < 0 || p.Bytes < 0 {
		return nil, errors.New("保留策略须至少保留1份，数量不超过4096，时间和容量不能为负")
	}
	i, e := loadBackupIndex(dir)
	if e != nil {
		return nil, e
	}
	sort.Slice(i.Files, func(a, b int) bool { return i.Files[a].CreatedAt.After(i.Files[b].CreatedAt) })
	var keep []managedBackup
	var remove []string
	var total int64
	now := time.Now().UTC()
	// Protect current even if it is older or larger than the requested budget.
	for _, r := range i.Files {
		if r.Name == i.Current || r.Name == i.ProtectedComplete {
			keep = append(keep, r)
			total += r.Size
		}
	}
	for _, r := range i.Files {
		b, err := readManagedBackup(filepath.Join(dir, r.Name))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		if int64(len(b)) != r.Size || hex.EncodeToString(h[:]) != r.SHA256 {
			return nil, errors.New("备份被外部修改，未清理任何文件")
		}
		if r.Name == i.Current || r.Name == i.ProtectedComplete {
			continue
		}
		expired := p.MaxAge > 0 && now.Sub(r.CreatedAt) > p.MaxAge
		overflow := p.Bytes > 0 && total+r.Size > p.Bytes
		if len(keep) >= p.Count || expired || overflow {
			remove = append(remove, r.Name)
		} else {
			keep = append(keep, r)
			total += r.Size
		}
	}
	if !apply {
		return remove, nil
	}
	// Move candidates to owned quarantine first; index is committed before any deletion.
	trash, err := os.MkdirTemp(dir, ".retention-")
	if err != nil {
		return nil, err
	}
	rollback := func() {
		for _, n := range remove {
			if _, e := os.Lstat(filepath.Join(trash, n)); e == nil {
				_ = os.Rename(filepath.Join(trash, n), filepath.Join(dir, n))
			}
		}
		_ = os.Remove(trash)
	}
	for _, n := range remove {
		if err = os.Rename(filepath.Join(dir, n), filepath.Join(trash, n)); err != nil {
			rollback()
			return nil, err
		}
	}
	i.Files = keep
	if err = saveBackupIndex(dir, i); err != nil {
		rollback()
		return nil, err
	}
	if err = os.RemoveAll(trash); err != nil {
		return remove, fmt.Errorf("索引已提交，待清理隔离目录 %s：%w", filepath.Base(trash), err)
	}
	return remove, SyncDir(dir)
}
