package node

// Optional-service transactions are separate from proxy State transactions.
// Definitions are regenerated from typed local settings, including during
// recovery; neither an archive nor a journal can supply executable unit text.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"qingnode/internal/platform"
)

type AuxiliaryServiceFile struct {
	Name     string      `json:"name"`
	Contents []byte      `json:"contents"`
	Mode     os.FileMode `json:"mode"`
}

type AuxiliaryServicePlan struct {
	Name        string
	Manager     platform.Manager
	PublicURL   string
	Definitions []AuxiliaryServiceFile
}

type AuxiliaryServicePreview struct {
	Version     int                    `json:"version"`
	Name        string                 `json:"name"`
	Manager     platform.InitKind      `json:"manager"`
	Action      string                 `json:"action"`
	Installed   bool                   `json:"installed"`
	Pending     bool                   `json:"pending"`
	Definitions []string               `json:"definitions"`
	WasActive   bool                   `json:"was_active"`
	WasEnabled  bool                   `json:"was_enabled"`
	States      []auxiliaryNativeState `json:"states,omitempty"`
}

const auxiliaryMonitorService = "# Managed by QingNode\n[Unit]\nDescription=QingNode bounded observation\nAfter=network.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/qingnode monitor run\nTimeoutStartSec=180\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\n"
const auxiliaryMonitorTimer = "# Managed by QingNode\n[Unit]\nDescription=QingNode optional observation timer\n\n[Timer]\nOnBootSec=60s\nOnUnitInactiveSec=60s\nRandomizedDelaySec=10s\nAccuracySec=1s\nUnit=qingnode-monitor.service\n\n[Install]\nWantedBy=timers.target\n"

const AuxiliaryMonitorSystemdService = auxiliaryMonitorService
const AuxiliaryMonitorSystemdTimer = auxiliaryMonitorTimer

// NewAuxiliaryServicePlan accepts only the two built-in service types. A
// subscription public URL is typed deployment data, never shell/unit input.
func NewAuxiliaryServicePlan(manager platform.Manager, name, publicURL string) (AuxiliaryServicePlan, error) {
	p := AuxiliaryServicePlan{Name: name, Manager: manager, PublicURL: publicURL}
	if !auxiliaryName(name) || manager.ResolvedKind() != platform.InitSystemd && manager.ResolvedKind() != platform.InitOpenRC {
		return p, errors.New("只支持当前systemd/OpenRC的青节点监控或订阅服务")
	}
	var spec platform.ServiceSpec
	switch name {
	case "qingnode-monitor":
		if publicURL != "" {
			return p, errors.New("监控服务不接受公开订阅地址")
		}
		if manager.ResolvedKind() == platform.InitSystemd {
			p.Definitions = []AuxiliaryServiceFile{{name + ".service", []byte(auxiliaryMonitorService), 0644}, {name + ".timer", []byte(auxiliaryMonitorTimer), 0644}}
			return p, nil
		}
		spec = platform.ServiceSpec{Name: name, Description: "QingNode bounded periodic observation", Command: "/usr/local/bin/qingnode", Args: []string{"monitor", "watch"}, User: "root", Group: "root", WritablePaths: []string{"/var/lib/qingnode"}}
	case "qingnode-subscription":
		u, err := url.Parse(publicURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return p, errors.New("订阅服务需要无凭据、令牌或查询参数的明确HTTPS公开地址")
		}
		p.PublicURL = u.String()
		spec = platform.ServiceSpec{Name: name, Description: "QingNode read-only subscription", Command: "/usr/local/bin/qingnode", Args: []string{"subscription", "serve", "--dir", "/var/lib/qingnode-subscription", "--listen", "127.0.0.1:8389", "--public-url", u.String(), "--reverse-proxy"}, User: "qingnode-sub", Group: "qingnode-sub"}
	}
	var body string
	var err error
	mode := os.FileMode(0644)
	filename := name + ".service"
	if manager.ResolvedKind() == platform.InitOpenRC {
		body, err = platform.RenderOpenRC(spec)
		mode, filename = 0755, name
	} else {
		body, err = platform.RenderSystemd(spec)
	}
	if err != nil {
		return p, err
	}
	p.Definitions = []AuxiliaryServiceFile{{filename, []byte(body), mode}}
	return p, nil
}

type auxiliarySettings struct {
	Name      string            `json:"name"`
	Kind      platform.InitKind `json:"manager"`
	PublicURL string            `json:"public_url,omitempty"`
}
type auxiliaryFileSnapshot struct {
	AuxiliaryServiceFile
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}
type auxiliarySnapshot struct {
	Settings auxiliarySettings       `json:"settings"`
	Present  bool                    `json:"present"`
	Files    []auxiliaryFileSnapshot `json:"files"`
	States   []auxiliaryNativeState  `json:"states"`
	Receipt  []byte                  `json:"receipt,omitempty"`
}
type auxiliaryInstalled struct {
	Version  int               `json:"version"`
	Settings auxiliarySettings `json:"settings"`
}
type auxiliaryJournal struct {
	Version   int               `json:"version"`
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Phase     string            `json:"phase"`
	Before    auxiliarySnapshot `json:"before"`
	Candidate auxiliarySettings `json:"candidate"`
	// Exact source bytes are retained by explicit recovery. A semantically equal
	// but externally rewritten journal is still not this writer's record.
	source []byte
}

func auxiliaryName(name string) bool {
	return name == "qingnode-monitor" || name == "qingnode-subscription"
}
func auxiliaryPath(root, name, suffix string) string {
	return filepath.Join(root, ".auxiliary-"+name+suffix+".json")
}
func auxiliarySettingsFor(p AuxiliaryServicePlan) auxiliarySettings {
	return auxiliarySettings{p.Name, p.Manager.ResolvedKind(), p.PublicURL}
}

func auxiliaryValidateRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return errors.New("附属服务需要现有受管状态目录")
	}
	i, err := os.Lstat(root)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0022 != 0 {
		return errors.New("附属服务状态目录不是安全的现有目录")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.New("附属服务状态目录属主不匹配")
	}
	b, err := auxiliaryReadPrivate(filepath.Join(root, ".qingnode-owner"))
	if err != nil || string(b) != OwnerMarker {
		return errors.New("附属服务状态目录缺少有效所有权标记")
	}
	return nil
}

func auxiliaryReadPrivate(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Size > 1<<20 {
		return nil, errors.New("附属服务恢复材料不是当前用户的私有普通文件")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, errors.New("附属服务恢复材料读取失败或超过上限")
	}
	return b, nil
}

func auxiliaryDecode(b []byte, value any) error {
	// The shared bounded envelope walker rejects duplicate/aliased keys, null,
	// excessive nesting and trailing JSON before encoding/json can pick a winner.
	if err := rejectMigrationJSON(b); err != nil {
		return errors.New("附属服务恢复材料含重复、歧义或无效JSON字段")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("附属服务恢复材料格式不受支持")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("附属服务恢复材料包含多余条目")
	}
	return nil
}

func auxiliaryCanonical(p AuxiliaryServicePlan) (AuxiliaryServicePlan, error) {
	canonical, err := NewAuxiliaryServicePlan(p.Manager, p.Name, p.PublicURL)
	if err != nil {
		return p, err
	}
	if len(p.Definitions) != 0 {
		if len(p.Definitions) != len(canonical.Definitions) {
			return p, errors.New("附属服务定义集合不完整")
		}
		for i, file := range p.Definitions {
			want := canonical.Definitions[i]
			if file.Name != want.Name || file.Mode != want.Mode || !bytes.Equal(file.Contents, want.Contents) {
				return p, errors.New("只接受本机固定类型渲染的附属服务定义")
			}
		}
	}
	return canonical, nil
}

func auxiliaryReceipt(root string, p AuxiliaryServicePlan) (AuxiliaryServicePlan, []byte, error) {
	b, err := auxiliaryReadPrivate(auxiliaryPath(root, p.Name, ".installed"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil, nil
	}
	if err != nil {
		return p, nil, err
	}
	var record auxiliaryInstalled
	if err := auxiliaryDecode(b, &record); err != nil {
		return p, nil, err
	}
	if record.Version != 1 || record.Settings.Name != p.Name || record.Settings.Kind != p.Manager.ResolvedKind() {
		return p, nil, errors.New("附属服务安装记录版本、名称或目标init不匹配")
	}
	old, err := NewAuxiliaryServicePlan(p.Manager, p.Name, record.Settings.PublicURL)
	return old, b, err
}

// AuxiliaryServicePending is strictly read-only: queries do not create locks,
// repair transactions, reload definitions, or change a service's state.
func AuxiliaryServicePending(root, name string) (bool, error) {
	if !auxiliaryName(name) {
		return false, errors.New("未知附属服务")
	}
	if err := auxiliaryValidateRoot(root); err != nil {
		return false, err
	}
	if conflict, err := auxiliaryConflictPending(root, name); err != nil || conflict {
		return conflict, err
	}
	_, err := auxiliaryReadPrivate(auxiliaryPath(root, name, ".journal"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// PendingAuxiliaryService prevents uninstall/migration from discarding the
// only remaining recovery material after a crash midway through removal.
func PendingAuxiliaryService(root string) error {
	for _, name := range []string{"qingnode-monitor", "qingnode-subscription"} {
		if conflict, err := auxiliaryConflictPending(root, name); err != nil {
			return err
		} else if conflict {
			return fmt.Errorf("附属服务%s保留冲突见证；先人工核对恢复材料，再显式service recover --name %s", name, name)
		}
		_, err := auxiliaryReadPrivate(auxiliaryPath(root, name, ".journal"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("附属服务恢复材料无法安全核对：%w", err)
		}
		return fmt.Errorf("附属服务%s有未完成事务；请先service recover --name %s，保留当前恢复材料", name, name)
	}
	return nil
}

// AuxiliaryServiceMigrationGaps inventories deployment settings offline. QNBK3
// v1 has no auxiliary-deployment asset type: report that limitation rather than
// silently claiming the target will inherit native services or autostart state.
func AuxiliaryServiceMigrationGaps(root string) ([]string, error) {
	if err := PendingAuxiliaryService(root); err != nil {
		return nil, err
	}
	gaps := []string{}
	for _, name := range []string{"qingnode-monitor", "qingnode-subscription"} {
		b, err := auxiliaryReadPrivate(auxiliaryPath(root, name, ".installed"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var record auxiliaryInstalled
		if err := auxiliaryDecode(b, &record); err != nil {
			return nil, err
		}
		if record.Version != 1 || record.Settings.Name != name || record.Settings.Kind != platform.InitSystemd && record.Settings.Kind != platform.InitOpenRC {
			return nil, errors.New("附属部署资料版本、名称或init类型不受支持")
		}
		// Explicit Kind is used only for deterministic local rendering. No native
		// query, host-init discovery, lock creation or lifecycle call occurs here.
		p, err := NewAuxiliaryServicePlan(platform.Manager{Kind: record.Settings.Kind}, name, record.Settings.PublicURL)
		if err != nil || p.PublicURL != record.Settings.PublicURL {
			return nil, errors.New("附属部署资料不等于受支持的本地类型化设置")
		}
		gaps = append(gaps, fmt.Sprintf("附属服务%s的部署设置不在QNBK3 v1资产中；请保留本机部署资料，在目标显式service install并重新核对运行/自启动；不执行来源unit", name))
	}
	return gaps, nil
}

func PreviewAuxiliaryService(root string, p AuxiliaryServicePlan, action string) (AuxiliaryServicePreview, error) {
	r := AuxiliaryServicePreview{Version: 1, Name: p.Name, Manager: p.Manager.ResolvedKind(), Action: action, Definitions: []string{}}
	if action != "install" && action != "remove" && action != "inspect" && action != "recover" {
		return r, errors.New("未知附属服务事务操作")
	}
	if !auxiliaryName(p.Name) {
		return r, errors.New("未知附属服务")
	}
	if err := auxiliaryValidateRoot(root); err != nil {
		return r, err
	}
	pending, err := AuxiliaryServicePending(root, p.Name)
	if err != nil {
		return r, err
	}
	r.Pending = pending
	if pending {
		return r, nil
	}
	old, receipt, err := auxiliaryReceipt(root, p)
	if err != nil {
		return r, err
	}
	if receipt == nil && len(p.Definitions) == 0 && p.Name == "qingnode-subscription" && p.PublicURL == "" {
		// A missing service can be inspected/removed without guessing a URL.
		if _, err := os.Lstat(auxiliaryDefinitionPath(p.Manager, p.Name+auxiliarySuffix(p.Manager))); !errors.Is(err, os.ErrNotExist) {
			return r, errors.New("既有订阅服务没有安装记录；须提供原HTTPS地址以核对本地定义")
		}
		old.PublicURL = "https://unconfigured.invalid"
	}
	old, err = auxiliaryCanonical(old)
	if err != nil {
		return r, err
	}
	if action == "install" {
		if _, err = auxiliaryCanonical(p); err != nil {
			return r, err
		}
	}
	snapshot, err := auxiliaryCapture(old, receipt)
	if err != nil {
		return r, err
	}
	r.Installed, r.States = snapshot.Present, snapshot.States
	for _, file := range old.Definitions {
		r.Definitions = append(r.Definitions, file.Name)
	}
	for _, state := range snapshot.States {
		r.WasActive = r.WasActive || state.Active
		r.WasEnabled = r.WasEnabled || state.Enabled == "enabled" || len(state.Runlevels) > 0
	}
	return r, nil
}

func ApplyAuxiliaryService(root string, p AuxiliaryServicePlan, action string) error {
	if action != "install" && action != "remove" {
		return errors.New("附属事务只支持install/remove")
	}
	if !auxiliaryName(p.Name) {
		return errors.New("未知附属服务")
	}
	if err := auxiliaryValidateRoot(root); err != nil {
		return err
	}
	release, err := auxiliaryLease(root, p.Name)
	if err != nil {
		return err
	}
	defer release()
	if pending, err := AuxiliaryServicePending(root, p.Name); err != nil || pending {
		if err != nil {
			return err
		}
		return errors.New("附属服务有未完成事务；先只读预览并显式service recover")
	}
	old, receipt, err := auxiliaryReceipt(root, p)
	if err != nil {
		return err
	}
	if receipt == nil && p.Name == "qingnode-subscription" && p.PublicURL == "" && len(p.Definitions) == 0 {
		if _, e := os.Lstat(auxiliaryDefinitionPath(p.Manager, p.Name+auxiliarySuffix(p.Manager))); !errors.Is(e, os.ErrNotExist) {
			return errors.New("无安装记录的既有订阅服务需要原公开HTTPS地址核对")
		}
		old.PublicURL = "https://unconfigured.invalid"
	}
	old, err = auxiliaryCanonical(old)
	if err != nil {
		return err
	}
	candidate := old
	if action == "install" {
		candidate, err = auxiliaryCanonical(p)
		if err != nil {
			return err
		}
	}
	before, err := auxiliaryCapture(old, receipt)
	if err != nil {
		return err
	}
	if action == "remove" && !before.Present && receipt == nil {
		return nil
	}
	j := auxiliaryJournal{Version: 1, ID: Token(16), Action: action, Phase: "prepared", Before: before, Candidate: auxiliarySettingsFor(candidate)}
	journalPath := auxiliaryPath(root, p.Name, ".journal")
	if err = auxiliaryCreateJournal(journalPath, j); err != nil {
		return err
	}
	if err = auxiliaryApplyPrepared(root, p.Manager, j); err != nil {
		original := err
		if recovery := auxiliaryRollback(root, p.Manager, j); recovery != nil {
			return fmt.Errorf("附属服务%s失败，自动恢复也未完成；恢复材料已保留，请显式recover：%v；恢复：%w", action, original, recovery)
		}
		if e := auxiliaryFinish(root, p.Manager, j, "rolled_back"); e != nil {
			return fmt.Errorf("附属服务已恢复，恢复记录收尾失败：%w", e)
		}
		return fmt.Errorf("附属服务%s失败，已恢复原定义、运行及自启动状态：%w", action, original)
	}
	return auxiliaryFinish(root, p.Manager, j, "committed")
}

func RecoverAuxiliaryService(root string, p AuxiliaryServicePlan, preview bool) (AuxiliaryServicePreview, error) {
	r := AuxiliaryServicePreview{Version: 1, Name: p.Name, Manager: p.Manager.ResolvedKind(), Action: "recover", Definitions: []string{}}
	if !auxiliaryName(p.Name) {
		return r, errors.New("未知附属服务")
	}
	if err := auxiliaryValidateRoot(root); err != nil {
		return r, err
	}
	var release func()
	var err error
	if !preview {
		release, err = auxiliaryLease(root, p.Name)
		if err != nil {
			return r, err
		}
		defer release()
	}
	if conflict, err := auxiliaryConflictPending(root, p.Name); err != nil {
		return r, err
	} else if conflict {
		r.Pending = true
		return r, errors.New("存在附属服务冲突见证；请先人工核对原记录和外部改动，未自动接管或替换主记录")
	}
	b, err := auxiliaryReadPrivate(auxiliaryPath(root, p.Name, ".journal"))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	r.Pending = true
	var j auxiliaryJournal
	if err = auxiliaryDecode(b, &j); err != nil {
		return r, err
	}
	j.source = append([]byte(nil), b...)
	if err = auxiliaryValidateJournal(p.Manager, p.Name, j); err != nil {
		return r, err
	}
	if err = auxiliaryRecoverySafe(root, p.Manager, j); err != nil {
		return r, err
	}
	r.Installed = j.Before.Present
	for _, f := range j.Before.Files {
		r.Definitions = append(r.Definitions, f.Name)
	}
	for _, state := range j.Before.States {
		r.WasActive = r.WasActive || state.Active
		r.WasEnabled = r.WasEnabled || state.Enabled == "enabled" || len(state.Runlevels) > 0
	}
	if preview {
		return r, nil
	}
	if err = auxiliaryRollback(root, p.Manager, j); err != nil {
		return r, fmt.Errorf("附属服务恢复未完成，私有恢复材料已保留：%w", err)
	}
	if err = auxiliaryFinish(root, p.Manager, j, "rolled_back"); err != nil {
		return r, err
	}
	r.Pending = false
	return r, nil
}

func auxiliaryCreateJournal(path string, j auxiliaryJournal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("无法创建独占附属服务恢复记录，未开始修改")
	}
	f := os.NewFile(uintptr(fd), path)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = SyncDir(filepath.Dir(path))
	}
	return err
}

func auxiliaryFinish(root string, manager platform.Manager, j auxiliaryJournal, phase string) error {
	_, check := auxiliaryGuardedManager(root, manager, j)
	if err := check(); err != nil {
		return err
	}
	path := auxiliaryPath(root, j.Before.Settings.Name, ".journal")
	history := auxiliaryPath(root, j.Before.Settings.Name, ".recovery-"+j.ID)
	if _, err := os.Lstat(history); !errors.Is(err, os.ErrNotExist) {
		return errors.New("恢复历史路径已存在，未覆盖")
	}
	if err := check(); err != nil {
		return err
	}
	j.Phase, j.source = phase, nil
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err = AtomicWrite(path, b, 0600); err != nil {
		return err
	}
	_, finalCheck := auxiliaryGuardedManager(root, manager, j)
	if err := finalCheck(); err != nil {
		return err
	}
	// A concurrent administrator may create the history target after our last
	// lstat. Never replace it: a plain rename would silently lose that evidence.
	if err = unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, history, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return SyncDir(root)
}

func auxiliaryValidateJournal(manager platform.Manager, name string, j auxiliaryJournal) error {
	if j.Version != 1 || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(j.ID) || j.Action != "install" && j.Action != "remove" || j.Phase != "prepared" && j.Phase != "committed" && j.Phase != "rolled_back" {
		return errors.New("附属服务恢复记录版本或阶段不受支持")
	}
	if j.Before.Settings.Name != name || j.Candidate.Name != name || j.Before.Settings.Kind != manager.ResolvedKind() || j.Candidate.Kind != manager.ResolvedKind() {
		return errors.New("附属服务恢复目标或init与本机不匹配")
	}
	old, err := NewAuxiliaryServicePlan(manager, name, j.Before.Settings.PublicURL)
	if err != nil {
		return err
	}
	if _, err = NewAuxiliaryServicePlan(manager, name, j.Candidate.PublicURL); err != nil {
		return err
	}
	if j.Before.Present && len(j.Before.Files) != len(old.Definitions) || !j.Before.Present && len(j.Before.Files) != 0 || len(j.Before.States) != len(old.Definitions) {
		return errors.New("附属服务恢复记录的定义或状态集合不完整")
	}
	for i, f := range j.Before.Files {
		want := old.Definitions[i]
		if f.Name != want.Name || f.Mode != want.Mode || !bytes.Equal(f.Contents, want.Contents) || f.UID != uint32(os.Geteuid()) {
			return errors.New("恢复定义不等于固定本地渲染，拒绝执行来源命令")
		}
	}
	for i, state := range j.Before.States {
		if state.Member != old.Definitions[i].Name || state.Enabled != "enabled" && state.Enabled != "disabled" && state.Enabled != "static" && state.Enabled != "absent" {
			return errors.New("恢复服务状态不受支持")
		}
		if !j.Before.Present && (state.Active || state.Enabled != "absent" || len(state.Runlevels) > 0) {
			return errors.New("缺失定义却记录了运行状态，拒绝猜测恢复")
		}
		for _, l := range state.Runlevels {
			if !regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`).MatchString(l) {
				return errors.New("恢复runlevel无效")
			}
		}
	}
	if len(j.Before.Receipt) > 0 {
		var record auxiliaryInstalled
		if auxiliaryDecode(j.Before.Receipt, &record) != nil || record.Version != 1 || record.Settings != j.Before.Settings {
			return errors.New("恢复安装记录与固定本地设置不符")
		}
	}
	return nil
}

func auxiliaryApplyPrepared(root string, manager platform.Manager, j auxiliaryJournal) error {
	manager, check := auxiliaryGuardedManager(root, manager, j)
	if err := check(); err != nil {
		return err
	}
	if err := auxiliaryStopCurrent(manager, j.Before.Settings.Name); err != nil {
		return err
	}
	candidate, _ := NewAuxiliaryServicePlan(manager, j.Candidate.Name, j.Candidate.PublicURL)
	if j.Action == "remove" {
		if err := auxiliaryDisableCurrent(manager, candidate.Name); err != nil {
			return err
		}
		for _, file := range candidate.Definitions {
			if err := check(); err != nil {
				return err
			}
			if err := auxiliaryRemoveDefinition(manager, file.Name); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
		}
	} else {
		for _, file := range candidate.Definitions {
			if err := check(); err != nil {
				return err
			}
			if err := AtomicWrite(auxiliaryDefinitionPath(manager, file.Name), file.Contents, file.Mode); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
		}
	}
	if err := manager.ReloadDefinitions(); err != nil {
		return err
	}
	if j.Action == "install" {
		if err := auxiliaryRestoreNative(manager, candidate.Name, j.Before.States, j.Before.Present); err != nil {
			return err
		}
		if err := auxiliaryWaitStable(manager, candidate.Name); err != nil {
			return err
		}
		if _, err := auxiliaryCapture(candidate, nil); err != nil {
			return err
		}
		if err := auxiliaryVerifyNative(manager, candidate.Name, j.Before.States, j.Before.Present, true); err != nil {
			return err
		}
		record, _ := json.Marshal(auxiliaryInstalled{1, j.Candidate})
		if err := check(); err != nil {
			return err
		}
		if err := AtomicWrite(auxiliaryPath(root, candidate.Name, ".installed"), record, 0600); err != nil {
			return err
		}
		return check()
	}
	if err := auxiliaryVerifyNative(manager, candidate.Name, j.Before.States, false, false); err != nil {
		return err
	}
	path := auxiliaryPath(root, candidate.Name, ".installed")
	if err := check(); err != nil {
		return err
	}
	if _, err := auxiliaryReadPrivate(path); err == nil {
		if err := check(); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		return SyncDir(root)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func auxiliaryRollback(root string, manager platform.Manager, j auxiliaryJournal) error {
	if err := auxiliaryValidateJournal(manager, j.Before.Settings.Name, j); err != nil {
		return err
	}
	manager, check := auxiliaryGuardedManager(root, manager, j)
	if err := check(); err != nil {
		return err
	}
	// A crash may have occurred between one atomic definition write/remove and
	// daemon-reload. Reconcile only the already-attested local definitions before
	// querying active state; read-only preview never performs this reload.
	if err := manager.ReloadDefinitions(); err != nil {
		return err
	}
	if err := auxiliaryStopCurrent(manager, j.Before.Settings.Name); err != nil {
		return err
	}
	if err := auxiliaryDisableCurrent(manager, j.Before.Settings.Name); err != nil {
		return err
	}
	old, _ := NewAuxiliaryServicePlan(manager, j.Before.Settings.Name, j.Before.Settings.PublicURL)
	if j.Before.Present {
		for _, file := range j.Before.Files {
			path := auxiliaryDefinitionPath(manager, file.Name)
			if err := check(); err != nil {
				return err
			}
			if err := AtomicWrite(path, file.Contents, file.Mode); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
			if err := os.Chown(path, int(file.UID), int(file.GID)); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
		}
	} else {
		for _, file := range old.Definitions {
			if err := check(); err != nil {
				return err
			}
			if err := auxiliaryRemoveDefinition(manager, file.Name); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
		}
	}
	if err := manager.ReloadDefinitions(); err != nil {
		return err
	}
	if err := auxiliaryRestoreNative(manager, old.Name, j.Before.States, j.Before.Present); err != nil {
		return err
	}
	if err := auxiliaryWaitStable(manager, old.Name); err != nil {
		return err
	}
	if j.Before.Present {
		if _, err := auxiliaryCapture(old, nil); err != nil {
			return err
		}
	}
	if err := auxiliaryVerifyNative(manager, old.Name, j.Before.States, j.Before.Present, j.Before.Present); err != nil {
		return err
	}
	path := auxiliaryPath(root, old.Name, ".installed")
	if err := check(); err != nil {
		return err
	}
	if len(j.Before.Receipt) > 0 {
		if err := AtomicWrite(path, j.Before.Receipt, 0600); err != nil {
			return err
		}
		return check()
	}
	if _, err := auxiliaryReadPrivate(path); err == nil {
		if err := check(); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		return SyncDir(root)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func auxiliaryRecoverySafe(root string, manager platform.Manager, j auxiliaryJournal) error {
	if err := auxiliaryFilesystemSafe(root, manager, j); err != nil {
		return err
	}
	old, err := NewAuxiliaryServicePlan(manager, j.Before.Settings.Name, j.Before.Settings.PublicURL)
	if err != nil {
		return err
	}
	for _, file := range old.Definitions {
		if err = auxiliaryVerifyNativeSource(manager, file.Name); err != nil {
			return err
		}
	}
	// Re-read local bytes after the last controller observation: an injected or
	// external source query must not reopen a callback-sized mutation window.
	return auxiliaryFilesystemSafe(root, manager, j)
}

func auxiliaryReceiptSafe(root string, j auxiliaryJournal) error {
	b, err := auxiliaryReadPrivate(auxiliaryPath(root, j.Before.Settings.Name, ".installed"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	next, _ := json.Marshal(auxiliaryInstalled{1, j.Candidate})
	if !bytes.Equal(b, j.Before.Receipt) && !bytes.Equal(b, next) {
		return errors.New("附属安装记录已被外部修改，未覆盖")
	}
	return nil
}

func auxiliaryCapture(p AuxiliaryServicePlan, receipt []byte) (auxiliarySnapshot, error) {
	s := auxiliarySnapshot{Settings: auxiliarySettingsFor(p), Receipt: receipt, Files: []auxiliaryFileSnapshot{}, States: []auxiliaryNativeState{}}
	present := 0
	for _, file := range p.Definitions {
		if err := auxiliaryCheckOverrides(p.Manager, file.Name); err != nil {
			return s, err
		}
		b, uid, gid, err := auxiliaryReadDefinition(p.Manager, file.Name, file.Mode)
		if err == nil {
			if !bytes.Equal(b, file.Contents) {
				return s, errors.New("既有服务定义已被外部修改，拒绝安装或删除")
			}
			present++
			s.Files = append(s.Files, auxiliaryFileSnapshot{AuxiliaryServiceFile{file.Name, b, file.Mode}, uid, gid})
		} else if !errors.Is(err, os.ErrNotExist) {
			return s, err
		}
		state, err := auxiliaryNative(p.Manager, file.Name, err == nil)
		if err != nil {
			return s, err
		}
		s.States = append(s.States, state)
	}
	if present != 0 && present != len(p.Definitions) {
		return s, errors.New("监控service/timer必须作为完整对象，不能接管残缺定义")
	}
	s.Present = present > 0
	if receipt != nil && !s.Present {
		return s, errors.New("安装记录存在但定义丢失；先调查外部改动，不自动修复")
	}
	return s, nil
}

func auxiliaryReadDefinition(manager platform.Manager, member string, mode os.FileMode) ([]byte, uint32, uint32, error) {
	path := auxiliaryDefinitionPath(manager, member)
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 {
		return nil, 0, 0, errors.New("服务定义目录不安全或不可用")
	}
	ps, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || ps.Uid != uint32(os.Geteuid()) {
		return nil, 0, 0, errors.New("服务定义目录属主不匹配")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&07777 != uint32(mode) || st.Uid != uint32(os.Geteuid()) || st.Size > 128<<10 {
		return nil, 0, 0, errors.New("服务定义的类型、链接、属主或权限异常")
	}
	b, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil || len(b) > 128<<10 {
		return nil, 0, 0, errors.New("服务定义读取失败或超限")
	}
	return b, st.Uid, st.Gid, nil
}

func auxiliaryRemoveDefinition(manager platform.Manager, member string) error {
	path := auxiliaryDefinitionPath(manager, member)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

func auxiliarySuffix(manager platform.Manager) string {
	if manager.ResolvedKind() == platform.InitSystemd {
		return ".service"
	}
	return ""
}
func auxiliaryDefinitionPath(manager platform.Manager, member string) string {
	root := manager.DefinitionRoot
	if root == "" {
		if manager.ResolvedKind() == platform.InitSystemd {
			root = "/etc/systemd/system"
		} else {
			root = "/etc/init.d"
		}
	}
	return filepath.Join(root, member)
}

func auxiliaryCheckOverrides(manager platform.Manager, member string) error {
	if manager.ResolvedKind() == platform.InitSystemd {
		if _, err := os.Lstat(auxiliaryDefinitionPath(manager, member) + ".d"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("存在外部systemd drop-in或异常路径，拒绝操作")
		}
	} else {
		root := manager.ConfigRoot
		if root == "" {
			root = "/etc/conf.d"
		}
		if _, err := os.Lstat(filepath.Join(root, member)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("存在外部OpenRC conf.d覆盖，拒绝操作")
		}
	}
	return nil
}

func auxiliaryEqualStrings(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func auxiliaryLease(root, name string) (func(), error) {
	var release func()
	store := &Store{Root: root, GID: -1}
	err := store.InspectExisting(func() error {
		if err := auxiliaryValidateRoot(root); err != nil {
			return err
		}
		var err error
		release, err = AuxiliaryControlLease(root, name)
		return err
	})
	if err != nil && release != nil {
		release()
		release = nil
	}
	return release, err
}
