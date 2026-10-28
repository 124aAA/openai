package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"qingnode/internal/node"
	"qingnode/internal/platform"
	"qingnode/internal/subscription"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (a *app) backupPath(prefix string) (string, error) {
	dir := filepath.Join(a.store.Root, "backups")
	if i, e := os.Lstat(dir); e == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
		return "", errors.New("备份目录不能是符号链接")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	return filepath.Join(dir, prefix+"-"+time.Now().UTC().Format("20060102-150405")+"-"+node.Token(4)+".qnbak"), nil
}
func (a *app) snapshot(s node.State) (node.Snapshot, error) {
	unit := node.ServiceUnit
	if !a.offline {
		manager := platform.NewManager("", nil)
		path, e := manager.DefinitionPath("qingnode")
		if e != nil {
			return node.Snapshot{}, e
		}
		b, e := os.ReadFile(path)
		if e != nil && !os.IsNotExist(e) {
			return node.Snapshot{}, e
		}
		if e == nil {
			unit = string(b)
		}
	}
	return node.Capture(a.store.Root, s, version, unit)
}
func (a *app) backup(cmd string, args []string) error {
	f := fs(cmd)
	file := f.String("file", "", "加密备份路径，备份时可省略以自动命名")
	pass := f.String("password-file", "", "权限 600 的口令文件")
	yes := f.Bool("yes", false, "确认恢复替换节点")
	manual := f.Bool("manual-firewall", false, "恢复时不启用自动防火墙管理")
	plain := f.Bool("snapshot", false, "恢复权限 600 的卸载前明文 JSON 快照；恢复前备份仍加密")
	full := f.Bool("full", false, "创建QNBK3完整迁移包；普通备份仍为QNBK2配置备份")
	preview := f.Bool("preview", false, "只读预检，显示资产、目标映射和服务短停范围，不写备份或恢复")
	quiesce := f.Bool("quiesce", false, "明确允许为一致快照短暂停止本项目代理，完成后恢复原运行状态")
	limited := f.Bool("allow-incomplete", false, "明确允许带外部/缺失资产清单的受限迁移包；不称完整")
	restoreSubscriptions := f.Bool("restore-subscriptions", false, "明确恢复包中的订阅下载权限；可能重新允许包中当时有效的令牌")
	subDir := f.String("subscription-directory", "", "恢复订阅时本机专用发布目录；不沿用归档绝对路径")
	subGroup := f.Int("subscription-group", -1, "恢复订阅服务在目标机的实际组ID；默认当前进程组")
	recoverMigration := f.Bool("recover-migration", false, "显式恢复中断的完整迁移资产与原服务状态，需要--yes")
	prune := f.Bool("prune", false, "按受管索引清理备份；默认只预览，--yes才执行")
	retainCount := f.Int("retain-count", 10, "受管保留份数，至少1；当前恢复点始终保留")
	retainAge := f.Duration("retain-age", 0, "最长保留时间，0表示不限；当前恢复点始终保留")
	retainBytes := f.Int64("retain-bytes", 0, "总容量字节上限，0表示不限；当前恢复点即使超限也保留")
	if e := parse(f, args); e != nil {
		return e
	}
	if *prune {
		if cmd != "backup" || *full || *file != "" || *plain || *recoverMigration {
			return errors.New("--prune仅用于受管备份保留，不与备份/恢复输入混用")
		}
		return a.store.InspectExisting(func() error {
			names, e := node.PruneManagedBackups(filepath.Join(a.store.Root, "backups"), node.BackupRetention{Count: *retainCount, MaxAge: *retainAge, Bytes: *retainBytes}, *yes && !*preview)
			if e != nil {
				return e
			}
			fmt.Printf("受管备份清理%s：%d份；当前恢复点与非受管文件不删除\n", map[bool]string{true: "已执行", false: "预览"}[*yes && !*preview], len(names))
			for _, name := range names {
				fmt.Println(name)
			}
			return nil
		})
	}
	if *recoverMigration {
		if cmd != "restore" || !*yes || *file != "" || *plain || *preview {
			return errors.New("恢复中断迁移使用 restore --recover-migration --yes，不与文件或预览混用")
		}
		return a.store.InspectExisting(func() error { return a.store.RecoverMigrationAssets() })
	}
	if cmd == "restore" && ((!*yes && !*preview) || *file == "") {
		return errors.New("恢复需要 --file 和 --yes")
	}
	if *plain && cmd != "restore" {
		return errors.New("--snapshot 仅用于恢复卸载快照")
	}
	if cmd == "backup" && *restoreSubscriptions {
		return errors.New("--restore-subscriptions仅用于恢复")
	}
	if *full && *plain {
		return errors.New("完整迁移包不能作为卸载明文快照")
	}
	if cmd == "backup" && (*full || *preview) {
		return a.backupFull(*file, *pass, *preview, *quiesce, *limited, *full)
	}
	if *plain {
		i, e := os.Lstat(*file)
		if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
			return errors.New("明文快照必须是权限 600 的普通文件")
		}
		a.message("INFO", "恢复明文快照；请为当前配置的自动备份设置口令")
	}
	p, e := password(*pass, cmd == "backup" || *plain)
	if e != nil {
		return e
	}
	if cmd == "restore" {
		b, err := readLimited(*file, node.MaxMigrationBytes)
		if err != nil {
			return err
		}
		if node.IsMigrationBackup(b) {
			return a.restoreFull(b, p, *preview, *quiesce, *limited, *restoreSubscriptions, *subDir, *subGroup, *manual)
		}
		if *full {
			return errors.New("--full恢复要求QNBK3迁移包；QNBK1/2请使用普通恢复")
		}
		if *preview {
			var snap node.Snapshot
			if *plain {
				snap, err = node.RestorePlainSnapshot(b)
			} else {
				snap, err = node.RestoreSnapshot(b, p)
			}
			if err != nil {
				return err
			}
			return a.store.InspectExisting(func() error {
				if err := backupNoPending(a.store.Root); err != nil {
					return err
				}
				fmt.Printf("配置恢复预览：State %d，核心 %s，节点 %d；服务文件按本机渲染。恢复前保存当前完整可导出资产。\n", snap.State.Schema, snap.State.CoreVersion, len(snap.State.Nodes))
				return a.printMigrationInventory(snap.State)
			})
		}
	}
	operation := func(s *node.State) error {
		snap, e := a.snapshot(*s)
		if e != nil {
			return e
		}
		if cmd == "backup" {
			automatic := *file == ""
			if *file == "" {
				*file, e = a.backupPath("backup")
				if e != nil {
					return e
				}
			}
			b, e := node.BackupSnapshot(snap, p)
			if e != nil {
				return e
			}
			if e = writeOutput(*file, b); e != nil {
				return e
			}
			if automatic {
				if e = node.RegisterManagedBackup(filepath.Dir(*file), *file); e != nil {
					return fmt.Errorf("备份已完成，受管索引登记失败：%w", e)
				}
			}
			a.noteBackup(*file)
			fmt.Println("加密备份：" + *file)
			return nil
		}
		b, e := readLimited(*file, 32<<20)
		if e != nil {
			return e
		}
		var restored node.Snapshot
		if *plain {
			restored, e = node.RestorePlainSnapshot(b)
		} else {
			restored, e = node.RestoreSnapshot(b, p)
		}
		if e != nil {
			return e
		}
		if *manual {
			restored.State.Firewall = ""
		}
		before, e := a.backupPath("before-restore")
		if e != nil {
			return e
		}
		old, complete, e := a.preRestoreBackup(*s, snap, p, *quiesce, *limited)
		if e != nil {
			return e
		}
		if e = writeOutput(before, old); e != nil {
			return e
		}
		if e = node.RegisterManagedBackup(filepath.Dir(before), before, complete); e != nil {
			return fmt.Errorf("恢复前备份已创建，登记失败，尚未替换配置：%w", e)
		}
		a.noteBackup(before)
		a.message("INFO", "当前配置已自动加密备份到："+before+"；口令与本次恢复使用的口令相同")
		// Backed-up unit/config are evidence. Only typed State is restored; no executable unit from an archive is run.
		if e = a.store.Apply(restored.State); e != nil {
			return e
		}
		a.message("SUCCESS", "配置恢复完成；服务文件使用当前管理器的受控定义")
		return nil
	}
	if cmd != "backup" {
		return a.locked(operation)
	}
	return a.store.InspectExisting(func() error {
		if e := backupNoPending(a.store.Root); e != nil {
			return e
		}
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		return operation(&s)
	})
}

func backupNoPending(root string) error {
	for _, name := range []string{"transaction.json", "uninstall.json", node.MigrationJournalName} {
		if _, e := os.Lstat(filepath.Join(root, name)); e == nil {
			return errors.New("存在未完成事务，当前配置尚未确认提交，未创建备份；请先用 qingnode doctor 检查，再决定用 qingnode recover 或 restore --recover-migration 恢复")
		} else if !errors.Is(e, os.ErrNotExist) {
			return fmt.Errorf("无法核查未完成事务，未创建备份：%w", e)
		}
	}
	return nil
}

func (a *app) migrationInventory(st node.State) ([]node.MigrationRoot, []string, error) {
	roots := []node.MigrationRoot{}
	external := []string{}
	deploymentGaps, err := node.AuxiliaryServiceMigrationGaps(a.store.Root)
	if err != nil {
		return nil, nil, err
	}
	external = append(external, deploymentGaps...)
	// Independent notification secrets and recovery policy are not part of the
	// v1 QNBK3 typed roots. Never label a package complete while omitting them.
	if _, err := os.Lstat(filepath.Join(a.store.Root, "monitor")); err == nil {
		external = append(external, "监控私有计划与通知授权未打包：在目标机重新审查configure和timer；历史为本机观测，不自动移用恢复策略")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	assets, e := node.CertificateAssetInventory(st, a.store.Root)
	if e != nil {
		return nil, nil, e
	}
	acme := false
	for _, asset := range assets {
		if !asset.Managed {
			external = append(external, asset.ResourceID+":"+asset.Kind+":"+asset.Path)
			continue
		}
		if strings.Contains(asset.Kind, "acme") {
			acme = true
		}
	}
	if acme {
		p := filepath.Join(a.store.Root, "acme")
		if _, e = os.Lstat(p); errors.Is(e, os.ErrNotExist) {
			external = append(external, "ACME存储未生成：尚未包含账户与已签发证书")
		} else if e != nil {
			return nil, nil, e
		} else {
			owner, err := migrationSourceOwner(p)
			if err != nil {
				return nil, nil, err
			}
			roots = append(roots, node.MigrationRoot{ID: "acme", Kind: "acme-storage", Source: p, GroupID: a.store.GID, OwnerID: owner})
		}
	}
	c, ok, e := a.publisherConfig()
	if e != nil {
		return nil, nil, e
	}
	if ok {
		if _, e = subscription.Read(c.Directory); e != nil {
			return nil, nil, fmt.Errorf("订阅发布资产无效，未创建完整迁移包：%w", e)
		}
		owner, err := migrationSourceOwner(c.Directory)
		if err != nil {
			return nil, nil, err
		}
		roots = append(roots, node.MigrationRoot{ID: "subscription", Kind: "subscription-publication", Source: c.Directory, GroupID: c.GroupID, OwnerID: owner}, node.MigrationRoot{ID: "publisher", Kind: "subscription-config", Source: a.store.Root, GroupID: -1, OwnerID: os.Geteuid()})
	}
	return roots, external, nil
}

func (a *app) printMigrationInventory(st node.State) error {
	roots, external, e := a.migrationInventory(st)
	if e != nil {
		return e
	}
	for _, r := range roots {
		fmt.Printf("受管资产 %s：%s（目标机需重新映射属组）\n", r.Kind, r.Source)
	}
	for _, ref := range external {
		fmt.Println("外部或尚缺资产：" + ref)
	}
	active, activityErr := node.BackendActivity(a.store.Backend)
	if activityErr != nil {
		fmt.Println("运行状态：未知；完整资产快照前必须恢复服务状态查询，不能把查询失败当作已停止。")
	} else {
		fmt.Printf("运行状态：%t；完整资产快照需要确认本项目核心停止，短停范围仅本项目代理；运行时需显式--quiesce，不会调用enable/disable。\n", active)
	}
	if isOfflineMigrationBackend(a.store.Backend) {
		fmt.Println("离线后端无法证明ACME运行存储无写入：默认拒绝包含该目录的完整包；--allow-incomplete时仅列缺项，不复制ACME目录。")
	}
	fmt.Println("不收集用户外部原文件、原始订阅链接/令牌材料、可重建缓存、日志或核心程序；下载权限保存的是令牌哈希，已有链接需由用户保管。")
	return nil
}

func (a *app) withStoppedMigration(st node.State, allow bool, fn func() error) (err error) {
	wasActive, activityErr := node.BackendActivity(a.store.Backend)
	if activityErr != nil {
		return fmt.Errorf("无法确认迁移前运行状态，尚未停止服务或复制资产：%w", activityErr)
	}
	if wasActive && !allow {
		return errors.New("完整迁移需要短暂停止本项目代理以保存一致资产；请先--preview，再显式加--quiesce；普通配置备份不会停止服务")
	}
	defer func() {
		if !wasActive {
			return
		}
		active, e := node.BackendActivity(a.store.Backend)
		if e != nil {
			err = errors.Join(err, fmt.Errorf("无法确认迁移后运行状态；未盲目启动或重启，请恢复控制器查询后核查：%w", e))
			return
		}
		if !active {
			if e := backupNoPending(a.store.Root); e != nil {
				err = errors.Join(err, fmt.Errorf("迁移恢复尚未完成，服务保持停止；先核查并显式恢复后再启动：%w", e))
				return
			}
			current, e := a.store.Load()
			if e != nil {
				err = errors.Join(err, e)
				return
			}
			if e = a.store.Backend.Activate(current); e != nil {
				err = errors.Join(err, fmt.Errorf("恢复原运行状态失败：%w", e))
			}
		}
	}()
	if wasActive {
		a.message("INFO", "为一致资产快照短暂停止本项目代理；完成后恢复原运行状态，自启状态不变")
		if err = a.store.Backend.Stop(); err != nil {
			return err
		}
	}
	if err = node.ConfirmMigrationStopped(a.store.Backend); err != nil {
		return err
	}
	return fn()
}

func (a *app) captureFull(st node.State, snap node.Snapshot, allowStop, allowLimited bool) (node.MigrationPackage, error) {
	roots, external, e := a.migrationInventory(st)
	if e != nil {
		return node.MigrationPackage{}, e
	}
	if len(external) > 0 && !allowLimited {
		return node.MigrationPackage{}, errors.New("完整迁移存在外部或缺失资产；请先--preview补齐，或明确--allow-incomplete生成受限包")
	}
	if isOfflineMigrationBackend(a.store.Backend) {
		var kept []node.MigrationRoot
		for _, r := range roots {
			if r.ID == "acme" {
				if !allowLimited {
					return node.MigrationPackage{}, errors.New("离线后端不能证明ACME写入已停止，未复制运行目录；请使用受管服务的停止确认，或明确--allow-incomplete仅保存缺项")
				}
				external = append(external, "离线模式未复制ACME运行存储：无法证明写入已经停止")
			} else {
				kept = append(kept, r)
			}
		}
		roots = kept
	}
	var m node.MigrationPackage
	if len(roots) == 0 {
		m, e = node.CaptureMigration(snap, roots, external, true)
		if e == nil {
			e = a.fillMigrationManifest(&m)
		}
		return m, e
	}
	e = a.withStoppedMigration(st, allowStop, func() error {
		var err error
		m, err = node.CaptureMigration(snap, roots, external, true)
		if err == nil && m.Mode == "limited" && !allowLimited {
			return errors.New("ACME证书/账户等必需资产未生成或不完整；请--preview核查，或明确--allow-incomplete生成受限迁移包")
		}
		return err
	})
	if e == nil {
		e = a.fillMigrationManifest(&m)
	}
	return m, e
}

func isOfflineMigrationBackend(b node.Backend) bool {
	switch b.(type) {
	case node.OfflineBackend, *node.OfflineBackend:
		return true
	}
	return false
}
func (a *app) fillMigrationManifest(m *node.MigrationPackage) error {
	m.Manifest.ManagerRevision = revision
	m.Manifest.ServiceManager = string(platform.DetectServiceManager())
	if m.Manifest.ServiceManager == string(platform.InitUnavailable) {
		m.Manifest.ServiceManager = "unknown"
	}
	if a.offline {
		m.Manifest.ServiceManager = "offline"
	}
	p := node.CorePath(a.store.Root, m.Snapshot.State.CoreVersion)
	info, e := os.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		return m.Validate()
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 160<<20 {
		return errors.New("核心来源摘要只能读取160MiB内的普通文件，不随包归档或执行")
	}
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return errors.New("核心来源文件在读取时变化")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (160<<20)+1))
	if e != nil || n > 160<<20 {
		return errors.New("无法读取核心来源摘要")
	}
	after, e := f.Stat()
	if e != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return errors.New("核心来源在摘要期间变化")
	}
	m.Manifest.CoreBinarySHA256 = hex.EncodeToString(h.Sum(nil))
	return m.Validate()
}

func (a *app) backupFull(file, passFile string, preview, quiesce, limited, full bool) error {
	return a.store.InspectExisting(func() error {
		if full {
			if err := node.PendingAuxiliaryService(a.store.Root); err != nil {
				return err
			}
		}
		if e := backupNoPending(a.store.Root); e != nil {
			return e
		}
		st, e := a.store.Load()
		if e != nil {
			return e
		}
		if preview {
			if full {
				fmt.Println("完整迁移预览：QNBK3，最多1024条/64MiB资产；遇运行资产需显式暂停，所有外部/缺失项必须明示。")
			} else {
				fmt.Println("配置备份预览：QNBK2，仅State与原配置/服务证据，不包含ACME运行存储或独立订阅权限，不停止服务。")
			}
			return a.printMigrationInventory(st)
		}
		p, e := password(passFile, true)
		if e != nil {
			return e
		}
		snap, e := a.snapshot(st)
		if e != nil {
			return e
		}
		m, e := a.captureFull(st, snap, quiesce, limited)
		if e != nil {
			return e
		}
		b, e := node.BackupMigration(m, p)
		if e != nil {
			return e
		}
		automatic := file == ""
		if automatic {
			file, e = a.backupPath("migration")
			if e != nil {
				return e
			}
		}
		if e = writeOutput(file, b); e != nil {
			return e
		}
		if automatic {
			if e = node.RegisterManagedBackup(filepath.Dir(file), file, m.Mode == "complete"); e != nil {
				return fmt.Errorf("备份已写入，受管索引登记失败：%w", e)
			}
		}
		a.noteBackup(file)
		fmt.Println(node.MigrationSummary(m))
		fmt.Println("加密迁移包：" + file)
		return nil
	})
}

func (a *app) preRestoreBackup(st node.State, snap node.Snapshot, p string, quiesce, limited bool) ([]byte, bool, error) {
	roots, external, e := a.migrationInventory(st)
	if e != nil {
		return nil, false, e
	}
	if len(roots) == 0 && len(external) == 0 {
		b, e := node.BackupSnapshot(snap, p)
		return b, false, e
	}
	m, e := a.captureFull(st, snap, quiesce, limited)
	if e != nil {
		return nil, false, e
	}
	b, e := node.BackupMigration(m, p)
	return b, m.Mode == "complete", e
}

func migrationSourceOwner(p string) (int, error) {
	i, e := os.Lstat(p)
	if e != nil {
		return 0, e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("迁移来源目录所有权不可验证")
	}
	return int(st.Uid), nil
}
func (a *app) migrationACMEOwner() (int, error) {
	if a.offline {
		return os.Geteuid(), nil
	}
	u, e := user.Lookup("qingnode")
	if e != nil {
		return 0, errors.New("目标机缺少受管qingnode服务用户，请先完成当前安装器的服务准备")
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil || uid <= 0 {
		return 0, errors.New("受管qingnode服务用户ID无效")
	}
	return uid, nil
}

func (a *app) restoreFull(b []byte, p string, preview, quiesce, limited, restoreSubscriptions bool, subDirectory string, subGroup int, manual bool) error {
	m, e := node.RestoreMigration(b, p)
	if e != nil {
		return e
	}
	if m.Mode == "limited" && !limited && !preview {
		return errors.New("这是受限迁移包，缺失/外部资产未包含；先--preview核查后显式--allow-incomplete")
	}
	if manual {
		m.Snapshot.State.Firewall = ""
	}
	for _, r := range m.Roots {
		if r.ID == "subscription" && !restoreSubscriptions && !preview {
			return errors.New("恢复订阅下载权限需要显式--restore-subscriptions；这可能重新允许备份时有效的令牌")
		}
	}
	operation := func() error {
		if err := node.PendingAuxiliaryService(a.store.Root); err != nil {
			return err
		}
		if e := backupNoPending(a.store.Root); e != nil {
			return e
		}
		old, e := a.store.Load()
		if e != nil {
			return e
		}
		targets := node.MigrationTargets{}
		hasSubscriptions := false
		for _, r := range m.Roots {
			switch r.ID {
			case "acme":
				uid, err := a.migrationACMEOwner()
				if err != nil {
					return err
				}
				targets[r.ID] = node.MigrationTarget{Path: filepath.Join(a.store.Root, "acme"), GroupID: a.store.GID, OwnerID: uid}
			case "publisher":
				targets[r.ID] = node.MigrationTarget{Path: filepath.Join(a.store.Root, publisherConfigName), GroupID: -1, OwnerID: os.Geteuid()}
			case "subscription":
				hasSubscriptions = true
				if subDirectory == "" {
					c, ok, err := a.publisherConfig()
					if err != nil {
						return err
					}
					if ok {
						subDirectory = c.Directory
						subGroup = c.GroupID
					}
				}
				if subDirectory == "" && !preview {
					return errors.New("迁移订阅需要--subscription-directory指定目标机专用目录，不直接采用包中路径")
				}
				if subDirectory != "" {
					targets[r.ID] = node.MigrationTarget{Path: subDirectory, GroupID: subGroup, OwnerID: os.Geteuid()}
				}
			}
		}
		if preview {
			fmt.Println(node.MigrationSummary(m))
			fmt.Printf("来源版本：%s/%s；管理器 %s (%s)；服务管理器 %s；缺失的核心摘要保持未知，恢复不执行包内程序。\n", m.Manifest.OS, m.Manifest.Architecture, m.Manifest.ManagerVersion, m.Manifest.ManagerRevision, m.Manifest.ServiceManager)
			a.printMigrationTargetPreflight(m.Snapshot.State)
			for _, r := range m.Roots {
				t := targets[r.ID]
				fmt.Printf("资产映射 %s：%s → %s；目标组 %d\n", r.ID, r.Source, t.Path, t.GroupID)
			}
			for _, x := range m.External {
				fmt.Println("未包含：" + x)
			}
			fmt.Printf("节点 %d；本机服务管理器按当前管理器定义；核心版本 %s 必须已从可信发行安装并通过摘要核验。\n", len(m.Snapshot.State.Nodes), m.Snapshot.State.CoreVersion)
			if hasSubscriptions {
				fmt.Println("含订阅权限：实际恢复必须--restore-subscriptions；可能重新授权包中当时有效的下载令牌，原始链接不在本包中。")
			}
			fmt.Println("提交前加密保存原资产；运行服务需--quiesce明确短停；跨主机DNS/公网地址切换由用户分端完成。保留包中监听/连接端点，需改地址请先在离线目标预检后使用现有批量编辑。")
			return nil
		}
		if hasSubscriptions && !restoreSubscriptions {
			return errors.New("恢复订阅下载权限需要显式--restore-subscriptions；这可能重新允许备份时有效的令牌")
		}
		if subGroup < -1 {
			return errors.New("目标订阅组ID无效")
		}
		// Re-render the local publisher path and group; archived paths are evidence.
		for i := range m.Files {
			f := &m.Files[i]
			if f.RootID != "publisher" {
				continue
			}
			c, err := decodePublisherConfig(f.Data)
			if err != nil {
				return err
			}
			c.Directory = subDirectory
			c.GroupID = subGroup
			f.Data, err = json.MarshalIndent(c, "", "  ")
			if err != nil {
				return err
			}
			h := sha256.Sum256(f.Data)
			f.SHA256 = hex.EncodeToString(h[:])
		}
		for i := range m.Roots {
			if m.Roots[i].ID == "subscription" {
				m.Roots[i].Source = subDirectory
				m.Roots[i].GroupID = subGroup
				m.Roots[i].OwnerID = os.Geteuid()
			}
		}
		wasActive := a.store.Backend.Active()
		return a.withStoppedMigration(old, quiesce, func() error {
			snap, e := a.snapshot(old)
			if e != nil {
				return e
			}
			oldBackup, complete, e := a.preRestoreBackup(old, snap, p, false, limited)
			if e != nil {
				return e
			}
			before, e := a.backupPath("before-restore")
			if e != nil {
				return e
			}
			if e = writeOutput(before, oldBackup); e != nil {
				return e
			}
			if e = node.RegisterManagedBackup(filepath.Dir(before), before, complete); e != nil {
				return e
			}
			a.noteBackup(before)
			a.message("INFO", "原配置及可导出资产已加密保存："+before)
			beforeHook, afterHook := a.store.BeforeCommit, a.store.AfterCommit
			// Explicit subscription asset restore is a separately authorized registry migration.
			if hasSubscriptions {
				a.store.BeforeCommit = nil
				a.store.AfterCommit = nil
			}
			defer func() { a.store.BeforeCommit = beforeHook; a.store.AfterCommit = afterHook }()
			err := a.store.RestoreMigrationAssets(m, targets, wasActive)
			if !wasActive && a.store.Backend.Active() {
				err = errors.Join(err, a.store.Backend.Stop())
			}
			if err == nil {
				a.message("SUCCESS", "完整迁移已提交；证书资产与用户身份保留，公网DNS/端点切换尚需外部验证")
			}
			return err
		})
	}
	if _, e := os.Lstat(a.store.Root); errors.Is(e, os.ErrNotExist) {
		if preview {
			return a.store.Inspect(operation)
		}
		return a.store.WithLock(operation)
	}
	return a.store.InspectExisting(operation)
}
