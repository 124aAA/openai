package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"qingnode/internal/node"
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
		b, e := os.ReadFile("/etc/systemd/system/qingnode.service")
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
	if e := parse(f, args); e != nil {
		return e
	}
	if cmd == "restore" && (!*yes || *file == "") {
		return errors.New("恢复需要 --file 和 --yes")
	}
	if *plain && cmd != "restore" {
		return errors.New("--snapshot 仅用于恢复卸载快照")
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
	return a.locked(func(s *node.State) error {
		snap, e := a.snapshot(*s)
		if e != nil {
			return e
		}
		if cmd == "backup" {
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
		old, e := node.BackupSnapshot(snap, p)
		if e != nil {
			return e
		}
		if e = writeOutput(before, old); e != nil {
			return e
		}
		a.noteBackup(before)
		a.message("INFO", "当前配置已自动加密备份到："+before+"；口令与本次恢复使用的口令相同")
		// Backed-up unit/config are evidence. Only typed State is restored; no executable unit from an archive is run.
		if e = a.store.Apply(restored.State); e != nil {
			return e
		}
		a.message("SUCCESS", "配置恢复完成；服务文件使用当前管理器的受控定义")
		return nil
	})
}
