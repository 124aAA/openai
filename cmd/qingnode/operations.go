package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"qingnode/internal/node"
	"strings"
	"syscall"
	"time"
)

func (a *app) operation(cmd string, args []string) error {
	f := fs(cmd)
	if e := parse(f, args); e != nil {
		return e
	}
	if cmd == "status" || cmd == "doctor" || cmd == "logs" {
		return a.store.Inspect(func() error {
			s, err := a.store.Load()
			if err != nil {
				a.message("ERROR", "读取状态失败："+node.Redact(err.Error()))
				s = node.NewState()
			}
			switch cmd {
			case "status":
				if e := a.status(s); e != nil {
					return e
				}
				return err
			case "doctor":
				return a.doctor(s, err)
			default:
				if a.offline {
					return errors.New("离线模式没有 systemd 日志")
				}
				a.recentLogs(s)
				return err
			}
		})
	}
	return a.locked(func(s *node.State) error {
		if cmd == "rollback" {
			return a.store.Rollback()
		}
		if cmd == "check" {
			b := node.SystemBackend{Root: a.store.Root}
			if e := b.Check(*s, filepath.Join(a.store.Root, "current", "server.json")); e != nil {
				return e
			}
			fmt.Println("官方核心配置检查通过；未测试公网连接。")
			return nil
		}
		if a.offline {
			return errors.New("离线模式不操作服务")
		}
		if cmd == "stop" {
			return a.store.Backend.Stop()
		}
		if e := a.store.Backend.Check(*s, filepath.Join(a.store.Root, "current", "server.json")); e != nil {
			return e
		}
		enabled := false
		for _, n := range s.Nodes {
			enabled = enabled || n.Enabled
		}
		if !enabled {
			return errors.New("没有启用的节点")
		}
		if fx, ok := a.store.Backend.(node.Effects); ok {
			if e := fx.PrepareEffects(node.NewState(), *s); e != nil {
				return e
			}
		}
		err := a.store.Backend.Activate(*s)
		if err != nil {
			a.recentLogs(*s)
		}
		return err
	})
}
func serve(root string) error {
	// Read metadata accessible to the service group; the root-only state file stays private.
	g, e := os.Readlink(filepath.Join(root, "current"))
	if e != nil {
		return e
	}
	if !strings.HasPrefix(g, "generations/g-") || filepath.Clean(g) != g || strings.Contains(g, "..") {
		return errors.New("配置指针无效")
	}
	dir := filepath.Join(root, g)
	b, e := os.ReadFile(filepath.Join(dir, "core-version"))
	if e != nil {
		return e
	}
	v := string(b)
	if e = node.VerifyCore(root, v); e != nil {
		return e
	}
	p := node.CorePath(root, v)
	return syscall.Exec(p, []string{p, "run", "-c", filepath.Join(dir, "server.json")}, os.Environ())
}
func (a *app) uninstall(args []string) error {
	f := fs("uninstall")
	purge := f.Bool("purge", false, "删除 QingNode 自身的所有节点、核心、证书与历史配置")
	yes := f.Bool("yes", false, "确认卸载")
	if e := parse(f, args); e != nil {
		return e
	}
	if !*yes {
		return errors.New("卸载需要 --yes；建议先备份")
	}
	if a.offline {
		return errors.New("离线目录请自行归档/删除，不运行系统卸载")
	}
	return a.store.WithLock(func() error {
		st, e := a.store.Load()
		if e != nil {
			return e
		}
		snap, e := a.snapshot(st)
		if e != nil {
			return e
		}
		data, e := json.MarshalIndent(snap, "", "  ")
		if e != nil {
			return e
		}
		backupDir := "/var/backups/qingnode"
		if i, e := os.Lstat(backupDir); e == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
			return errors.New("备份目录无效")
		}
		if e = os.MkdirAll(backupDir, 0700); e != nil {
			return e
		}
		path := filepath.Join(backupDir, "before-uninstall-"+time.Now().UTC().Format("20060102-150405")+"-"+node.Token(4)+".json")
		if e = writeOutput(path, data); e != nil {
			return e
		}
		a.message("INFO", "已保存卸载前快照："+path+"（权限 600，含凭据，请妥善保管）")
		a.message("INFO", "重装后可用 qingnode restore --snapshot --file "+path+" --yes 恢复")
		r := node.Removal{Root: a.store.Root, Unit: "/etc/systemd/system/qingnode.service", Binary: "/usr/local/bin/qingnode", Library: "/usr/local/lib/qingnode"}
		if *purge {
			if e = r.RecordAccount(filepath.Join(backupDir, ".qingnode-account")); e != nil {
				return e
			}
		}
		if e = r.Remove(*purge); e != nil {
			return e
		}
		if *purge {
			if e = os.RemoveAll(a.store.Root); e != nil {
				return e
			}
			fmt.Println("已完全卸载 QingNode；卸载前快照保留于 /var/backups/qingnode。")
		} else {
			fmt.Println("sing-box 核心已移除，配置与管理器保留；core install 后可重新启动。")
		}
		return nil
	})
}
