package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"qingnode/internal/node"
)

func printExpirationPlan(p node.ExpirationPlan) {
	fmt.Printf("代理凭据到期检查时间=%s\t已到期=%d\t可执行=%d\t被阻止=%d\n", p.EvaluatedAt, p.Due, p.Ready, p.Blocked)
	for _, d := range p.Items {
		scope := "用户凭据"
		if d.DeviceID != "" {
			scope = "设备指定绑定"
		}
		status := map[string]string{"scheduled": "等待到期", "due": "已到期待执行", "disabled": "已执行停用", "blocked": "共享凭据阻止"}[d.Status]
		fmt.Printf("%s\t范围=%s\t节点=%s\t凭据=%s\t设备=%s\t到期=%s\t状态=%s\t已停用=%s\t影响设备=%s\t停节点=%t\n", d.ID, scope, d.NodeID, d.UserID, d.DeviceID, d.ExpiresAt, status, d.DisabledAt, strings.Join(d.AffectedDeviceIDs, ","), d.StopsNode)
		if d.Reason != "" {
			fmt.Println(d.Reason)
		}
	}
	fmt.Println("每条计划只停指定节点的一条代理凭据；多绑定设备保留其它绑定。下载令牌到期独立管理，查询不会停用代理。")
}

func (a *app) expiration(args []string) error {
	return a.expirationAt(args, time.Now())
}

// The evaluation time is injectable for tests and bounded observers. There is
// deliberately no public --now flag that could accidentally expire future users.
func (a *app) expirationAt(args []string, now time.Time) error {
	if len(args) == 0 {
		return errors.New("用法：expiration list|set|remove|apply；set须明确--node NODE_ID --user USER_ID --expires-at UTC时间，可选--device DEVICE_ID；写入需--yes或只读--preview")
	}
	action := args[0]
	f := fs("expiration " + action)
	machine := f.Bool("json", false, "仅list：版本1精确身份到期计划；查询不会停用凭据")
	id := f.String("id", "", "到期计划稳定ID；set省略时新建，remove必须填写")
	nodeID := f.String("node", "", "精确节点稳定ID，不接受显示名称")
	userID := f.String("user", "", "精确凭据稳定ID，不接受名称或默认第一用户")
	deviceID := f.String("device", "", "可选精确设备ID；共享凭据会阻止该设备的到期操作")
	deadline := f.String("expires-at", "", "明确RFC3339 UTC时间，例如2030-01-02T03:04:05Z")
	preview := f.Bool("preview", false, "只读预览计划或全部已到期凭据的候选影响")
	yes := f.Bool("yes", false, "确认保存计划、移除计划或应用全部到期停用")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if flagSet(f, "json") && action != "list" {
		return errors.New("--json仅用于expiration list")
	}
	switch action {
	case "list":
		if err := rejectTopologyFlags(f, "json"); err != nil {
			return err
		}
		return a.inspectState(func(st *node.State) error {
			p, err := node.PlanExpirations(*st, now)
			if err == nil && *machine {
				return queryJSON("qingnode-credential-expiration-plan", p)
			}
			if err == nil {
				printExpirationPlan(p)
			}
			return err
		})
	case "set":
		if err := rejectTopologyFlags(f, "id", "node", "user", "device", "expires-at", "preview", "yes"); err != nil {
			return err
		}
		if !*yes && !*preview {
			return errors.New("保存到期计划需要--yes，或先用--preview查看；只有显式apply或启用到期执行的监控才会停用代理")
		}
		if _, err := node.ParseExpirationTime(*deadline); err != nil {
			return err
		}
		if *id == "" {
			*id = node.Token(8)
		}
		e := node.CredentialExpiration{ID: *id, NodeID: *nodeID, UserID: *userID, DeviceID: *deviceID, ExpiresAt: *deadline}
		if err := a.changeTopology(*preview, func(st *node.State) error {
			if err := node.SetCredentialExpiration(st, e); err != nil {
				return err
			}
			p, err := node.PlanExpirations(*st, now)
			if err == nil {
				printExpirationPlan(p)
			}
			return err
		}); err != nil {
			return err
		}
		fmt.Printf("到期计划ID：%s；仅保存计划不会自行停用服务。\n", *id)
		return nil
	case "remove":
		if err := rejectTopologyFlags(f, "id", "preview", "yes"); err != nil {
			return err
		}
		if !*yes && !*preview {
			return errors.New("移除到期计划需要--yes；不会恢复已删除凭据、绑定或已停用节点")
		}
		if err := a.changeTopology(*preview, func(st *node.State) error { return node.RemoveCredentialExpiration(st, *id) }); err != nil {
			return err
		}
		fmt.Println("已处理计划移除请求；不会恢复已删除凭据、设备绑定或节点监听。")
		return nil
	case "apply":
		if err := rejectTopologyFlags(f, "preview", "yes"); err != nil {
			return err
		}
		if !*yes && !*preview {
			return errors.New("停用全部已到期代理凭据需要--yes；请先用--preview查看共享凭据及连接影响")
		}
		change := func(st *node.State) error {
			candidate, p, err := node.ApplyDueExpirations(*st, now)
			printExpirationPlan(p)
			if err != nil {
				return err
			}
			*st = candidate
			return nil
		}
		if *preview {
			return a.changeTopology(true, change)
		}
		return a.locked(func(st *node.State) error {
			candidate, p, err := node.ApplyDueExpirations(*st, now)
			printExpirationPlan(p)
			if err != nil {
				return err
			}
			if p.Ready == 0 {
				fmt.Println("没有可执行的到期计划；未提交配置。")
				return nil
			}
			impact, err := a.store.Preview(candidate)
			if err != nil {
				return err
			}
			printChangeImpact(topologySafeImpact(impact, *st, candidate))
			if err = a.store.Apply(candidate); err != nil {
				return fmt.Errorf("到期停用应用失败，请检查代理事务状态；下载权限可能已按提交前保护撤销，不能据此认定代理已停：%w", err)
			}
			if a.offline {
				fmt.Fprintln(os.Stderr, "已保存离线到期停用结果；未启动服务，尚未验证真实连接。")
			} else {
				fmt.Fprintln(os.Stderr, "到期停用配置已应用；共享核心运行配置变化会重启核心并断开其已有连接。最后凭据会保留在停用节点，重新启用前须显式处理该计划。")
			}
			return nil
		})
	default:
		return errors.New("未知expiration操作；支持list/set/remove/apply")
	}
}
