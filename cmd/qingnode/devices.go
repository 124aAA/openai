package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"qingnode/internal/node"
)

type deviceBatch struct {
	Version  int                  `json:"version"`
	Profiles []node.DeviceProfile `json:"profiles"`
}

func decodeDeviceBatch(raw []byte) (deviceBatch, error) {
	var b deviceBatch
	if len(raw) > maxBatchBytes {
		return b, errors.New("设备输入超过1MiB")
	}
	if err := checkTopologyJSON(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return b, fmt.Errorf("设备输入无效：%w", err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return b, errors.New("设备输入含未知字段或格式错误")
	}
	if d.Decode(new(any)) != io.EOF || b.Version != 1 || len(b.Profiles) < 1 || len(b.Profiles) > 128 {
		return b, errors.New("设备请求须为version:1，profiles含1–128项，且无额外JSON")
	}
	return b, nil
}

func applyDevices(st *node.State, profiles []node.DeviceProfile) error {
	c := st.Clone()
	seen := map[string]bool{}
	for _, p := range profiles {
		if seen[p.ID] {
			return errors.New("同一批不能重复修改设备ID")
		}
		seen[p.ID] = true
		found := false
		for i := range c.Devices {
			if c.Devices[i].ID == p.ID {
				c.Devices[i] = p
				found = true
				break
			}
		}
		if !found {
			c.Devices = append(c.Devices, p)
		}
	}
	if err := c.Validate(); err != nil {
		return err
	}
	*st = c
	return nil
}

func (a *app) device(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：device list|show|create|apply|remove|disable|tags；批量输入用apply --file私有JSON [--preview]")
	}
	cmd := args[0]
	f := fs("device " + cmd)
	machine := f.Bool("json", false, "仅list/show：版本1设备公开绑定与策略，不含凭据或订阅令牌")
	id := f.String("id", "", "设备稳定ID或名称；tags操作为节点ID")
	name := f.String("name", "", "设备名称")
	file := f.String("file", "", "version:1的私有设备批量文件")
	preview := f.Bool("preview", false, "只读检查整体候选及影响")
	yes := f.Bool("yes", false, "确认移除或停用设备")
	disableCredentials := f.Bool("disable-credentials", false, "停用该设备实际绑定的独立凭据；共享凭据会拒绝整批")
	strategy := f.String("strategy", "manual", "manual/auto/fallback；sing-box不支持有序fallback")
	allowDegradedAuto := f.Bool("allow-degraded-auto", false, "仅auto：明确接受Mihomo 1.19.30首成员容差缺陷；默认拒绝该客户端完整auto配置")
	routing := f.String("routing", "global", "global或basic（仅明确的局域网网段直连）")
	testURL := f.String("test-url", "", "auto/fallback使用自己的HTTPS健康目标，不验证UDP")
	interval := f.Int("interval", 300, "自动测试间隔秒，60–3600")
	tolerance := f.Int("tolerance", 50, "自动选择容差毫秒")
	timeout := f.Int("timeout", 0, "Mihomo测试超时毫秒；0采用5000，sing-box不支持此独立设置")
	tags := f.String("tags", "", "逗号分隔标签；空值清除；设备仅过滤明确绑定")
	subscriptionFormats := f.String("subscription-formats", "", "本设备发布格式子集，逗号分隔；省略继承发布配置")
	var bindings []string
	f.Func("binding", "可重复NODE_ID:USER_ID[:ENDPOINT_ID]，必须明确凭据", func(v string) error { bindings = append(bindings, v); return nil })
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if flagSet(f, "json") && cmd != "list" && cmd != "show" {
		return errors.New("--json仅用于device list/show")
	}
	switch cmd {
	case "list", "show":
		if err := rejectTopologyFlags(f, "id", "json"); err != nil {
			return err
		}
		return a.inspectState(func(st *node.State) error {
			if err := st.Validate(); err != nil {
				return err
			}
			if *machine {
				profiles := st.Devices
				if cmd == "show" || *id != "" {
					p, err := node.FindDevice(st, *id)
					if err != nil {
						return err
					}
					profiles = []node.DeviceProfile{*p}
				}
				rows := []publicDevice{}
				for _, p := range profiles {
					rows = append(rows, publicDevice{p.ID, publicQueryText(p.Name, *st), p.Strategy, p.Routing, append([]node.DeviceBinding{}, p.Bindings...), p.Disabled})
				}
				return queryJSON("qingnode-device-bindings", rows)
			}
			if cmd == "show" {
				p, e := node.FindDevice(st, *id)
				if e != nil {
					return e
				}
				b, e := json.MarshalIndent(p, "", "  ")
				if e != nil {
					return e
				}
				return writeOutput("", b)
			}
			for _, p := range st.Devices {
				fmt.Printf("%s\t%s\t策略=%s\t绑定=%d\t停用=%t\n", p.ID, p.Name, p.Strategy, len(p.Bindings), p.Disabled)
			}
			return nil
		})
	case "create":
		if err := rejectTopologyFlags(f, "name", "binding", "strategy", "allow-degraded-auto", "routing", "test-url", "interval", "tolerance", "timeout", "tags", "preview", "subscription-formats"); err != nil {
			return err
		}
		p := node.DeviceProfile{ID: node.Token(8), Name: *name, Strategy: *strategy, AllowDegradedAuto: *allowDegradedAuto, Routing: *routing, TestURL: *testURL, IntervalSeconds: *interval, ToleranceMS: *tolerance, TimeoutMS: *timeout}
		if *subscriptionFormats != "" {
			p.SubscriptionFormats = strings.Split(*subscriptionFormats, ",")
		}
		if p.Strategy == "manual" {
			if !flagSet(f, "interval") {
				p.IntervalSeconds = 0
			}
			if !flagSet(f, "tolerance") {
				p.ToleranceMS = 0
			}
		}
		if p.Strategy == "fallback" && !flagSet(f, "tolerance") {
			p.ToleranceMS = 0
		}
		if *tags != "" {
			p.NodeTags = strings.Split(*tags, ",")
		}
		for _, raw := range bindings {
			parts := strings.Split(raw, ":")
			if len(parts) < 2 || len(parts) > 3 {
				return errors.New("binding须为NODE_ID:USER_ID[:ENDPOINT_ID]")
			}
			b := node.DeviceBinding{NodeID: parts[0], UserID: parts[1], EndpointID: "default"}
			if len(parts) == 3 {
				b.EndpointID = parts[2]
			}
			p.Bindings = append(p.Bindings, b)
		}
		if err := a.changeTopology(*preview, func(st *node.State) error { return applyDevices(st, []node.DeviceProfile{p}) }); err != nil {
			return err
		}
		fmt.Printf("设备ID：%s\n", p.ID)
		return nil
	case "apply":
		if err := rejectTopologyFlags(f, "file", "preview"); err != nil {
			return err
		}
		raw, e := readTopologyFile(*file)
		if e != nil {
			return e
		}
		b, e := decodeDeviceBatch(raw)
		if e != nil {
			return e
		}
		return a.changeTopology(*preview, func(st *node.State) error { return applyDevices(st, b.Profiles) })
	case "tags":
		if err := rejectTopologyFlags(f, "id", "tags", "preview"); err != nil {
			return err
		}
		if !flagSet(f, "tags") {
			return errors.New("请明确提供--tags，空值表示清除")
		}
		list := []string{}
		if *tags != "" {
			list = strings.Split(*tags, ",")
		}
		return a.changeTopology(*preview, func(st *node.State) error {
			n, e := st.Find(*id)
			if e != nil {
				return e
			}
			if e = node.ValidateNodeTags(list); e != nil {
				return e
			}
			n.Tags = list
			return nil
		})
	case "remove":
		if err := rejectTopologyFlags(f, "id", "yes", "preview"); err != nil {
			return err
		}
		if !*yes && !*preview {
			return errors.New("移除设备需要--yes；已下载凭据不会因此失效")
		}
		return a.changeTopology(*preview, func(st *node.State) error {
			p, e := node.FindDevice(st, *id)
			if e != nil {
				return e
			}
			for i := range st.Devices {
				if st.Devices[i].ID == p.ID {
					st.Devices = append(st.Devices[:i], st.Devices[i+1:]...)
					return nil
				}
			}
			return nil
		})
	case "disable":
		if err := rejectTopologyFlags(f, "id", "yes", "disable-credentials", "preview"); err != nil {
			return err
		}
		if !*yes && !*preview {
			return errors.New("停用设备需要--yes；--disable-credentials另行停用代理认证")
		}
		change := func(st *node.State) error {
			if *disableCredentials {
				return node.DisableDeviceCredentials(st, *id)
			}
			p, e := node.FindDevice(st, *id)
			if e != nil {
				return e
			}
			p.Disabled = true
			return nil
		}
		if *preview {
			return a.changeTopology(true, change)
		}
		return a.locked(func(st *node.State) error {
			candidate := st.Clone()
			if e := change(&candidate); e != nil {
				return e
			}
			if e := candidate.Validate(); e != nil {
				return e
			}
			p, e := node.FindDevice(st, *id)
			if e != nil {
				return e
			}
			// Revoke first. If proxy Apply fails, download authorization remains
			// revoked and is never revived by transaction/State rollback.
			if e = a.revokePublishedDevice(p.ID); e != nil {
				return e
			}
			if e = a.store.Apply(candidate); e != nil {
				return fmt.Errorf("下载权限已撤销；代理配置应用结果请检查：%w", e)
			}
			fmt.Fprintln(os.Stderr, "设备已停用；若绑定最后一条凭据，其节点监听已停用且凭据保留，显式重新启用节点会恢复认证。")
			return nil
		})
	default:
		return errors.New("未知device操作；支持list/show/create/apply/remove/disable/tags")
	}
}

func (a *app) exportDevice(deviceID, profileFile, format, clientVersion, out string, allowLossy bool) error {
	if out == "" {
		return errors.New("批量设备导出包含私密凭据，请用--out保存新私有文件")
	}
	if (deviceID == "") == (profileFile == "") {
		return errors.New("--device与--profile-file必须且只能提供一个")
	}
	var st node.State
	var p node.DeviceProfile
	if err := a.inspectState(func(s *node.State) error {
		if e := s.Validate(); e != nil {
			return e
		}
		st = s.Clone()
		if deviceID != "" {
			v, e := node.FindDevice(&st, deviceID)
			if e != nil {
				return e
			}
			p = *v
		}
		return nil
	}); err != nil {
		return err
	}
	if profileFile != "" {
		raw, e := readTopologyFile(profileFile)
		if e != nil {
			return e
		}
		b, e := decodeDeviceBatch(raw)
		if e != nil {
			return e
		}
		if len(b.Profiles) != 1 {
			return errors.New("临时批量导出仅接受一份设备Profile")
		}
		p = b.Profiles[0]
	}
	result, e := node.ExportDeviceProfile(st, p, format, clientVersion, allowLossy)
	if e != nil {
		return e
	}
	for _, warning := range result.Warnings {
		fmt.Fprintln(os.Stderr, "[WARN]", warning)
	}
	if e = a.probeOutput(out); e != nil {
		return e
	}
	pinned, e := pinNewOutput(out)
	if e != nil {
		return e
	}
	defer pinned.root.Close()
	return pinned.write(result.Content)
}
