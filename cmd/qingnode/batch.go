package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"qingnode/internal/node"
)

const maxBatchBytes = 1 << 20
const maxBatchEdits = 256

// The request has its own version; it does not change the persisted State schema.
type editBatch struct {
	Version int        `json:"version"`
	Edits   []nodeEdit `json:"edits"`
}

// Fields are optional: omitted values always keep the saved selection and identity.
// Certificates are explicit local file paths, matching the existing edit flags.
type nodeEdit struct {
	ID                  string                     `json:"id"`
	Name                *string                    `json:"name,omitempty"`
	Server              *string                    `json:"server,omitempty"`
	Listen              *string                    `json:"listen,omitempty"`
	Port                *int                       `json:"port,omitempty"`
	ConnectPort         *int                       `json:"connect_port,omitempty"`
	AdditionalEndpoints *[]node.ConnectionEndpoint `json:"additional_endpoints,omitempty"`
	Fingerprint         *string                    `json:"fingerprint,omitempty"`
	SNI                 *string                    `json:"sni,omitempty"`
	Target              *string                    `json:"target,omitempty"`
	Cert                *string                    `json:"cert,omitempty"`
	Key                 *string                    `json:"key,omitempty"`
	ACMEEmail           *string                    `json:"acme_email,omitempty"`
	Enabled             *bool                      `json:"enabled,omitempty"`
	EgressID            *string                    `json:"egress_id,omitempty"`
	Tags                *[]string                  `json:"tags,omitempty"`
	Method              *string                    `json:"method,omitempty"`
}

func (e nodeEdit) empty() bool {
	return e.Name == nil && e.Server == nil && e.Listen == nil && e.Port == nil && e.ConnectPort == nil && e.AdditionalEndpoints == nil &&
		e.Fingerprint == nil && e.SNI == nil && e.Target == nil && e.Cert == nil &&
		e.Key == nil && e.ACMEEmail == nil && e.Enabled == nil && e.EgressID == nil && e.Tags == nil && e.Method == nil
}

func editString(s string) *string {
	if s == "" {
		return nil // Preserve the established CLI edit meaning of an empty string.
	}
	return &s
}

func editValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func decodeEditBatch(data []byte) (editBatch, error) {
	var batch editBatch
	if len(data) > maxBatchBytes {
		return batch, errors.New("批量文件超过 1 MiB 上限")
	}
	// encoding/json otherwise silently takes the last duplicate key or ignores null.
	// Reject ambiguous input before decoding optional fields.
	if err := checkBatchJSON(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return batch, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&batch); err != nil {
		return batch, fmt.Errorf("批量文件格式无效：%w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return batch, errors.New("批量文件含多余数据")
	}
	if batch.Version != 1 {
		return batch, fmt.Errorf("不支持批量请求版本 %d；当前仅接受 version: 1", batch.Version)
	}
	if len(batch.Edits) < 1 || len(batch.Edits) > maxBatchEdits {
		return batch, errors.New("批量 edits 须含 1–256 项修改")
	}
	for i, e := range batch.Edits {
		if e.ID == "" || e.empty() {
			return batch, fmt.Errorf("第 %d 项需要 id 和至少一个修改字段", i+1)
		}
		for _, v := range []*string{e.Name, e.Server, e.Listen, e.Fingerprint, e.SNI, e.Target, e.Cert, e.Key, e.ACMEEmail, e.EgressID, e.Method} {
			if v != nil && *v == "" {
				return batch, fmt.Errorf("第 %d 项不能用空字符串修改字段；保留旧值请省略字段", i+1)
			}
		}
	}
	return batch, nil
}

func checkBatchJSON(d *json.Decoder) error {
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return fmt.Errorf("批量文件格式无效：%w", err)
		}
		if t == nil {
			return errors.New("批量文件不接受 null；保留旧值请省略字段")
		}
		switch t {
		case json.Delim('{'):
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || key != strings.ToLower(key) || keys[key] {
					return errors.New("批量文件含重复或无效 JSON 字段")
				}
				for _, r := range key {
					if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
						return errors.New("批量字段只接受ASCII小写名称")
					}
				}
				keys[key] = true
				if err := value(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("批量文件含多余数据")
	}
	return nil
}

// Resolve every target against the original State, then validate the final State.
// This allows atomic name/port swaps without order-dependent target selection.
func applyNodeEdits(s *node.State, edits []nodeEdit) ([]string, error) {
	original := s.Clone()
	ids := make([]string, len(edits))
	seen := map[string]bool{}
	for i, e := range edits {
		n, err := original.Find(e.ID)
		if err != nil {
			return nil, fmt.Errorf("第 %d 项：%w", i+1, err)
		}
		if seen[n.ID] {
			return nil, fmt.Errorf("第 %d 项重复修改节点 %s；每个节点请合并为一项", i+1, n.ID)
		}
		seen[n.ID] = true
		ids[i] = n.ID
	}
	candidate := original.Clone()
	var realityChecks []string
	for i, e := range edits {
		n, _ := candidate.Find(ids[i])
		if err := e.apply(n); err != nil {
			return nil, fmt.Errorf("第 %d 项（节点 %s）：%w", i+1, n.ID, err)
		}
		if n.Reality != nil && (e.SNI != nil || e.Target != nil) {
			realityChecks = append(realityChecks, n.ID)
		}
	}
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	*s = candidate
	return realityChecks, nil
}

func (e nodeEdit) apply(n *node.Node) error {
	if e.Tags != nil {
		if err := node.ValidateNodeTags(*e.Tags); err != nil {
			return err
		}
		n.Tags = append([]string{}, (*e.Tags)...)
	}
	if e.Name != nil {
		n.Name = *e.Name
	}
	if e.Server != nil {
		h, err := node.NormalizeEndpointHost(*e.Server)
		if err != nil {
			return err
		}
		n.Host = h
	}
	if e.Listen != nil {
		n.Listen = *e.Listen
	}
	if e.Port != nil {
		// Freeze a default port before changing the local listener, including
		// in-memory callers which have not persisted an explicit ConnectPort.
		if n.ConnectPort == nil {
			old := n.Port
			n.ConnectPort = &old
		}
		n.Port = *e.Port
	}
	if e.ConnectPort != nil {
		v := *e.ConnectPort
		n.ConnectPort = &v
	}
	if e.AdditionalEndpoints != nil {
		n.AdditionalEndpoints = append([]node.ConnectionEndpoint{}, (*e.AdditionalEndpoints)...)
		for i := range n.AdditionalEndpoints {
			h, err := node.NormalizeEndpointHost(n.AdditionalEndpoints[i].Host)
			if err != nil {
				return err
			}
			n.AdditionalEndpoints[i].Host = h
		}
	}
	if e.Enabled != nil {
		n.Enabled = *e.Enabled
	}
	if e.EgressID != nil {
		n.EgressID = directEgress(*e.EgressID)
	}
	if n.Protocol != "reality" && e.Fingerprint != nil {
		return errors.New("fingerprint 仅用于 REALITY")
	}
	if e.Method != nil {
		if n.Protocol != "ss-aead" {
			return errors.New("方法仅能编辑传统ss-aead；不改变SS2022方法和密钥")
		}
		settings, err := node.NewShadowsocksAEAD(*e.Method)
		if err != nil {
			return err
		}
		n.Shadowsocks = settings
	}
	switch n.Protocol {
	case "reality":
		if e.Cert != nil || e.Key != nil || e.ACMEEmail != nil {
			return errors.New("REALITY 不使用证书参数")
		}
		if e.SNI != nil {
			oldSNI := n.Reality.ServerName
			n.Reality.ServerName = *e.SNI
			if e.Target == nil && n.Reality.Target == net.JoinHostPort(oldSNI, "443") {
				n.Reality.Target = net.JoinHostPort(*e.SNI, "443")
			}
		}
		if e.Target != nil {
			n.Reality.Target = *e.Target
		}
		if e.Fingerprint != nil {
			n.Reality.Fingerprint = *e.Fingerprint
		}
		if e.SNI != nil || e.Target != nil {
			return node.RealityTargetPolicy(n.Reality)
		}
	case "hysteria2", "anytls", "trojan", "tuic":
		if e.Target != nil {
			return errors.New("Hysteria2 不使用 REALITY 目标")
		}
		if e.SNI != nil {
			n.Certificate.ServerName = *e.SNI
		}
		if e.Cert != nil || e.Key != nil || e.ACMEEmail != nil {
			c, err := loadCert(n.Certificate.ServerName, editValue(e.Cert), editValue(e.Key), editValue(e.ACMEEmail))
			if err != nil {
				return err
			}
			n.Certificate = c
		}
	case "ss2022", "ss-aead":
		if e.SNI != nil || e.Target != nil || e.Cert != nil || e.Key != nil || e.ACMEEmail != nil {
			return errors.New("SS2022 不接受 TLS/REALITY 参数")
		}
	}
	return nil
}

func (a *app) checkEditedReality(s node.State, ids []string) error {
	if a.offline {
		return nil
	}
	for _, id := range ids {
		n, _ := s.Find(id)
		if err := node.CheckReality(n.Reality); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) previewEdits(edits []nodeEdit, asJSON ...bool) error {
	return a.store.InspectExisting(func() error {
		// A preview is never permission to repair an unfinished operation.
		for _, name := range []string{"transaction.json", "uninstall.json"} {
			if _, err := os.Lstat(filepath.Join(a.store.Root, name)); err == nil {
				return errors.New("存在未完成事务；预览不会恢复，请先核查 doctor 并显式执行 recover")
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("不能确认事务状态：%w", err)
			}
		}
		s, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = s.Validate(); err != nil {
			return err
		}
		before := s.Clone()
		if _, err = applyNodeEdits(&s, edits); err != nil {
			return err
		}
		impact, err := a.store.Preview(s)
		if err != nil {
			return err
		}
		if len(asJSON) > 0 && asJSON[0] {
			return json.NewEncoder(os.Stdout).Encode(struct {
				Version  int               `json:"version"`
				Impact   node.ChangeImpact `json:"impact"`
				ReadOnly bool              `json:"read_only"`
			}{1, topologySafeImpact(impact, before, s), true})
		}
		printChangeImpact(impact)
		fmt.Println("这是只读预览：未保存、未恢复事务、未启停服务；应用时会重新校验，在线目标与核心检查尚未执行。")
		return nil
	})
}

func printChangeImpact(impact node.ChangeImpact) {
	yesNo := func(v bool) string {
		if v {
			return "有"
		}
		return "无"
	}
	for _, d := range impact.Devices {
		fmt.Printf("  设备 %s（%s）：展示 %s；客户端导出 %s；所选入口节点 %s。\n", d.Name, d.ID, yesNo(d.Display), yesNo(d.ClientExport), strings.Join(d.NodeIDs, ","))
	}
	fmt.Printf("变更影响：展示 %s；客户端导出 %s；服务端运行配置 %s；宿主网络/服务效果 %s；派生文件修复 %s。\n",
		yesNo(impact.Display), yesNo(impact.ClientExport), yesNo(impact.ServerRuntime), yesNo(impact.HostEffects), yesNo(impact.RepairDerived))
	if impact.NeedsRestart {
		fmt.Println("服务端运行输入变化，应用将按启用节点启动/重启或停止服务；可能断流。")
	} else {
		fmt.Println("无需重新启动服务；保持原运行/停止及开机自启状态。")
	}
	for _, n := range impact.Nodes {
		if !n.Changed && !n.ServerRuntime && !n.HostEffects && !n.ClientExport && !n.Display {
			continue
		}
		var effects []string
		for _, x := range []struct {
			changed bool
			label   string
		}{{n.Display, "展示"}, {n.ClientExport, "客户端导出"}, {n.ServerRuntime, "服务端配置"}, {n.HostEffects, "宿主效果"}} {
			if x.changed {
				effects = append(effects, x.label)
			}
		}
		fmt.Printf("  节点 %s（%s）：%s\n", n.Name, n.ID, strings.Join(effects, "、"))
	}
	for _, v := range impact.Forwards {
		if !v.Changed && !v.ServerRuntime && !v.HostEffects && !v.Display {
			continue
		}
		var effects []string
		for _, x := range []struct {
			changed bool
			label   string
		}{{v.Display, "展示"}, {v.ServerRuntime, "服务端配置"}, {v.HostEffects, "宿主效果"}} {
			if x.changed {
				effects = append(effects, x.label)
			}
		}
		fmt.Printf("  中转 %s（%s）：%s\n", v.Name, v.ID, strings.Join(effects, "、"))
	}
	if !impact.Changed && !impact.RepairDerived {
		fmt.Println("配置与派生文件一致，无需创建新历史代。")
	}
}

func (a *app) batch(args []string) error {
	f := fs("batch")
	file := f.String("file", "", "version:1 的批量编辑 JSON 文件；最多 256 项/1 MiB")
	preview := f.Bool("preview", false, "只读显示影响，不保存、不恢复事务、不启停服务")
	asJSON := f.Bool("json", false, "仅--preview：输出版本1变更影响JSON")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "用法：qingnode batch --file edits.json [--preview]")
		f.PrintDefaults()
		fmt.Fprintln(f.Output(), `JSON 示例：{"version":1,"edits":[{"id":"节点ID或旧名称","name":"新名称"}]}`)
		fmt.Fprintln(f.Output(), "修改字段：name / server / listen / port（本地）/ connect_port（客户端）/ additional_endpoints / fingerprint / sni / target / cert / key / acme_email / enabled / egress_id（direct明确直连）。")
		fmt.Fprintln(f.Output(), "每项需要 id 和至少一个修改字段；省略字段保留旧值，cert/key 为本地 PEM 文件路径。")
		fmt.Fprintln(f.Output(), "所有目标按修改前的状态定位；无效项、未知字段、重复节点、null 和空字符串整批拒绝。")
		fmt.Fprintln(f.Output(), "批量编辑保留现有身份与凭据；随机端口和凭据轮换请用已有专用命令。")
	}
	if err := parse(f, args); err != nil {
		return err
	}
	if *asJSON && !*preview {
		return errors.New("batch --json仅与--preview一起使用；未执行任何修改")
	}
	if *file == "" {
		return errors.New("缺少 --file；格式示例：{\"version\":1,\"edits\":[{\"id\":\"节点ID\",\"name\":\"新名称\"}]}")
	}
	data, err := readLimited(*file, maxBatchBytes)
	if err != nil {
		return err
	}
	b, err := decodeEditBatch(data)
	if err != nil {
		return err
	}
	if *preview {
		return a.previewEdits(b.Edits, *asJSON)
	}
	return a.mutate(func(s *node.State) error {
		ids, err := applyNodeEdits(s, b.Edits)
		if err != nil {
			return err
		}
		if err = a.checkEditedReality(*s, ids); err != nil {
			return err
		}
		impact, err := a.store.Preview(*s)
		if err != nil {
			return err
		}
		printChangeImpact(impact)
		return nil
	})
}
