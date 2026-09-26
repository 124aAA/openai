package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"qingnode/internal/node"
)

type checkRecord struct {
	At               time.Time
	Fingerprint      string
	Errors, Warnings int
	Offline          bool
}
type publicRecord struct {
	At                            time.Time
	Fingerprint, TCP, UDP, Source string
}
type backupRecord struct {
	At   time.Time
	Path string
	Size int64
}
type updateRecord struct {
	CheckedAt, At                 time.Time
	Installed, Latest, Compatible string
	Failed                        bool
}
type dashboardHistory struct {
	Schema     int
	Diagnostic *checkRecord
	Backup     *backupRecord
	Public     map[string]publicRecord
	Updates    map[string]updateRecord
}

func stateFingerprint(s node.State) string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func publicFingerprint(s node.State, n node.Node) string {
	s.Nodes = []node.Node{n}
	return stateFingerprint(s)
}

func readDashboardHistory(root string) (dashboardHistory, error) {
	h := dashboardHistory{Schema: 1}
	p := filepath.Join(root, "observations.json")
	i, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return h, nil
	}
	if e != nil {
		return h, e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > 128<<10 {
		return h, errors.New("观测记录须为私有普通文件且不超过128KiB")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return h, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	h = dashboardHistory{}
	if e = d.Decode(&h); e != nil {
		return dashboardHistory{}, errors.New("观测记录格式损坏")
	}
	if d.Decode(new(any)) != io.EOF || h.Schema != 1 {
		return dashboardHistory{}, errors.New("观测记录版本或格式无效")
	}
	if len(h.Public) > 500 || len(h.Updates) > 2 {
		return dashboardHistory{}, errors.New("观测记录数量异常")
	}
	for _, r := range h.Public {
		if !validSource(r.Source) || !validProbeResult(r.TCP) || !validProbeResult(r.UDP) {
			return dashboardHistory{}, errors.New("公网记录无效")
		}
	}
	if r := h.Diagnostic; r != nil && (r.Errors < 0 || r.Warnings < 0) {
		return dashboardHistory{}, errors.New("自检记录无效")
	}
	for _, r := range h.Updates {
		for _, v := range []string{r.Latest, r.Compatible, r.Installed} {
			if v != "" && !dashboardTag.MatchString(v) {
				return dashboardHistory{}, errors.New("更新记录无效")
			}
		}
	}
	return h, nil
}

// Caller holds Inspect or the existing operation lock; no recovery or State write.
func (a *app) noteHistory(change func(*dashboardHistory)) error {
	h, e := readDashboardHistory(a.store.Root)
	if e != nil {
		return e
	}
	change(&h)
	b, e := json.MarshalIndent(h, "", "  ")
	if e != nil {
		return e
	}
	if len(b) > 128<<10 {
		return errors.New("观测记录过大")
	}
	return node.AtomicWrite(filepath.Join(a.store.Root, "observations.json"), append(b, '\n'), 0600)
}
func (a *app) updateHistory(change func(*dashboardHistory)) error {
	return a.store.Inspect(func() error { return a.noteHistory(change) })
}
func (a *app) noteBackup(path string) {
	p, e := filepath.Abs(path)
	if e != nil {
		return
	}
	i, e := os.Lstat(p)
	if e != nil || !i.Mode().IsRegular() {
		return
	}
	if e := a.noteHistory(func(h *dashboardHistory) { h.Backup = &backupRecord{At: time.Now().UTC(), Path: p, Size: i.Size()} }); e != nil {
		a.message("WARN", "备份已完成，但首页记录保存失败："+node.Redact(e.Error()))
	}
}

func validProbeResult(v string) bool { return v == "pass" || v == "fail" || v == "untested" }
func validSource(v string) bool {
	if strings.TrimSpace(v) == "" || len(v) > 80 || node.Redact(v) != v {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (a *app) publicCheck(args []string) error {
	if a.offline {
		return errors.New("公网验证记录须在已安装的主机上登记")
	}
	f := fs("public-check")
	id := f.String("id", "", "实测的节点 ID 或名称")
	tcp := f.String("tcp", "untested", "客户端经节点的 TCP：pass/fail/untested")
	udp := f.String("udp", "untested", "客户端经节点的 UDP：pass/fail/untested")
	source := f.String("source", "", "验证来源，例如 Windows sing-box；不得填写凭据")
	if e := parse(f, args); e != nil {
		return e
	}
	if *id == "" || !validSource(*source) || !validProbeResult(*tcp) || !validProbeResult(*udp) || (*tcp == "untested" && *udp == "untested") {
		return errors.New("提供 --id、--source 和至少一项 --tcp/--udp pass或fail；仅在实际客户端测试后登记")
	}
	return a.store.Inspect(func() error {
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		if e = s.Validate(); e != nil {
			return e
		}
		if node.Redact(*source, s) != *source {
			return errors.New("验证来源中不得包含连接凭据")
		}
		n, e := s.Find(*id)
		if e != nil {
			return e
		}
		if !n.Enabled {
			return errors.New("请先启用节点并完成实际客户端测试")
		}
		e = a.noteHistory(func(h *dashboardHistory) {
			if h.Public == nil {
				h.Public = map[string]publicRecord{}
			}
			// Drop records for deleted nodes so history remains bounded.
			for key := range h.Public {
				if _, err := s.Find(key); err != nil {
					delete(h.Public, key)
				}
			}
			h.Public[n.ID] = publicRecord{At: time.Now().UTC(), Fingerprint: publicFingerprint(s, *n), TCP: *tcp, UDP: *udp, Source: *source}
		})
		if e == nil {
			fmt.Println("已登记客户端实测；这是管理员提供的历史结果，程序未自动验证公网。")
		}
		return e
	})
}

func (a *app) publicCheckWizard() error {
	fmt.Fprintln(os.Stderr, "公网验证需在实际客户端导入节点后测试 HTTPS 和 UDP。服务器自检不能代替公网实测。\n这里只登记管理员完成的测试；未测试请选择0返回，记录不代表持续在线。")
	n, e := a.selectNode()
	if e != nil {
		return e
	}
	source, e := a.prompt("客户端/网络来源（例如 Windows sing-box；0 返回）", "")
	if e != nil || source == "0" {
		return e
	}
	results := []string{}
	for _, network := range []string{"TCP", "UDP"} {
		r, err := a.prompt(network+" 实测结果：pass 通过 / fail 失败 / untested 未测", "untested")
		if err != nil {
			return err
		}
		results = append(results, r)
	}
	return a.publicCheck([]string{"--id", n.ID, "--source", source, "--tcp", results[0], "--udp", results[1]})
}
