package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"qingnode/internal/node"
	"qingnode/internal/probe"
)

const maxHY2PlanBytes = 128 << 10

type hy2Evidence struct {
	MeasuredAt    time.Time `json:"measured_at"`
	Initiator     string    `json:"initiator"`
	UploadBasis   string    `json:"upload_basis"`
	DownloadBasis string    `json:"download_basis"`
}

type hy2Resources struct {
	ObservedAt             time.Time `json:"observed_at"`
	MemAvailableBytes      *uint64   `json:"server_mem_available_bytes"`
	ServerWindowBytes      int64     `json:"server_connection_window_bytes"`
	RequiredAvailableBytes uint64    `json:"required_server_available_bytes"`
	ClientResources        string    `json:"client_resources"`
}

type hy2Plan struct {
	Version         int                  `json:"version"`
	CreatedAt       time.Time            `json:"created_at"`
	NodeID          string               `json:"node_id"`
	UserID          string               `json:"user_id"`
	CoreVersion     string               `json:"core_version"`
	GlobalSHA       string               `json:"global_sha256"`
	BeforeNodeSHA   string               `json:"before_node_sha256"`
	AfterNodeSHA    string               `json:"after_node_sha256"`
	BeforeClientSHA string               `json:"before_client_sha256"`
	AfterClientSHA  string               `json:"after_client_sha256"`
	BeforeServerSHA string               `json:"before_server_sha256"`
	AfterServerSHA  string               `json:"after_server_sha256"`
	Preset          string               `json:"preset"`
	Before          *node.HY2Performance `json:"before"`
	After           *node.HY2Performance `json:"after"`
	RenderedBefore  hy2Rendered          `json:"rendered_before"`
	RenderedAfter   hy2Rendered          `json:"rendered_after"`
	Evidence        *hy2Evidence         `json:"evidence,omitempty"`
	Resources       hy2Resources         `json:"resources"`
	Warnings        []string             `json:"warnings"`
	Impact          node.ChangeImpact    `json:"impact"`
}

func hy2SHA(value any) (string, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func hy2PlanSHA(p hy2Plan) (string, error)   { return hy2SHA(p) }
func hy2NodeSHA(n node.Node) (string, error) { n.CreatedAt = ""; n.UpdatedAt = ""; return hy2SHA(n) }
func hy2GlobalSHA(s node.State) (string, error) {
	return hy2SHA(struct {
		Core, Archive, Firewall string
		DNS                     *node.DNSSettings
	}{s.CoreVersion, s.CoreArchiveSHA256, s.Firewall, s.DNS})
}
func hy2ServerSHA(s node.State, root string) (string, error) {
	b, e := node.Server(s, root)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func hy2ClientSHA(n node.Node, u node.User, version string) (string, error) {
	if err := node.ValidateHY2ClientCertificate(n, "sing-box"); err != nil {
		return "", err
	}
	b, e := json.Marshal(node.Outbound(n, u))
	if e != nil {
		return "", e
	}
	p, e := probe.NewProfile(n.ID, version, b)
	return p.ConfigSHA256, e
}

func hy2SafeImpact(impact node.ChangeImpact, s node.State) node.ChangeImpact {
	impact.Nodes = append([]node.NodeImpact{}, impact.Nodes...)
	for i := range impact.Nodes {
		impact.Nodes[i].Name = node.Redact(impact.Nodes[i].Name, s)
	}
	return impact
}
func hy2Clone(p *node.HY2Performance) *node.HY2Performance {
	if p == nil {
		return nil
	}
	b, _ := json.Marshal(p)
	var v node.HY2Performance
	_ = json.Unmarshal(b, &v)
	return &v
}
func hy2Text(s string) bool {
	if s == "" || len(s) > 2048 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func hy2Digest(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

func readHY2File(path string, private bool) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Size() > maxHY2PlanBytes {
		return nil, errors.New("HY2输入须为最多128KiB的普通文件，不接受符号链接、管道或设备")
	}
	if private && i.Mode().Perm()&0077 != 0 {
		return nil, errors.New("性能计划须为私有文件，请先chmod 600")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !os.SameFile(i, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("读取期间HY2输入文件发生变化")
	}
	b, e := io.ReadAll(io.LimitReader(f, maxHY2PlanBytes+1))
	if len(b) > maxHY2PlanBytes {
		return nil, errors.New("HY2文件超过128KiB")
	}
	return b, e
}

func readHY2Plan(path string) (hy2Plan, error) {
	var p hy2Plan
	b, e := readHY2File(path, true)
	if e != nil {
		return p, e
	}
	if e = probe.StrictJSON(b, &p); e != nil {
		return p, e
	}
	return p, validateHY2Plan(p)
}
func validateHY2Plan(p hy2Plan) error {
	if p.Version != 1 {
		return errors.New("不支持性能计划版本；当前仅支持version 1")
	}
	if p.CreatedAt.IsZero() || p.CreatedAt.After(time.Now().Add(5*time.Minute)) || len(p.NodeID) != 16 || len(p.UserID) != 16 || !node.SupportedVersion(p.CoreVersion) {
		return errors.New("性能计划身份、时间或核心版本无效")
	}
	for _, id := range []string{p.NodeID, p.UserID} {
		if _, e := hex.DecodeString(id); e != nil {
			return errors.New("性能计划节点或凭据ID无效")
		}
	}
	for _, h := range []string{p.GlobalSHA, p.BeforeNodeSHA, p.AfterNodeSHA, p.BeforeClientSHA, p.AfterClientSHA, p.BeforeServerSHA, p.AfterServerSHA} {
		if !hy2Digest(h) {
			return errors.New("性能计划缺少有效配置摘要")
		}
	}
	switch p.Preset {
	case "core-default", "automatic", "fixed", "conservative", "custom":
	default:
		return errors.New("性能计划预设无效")
	}
	for _, v := range []*node.HY2Performance{p.Before, p.After} {
		if e := node.ValidateHY2Capabilities(node.Node{Protocol: "hysteria2", HY2: v}, p.CoreVersion, nil); e != nil {
			return e
		}
	}
	if e := validateHY2Rendered(p.RenderedBefore); e != nil {
		return e
	}
	if e := validateHY2Rendered(p.RenderedAfter); e != nil {
		return e
	}
	if p.Preset == "core-default" && p.After != nil {
		return errors.New("核心默认计划必须明确清除性能设置")
	}
	if p.Preset == "fixed" {
		if p.After == nil || p.After.ClientMode != "brutal" || p.After.ClientUpMbps == nil || p.After.ClientDownMbps == nil || p.Evidence == nil {
			return errors.New("固定速率计划缺少双向预期或独立测量依据")
		}
		if e := validateHY2Evidence(*p.Evidence); e != nil {
			return e
		}
	}
	if p.Preset == "conservative" {
		if p.After == nil || p.After.Server == nil || p.After.Server.BBRProfile != "conservative" || p.After.Server.QUIC == nil || p.After.Server.QUIC.StreamReceiveWindow == nil || *p.After.Server.QUIC.StreamReceiveWindow != 1<<20 || p.After.Server.QUIC.ConnectionReceiveWindow == nil || *p.After.Server.QUIC.ConnectionReceiveWindow != 4<<20 {
			return errors.New("保守预设必须保持本机1MiB/4MiB窗口与conservative BBR")
		}
	}
	if p.Resources.ClientResources != "unknown" {
		return errors.New("服务器计划不能虚构远端客户端资源证据")
	}
	window, required := hy2WindowBudget(p.After)
	if p.Resources.ServerWindowBytes != window || p.Resources.RequiredAvailableBytes != required {
		return errors.New("性能计划资源预算与实际服务器窗口不一致")
	}
	if p.Resources.RequiredAvailableBytes > 0 && (p.Resources.MemAvailableBytes == nil || *p.Resources.MemAvailableBytes < p.Resources.RequiredAvailableBytes || p.Resources.ObservedAt.IsZero()) {
		return errors.New("性能计划缺少足够的本机内存证据")
	}
	for _, w := range p.Warnings {
		if !hy2Text(w) {
			return errors.New("性能计划说明无效或过长")
		}
	}
	return nil
}

func validateHY2Evidence(e hy2Evidence) error {
	if e.MeasuredAt.IsZero() || e.MeasuredAt.After(time.Now().Add(5*time.Minute)) || !hy2Text(e.Initiator) || !hy2Text(e.UploadBasis) || !hy2Text(e.DownloadBasis) {
		return errors.New("固定速率须分别提供上传和下载测量依据、发起点及有效测量时间")
	}
	for _, s := range []string{e.Initiator, e.UploadBasis, e.DownloadBasis} {
		if strings.Contains(s, "://") || node.Redact(s) != s {
			return errors.New("测量依据不能含URL、分享链接、UUID或凭据；请只填工具说明、文件名或SHA摘要")
		}
	}
	return nil
}

func hy2MemAvailable() (*uint64, error) {
	return node.AvailableMemory("", "")
}

var readHY2MemAvailable = hy2MemAvailable

func hy2WindowBudget(p *node.HY2Performance) (int64, uint64) {
	var window int64
	if p != nil && p.Server != nil && p.Server.QUIC != nil {
		q := p.Server.QUIC
		if q.ConnectionReceiveWindow != nil {
			window = *q.ConnectionReceiveWindow
		} else if q.StreamReceiveWindow != nil {
			window = *q.StreamReceiveWindow
		}
	}
	if window <= 0 {
		return 0, 0
	}
	required := uint64(window) * 8
	if required < 128<<20 {
		required = 128 << 20
	}
	return window, required
}

func hy2ResourceEvidence(p *node.HY2Performance) (hy2Resources, error) {
	r := hy2Resources{ObservedAt: time.Now().UTC(), ClientResources: "unknown"}
	r.MemAvailableBytes, _ = readHY2MemAvailable()
	if p != nil && p.Server != nil && p.Server.QUIC != nil {
		q := p.Server.QUIC
		if q.ConnectionReceiveWindow != nil {
			r.ServerWindowBytes = *q.ConnectionReceiveWindow
		} else if q.StreamReceiveWindow != nil {
			r.ServerWindowBytes = *q.StreamReceiveWindow
		}
		if r.ServerWindowBytes > 0 {
			r.RequiredAvailableBytes = uint64(r.ServerWindowBytes) * 8
			if r.RequiredAvailableBytes < 128<<20 {
				r.RequiredAvailableBytes = 128 << 20
			}
			if r.MemAvailableBytes == nil || *r.MemAvailableBytes < r.RequiredAvailableBytes {
				return r, errors.New("本机可用内存不足或未知，拒绝该服务器窗口方案；不会用VPS资源推断客户端资源")
			}
		}
	}
	return r, nil
}

func hy2UsageWarnings(n node.Node) []string {
	p := n.HY2
	if p == nil {
		return nil
	}
	warnings := []string{}
	if p.Client != nil && p.Client.BBRProfile != "" && p.ClientUpMbps != nil {
		warnings = append(warnings, "客户端已声明Brutal预期速率；BBR配置只在连接实际协商为用户态QUIC BBR时生效，不保证两种控制器同时起效。")
	}
	if p.ClientMode == "brutal" {
		warnings = append(warnings, "brutal表示客户端发送双向预期速率请求；实际拥塞控制器仍由两端协商决定，不能据此宣称已强制启用Brutal。")
	}
	if p.Server != nil && p.Server.BBRProfile != "" {
		warnings = append(warnings, "服务端BBR配置仅在实际使用QUIC BBR时起效；已登记的速率参与协商，既不是BBR的硬速率保证，也不是VPS总限速。")
	}
	if p.ClientMode == "bbr" && (p.ServerUpMbps != nil || p.ServerDownMbps != nil) {
		warnings = append(warnings, "客户端明确不声明Brutal速率时，服务端配置的Brutal协商上限不保证作用于这条BBR连接。")
	}
	if p.Client != nil && p.Client.QUIC != nil {
		warnings = append(warnings, "客户端窗口或超时为显式请求；本机没有该客户端的可用内存与负载证据，是否适用仍未知。")
	}
	return warnings
}

func atomicHY2Plan(path string, p hy2Plan) error {
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	parent := filepath.Dir(path)
	f, e := os.CreateTemp(parent, ".qingnode-hy2-plan-")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if _, e = f.Write(append(b, '\n')); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	// Link creates the destination atomically and refuses every existing path,
	// including symlinks. It never exposes a half-written plan or overwrites one.
	if e = os.Link(temp, path); e != nil {
		return e
	}
	return node.SyncDir(parent)
}

func (a *app) hy2(args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "show":
		f := fs("hy2 show")
		id := f.String("id", "", "节点ID或名称，省略列出HY2设置")
		machine := f.Bool("json", false, "版本1性能设置声明，方向和默认值说明位于JSON内")
		if e := parse(f, args[1:]); e != nil {
			return e
		}
		return a.inspectReadyState(func(s *node.State) error {
			rows := []any{}
			for _, n := range s.Nodes {
				if n.Protocol != "hysteria2" {
					continue
				}
				if *id != "" && n.ID != *id && n.Name != *id {
					continue
				}
				warnings := append(node.HY2ExportWarnings(n, "sing-box"), hy2UsageWarnings(n)...)
				rows = append(rows, struct {
					ID          string               `json:"id"`
					Name        string               `json:"name"`
					Core        string               `json:"core_version"`
					Performance *node.HY2Performance `json:"performance"`
					Warnings    []string             `json:"warnings"`
				}{n.ID, publicQueryText(n.Name, *s), s.CoreVersion, n.HY2, warnings})
			}
			if *id != "" && len(rows) == 0 {
				return errors.New("未找到所选Hysteria2节点")
			}
			if *machine {
				return queryJSON("qingnode-hy2-settings", struct {
					Nodes                 []any  `json:"nodes"`
					ServerUploadDirection string `json:"server_upload_direction"`
					ClientUploadDirection string `json:"client_upload_direction"`
					NullMeaning           string `json:"null_meaning"`
					RateScope             string `json:"rate_scope"`
				}{rows, "VPS-to-client", "client-to-VPS", "core-default", "per-QUIC-connection-negotiation-not-server-total-limit"})
			}
			b, _ := json.MarshalIndent(rows, "", "  ")
			fmt.Println(string(b))
			fmt.Println("server up为VPS发往客户端，client up为客户端上传；速率是每条QUIC连接协商值，不是VPS总限速。nil表示保留核心默认。")
			return nil
		})
	case "plan":
		return a.hy2Plan(args[1:])
	case "apply", "revert":
		f := fs("hy2 " + args[0])
		path := f.String("file", "", "私有性能计划")
		if e := parse(f, args[1:]); e != nil {
			return e
		}
		if *path == "" {
			return errors.New("apply/revert需要--file指定性能计划")
		}
		p, e := readHY2Plan(*path)
		if e != nil {
			return e
		}
		return a.applyHY2Plan(p, args[0] == "revert")
	case "compare":
		return a.hy2Compare(args[1:])
	case "help", "--help":
		fmt.Println(hy2Help)
		return nil
	default:
		return errors.New("未知Hysteria2性能操作；使用hy2 --help")
	}
}

const hy2Help = `hy2 show [--id ID] [--json]
hy2 plan --id ID [--user ID] --preset core-default|automatic|fixed|conservative|custom --out 新计划.json [--json]
  fixed: --up-mbps N --down-mbps N --measured-at RFC3339 --initiator 测试发起点 --upload-basis 上传依据 --download-basis 下载依据
  custom: --settings typed性能JSON文件（只接受HY2Performance字段）
hy2 apply --file 计划.json | hy2 revert --file 计划.json
hy2 compare --help
plan只读并保存独立私有文件；apply/revert验证未过期摘要后只修改性能。恢复核心默认会清除本节点全部HY2性能选择。
automatic仅把客户端恢复为不声明速率的BBR；fixed仅设置客户端双向预期，测量依据由用户分别登记，不冒充本工具已验证。
依据只填工具文字说明、文件名或SHA摘要；不接受URL、分享链接或凭据。
conservative仅改本机服务端BBR及1MiB/4MiB窗口，须MemAvailable证据，不改客户端。
Chrome QUIC伪装默认保留，可能覆盖部分客户端参数；计划会列出实际导出限制。`

func (a *app) hy2Plan(args []string) error {
	f := fs("hy2 plan")
	machine := f.Bool("json", false, "只向stdout输出已保存的版本1计划；不修改节点")
	id := f.String("id", "", "节点ID或名称")
	user := f.String("user", "", "客户端凭据ID，多凭据时必填")
	preset := f.String("preset", "", "明确选择预设")
	out := f.String("out", "", "新的私有计划路径")
	settings := f.String("settings", "", "custom typed JSON")
	up := f.Int("up-mbps", 0, "客户端上传预期Mbps")
	down := f.Int("down-mbps", 0, "客户端下载预期Mbps")
	at := f.String("measured-at", "", "双向测量时间RFC3339")
	initiator := f.String("initiator", "", "双向测量发起点")
	uploadBasis := f.String("upload-basis", "", "独立客户端上传测量依据")
	downloadBasis := f.String("download-basis", "", "独立客户端下载测量依据")
	if e := parse(f, args); e != nil {
		return e
	}
	if *id == "" || *out == "" {
		return errors.New("plan需要--id和--out；不会自动选择性能方案")
	}
	if e := a.probeOutput(*out); e != nil {
		return e
	}
	if *preset != "fixed" && (*up != 0 || *down != 0 || *at != "" || *initiator != "" || *uploadBasis != "" || *downloadBasis != "") {
		return errors.New("双向Mbps及测量依据只适用于fixed预设")
	}
	if *preset != "custom" && *settings != "" {
		return errors.New("--settings只适用于custom预设")
	}
	var evidence *hy2Evidence
	var custom *node.HY2Performance
	if *preset == "fixed" {
		stamp, e := time.Parse(time.RFC3339, *at)
		if e != nil {
			return errors.New("fixed必须提供RFC3339测量时间")
		}
		evidence = &hy2Evidence{stamp.UTC(), *initiator, *uploadBasis, *downloadBasis}
		if e = validateHY2Evidence(*evidence); e != nil {
			return e
		}
	}
	if *preset == "custom" {
		if *settings == "" {
			return errors.New("custom必须提供--settings")
		}
		b, e := readHY2File(*settings, false)
		if e != nil {
			return e
		}
		if e = probe.StrictJSON(b, &custom); e != nil {
			return e
		}
		if custom == nil {
			return errors.New("custom需要性能对象；清除全部请选core-default")
		}
	}
	return a.inspectReadyState(func(s *node.State) error {
		n, e := s.Find(*id)
		if e != nil {
			return e
		}
		if n.Protocol != "hysteria2" {
			return errors.New("性能计划只支持Hysteria2节点")
		}
		u, e := node.SelectUser(*n, *user)
		if e != nil {
			return e
		}
		after := hy2Clone(n.HY2)
		if after == nil {
			after = &node.HY2Performance{}
		}
		switch *preset {
		case "core-default":
			after = nil
		case "automatic":
			after.ClientMode = "bbr"
			after.ClientUpMbps = nil
			after.ClientDownMbps = nil
		case "fixed":
			after.ClientMode = "brutal"
			after.ClientUpMbps = up
			after.ClientDownMbps = down
		case "conservative":
			if after.Server == nil {
				after.Server = &node.HY2Transport{}
			}
			if after.Server.QUIC == nil {
				after.Server.QUIC = &node.HY2QUIC{}
			}
			stream, connection := int64(1<<20), int64(4<<20)
			after.Server.BBRProfile = "conservative"
			after.Server.QUIC.StreamReceiveWindow = &stream
			after.Server.QUIC.ConnectionReceiveWindow = &connection
		case "custom":
			after = hy2Clone(custom)
		default:
			return errors.New("预设必须为core-default、automatic、fixed、conservative或custom")
		}
		next := s.Clone()
		nn, _ := next.Find(n.ID)
		nn.HY2 = after
		if e = next.Validate(); e != nil {
			return e
		}
		resources, e := hy2ResourceEvidence(after)
		if e != nil {
			return e
		}
		impact, e := a.store.Preview(next)
		if e != nil {
			return e
		}
		impact = hy2SafeImpact(impact, *s)
		p := hy2Plan{Version: 1, CreatedAt: time.Now().UTC(), NodeID: n.ID, UserID: u.ID, CoreVersion: s.CoreVersion, Preset: *preset, Before: hy2Clone(n.HY2), After: hy2Clone(after), Evidence: evidence, Resources: resources, Impact: impact, Warnings: []string{"服务器速率仅参与各QUIC连接协商，不是整个VPS带宽硬上限。", "客户端资源未知；本机内存证据不能证明手机或桌面客户端资源充足。", "接收窗口不是总RSS承诺；并发连接数与实际负载仍需单独验证。"}}
		p.GlobalSHA, e = hy2GlobalSHA(*s)
		if e != nil {
			return e
		}
		p.BeforeNodeSHA, e = hy2NodeSHA(*n)
		if e != nil {
			return e
		}
		p.AfterNodeSHA, e = hy2NodeSHA(*nn)
		if e != nil {
			return e
		}
		p.BeforeClientSHA, e = hy2ClientSHA(*n, u, s.CoreVersion)
		if e != nil {
			return e
		}
		p.AfterClientSHA, e = hy2ClientSHA(*nn, u, next.CoreVersion)
		if e != nil {
			return e
		}
		p.BeforeServerSHA, e = hy2ServerSHA(*s, a.store.Root)
		if e != nil {
			return e
		}
		p.AfterServerSHA, e = hy2ServerSHA(next, a.store.Root)
		if e != nil {
			return e
		}
		p.RenderedBefore, e = hy2RenderedFields(*s, n.ID, u.ID, a.store.Root)
		if e != nil {
			return e
		}
		p.RenderedAfter, e = hy2RenderedFields(next, n.ID, u.ID, a.store.Root)
		if e != nil {
			return e
		}
		if evidence != nil {
			for _, text := range []string{evidence.Initiator, evidence.UploadBasis, evidence.DownloadBasis} {
				if node.Redact(text, *s) != text {
					return errors.New("测量依据不能复制已保存的节点凭据或私钥")
				}
			}
		}
		for _, format := range []string{"sing-box", "mihomo", "uri"} {
			p.Warnings = append(p.Warnings, node.HY2ExportWarnings(*nn, format)...)
		}
		p.Warnings = append(p.Warnings, hy2UsageWarnings(*nn)...)
		if evidence != nil {
			p.Warnings = append(p.Warnings, "fixed依据为用户登记；本工具没有用下载结果推算上传能力，也没有验证所登记的外部测量。")
		}
		if e = validateHY2Plan(p); e != nil {
			return e
		}
		if e = atomicHY2Plan(*out, p); e != nil {
			return e
		}
		if *machine {
			return json.NewEncoder(os.Stdout).Encode(p)
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
		fmt.Println("已保存只读计划；节点、凭据与服务均未修改。应用使用hy2 apply --file，回退使用同一计划的hy2 revert --file。")
		return nil
	})
}

func (a *app) applyHY2Plan(p hy2Plan, revert bool) error {
	if e := validateHY2Plan(p); e != nil {
		return e
	}
	// Reject an already pending transaction without triggering recovery. The
	// write lock then repeats all state and digest checks before one Apply.
	if e := a.inspectReadyState(func(*node.State) error { return nil }); e != nil {
		return e
	}
	return a.store.WithLock(func() error {
		s, e := a.store.Load()
		if e != nil {
			return e
		}
		if e = s.Validate(); e != nil {
			return e
		}
		n, e := s.Find(p.NodeID)
		if e != nil {
			return e
		}
		if n.Protocol != "hysteria2" || s.CoreVersion != p.CoreVersion {
			return errors.New("节点协议或核心版本已变化；请重新生成计划")
		}
		global, e := hy2GlobalSHA(s)
		if e != nil {
			return e
		}
		if global != p.GlobalSHA {
			return errors.New("核心、DNS或防火墙选择已变化；旧计划不能直接应用或回退")
		}
		expectNode, expectClient, expectServer := p.BeforeNodeSHA, p.BeforeClientSHA, p.BeforeServerSHA
		target, targetNode, targetClient, targetServer := p.After, p.AfterNodeSHA, p.AfterClientSHA, p.AfterServerSHA
		expectRendered, targetRendered := p.RenderedBefore, p.RenderedAfter
		if revert {
			expectNode, expectClient, expectServer = p.AfterNodeSHA, p.AfterClientSHA, p.AfterServerSHA
			target, targetNode, targetClient, targetServer = p.Before, p.BeforeNodeSHA, p.BeforeClientSHA, p.BeforeServerSHA
			expectRendered, targetRendered = p.RenderedAfter, p.RenderedBefore
		}
		current, e := hy2NodeSHA(*n)
		if e != nil {
			return e
		}
		u, e := node.SelectUser(*n, p.UserID)
		if e != nil {
			return e
		}
		currentRendered, e := hy2RenderedFields(s, n.ID, u.ID, a.store.Root)
		if e != nil {
			return e
		}
		if current == targetNode && current != expectNode {
			existingClient, ce := hy2ClientSHA(*n, u, s.CoreVersion)
			existingServer, se := hy2ServerSHA(s, a.store.Root)
			if ce == nil && se == nil && existingClient == targetClient && existingServer == targetServer {
				if !equalHY2JSON(currentRendered, targetRendered) {
					return errors.New("已应用节点的实际派生字段与计划不一致")
				}
				if !equalHY2JSON(n.HY2, target) {
					return errors.New("计划性能内容与已匹配目标摘要不一致")
				}
				if _, e = hy2ResourceEvidence(target); e != nil {
					return e
				}
				if e = a.store.Apply(s); e != nil {
					return e
				}
				fmt.Println("节点已处于目标性能状态；已按正常应用流程检查重复应用与派生文件修复。")
				return nil
			}
		}
		if current != expectNode {
			return errors.New("节点在计划后已有相关修改；拒绝覆盖，请重新生成计划")
		}
		if !equalHY2JSON(currentRendered, expectRendered) {
			return errors.New("当前实际派生字段与计划起点不一致")
		}
		client, e := hy2ClientSHA(*n, u, s.CoreVersion)
		if e != nil {
			return e
		}
		server, e := hy2ServerSHA(s, a.store.Root)
		if e != nil {
			return e
		}
		if client != expectClient || server != expectServer {
			return errors.New("实际客户端或服务器配置已变化，旧计划不再匹配")
		}
		next := s.Clone()
		nn, _ := next.Find(p.NodeID)
		nn.HY2 = hy2Clone(target)
		if e = next.Validate(); e != nil {
			return e
		}
		afterNode, e := hy2NodeSHA(*nn)
		if e != nil {
			return e
		}
		afterClient, e := hy2ClientSHA(*nn, u, next.CoreVersion)
		if e != nil {
			return e
		}
		afterServer, e := hy2ServerSHA(next, a.store.Root)
		if e != nil {
			return e
		}
		afterRendered, e := hy2RenderedFields(next, n.ID, u.ID, a.store.Root)
		if e != nil {
			return e
		}
		if !equalHY2JSON(afterRendered, targetRendered) {
			return errors.New("实际派生目标字段与计划不一致")
		}
		if afterNode != targetNode || afterClient != targetClient || afterServer != targetServer {
			return errors.New("计划内容与保存的目标摘要不一致；拒绝被修改或不完整的计划")
		}
		if _, e = hy2ResourceEvidence(target); e != nil {
			return e
		}
		impact, e := a.store.Preview(next)
		if e != nil {
			return e
		}
		impact = hy2SafeImpact(impact, s)
		if !revert && !equalHY2JSON(impact, p.Impact) {
			return errors.New("实际变更影响与原计划不一致；请重新生成计划")
		}
		if e = a.store.Apply(next); e != nil {
			return e
		}
		operation := "应用"
		if revert {
			operation = "回退"
		}
		fmt.Printf("已%s所选节点性能设置；凭据与其他节点保持。服务是否重启按实际服务器影响决定。\n", operation)
		return nil
	})
}

func equalHY2JSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
