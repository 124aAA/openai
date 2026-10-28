package node

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"qingnode/internal/platform"
)

var pinned = map[string]string{
	"amd64": "2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63",
	"arm64": "04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088",
}

func CorePath(root, version string) string { return filepath.Join(root, "cores", version, "sing-box") }
func Run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	b, e := cmd.CombinedOutput()
	if c.Err() != nil {
		return b, c.Err()
	}
	return b, e
}
func VerifyCore(root, v string) error {
	if !SupportedVersion(v) {
		return errors.New("核心版本尚未适配")
	}
	p := CorePath(root, v)
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() {
		return errors.New("核心必须为普通文件")
	}
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil {
		return e
	}
	sum, e := os.ReadFile(p + ".sha256")
	if e != nil || strings.TrimSpace(string(sum)) != hex.EncodeToString(h.Sum(nil)) {
		return errors.New("已安装核心摘要不匹配，请重新安装")
	}
	b, e := Run(10*time.Second, p, "version")
	if e != nil || !strings.Contains(string(b), "sing-box version "+v+"\n") {
		return errors.New("核心版本与锁定版本不一致")
	}
	return verifyCoreTags(string(b))
}

// A compatible version alone does not guarantee that the upstream binary was
// built with the TLS, QUIC and certificate features used by our adapters.
func verifyCoreTags(output string) error {
	tags := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Tags:") {
			for _, tag := range strings.FieldsFunc(strings.TrimPrefix(line, "Tags:"), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
				tags[tag] = true
			}
		}
	}
	for _, tag := range []string{"with_quic", "with_utls", "with_acme"} {
		if !tags[tag] {
			return fmt.Errorf("核心构建缺少 %s 能力", tag)
		}
	}
	return nil
}
func InstallCore(root, v, sum, archive string) error {
	if !SupportedVersion(v) {
		return errors.New("仅支持 1.14.x 正式版本；跨版本须先更新适配器")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("首版仅支持 amd64/arm64")
	}
	if sum == "" && v == DefaultCore {
		sum = pinned[runtime.GOARCH]
	}
	d, e := hex.DecodeString(sum)
	if e != nil || len(d) != 32 {
		return errors.New("此版本需要显式提供官方归档的 SHA-256")
	}
	openrc := platform.DetectServiceManager() == platform.InitOpenRC
	if openrc {
		if info, statErr := os.Lstat(CorePath(root, v)); statErr == nil {
			if !info.Mode().IsRegular() {
				return errors.New("现有OpenRC核心必须是普通文件；拒绝接管")
			}
			if _, e = openRCCoreFileCapabilityWithRunner(CorePath(root, v), Run); e != nil {
				return e
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
	}
	if archive == "" && installedCoreReady(root, v) {
		return nil
	}
	var src io.ReadCloser
	if archive != "" {
		src, e = os.Open(archive)
	} else {
		url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", v, v, runtime.GOARCH)
		client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme != "https" || len(via) > 8 {
				return errors.New("拒绝不安全下载跳转")
			}
			return nil
		}}
		var resp *http.Response
		resp, e = client.Get(url)
		if e == nil {
			if resp.StatusCode != 200 {
				resp.Body.Close()
				return fmt.Errorf("核心下载失败 HTTP %d", resp.StatusCode)
			}
			src = resp.Body
		}
	}
	if e != nil {
		return e
	}
	defer src.Close()
	tmp, e := os.CreateTemp(root, ".core-archive-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, (256<<20)+1))
	if e != nil {
		return e
	}
	if n > 256<<20 {
		return errors.New("下载文件超过大小限制")
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sum) {
		return errors.New("下载归档 SHA-256 不匹配，拒绝执行")
	}
	if _, e = tmp.Seek(0, 0); e != nil {
		return e
	}
	gz, e := gzip.NewReader(tmp)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var binary []byte
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if filepath.Base(hdr.Name) != "sing-box" {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > 160<<20 || binary != nil {
			return errors.New("核心归档内容异常")
		}
		binary, e = io.ReadAll(io.LimitReader(tr, (160<<20)+1))
		if e != nil {
			return e
		}
	}
	if len(binary) == 0 {
		return errors.New("归档没有核心可执行文件")
	}
	dir := filepath.Dir(CorePath(root, v))
	if i, e := os.Lstat(dir); e == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
		return errors.New("核心版本目录无效")
	}
	stage, e := os.MkdirTemp(filepath.Join(root, "cores"), ".install-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	if e = os.Chmod(stage, 0755); e != nil {
		return e
	}
	staged := filepath.Join(stage, "sing-box")
	if e = AtomicWrite(staged, binary, 0755); e != nil {
		return e
	}
	if _, e = CheckCoreABI(staged, runtime.GOARCH); e != nil {
		return e
	}
	b, e := Run(10*time.Second, staged, "version")
	if e != nil || !strings.Contains(string(b), "sing-box version "+v+"\n") {
		return errors.New("下载核心的架构或版本不匹配")
	}
	if e = verifyCoreTags(string(b)); e != nil {
		return e
	}
	// Both managers supply a narrow ambient bind capability. A fresh staged
	// executable has no file capability: such an xattr clears ambient at exec,
	// which breaks low-port binding through a second compatibility-loader exec.
	// Legacy exact bind xattrs remain on the old inode in recovery materials.
	if openrc {
		if e = verifyOpenRCCoreFileCapability(staged); e != nil {
			return e
		}
	}
	bh := sha256.Sum256(binary)
	if e = AtomicWrite(staged+".sha256", []byte(hex.EncodeToString(bh[:])+"\n"), 0644); e != nil {
		return e
	}
	if installedCoreReady(root, v) {
		return nil
	}
	broken := dir + ".previous-" + Token(8)
	existed := false
	if _, e = os.Lstat(dir); e == nil {
		if e = os.Rename(dir, broken); e != nil {
			return e
		}
		existed = true
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.Rename(stage, dir); e != nil {
		if existed {
			if re := os.Rename(broken, dir); re != nil {
				return fmt.Errorf("核心安装失败：%v；恢复失败：%w", e, re)
			}
		}
		return e
	}
	return SyncDir(filepath.Dir(dir))
}

type Runner func(time.Duration, string, ...string) ([]byte, error)

type SystemBackend struct {
	Root          string
	Execute       Runner
	ProcRoot      string
	CgroupRoot    string
	ManagerKind   platform.InitKind
	OpenRCPIDFile string // optional isolated stop-proof fixture; real default is fixed
}

func (b SystemBackend) run(t time.Duration, name string, args ...string) ([]byte, error) {
	if b.Execute != nil {
		return b.Execute(t, name, args...)
	}
	return Run(t, name, args...)
}
func (b SystemBackend) PID() int {
	pid, _ := b.ServiceManager().PID("qingnode")
	return pid
}
func (b SystemBackend) Sockets() []Socket {
	p := b.ProcRoot
	if p == "" {
		p = "/proc"
	}
	return ReadSockets(p, b.PID())
}

func (b SystemBackend) Check(s State, path string) error {
	var certificateErr error
	s, certificateErr = CanonicalCertificates(s)
	if certificateErr != nil {
		return certificateErr
	}
	if e := CheckCertificateFilePermissions(s); e != nil {
		return e
	}
	if e := (Firewall{Execute: b.Execute}).Check(s); e != nil {
		return e
	}
	if e := ValidateCertificateDates(s); e != nil {
		return e
	}
	if e := VerifyCore(b.Root, s.CoreVersion); e != nil {
		return e
	}
	if len(s.Egresses) > 0 || len(s.Nodes) > 0 {
		version, err := Run(10*time.Second, CorePath(b.Root, s.CoreVersion), "version")
		if err != nil {
			return errors.New("无法读取节点与拓扑所需的核心构建能力")
		}
		if err = ValidateProtocolCapabilities(s, CoreBuildTags(string(version))); err != nil {
			return err
		}
		if err = ValidateEgressCapabilities(s, CoreBuildTags(string(version))); err != nil {
			return err
		}
	}
	expected, e := Server(s, b.Root)
	if e != nil {
		return e
	}
	actual, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !bytes.Equal(bytes.TrimSpace(expected), bytes.TrimSpace(actual)) {
		return errors.New("核心配置与节点状态不一致，拒绝应用；请回退或通过管理命令重新生成")
	}
	out, e := Run(20*time.Second, CorePath(b.Root, s.CoreVersion), "check", "-c", path)
	if e != nil {
		return fmt.Errorf("sing-box check 未通过（%s）；请运行 doctor 查看非敏感诊断", e)
	}
	_ = out
	old, oldErr := ReadState(filepath.Join(b.Root, "current", "state.json"))
	if oldErr != nil || old.Validate() != nil {
		old = State{}
	}
	proc := b.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	pid := b.PID()
	snapshot, _ := ReadSocketSnapshot(proc, pid)
	if pid > 0 && !snapshot.NamespaceVerified {
		return errors.New("无法在服务实际网络命名空间中完成本地监听预检；请先核对服务隔离设置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := ValidateTopologyNetwork(ctx, s); e != nil {
		return e
	}
	if _, e := ProbeLocalBindings(ctx, StateBindings(s), BindingProbeOptions{Previous: StateBindings(old), Sockets: snapshot.Sockets, SnapshotComplete: snapshot.Complete}); e != nil {
		return e
	}
	return probeCertificateChallengeBindings(ctx, s, old, snapshot)
}

// CertMagic's fixed challenge solver uses net.Listen("tcp", ":port"). Match
// its actual wildcard family instead of assuming IPv4, and defer a busy port
// only when the complete socket snapshot proves an old challenge owns it.
func probeCertificateChallengeBindings(ctx context.Context, next, old State, snapshot SocketSnapshot) error {
	bindings := CertificateChallengeBindings(next)
	if len(bindings) == 0 {
		return nil
	}
	var lc net.ListenConfig
	listener, e := lc.Listen(ctx, "tcp", ":0")
	if e != nil {
		return fmt.Errorf("无法预检ACME挑战监听能力：%w", e)
	}
	address, _, splitErr := net.SplitHostPort(listener.Addr().String())
	closeErr := listener.Close()
	if splitErr != nil || closeErr != nil {
		return errors.New("无法确认ACME挑战实际监听地址族")
	}
	for i := range bindings {
		bindings[i].Address = address
	}
	var previous []LocalBinding
	for _, binding := range CertificateChallengeBindings(old) {
		// Both are possible representations of the same fixed wildcard
		// solver. Neither grants ownership without the observed inode.
		binding.Address = "0.0.0.0"
		previous = append(previous, binding)
		binding.Address = "::"
		previous = append(previous, binding)
	}
	_, e = ProbeLocalBindings(ctx, bindings, BindingProbeOptions{Previous: previous, Sockets: snapshot.Sockets, SnapshotComplete: snapshot.Complete && snapshot.NamespaceVerified})
	if e != nil {
		return fmt.Errorf("ACME本地挑战监听未通过；HTTP-01仍需公网80、TLS-ALPN仍需公网443正确转发：%w", e)
	}
	return nil
}

func CoreBuildTags(output string) []string {
	var tags []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Tags:") {
			tags = append(tags, strings.FieldsFunc(strings.TrimPrefix(line, "Tags:"), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' })...)
		}
	}
	return tags
}
func available(network, address string) error {
	host, port, e := splitLocalAddress(address)
	if e != nil {
		return e
	}
	_, e = ProbeLocalBindings(context.Background(), []LocalBinding{{Network: network, Address: host, Port: port}}, BindingProbeOptions{})
	return e
}
func (b SystemBackend) Active() bool {
	active, e := b.ServiceManager().Active("qingnode")
	return e == nil && active
}

// ActiveState preserves unknown controller results for write transactions.
// Active remains the legacy observation convenience; false alone is not a
// sufficient recovery snapshot when a backend can provide this stronger API.
func (b SystemBackend) ActiveState() (bool, error) {
	state, e := b.ServiceManager().State("qingnode")
	if e != nil {
		return false, e
	}
	switch state.State {
	case "active":
		if state.PID > 0 && state.SubState == "running" {
			return true, nil
		}
	case "inactive", "failed":
		if state.PID == 0 && (state.SubState == "dead" || state.SubState == "failed" || state.SubState == "stopped") {
			return false, nil
		}
	}
	return false, errors.New("服务状态未知或正在转换，未把它保存为停止状态")
}
func (b SystemBackend) restartService(s State) error {
	manager := b.ServiceManager()
	if manager.ResolvedKind() != platform.InitSystemd {
		out, e := manager.Command("restart", "qingnode")
		if e != nil {
			return fmt.Errorf("%s restart qingnode 失败：%w；%s", manager.ResolvedKind(), e, strings.TrimSpace(Redact(string(out), s)))
		}
		return nil
	}
	commandError := func(action string, out []byte, err error) error {
		detail := strings.TrimSpace(Redact(string(out), s))
		if detail == "" {
			return fmt.Errorf("systemctl %s qingnode.service 失败：%w", action, err)
		}
		return fmt.Errorf("systemctl %s qingnode.service 失败：%w；%s", action, err, detail)
	}
	restart := func() error {
		out, err := b.run(35*time.Second, "systemctl", "restart", "qingnode.service")
		if err != nil {
			return commandError("restart", out, err)
		}
		return nil
	}
	firstErr := restart()
	if firstErr == nil {
		return nil
	}
	result, err := b.run(10*time.Second, "systemctl", "show", "qingnode.service", "--property=Result", "--value")
	if err != nil {
		return errors.Join(firstErr, commandError("show --property=Result --value", result, err))
	}
	if strings.TrimSpace(string(result)) != "start-limit-hit" {
		return firstErr
	}
	// Manual configuration changes also consume systemd's start-rate budget.
	// Recover only this confirmed limit, once; automatic crash-loop limits remain intact.
	out, err := b.run(10*time.Second, "systemctl", "reset-failed", "qingnode.service")
	if err != nil {
		return errors.Join(firstErr, commandError("reset-failed", out, err))
	}
	if err = restart(); err != nil {
		return errors.Join(firstErr, fmt.Errorf("已清除启动限流，重试一次后仍失败：%w", err))
	}
	return nil
}
func (b SystemBackend) Activate(s State) error {
	// The service invokes the manager's serve command, which reads the same atomic generation.
	if e := b.restartService(s); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	unavailable, err := wireGuardUnavailableFamilies(ctx, s, net.ListenConfig{})
	cancel()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	success := 0
	for time.Now().Before(deadline) {
		if b.Active() && socketsReadyWithUnavailableFamilies(s, b.Sockets(), unavailable) {
			success++
			if success >= 3 {
				return nil
			}
		} else {
			success = 0
		}
		time.Sleep(time.Second)
	}
	return errors.New("服务未通过持续运行检查")
}
func (b SystemBackend) Stop() error {
	return b.ServiceManager().Stop("qingnode")
}
