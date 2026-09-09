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
	"strconv"
	"strings"
	"time"
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
	if archive == "" && VerifyCore(root, v) == nil {
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
	b, e := Run(10*time.Second, staged, "version")
	if e != nil || !strings.Contains(string(b), "sing-box version "+v+"\n") {
		return errors.New("下载核心的架构或版本不匹配")
	}
	if !strings.Contains(string(b), "with_quic") || !strings.Contains(string(b), "with_utls") || !strings.Contains(string(b), "with_acme") {
		return errors.New("核心构建缺少 QUIC/uTLS/ACME 能力")
	}
	bh := sha256.Sum256(binary)
	if e = AtomicWrite(staged+".sha256", []byte(hex.EncodeToString(bh[:])+"\n"), 0644); e != nil {
		return e
	}
	if VerifyCore(root, v) == nil {
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
	Root     string
	Execute  Runner
	ProcRoot string
}

func (b SystemBackend) run(t time.Duration, name string, args ...string) ([]byte, error) {
	if b.Execute != nil {
		return b.Execute(t, name, args...)
	}
	return Run(t, name, args...)
}
func (b SystemBackend) PID() int {
	out, e := b.run(8*time.Second, "systemctl", "show", "qingnode.service", "--property=MainPID", "--value")
	if e != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
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
	if e := (Firewall{Execute: b.Execute}).Check(s); e != nil {
		return e
	}
	if e := ValidateCertificateDates(s); e != nil {
		return e
	}
	if e := VerifyCore(b.Root, s.CoreVersion); e != nil {
		return e
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
	old, _ := ReadState(filepath.Join(b.Root, "current", "state.json"))
	owned := map[string]bool{}
	for _, socket := range b.Sockets() {
		if socket.Owned {
			owned[fmt.Sprintf("%s/%d/%s", socket.Network, socket.Port, socket.Address)] = true
		}
	}
	for _, n := range s.Nodes {
		if !n.Enabled {
			continue
		}
		address := net.JoinHostPort(n.Listen, fmt.Sprint(n.Port))
		for _, network := range Networks(n) {
			if !owned[fmt.Sprintf("%s/%d/%s", network, n.Port, n.Listen)] {
				if e := available(network, address); e != nil {
					return fmt.Errorf("端口 %s/%s 无法绑定；请用 qingnode ports 查看占用并选择新端口：%w", address, network, e)
				}
			}
		}
		if n.Certificate != nil && n.Certificate.Mode == "acme" {
			hadACME := false
			for _, o := range old.Nodes {
				if o.Enabled && o.Certificate != nil && o.Certificate.Mode == "acme" {
					hadACME = true
				}
			}
			if !hadACME {
				if e := available("tcp", "0.0.0.0:80"); e != nil {
					return errors.New("ACME HTTP-01 需要 TCP 80；该端口已被占用，请使用已有证书")
				}
			}
		}
	}
	return nil
}
func available(network, address string) error {
	if network == "udp" {
		l, e := net.ListenPacket(network, address)
		if e == nil {
			l.Close()
		}
		return e
	}
	l, e := net.Listen(network, address)
	if e == nil {
		l.Close()
	}
	return e
}
func (b SystemBackend) Active() bool {
	_, e := b.run(10*time.Second, "systemctl", "is-active", "--quiet", "qingnode.service")
	return e == nil
}
func (b SystemBackend) restartService(s State) error {
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
	deadline := time.Now().Add(45 * time.Second)
	success := 0
	for time.Now().Before(deadline) {
		if b.Active() && SocketsReady(s, b.Sockets()) {
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
	_, e := b.run(20*time.Second, "systemctl", "stop", "qingnode.service")
	return e
}
