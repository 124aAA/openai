package node

// This report has no node/configuration dependency. It reads bounded local
// facts and owns only temporary loopback sockets; it never applies policy.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type CapabilityOptions struct {
	// RootDir maps absolute Paths and fixed /dev and container-marker paths
	// into a test root. ProcRoot/SysRoot independently override its proc/sys.
	ProcRoot, SysRoot, RootDir string
	Paths                      []string
	Context                    context.Context
	Timeout                    time.Duration // per loopback check, capped at 2s
	SkipLoopback               bool
	SkipLoopbackExchange       bool
	// LoopbackProbe is a deterministic test seam, never an external command.
	LoopbackProbe func(context.Context, string, bool) CapabilityCheck
}

type CapabilityCheck struct {
	Available         *bool  `json:"available"`
	Exercised         bool   `json:"exercised"`
	ExchangeExercised bool   `json:"exchange_exercised"`
	ExchangeSucceeded *bool  `json:"exchange_succeeded"`
	Reason            string `json:"reason,omitempty"`
	ErrorCategory     string `json:"error_category,omitempty"`
}

type CapabilityValue struct {
	Value     *string `json:"value"`
	Exercised bool    `json:"exercised"`
	Reason    string  `json:"reason,omitempty"`
}

type CapabilityMemory struct {
	EffectiveAvailableBytes *uint64 `json:"effective_available_bytes"`
	Exercised               bool    `json:"exercised"`
	Reason                  string  `json:"reason,omitempty"`
}

type CapabilityPath struct {
	Path           string `json:"path"`
	Exists         *bool  `json:"exists"`
	CheckedPath    string `json:"checked_path,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Readable       *bool  `json:"readable"`
	Writable       *bool  `json:"writable"`
	Searchable     *bool  `json:"searchable"`
	WriteExercised bool   `json:"write_exercised"`
	Reason         string `json:"reason,omitempty"`
}

type CapabilityPrivileges struct {
	EffectiveUID    int     `json:"effective_uid"`
	EffectiveMask   *string `json:"effective_capabilities_hex"`
	NetAdmin        *bool   `json:"cap_net_admin"`
	NetBindService  *bool   `json:"cap_net_bind_service"`
	SysAdmin        *bool   `json:"cap_sys_admin"`
	NoNewPrivileges *bool   `json:"no_new_privileges"`
	SeccompMode     *uint64 `json:"seccomp_mode"`
	Reason          string  `json:"reason,omitempty"`
}

type CapabilityTUN struct {
	Present         *bool  `json:"device_present"`
	CharacterDevice *bool  `json:"character_device"`
	Readable        *bool  `json:"read_access"`
	Writable        *bool  `json:"write_access"`
	Available       *bool  `json:"available"`
	Exercised       bool   `json:"exercised"`
	Reason          string `json:"reason"`
}

type CapabilityContainer struct {
	Detected *bool    `json:"detected"`
	Evidence []string `json:"evidence"`
	Reason   string   `json:"reason"`
}

type RuntimeCapabilities struct {
	Version      int                        `json:"version"`
	Source       string                     `json:"source"`
	StartedAt    time.Time                  `json:"started_at"`
	FinishedAt   time.Time                  `json:"finished_at"`
	GOOS         string                     `json:"goos"`
	GOARCH       string                     `json:"goarch"`
	PID1         CapabilityValue            `json:"pid1_init"`
	SystemdPID1  *bool                      `json:"systemd_pid1"`
	Memory       CapabilityMemory           `json:"memory"`
	Privileges   CapabilityPrivileges       `json:"privileges"`
	Container    CapabilityContainer        `json:"container"`
	Sysctl       map[string]CapabilityValue `json:"sysctl"`
	Loopback     map[string]CapabilityCheck `json:"loopback"`
	TUN          CapabilityTUN              `json:"tun"`
	Paths        []CapabilityPath           `json:"paths"`
	PathsOmitted int                        `json:"paths_omitted"`
	RemotePath   CapabilityCheck            `json:"remote_path"`
	Notes        []string                   `json:"notes"`
}

var capabilitySysctlKeys = []string{
	"net.ipv6.bindv6only", "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6",
	"net.ipv4.ip_forward", "net.ipv4.tcp_available_congestion_control", "net.ipv4.tcp_congestion_control",
	"net.core.default_qdisc", "net.core.rmem_max", "net.core.wmem_max",
}

func capabilityBool(value bool) *bool { return &value }

// ProbeCapabilities never loads State, invokes services, writes files/sysctls,
// opens TUN, or changes routes. Available loopback means bind succeeded on this
// process's namespace; exchange success is a separate, strictly local fact.
func ProbeCapabilities(options CapabilityOptions) RuntimeCapabilities {
	r := RuntimeCapabilities{
		Version: 1, Source: "qingnode-local-capabilities", StartedAt: time.Now().UTC(),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		PID1:       CapabilityValue{Reason: "尚未读取PID1来源。"},
		Memory:     CapabilityMemory{Reason: "尚未读取有效内存来源。"},
		Privileges: CapabilityPrivileges{EffectiveUID: os.Geteuid(), Reason: "尚未读取进程能力来源。"},
		TUN:        CapabilityTUN{Reason: "尚未检查TUN设备；未打开设备或执行ioctl。"},
		Container:  CapabilityContainer{Evidence: []string{}, Reason: "尚未检查容器标记。"},
		Sysctl:     map[string]CapabilityValue{}, Loopback: map[string]CapabilityCheck{}, Paths: []CapabilityPath{},
		RemotePath: CapabilityCheck{Reason: "未发起远程测试；本机能力不证明代理认证、外部链路或公网可达。"},
		Notes: []string{
			"只读取当前进程可见事实；不代表专用服务账户、其它命名空间或远端客户端权限。",
			"IPv4/IPv6、TCP/UDP 分别报告；回环试验只绑定自有随机端口，每种最多发送32字节并接收32字节响应。",
			"bindv6only 是系统默认值，不等于已有套接字实际 IPV6_V6ONLY；回环能力也不证明生产 :: 入站双栈。",
			"目录与设备仅检查访问权限，不实际写入、打开TUN或执行ioctl；容器、LSM、只读挂载和服务沙箱仍可能另有限制。",
			"有效可用内存取宿主与当前进程可见cgroup余额最小值；不是预留内存或RSS保证。",
		},
	}
	root := options.RootDir
	if root == "" {
		root = string(filepath.Separator)
	}
	if !filepath.IsAbs(root) {
		r.Notes = append(r.Notes, "RootDir须为绝对路径；拒绝回落到真实宿主读取。")
		r.FinishedAt = time.Now().UTC()
		return r
	}
	root = filepath.Clean(root)
	proc, sys := options.ProcRoot, options.SysRoot
	if proc == "" {
		proc = filepath.Join(root, "proc")
	}
	if sys == "" {
		sys = filepath.Join(root, "sys")
	}
	r.PID1 = capabilityReadValue(filepath.Join(proc, "1", "comm"), false)
	if r.PID1.Value != nil {
		r.SystemdPID1 = capabilityBool(*r.PID1.Value == "systemd")
	}
	r.Memory.Exercised = true
	if memory, err := AvailableMemory(proc, sys); err != nil {
		r.Memory.Reason = Redact(err.Error())
	} else {
		r.Memory.EffectiveAvailableBytes = memory
		r.Memory.Reason = ""
	}
	r.Privileges = capabilityPrivileges(proc)
	r.Container = capabilityContainer(root, proc)
	for _, key := range capabilitySysctlKeys {
		r.Sysctl[key] = capabilityReadValue(filepath.Join(proc, "sys", filepath.FromSlash(strings.ReplaceAll(key, ".", "/"))), true)
	}
	r.TUN = capabilityTUN(root)
	paths := options.Paths
	if len(paths) > 32 {
		r.PathsOmitted = len(paths) - 32
		paths = paths[:32]
		r.Notes = append(r.Notes, "指定路径超过32项，超出部分未检查。")
	}
	for _, path := range paths {
		r.Paths = append(r.Paths, capabilityPath(root, path))
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	probe := options.LoopbackProbe
	if probe == nil {
		probe = capabilityLoopback
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		if options.SkipLoopback {
			r.Loopback[network] = CapabilityCheck{Reason: "本次明确未执行回环绑定或数据收发。"}
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, timeout)
		r.Loopback[network] = probe(bounded, network, !options.SkipLoopbackExchange)
		cancel()
	}
	r.FinishedAt = time.Now().UTC()
	return r
}

// A nonblocking, bounded regular-file reader avoids device/FIFO hangs and
// refuses a leaf symlink into credentials. Only fixed proc/sys paths call it.
func capabilityRead(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("不支持的只读来源类型或大小")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("只读来源超过大小上限")
	}
	return data, err
}

func capabilityReadValue(path string, tokensOnly bool) CapabilityValue {
	r := CapabilityValue{Exercised: true}
	data, err := capabilityRead(path, 4096)
	if err != nil {
		r.Reason = "本机来源缺失、无权限或格式不支持；值未知。"
		return r
	}
	value := strings.TrimSpace(string(data))
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
		r.Reason = "本机来源为空、过长或含不支持的多行值；值未知。"
		return r
	}
	if tokensOnly {
		for _, c := range value {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ' ') {
				r.Reason = "本机参数格式不支持；值未知。"
				return r
			}
		}
	}
	value = Redact(value)
	r.Value = &value
	return r
}

func capabilityPrivileges(proc string) CapabilityPrivileges {
	r := CapabilityPrivileges{EffectiveUID: os.Geteuid()}
	data, err := capabilityRead(filepath.Join(proc, "self", "status"), 64<<10)
	if err != nil {
		r.Reason = "无法读取当前进程能力与沙箱状态；不能由root身份推断权限。"
		return r
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	mask, err := strconv.ParseUint(values["CapEff"], 16, 64)
	if err == nil && len(values["CapEff"]) <= 16 {
		hex := strconv.FormatUint(mask, 16)
		r.EffectiveMask = &hex
		r.NetAdmin = capabilityBool(mask&(1<<12) != 0)
		r.NetBindService = capabilityBool(mask&(1<<10) != 0)
		r.SysAdmin = capabilityBool(mask&(1<<21) != 0)
	}
	if v := values["NoNewPrivs"]; v == "0" || v == "1" {
		r.NoNewPrivileges = capabilityBool(v == "1")
	}
	if v, e := strconv.ParseUint(values["Seccomp"], 10, 64); e == nil && v <= 2 {
		r.SeccompMode = &v
	}
	if r.EffectiveMask == nil || r.NoNewPrivileges == nil || r.SeccompMode == nil {
		r.Reason = "部分进程能力或沙箱字段缺失/无效；缺失项未知。"
	}
	return r
}

func capabilityContainer(root, proc string) CapabilityContainer {
	r := CapabilityContainer{Evidence: []string{}, Reason: "没有充分证据确认是否容器；未扫描环境变量或全机进程。"}
	for _, name := range []string{".dockerenv", "run/.containerenv", "run/systemd/container"} {
		if info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name))); err == nil && info.Mode().IsRegular() {
			r.Evidence = append(r.Evidence, "/"+name)
		}
	}
	if data, err := capabilityRead(filepath.Join(proc, "self", "cgroup"), 64<<10); err == nil {
		text := strings.ToLower(string(data))
		for _, marker := range []string{"docker", "kubepods", "containerd", "libpod", "lxc"} {
			if strings.Contains(text, marker) {
				r.Evidence = append(r.Evidence, "cgroup-marker:"+marker)
			}
		}
	}
	if len(r.Evidence) > 0 {
		r.Detected = capabilityBool(true)
		r.Reason = "检测到容器标记；仍须分别检查当前权限、设备与cgroup约束。"
	}
	return r
}

func capabilityAccess(path string, mode uint32) *bool {
	err := unix.Faccessat(unix.AT_FDCWD, path, mode, unix.AT_EACCESS)
	if err == nil {
		return capabilityBool(true)
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
		return capabilityBool(false)
	}
	return nil
}

func capabilityPath(root, requested string) CapabilityPath {
	r := CapabilityPath{Path: Redact(requested)}
	if !filepath.IsAbs(requested) || len(requested) > 4096 || strings.ContainsAny(requested, "\x00\r\n\t") {
		r.Path = "[无效路径]"
		r.Reason = "只检查明确的绝对路径；未访问无效输入。"
		return r
	}
	current := filepath.Join(root, strings.TrimPrefix(filepath.Clean(requested), string(filepath.Separator)))
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if r.Exists == nil {
				r.Exists = capabilityBool(true)
			}
			resolved, e := filepath.EvalSymlinks(current)
			if e != nil {
				r.Reason = "路径或祖先含无法解析的链接；不推断可写性。"
				return r
			}
			rel, e := filepath.Rel(root, resolved)
			if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				r.Reason = "解析后路径越过指定检查根；未访问目标。"
				return r
			}
			if info.Mode()&os.ModeSymlink != 0 {
				info, e = os.Stat(resolved)
				if e != nil {
					r.Reason = "链接目标状态未知。"
					return r
				}
			}
			if r.Exists != nil && !*r.Exists && !info.IsDir() {
				r.Reason = "最近现存祖先不是目录；目标路径不能据此创建。"
				return r
			}
			r.CheckedPath = Redact(resolved)
			r.Kind = "file"
			if info.IsDir() {
				r.Kind = "directory"
				r.Searchable = capabilityAccess(resolved, unix.X_OK)
			}
			r.Readable = capabilityAccess(resolved, unix.R_OK)
			writeMode := uint32(unix.W_OK)
			if info.IsDir() {
				writeMode |= unix.X_OK
			}
			r.Writable = capabilityAccess(resolved, writeMode)
			r.Reason = "仅按当前有效身份检查访问权限，write_exercised=false；未创建目录或文件，未验证实际写入。"
			if !*r.Exists {
				r.Reason = "目标不存在，仅检查最近现存父目录的访问权限；未创建目标，write_exercised=false。"
			}
			return r
		}
		if !os.IsNotExist(err) {
			r.Reason = "路径状态不可读；存在性与访问权限未知。"
			return r
		}
		if r.Exists == nil {
			r.Exists = capabilityBool(false)
		}
		parent := filepath.Dir(current)
		if parent == current {
			r.Reason = "没有可检查的现存父目录。"
			return r
		}
		current = parent
	}
}

func capabilityTUN(root string) CapabilityTUN {
	r := CapabilityTUN{Reason: "未打开TUN、未执行ioctl；设备访问位不证明实际创建接口权限。"}
	path := filepath.Join(root, "dev", "net", "tun")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		r.Present = capabilityBool(false)
		r.Available = capabilityBool(false)
		r.Reason = "当前/dev/net/tun不存在；未创建设备或加载模块。"
		return r
	}
	if err != nil {
		r.Reason = "TUN设备状态不可读，实际可用性未知；未打开设备。"
		return r
	}
	r.Present = capabilityBool(true)
	character := info.Mode()&os.ModeCharDevice != 0
	r.CharacterDevice = capabilityBool(character)
	if !character {
		r.Available = capabilityBool(false)
		r.Reason = "该路径不是字符设备；未打开、跟随链接或创建设备。"
		return r
	}
	r.Readable = capabilityAccess(path, unix.R_OK)
	r.Writable = capabilityAccess(path, unix.W_OK)
	return r
}

func capabilityLoopback(ctx context.Context, network string, exchange bool) CapabilityCheck {
	r := CapabilityCheck{}
	if err := ctx.Err(); err != nil {
		r.Reason = "回环检查在绑定前取消。"
		r.ErrorCategory = capabilityErrorCategory(err)
		return r
	}
	address := "127.0.0.1:0"
	if strings.HasSuffix(network, "6") {
		address = "[::1]:0"
	}
	var lc net.ListenConfig
	var listener net.Listener
	var packet net.PacketConn
	var err error
	if strings.HasPrefix(network, "tcp") {
		listener, err = lc.Listen(ctx, network, address)
	} else {
		packet, err = lc.ListenPacket(ctx, network, address)
	}
	r.Exercised = true
	if err != nil {
		r.ErrorCategory = capabilityErrorCategory(err)
		if r.ErrorCategory != "canceled" && r.ErrorCategory != "timeout" {
			r.Available = capabilityBool(false)
		}
		r.Reason = "该本机回环绑定失败；不推断其它地址族或远程链路。"
		return r
	}
	r.Available = capabilityBool(true)
	if listener != nil {
		defer listener.Close()
	} else {
		defer packet.Close()
	}
	stop := context.AfterFunc(ctx, func() {
		if listener != nil {
			listener.Close()
		} else {
			packet.Close()
		}
	})
	defer stop()
	if !exchange {
		r.Reason = "只完成本机临时绑定，未执行小包响应。"
		return r
	}
	r.ExchangeExercised = true
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(500 * time.Millisecond)
	}
	payload := make([]byte, 32)
	if _, err = rand.Read(payload); err != nil {
		r.Reason = "已绑定，但验证数据不可用。"
		r.ErrorCategory = "verification_unavailable"
		return r
	}
	if listener != nil {
		err = capabilityTCPExchange(ctx, network, listener, deadline, payload)
	} else {
		err = capabilityUDPExchange(ctx, network, packet, deadline, payload)
	}
	r.ExchangeSucceeded = capabilityBool(err == nil)
	if err != nil {
		r.ErrorCategory = capabilityErrorCategory(err)
		r.Reason = "本机绑定成功，但小包响应失败；不把绑定成功当作传输成功。"
	} else {
		r.Reason = "本机回环绑定与32字节请求/响应已完成；未测试代理或远程链路。"
	}
	return r
}

func capabilityTCPExchange(ctx context.Context, network string, listener net.Listener, deadline time.Time, payload []byte) error {
	if tcp, ok := listener.(*net.TCPListener); ok {
		if err := tcp.SetDeadline(deadline); err != nil {
			return err
		}
	}
	client, err := (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	if err != nil {
		return err
	}
	defer client.Close()
	stopClient := context.AfterFunc(ctx, func() { client.Close() })
	defer stopClient()
	if err = client.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err = client.Write(payload); err != nil {
		return err
	}
	server, err := listener.Accept()
	if err != nil {
		return err
	}
	defer server.Close()
	stopServer := context.AfterFunc(ctx, func() { server.Close() })
	defer stopServer()
	if err = server.SetDeadline(deadline); err != nil {
		return err
	}
	actual := make([]byte, len(payload))
	if _, err = io.ReadFull(server, actual); err != nil {
		return err
	}
	if !bytes.Equal(actual, payload) {
		return errors.New("回环验证数据不一致")
	}
	if _, err = server.Write(actual); err != nil {
		return err
	}
	if _, err = io.ReadFull(client, actual); err != nil {
		return err
	}
	if !bytes.Equal(actual, payload) {
		return errors.New("回环响应不一致")
	}
	return nil
}

func capabilityUDPExchange(ctx context.Context, network string, packet net.PacketConn, deadline time.Time, payload []byte) error {
	if err := packet.SetDeadline(deadline); err != nil {
		return err
	}
	client, err := (&net.Dialer{}).DialContext(ctx, network, packet.LocalAddr().String())
	if err != nil {
		return err
	}
	defer client.Close()
	stopClient := context.AfterFunc(ctx, func() { client.Close() })
	defer stopClient()
	if err = client.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err = client.Write(payload); err != nil {
		return err
	}
	actual := make([]byte, len(payload)+1)
	n, peer, err := packet.ReadFrom(actual)
	if err != nil {
		return err
	}
	if n != len(payload) || !bytes.Equal(actual[:n], payload) {
		return errors.New("UDP回环验证数据不一致")
	}
	if _, err = packet.WriteTo(payload, peer); err != nil {
		return err
	}
	n, err = client.Read(actual)
	if err != nil {
		return err
	}
	if n != len(payload) || !bytes.Equal(actual[:n], payload) {
		return errors.New("UDP回环响应不一致")
	}
	return nil
}

func capabilityErrorCategory(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return "permission_denied"
	}
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return "family_unavailable"
	}
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return "address_unavailable"
	}
	return "local_probe_failed"
}
