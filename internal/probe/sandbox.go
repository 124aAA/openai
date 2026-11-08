package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SandboxOptions struct {
	CoreBinary string
	SHA256     string // Explicit trusted binary digest, never a downloaded executable.
	TempParent string
}
type Sandbox struct {
	Address   string
	Directory string
	PID       int
	Version   string
	Username  string
	Password  string
	cmd       *exec.Cmd
	done      chan struct{}
	once      sync.Once
	closeErr  error
}

// SandboxConfig has exactly one outbound. Destination names are sent to the
// selected node. System DNS is used only to bootstrap that node's server name.
// Family-specific tests require literal destination IPs at the option boundary.
func SandboxConfig(p Profile, port int) ([]byte, error) {
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return sandboxConfig(p, port, "qingprobe", hex.EncodeToString(secret))
}
func sandboxConfig(p Profile, port int, username, password string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid temporary listener port")
	}
	return json.MarshalIndent(map[string]any{
		"log":       map[string]any{"disabled": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "bootstrap"}}},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "probe", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": username, "password": password}}}},
		"outbounds": []json.RawMessage{p.Outbound},
		"route":     map[string]any{"final": "proxy", "default_domain_resolver": "bootstrap"},
	}, "", "  ")
}

func verifyProbeCore(ctx context.Context, p Profile, opts SandboxOptions) (string, error) {
	var o outbound
	_ = json.Unmarshal(p.Outbound, &o)
	return verifyProbeCoreTypes(ctx, []string{o.Type}, opts)
}

func verifyProbeCoreTypes(ctx context.Context, kinds []string, opts SandboxOptions) (string, error) {
	if !filepath.IsAbs(opts.CoreBinary) || len(opts.SHA256) != 64 || strings.Trim(opts.SHA256, "0123456789abcdef") != "" {
		return "", errors.New("client core needs an absolute path and trusted lowercase binary SHA-256")
	}
	i, err := os.Lstat(opts.CoreBinary)
	if err != nil || !i.Mode().IsRegular() || i.Size() > 256<<20 {
		return "", errors.New("client core must be a regular executable file")
	}
	f, err := os.Open(opts.CoreBinary)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		var n int
		n, err = f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
		if err != nil {
			break
		}
	}
	f.Close()
	if err != nil {
		return "", err
	}
	if hex.EncodeToString(h.Sum(nil)) != opts.SHA256 {
		return "", errors.New("client core SHA-256 does not match")
	}
	vctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(vctx, opts.CoreBinary, "version")
	prepareProcess(cmd)
	var b limitedOutput
	cmd.Stdout = &b
	cmd.Stderr = &b
	if err = cmd.Run(); err != nil {
		return "", errors.New("client core version query failed")
	}
	version := ""
	tags := map[string]bool{}
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "sing-box version ") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "sing-box version "))
		}
		if strings.HasPrefix(line, "Tags:") {
			for _, t := range strings.FieldsFunc(strings.TrimPrefix(line, "Tags:"), func(r rune) bool { return r == ',' || r == ' ' || r == '\r' || r == '\t' }) {
				tags[t] = true
			}
		}
	}
	if err := checkProbeCoreCapabilities(version, tags, kinds); err != nil {
		return "", err
	}
	return version, nil
}

func checkProbeCoreCapabilities(version string, tags map[string]bool, kinds []string) error {
	if !compatibleCore.MatchString(version) {
		return errors.New("client core is outside the supported stable 1.14.x line")
	}
	for _, kind := range kinds {
		if kind == "vless" && !tags["with_utls"] {
			return errors.New("client core lacks with_utls")
		}
		if (kind == "hysteria2" || kind == "tuic") && !tags["with_quic"] {
			return errors.New("client core lacks with_quic")
		}
		if kind == "wireguard" && (!tags["with_wireguard"] || !tags["with_gvisor"]) {
			return errors.New("client core lacks with_wireguard or with_gvisor for userspace WireGuard")
		}
	}
	return nil
}

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (64 << 10) - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func StartSandbox(ctx context.Context, p Profile, opts SandboxOptions) (*Sandbox, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	version, err := verifyProbeCore(ctx, p, opts)
	if err != nil {
		return nil, err
	}
	return startSandbox(ctx, opts, version, func(port int, username, password string) ([]byte, error) {
		return sandboxConfig(p, port, username, password)
	})
}

// All private client entry points share process identity, local authentication,
// bounded validation, cancellation and ownership-based cleanup.
func startSandbox(ctx context.Context, opts SandboxOptions, version string, configFor func(int, string, string) ([]byte, error)) (*Sandbox, error) {
	dir, err := os.MkdirTemp(opts.TempParent, "qingprobe-")
	if err != nil {
		return nil, err
	}
	if err = protectPrivate(dir, true); err != nil {
		os.Remove(dir)
		return nil, err
	}
	s := &Sandbox{Directory: dir, Version: version, done: make(chan struct{})}
	secret := make([]byte, 24)
	if _, err = rand.Read(secret); err != nil {
		os.Remove(dir)
		return nil, err
	}
	s.Username = "qingprobe"
	s.Password = hex.EncodeToString(secret)
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	s.Address = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	config, err := configFor(port, s.Username, s.Password)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "client.json")
	if err = writePrivate(path, config); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	cmd := exec.CommandContext(cctx, opts.CoreBinary, "check", "-c", path)
	prepareProcess(cmd)
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	cancel()
	if err != nil {
		return nil, errors.New("isolated client configuration check failed (private logs suppressed)")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.cmd = exec.Command(opts.CoreBinary, "run", "-c", path)
	s.cmd.Stdout = io.Discard
	s.cmd.Stderr = io.Discard
	prepareProcess(s.cmd)
	if err = s.cmd.Start(); err != nil {
		s.cmd = nil
		return nil, errors.New("isolated client process could not start")
	}
	s.PID = s.cmd.Process.Pid
	go func() { _ = s.cmd.Wait(); close(s.done) }()
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	for {
		select {
		case <-s.done:
			return nil, errors.New("isolated client exited before becoming ready")
		default:
		}
		owned, ownErr := ownedListener(s.PID, port)
		if ownErr != nil {
			return nil, errors.New("temporary listener process ownership could not be verified")
		}
		if !owned {
			select {
			case <-readyCtx.Done():
				return nil, errors.New("owned client listener readiness exceeded deadline")
			case <-s.done:
				return nil, errors.New("isolated client exited during ownership check")
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		conn, e := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(readyCtx, "tcp4", s.Address)
		if e == nil {
			// Authenticate without dialing any destination. A process that races
			// to take the released port cannot pretend to be this temporary core.
			e = checkLocalAuth(conn, s.Username, s.Password, readyCtx)
			conn.Close()
			if e == nil {
				owned, ownErr = ownedListener(s.PID, port)
				if ownErr != nil || !owned {
					return nil, errors.New("temporary client listener ownership changed")
				}
				select {
				case <-s.done:
					return nil, errors.New("isolated client exited after authentication")
				default:
				}
				break
			}
		}
		select {
		case <-readyCtx.Done():
			return nil, errors.New("isolated client readiness exceeded its deadline")
		case <-s.done:
			return nil, errors.New("isolated client exited during readiness")
		case <-time.After(20 * time.Millisecond):
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.done:
		}
	}()
	ok = true
	return s, nil
}

func (s *Sandbox) Done() <-chan struct{} { return s.done }
func (s *Sandbox) Transport() *http.Transport {
	u := &url.URL{Scheme: "http", Host: s.Address, User: url.UserPassword(s.Username, s.Password)}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyURL(u)
	return t
}
func (s *Sandbox) Close() error {
	s.once.Do(func() {
		if s.cmd != nil && s.cmd.Process != nil {
			select {
			case <-s.done:
			default:
				stopProcess(s.cmd, false)
				select {
				case <-s.done:
				case <-time.After(2 * time.Second):
					stopProcess(s.cmd, true)
					<-s.done
				}
			}
		}
		// Directory was freshly created by this instance; no production path is
		// ever passed to RemoveAll. It also owns every file inside the directory.
		if s.Directory != "" {
			s.closeErr = os.RemoveAll(s.Directory)
		}
	})
	return s.closeErr
}

func checkLocalAuth(conn net.Conn, username, password string, ctx context.Context) error {
	deadline := time.Now().Add(200 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response != [2]byte{5, 2} {
		return errors.New("temporary listener did not select authentication")
	}
	b := append([]byte{1, byte(len(username))}, []byte(username)...)
	b = append(b, byte(len(password)))
	b = append(b, []byte(password)...)
	if _, err := conn.Write(b); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response != [2]byte{1, 0} {
		return errors.New("temporary listener authentication failed")
	}
	return nil
}
