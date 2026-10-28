package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"qingnode/internal/node"
	"qingnode/internal/probe"
	"qingnode/internal/probecli"
)

func (a *app) probe(args []string) error {
	if a.offline && len(args) > 0 && (args[0] == "run" || args[0] == "udp-echo") {
		return errors.New("--offline 不执行网络测试；在测试主机使用独立 qingprobe 工具")
	}
	if len(args) > 0 && args[0] == "run" && !probeHelp(args) {
		release, e := a.measurementLeaseIfManaged()
		if e != nil {
			return e
		}
		defer release()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return probecli.Execute(ctx, args, probecli.Hooks{Version: version + "/" + revision, SelectProfile: a.probeProfile, SelectEndpointProfile: a.probeEndpointProfile, DefaultCore: a.probeDefaultCore, ValidateOutput: a.probeOutput})
}

func probeHelp(args []string) bool {
	for _, s := range args {
		if s == "--help" || s == "-h" {
			return true
		}
	}
	return false
}

func (a *app) measurementLeaseIfManaged() (func(), error) {
	// An independent direct probe can predate installation. Do not initialize
	// a managed root solely to obtain a lock when no monitor can exist there.
	if _, e := os.Lstat(a.store.Root); errors.Is(e, os.ErrNotExist) {
		return func() {}, nil
	} else if e != nil {
		return nil, e
	}
	var release func()
	e := a.store.InspectExisting(func() error { var e error; release, e = node.MeasurementLease(a.store.Root); return e })
	return release, e
}
func (a *app) probeProfile(id, user string) (probe.Profile, error) {
	return a.probeEndpointProfile(id, user, "default")
}
func (a *app) probeEndpointProfile(id, user, endpoint string) (probe.Profile, error) {
	var p probe.Profile
	err := a.store.InspectExisting(func() error {
		for _, name := range []string{"transaction.json", "uninstall.json"} {
			_, err := os.Lstat(filepath.Join(a.store.Root, name))
			if err == nil {
				return errors.New("存在中断事务；测试不自动恢复，请先显式 recover")
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		s, err := a.store.Load()
		if err != nil {
			return err
		}
		p, err = buildProbeEndpointProfile(s, id, user, endpoint)
		return err
	})
	return p, err
}

// Build from one already-observed State without touching the management lock
// or reloading files. Each worker owns a clone, so validation and endpoint
// selection cannot mutate another worker's snapshot or mix configuration ages.
func buildProbeEndpointProfile(s node.State, id, user, endpoint string) (probe.Profile, error) {
	s = s.Clone()
	if err := s.Validate(); err != nil {
		return probe.Profile{}, err
	}
	n, err := s.Find(id)
	if err != nil {
		return probe.Profile{}, err
	}
	if !n.Enabled {
		return probe.Profile{}, errors.New("节点已停用，不能当作可用代理进行测试")
	}
	u, err := node.SelectUser(*n, user)
	if err != nil {
		return probe.Profile{}, err
	}
	selected, err := node.WithEndpoint(*n, endpoint)
	if err != nil {
		return probe.Profile{}, err
	}
	if err := node.ValidateHY2ClientCertificate(selected, "sing-box"); err != nil {
		return probe.Profile{}, err
	}
	b, err := json.Marshal(node.Outbound(selected, u))
	if err != nil {
		return probe.Profile{}, err
	}
	p, err := probe.NewProfile(n.ID, s.CoreVersion, b)
	if err != nil {
		return probe.Profile{}, err
	}
	digest, err := node.NodeRouteDigest(s, n.ID)
	if err != nil || digest == "" {
		// Legacy direct routes deliberately have no separate path digest.
		// Keep the valid v1 profile rather than returning an empty success.
		return p, err
	}
	return probe.WithServerPathDigest(p, digest)
}

func (a *app) probeDefaultCore(p probe.Profile) (probe.SandboxOptions, error) {
	path := node.CorePath(a.store.Root, p.CoreVersion)
	b, err := readMonitorBounded(path+".sha256", 128)
	if err != nil {
		return probe.SandboxOptions{}, errors.New("缺少已安装核心摘要；请明确提供 --core 和 --core-sha256")
	}
	return probe.SandboxOptions{CoreBinary: path, SHA256: strings.TrimSpace(string(b))}, nil
}
func (a *app) probeOutput(path string) error {
	return validateExternalOutput(path, []string{a.store.Root, node.NetworkStateDir}, []string{node.NetworkSysctlFile, node.BBRFile})
}

func validateExternalOutput(path string, managedRoots, managedFiles []string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	// Resolve the parent so a symlink cannot place a new result/journal inside
	// managed production data. Existing destinations are refused by O_EXCL.
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return err
	}
	destination := filepath.Join(parent, filepath.Base(abs))
	for _, name := range managedRoots {
		root, e := outputBoundary(name)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, destination)
		if e != nil {
			return e
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("测试结果、计划和私密Profile须保存到节点及宿主网络管理目录之外")
		}
	}
	for _, name := range managedFiles {
		protected, e := outputBoundary(name)
		if e != nil {
			return e
		}
		if destination == protected {
			return errors.New("结果文件不能占用宿主网络受管参数文件")
		}
	}
	return nil
}

// A guard may not exist yet. Resolve its closest existing ancestor so an alias
// cannot hide a future managed directory, without creating that directory.
func outputBoundary(name string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	current := abs
	var suffix []string
	for {
		resolved, e := filepath.EvalSymlinks(current)
		if e == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return "", e
		}
		// ENOENT can mean an existing dangling symlink, rather than an absent
		// boundary. Never replace that unresolved alias with its lexical path:
		// doing so would allow a result to occupy the managed link's target.
		if _, statErr := os.Lstat(current); statErr == nil {
			return "", errors.New("受管边界含无法解析的现有路径；拒绝写入结果")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", e
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}
