package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"qingnode/internal/node"
)

type applyConfirmation struct {
	Generation  *string `json:"generation"`
	DerivedHook string  `json:"derived_material_hook"`
}

type executionResult struct {
	Version            int                 `json:"version"`
	Kind               string              `json:"kind"`
	Command            string              `json:"command"`
	Started            time.Time           `json:"started_at"`
	Finished           *time.Time          `json:"finished_at"`
	Status             string              `json:"status"`
	ExitCode           *int                `json:"exit_code"`
	ExitCodeScope      string              `json:"exit_code_scope"`
	ApplyConfirmations []applyConfirmation `json:"apply_confirmations"`
	ApplyCount         int                 `json:"apply_confirmations_observed"`
	Truncated          bool                `json:"apply_history_truncated"`
	Coverage           string              `json:"apply_observation_scope"`
	SideEffects        string              `json:"side_effects_on_error"`
	Connectivity       string              `json:"connectivity"`
}

// This is a typed execution receipt, not captured human output or a replacement
// for command-specific data. An error may follow a committed Apply, revocation,
// recovery or host change. Never infer "unchanged" from a nonzero exit code.
type executionReporter struct {
	mu        sync.Mutex
	result    executionResult
	parent    *pinnedOutput
	directory *os.Root
	info      os.FileInfo
}

func executionCommand(args []string) string {
	if len(args) == 0 {
		return "unspecified"
	}
	for _, name := range []string{"init", "add", "install", "validate-install", "collect-install", "validate-state", "redact-log", "serve", "help", "version", "capabilities", "reality-targets", "overview", "check-updates", "public-check", "probe", "endpoint", "dns", "diagnose", "doctor", "wizard", "update", "service", "network", "firewall", "self-update", "ports", "recover", "list", "info", "edit", "batch", "hy2", "egress", "route", "forward", "topology", "wireguard", "device", "certificate", "protocols", "monitor", "expiration", "subscription", "enable", "disable", "delete", "user-add", "user-delete", "rotate", "export", "render", "core", "backup", "restore", "check", "apply", "rollback", "start", "stop", "restart", "status", "logs", "uninstall"} {
		if args[0] == name {
			return name
		}
	}
	return "unrecognized"
}

func beginExecutionReport(path, root string, args []string) (*executionReporter, error) {
	if err := validateExternalOutput(path, []string{root, node.NetworkStateDir}, []string{node.NetworkSysctlFile, node.BBRFile}); err != nil {
		return nil, err
	}
	p, err := pinNewOutput(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*executionReporter, error) { p.root.Close(); return nil, err }
	if err = p.root.Mkdir(p.name, 0700); err != nil {
		return fail(err)
	}
	dir, err := p.root.OpenRoot(p.name)
	if err != nil {
		return fail(err)
	}
	info, err := dir.Stat(".")
	if err != nil {
		dir.Close()
		return fail(err)
	}
	r := &executionReporter{parent: p, directory: dir, info: info, result: executionResult{Version: 1, Kind: "qingnode-command-result", Command: executionCommand(args), Started: time.Now().UTC(), Status: "running", ExitCodeScope: "operation-before-receipt-publication; also require the actual process exit code", ApplyConfirmations: []applyConfirmation{}, Coverage: "AfterCommit-hook-only; includes no-op confirmations; may be suppressed during full migration; excludes automatic recovery and other host changes", SideEffects: "unknown; never inferred from exit code", Connectivity: "not-inferred-from-command-success"}}
	if err = r.publish("started.json", r.result); err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

func (r *executionReporter) close() {
	r.directory.Close()
	r.parent.root.Close()
}

func (r *executionReporter) unchanged() error {
	if err := r.parent.unchanged(); err != nil {
		return err
	}
	info, err := r.parent.root.Lstat(r.parent.name)
	if err != nil || !os.SameFile(r.info, info) || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("回执目录已改变；未写入替换后的路径")
	}
	return nil
}

func (r *executionReporter) publish(name string, value executionResult) error {
	if err := r.unchanged(); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	staged := ".result-" + node.Token(8)
	f, err := r.directory.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer r.directory.Remove(staged)
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = r.unchanged(); err != nil {
		return err
	}
	// A hard link publishes a complete file without replacing an existing one.
	if err = r.directory.Link(staged, name); err != nil {
		return err
	}
	d, err := r.directory.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr = d.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return r.unchanged()
}

var executionGeneration = regexp.MustCompile(`^generations/g-[a-f0-9]{32}$`)

func (r *executionReporter) wrapApplyHook(store *node.Store) {
	original := store.AfterCommit
	store.AfterCommit = func(state node.State) error {
		var generation *string
		if value, err := os.Readlink(store.Root + string(os.PathSeparator) + "current"); err == nil && executionGeneration.MatchString(value) {
			generation = &value
		}
		r.mu.Lock()
		r.result.ApplyCount++
		index := len(r.result.ApplyConfirmations)
		if index < 64 {
			r.result.ApplyConfirmations = append(r.result.ApplyConfirmations, applyConfirmation{generation, "pending"})
		} else {
			r.result.Truncated = true
			index = -1
		}
		r.mu.Unlock()
		var err error
		if original != nil {
			err = original(state)
		}
		r.mu.Lock()
		if index >= 0 {
			status := "completed"
			if original == nil {
				status = "not-configured"
			} else if err != nil {
				status = "failed"
			}
			r.result.ApplyConfirmations[index].DerivedHook = status
		}
		r.mu.Unlock()
		return err
	}
}

func (r *executionReporter) finish(operationErr error) error {
	defer r.close()
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	code := commandExitCode(operationErr)
	status := "completed"
	if errors.Is(operationErr, flag.ErrHelp) {
		code = 0
		status = "help"
	} else if errors.Is(operationErr, errMenuCanceled) {
		code = 0
		status = "canceled"
	} else if errors.Is(operationErr, context.Canceled) {
		status = "canceled"
	} else if code == 130 || code == 143 {
		status = "interrupted"
	} else if operationErr != nil {
		status = "failed"
	}
	r.result.Finished, r.result.ExitCode, r.result.Status = &now, &code, status
	if err := r.publish("result.json", r.result); err != nil {
		return fmt.Errorf("命令已执行，但结果回执未能完整发布；不要自动重试写操作，请检查实际状态和恢复材料：%w", err)
	}
	return nil
}
