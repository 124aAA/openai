package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

type diagnosticCheck struct {
	ID       string `json:"id"`
	Scope    string `json:"scope"`
	Label    string `json:"label"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
	NextStep string `json:"next_step,omitempty"`
}

type diagnosticReport struct {
	Version       int               `json:"version"`
	Kind          string            `json:"kind"`
	At            time.Time         `json:"at"`
	Location      string            `json:"measurement_location"`
	Offline       bool              `json:"offline"`
	PublicIngress string            `json:"public_ingress"`
	Status        string            `json:"status"`
	Checks        []diagnosticCheck `json:"checks"`
	Issues        []string          `json:"issues"`
}

func (r *diagnosticReport) add(s node.State, id, scope, label, status, message, next string) {
	clean := func(v string) string { return ui.SanitizeText(node.Redact(v, s)) }
	r.Checks = append(r.Checks, diagnosticCheck{ID: id, Scope: scope, Label: clean(label), Status: status, Message: clean(message), NextStep: clean(next)})
}

func (r *diagnosticReport) finish() {
	if len(r.Checks) == 0 {
		r.Status = "unknown"
		return
	}
	r.Status = "healthy"
	if len(r.Issues) > 0 {
		r.Status = "degraded"
	}
	for _, c := range r.Checks {
		if c.Status == "failed" {
			r.Status = "failed"
			return
		}
		if c.Status == "degraded" {
			r.Status = "degraded"
		} else if c.Status == "unknown" && r.Status == "healthy" {
			r.Status = "unknown"
		}
	}
}

func (a *app) doctorJSON(w io.Writer) error {
	r := diagnosticReport{Version: 1, Kind: "qingnode-diagnostic", At: time.Now().UTC(), Location: "server", Offline: a.offline, PublicIngress: "unknown", Checks: []diagnosticCheck{}, Issues: []string{}}
	err := a.store.Inspect(func() error {
		if _, err := os.Lstat(filepath.Join(a.store.Root, "current")); errors.Is(err, os.ErrNotExist) {
			r.add(node.NewState(), "state", "local", "已提交配置", "unknown", "未发现已提交配置；尚未初始化或恢复材料需要核对", "qingnode status --json")
			r.add(node.NewState(), "remaining-checks", "not-measured", "其余检查", "unknown", "没有以默认配置代替真实配置进行检查", "")
			return errors.New("未发现已提交配置；未执行其余检查")
		}
		s, err := a.store.Load()
		if err == nil {
			err = s.Validate()
		}
		if err != nil {
			// Do not inspect a fabricated default State when the real format
			// cannot be read, or echo arbitrary unknown JSON keys as an error.
			r.add(node.NewState(), "state", "local", "读取受管状态", "failed", "状态格式、所有权或读取失败；保留原文件排查", "qingnode restore --help")
			r.add(node.NewState(), "remaining-checks", "local", "其余检查", "unknown", "缺少可读取的真实配置，未执行核心或网络检查", "")
			return errors.New("诊断无法读取受管状态；未执行其余检查")
		}
		return a.doctorWithReport(s, nil, &r)
	})
	if len(r.Checks) == 0 {
		r.add(node.NewState(), "inspection", "local", "只读检查锁与受管路径", "failed", "无法取得一致的只读视图；未修复事务或启动服务", "qingnode status --help")
		r.add(node.NewState(), "remaining-checks", "not-measured", "其余检查", "unknown", "未执行", "")
	}
	r.finish()
	return errors.Join(err, json.NewEncoder(w).Encode(r))
}
