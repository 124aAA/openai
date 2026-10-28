package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

type diagnosticRunner func(time.Duration, string, ...string) ([]byte, error)

type listenerObservation struct {
	Transport   string `json:"transport"`
	State       string `json:"state"`
	Local       string `json:"local_endpoint"`
	Peer        string `json:"peer_endpoint"`
	Family      string `json:"address_family"`
	ProcessIDs  []int  `json:"process_ids"`
	ProcessInfo string `json:"process_observation"`
	Ownership   string `json:"qingnode_ownership"`
}

type listenerReport struct {
	Version        int                   `json:"version"`
	Kind           string                `json:"kind"`
	At             time.Time             `json:"at"`
	Location       string                `json:"measurement_location"`
	QueryStatus    string                `json:"query_status"`
	PublicIngress  string                `json:"public_ingress"`
	Authentication string                `json:"proxy_authentication"`
	UDPBusiness    string                `json:"udp_business_traffic"`
	Listeners      []listenerObservation `json:"listeners"`
	UnparsedLines  int                   `json:"unparsed_lines_observed"`
	Truncated      bool                  `json:"truncated"`
	MaxRecords     int                   `json:"max_records"`
	ErrorCategory  string                `json:"error_category,omitempty"`
}

var listenerPID = regexp.MustCompile(`\bpid=([1-9][0-9]*)\b`)

func observeListeners(run diagnosticRunner) (listenerReport, error) {
	r := listenerReport{Version: 1, Kind: "qingnode-host-listeners", At: time.Now().UTC(), Location: "server", QueryStatus: "completed", PublicIngress: "unknown", Authentication: "not-tested", UDPBusiness: "not-tested", Listeners: []listenerObservation{}, MaxRecords: 4096}
	b, err := run(8*time.Second, "ss", "-H", "-lntup")
	if err != nil {
		r.QueryStatus, r.ErrorCategory = "failed", "listener-query-failed"
		r.Listeners = nil
		message := "无法读取本机监听；请核对ss工具、本机权限及系统日志"
		switch {
		case errors.Is(err, errDiagnosticOutputLimit):
			r.ErrorCategory, r.Truncated = "result-size-limit", true
			message = "监听结果超过4MiB上限；没有完整监听数据"
		case errors.Is(err, context.DeadlineExceeded):
			r.ErrorCategory = "timeout"
			message = "监听查询超过8秒预算；没有完整监听数据"
		case errors.Is(err, context.Canceled):
			r.QueryStatus, r.ErrorCategory = "canceled", "canceled"
			return r, errors.Join(errors.New("监听检查已取消；没有完整监听数据"), context.Canceled)
		case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist):
			r.ErrorCategory = "tool-unavailable"
			message = "未找到ss工具；请核对本机依赖"
		case errors.Is(err, os.ErrPermission):
			r.ErrorCategory = "permission-denied"
			message = "本机监听查询权限不足"
		}
		return r, errors.New(message)
	}
	if len(b) > 4<<20 {
		r.QueryStatus, r.ErrorCategory, r.Truncated = "failed", "result-size-limit", true
		r.Listeners = nil
		return r, errors.New("监听查询结果超过4MiB上限")
	}
	clean := func(v string) string { return ui.SanitizeText(node.Redact(v)) }
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(r.Listeners) >= r.MaxRecords {
			r.Truncated = true
			break
		}
		if len(fields) < 6 || (fields[0] != "tcp" && fields[0] != "udp") || !observedSocketEndpoint(fields[4], true) || !observedSocketEndpoint(fields[5], false) {
			r.UnparsedLines++
			continue
		}
		item := listenerObservation{Transport: fields[0], State: clean(fields[1]), Local: clean(fields[4]), Peer: clean(fields[5]), Family: "unknown", ProcessInfo: "unavailable", Ownership: "not-classified"}
		host, _, parseErr := net.SplitHostPort(fields[4])
		if parseErr == nil {
			if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
				host = host[:zone]
			}
			if ip := net.ParseIP(host); ip != nil {
				item.Family = "ipv6"
				if ip.To4() != nil {
					item.Family = "ipv4"
				}
			}
		}
		seen := map[int]bool{}
		for _, match := range listenerPID.FindAllStringSubmatch(strings.Join(fields[6:], " "), -1) {
			pid, err := strconv.Atoi(match[1])
			if err == nil && !seen[pid] {
				seen[pid] = true
				item.ProcessIDs = append(item.ProcessIDs, pid)
			}
		}
		if len(item.ProcessIDs) > 0 {
			item.ProcessInfo = "available"
			sort.Ints(item.ProcessIDs)
		}
		r.Listeners = append(r.Listeners, item)
	}
	if r.UnparsedLines > 0 || r.Truncated {
		r.QueryStatus, r.ErrorCategory = "partial", "unsupported-or-limited-listener-output"
		return r, errors.New("监听结果不完整；仅输出可识别记录，不能视为完整检查成功")
	}
	return r, nil
}

func observedSocketEndpoint(raw string, local bool) bool {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return false
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if host != "*" && net.ParseIP(host) == nil {
		return false
	}
	if port == "*" {
		return !local
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535 && (!local || n > 0)
}
