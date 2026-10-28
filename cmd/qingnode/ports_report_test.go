package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPortJSONSeparatesListenersFromTrafficAndUnknownProcesses(t *testing.T) {
	calls := 0
	run := func(timeout time.Duration, command string, args ...string) ([]byte, error) {
		calls++
		if timeout != 8*time.Second || command != "ss" || !reflect.DeepEqual(args, []string{"-H", "-lntup"}) {
			t.Fatal("unexpected host command or timeout")
		}
		return []byte("tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"private-process-label\",pid=42,fd=5))\n" +
			"udp UNCONN 0 0 [::]:443 [::]:*\n" +
			"tcp LISTEN 0 128 *:22 *:* users:((\"other\",pid=99,fd=7),(\"other\",pid=99,fd=8))\n"), nil
	}
	text, err := wizardOutput(t, func() error { return (&app{}).portsWithRunner([]string{"--json"}, run) })
	if err != nil {
		t.Fatal(err)
	}
	var report listenerReport
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || report.Version != 1 || report.Kind != "qingnode-host-listeners" || report.QueryStatus != "completed" || len(report.Listeners) != 3 {
		t.Fatal("invalid single host observation")
	}
	if report.PublicIngress != "unknown" || report.Authentication != "not-tested" || report.UDPBusiness != "not-tested" {
		t.Fatal("listening was mistaken for authenticated or public transport")
	}
	if report.Listeners[0].Family != "ipv4" || report.Listeners[1].Family != "ipv6" || report.Listeners[2].Family != "unknown" {
		t.Fatal("incorrect address family inference")
	}
	if report.Listeners[1].ProcessIDs != nil || report.Listeners[1].ProcessInfo != "unavailable" || !reflect.DeepEqual(report.Listeners[2].ProcessIDs, []int{99}) {
		t.Fatal("unknown or duplicate process IDs misreported")
	}
	if strings.Contains(text, "private-process-label") || report.Listeners[0].Ownership != "not-classified" {
		t.Fatal("process label exposed or ownership guessed")
	}
}

func TestPortJSONFailuresHaveUnknownDataAndDistinctCategories(t *testing.T) {
	for _, item := range []struct {
		err      error
		category string
	}{{context.DeadlineExceeded, "timeout"}, {context.Canceled, "canceled"}, {exec.ErrNotFound, "tool-unavailable"}, {errDiagnosticOutputLimit, "result-size-limit"}, {errors.New("unknown-private-error-sentinel"), "listener-query-failed"}} {
		t.Run(item.category, func(t *testing.T) {
			text, err := wizardOutput(t, func() error {
				return (&app{}).portsWithRunner([]string{"--json"}, func(time.Duration, string, ...string) ([]byte, error) {
					return []byte("partial private output"), item.err
				})
			})
			if err == nil {
				t.Fatal("failed query returned success")
			}
			var report listenerReport
			if err := json.Unmarshal([]byte(text), &report); err != nil {
				t.Fatal(err)
			}
			wantStatus := "failed"
			if item.category == "canceled" {
				wantStatus = "canceled"
			}
			if report.QueryStatus != wantStatus || report.ErrorCategory != item.category || report.Listeners != nil {
				t.Fatal("failed query became an empty successful listener list")
			}
			if strings.Contains(text, "private") || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("raw tool error leaked")
			}
		})
	}
}

func TestPortJSONUnsupportedAndLimitedOutputAreNotComplete(t *testing.T) {
	for _, input := range []string{"unsupported private header\n", "tcp LISTEN 0 0 malformed-private-address *:*\n", "tcp LISTEN 0 0 127.0.0.1:70000 *:*\n", strings.Repeat("tcp LISTEN 0 0 127.0.0.1:443 0.0.0.0:*\n", 4097)} {
		report, err := observeListeners(func(time.Duration, string, ...string) ([]byte, error) { return []byte(input), nil })
		if err == nil || report.QueryStatus != "partial" || (report.UnparsedLines == 0 && !report.Truncated) {
			t.Fatal("unparsed or truncated observations became a complete success")
		}
		if len(report.Listeners) > 4096 {
			t.Fatal("listener record limit exceeded")
		}
	}
}

func TestPortJSONCommandExecutesOneControlledToolWithoutInitializingState(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "ss")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nprintf '%s\\n' 'udp UNCONN 0 0 [::]:5353 [::]:*'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	root := filepath.Join(t.TempDir(), "not-initialized")
	text, err := wizardOutput(t, func() error { return run([]string{"--offline", "--root", root, "ports", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var report listenerReport
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		t.Fatal(err)
	}
	if report.QueryStatus != "completed" || len(report.Listeners) != 1 || report.Listeners[0].Family != "ipv6" {
		t.Fatal("actual command dispatch did not return structured observations")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("listener query initialized State", err)
	}
}
