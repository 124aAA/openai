package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
)

func networkCLIFixture(t *testing.T) (*app, node.NetworkHost, map[string]string, *int) {
	t.Helper()
	a, _ := batchFixture(t)
	a.offline = false
	values := map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.ipv4.tcp_available_congestion_control": "cubic bbr", "net.core.default_qdisc": "fq_codel"}
	writes := new(int)
	base := t.TempDir()
	h := node.NetworkHost{StateDir: filepath.Join(base, "state"), SysctlFile: filepath.Join(base, "owned.conf"), ProcRoot: filepath.Join(base, "missing-proc"), SysRoot: filepath.Join(base, "missing-sys"), Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name == "tc" {
			return []byte("[]"), nil
		}
		if name != "sysctl" || len(args) != 2 {
			return nil, errors.New("unexpected command")
		}
		if args[0] == "-n" {
			v, ok := values[args[1]]
			if !ok {
				return nil, os.ErrPermission
			}
			return []byte(v), nil
		}
		if args[0] != "-w" {
			return nil, errors.New("unexpected write")
		}
		*writes++
		key, value, _ := strings.Cut(args[1], "=")
		values[key] = value
		return nil, nil
	}}
	return a, h, values, writes
}

func TestNetworkCLIPlanApplyRestoreDoNotTouchNodesOrHistory(t *testing.T) {
	a, h, values, writes := networkCLIFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	g, before := savedBatchState(t, a)
	history := filepath.Join(a.store.Root, "observations.json")
	manual := []byte("manual-public-check-history")
	os.WriteFile(history, manual, 0600)
	journal := filepath.Join(a.store.Root, "transaction.json")
	pending := []byte("pending-node-transaction-must-remain")
	os.WriteFile(journal, pending, 0600)
	for _, args := range [][]string{{"status", "--json"}, {"plan", "--tcp", "bbr", "--qdisc", "fq"}, {"apply", "--tcp", "bbr", "--qdisc", "fq", "--preview"}, {"bbr", "--preview"}} {
		out, e := wizardOutput(t, func() error { return a.networkWithHost(args, h) })
		if e != nil {
			t.Fatal(e)
		}
		if args[0] == "status" {
			var s node.NetworkStatus
			if e = json.Unmarshal([]byte(out), &s); e != nil || s.Version != 1 {
				t.Fatal("JSON status invalid", e)
			}
		} else {
			if !strings.Contains(out, "cubic → 请求 bbr") || !strings.Contains(out, "原始恢复材料：") {
				t.Fatal("preview omitted actual original/recovery path", out)
			}
		}
	}
	if *writes != 0 {
		t.Fatal("read-only commands wrote sysctl")
	}
	if _, e := os.Stat(h.StateDir); !os.IsNotExist(e) {
		t.Fatal("preview initialized host state", e)
	}
	if _, e := wizardOutput(t, func() error { return a.networkWithHost([]string{"apply", "--tcp", "bbr", "--qdisc", "fq"}, h) }); e != nil {
		t.Fatal(e)
	}
	var active struct {
		SnapshotID string `json:"snapshot_id"`
	}
	data, _ := os.ReadFile(filepath.Join(h.StateDir, "active.json"))
	if e := json.Unmarshal(data, &active); e != nil || active.SnapshotID == "" {
		t.Fatal("missing applied snapshot", e)
	}
	count := *writes
	out, e := wizardOutput(t, func() error {
		return a.networkWithHost([]string{"restore", "--snapshot", active.SnapshotID, "--preview"}, h)
	})
	if e != nil || *writes != count || !strings.Contains(out, "bbr → 请求 cubic") {
		t.Fatal("restore preview mutated kernel or omitted actual values", e, out)
	}
	if _, e = wizardOutput(t, func() error { return a.networkWithHost([]string{"restore", "--snapshot", active.SnapshotID}, h) }); e != nil {
		t.Fatal(e)
	}
	if values["net.ipv4.tcp_congestion_control"] != "cubic" || values["net.core.default_qdisc"] != "fq_codel" {
		t.Fatal("CLI restore did not restore originals")
	}
	afterG, after := savedBatchState(t, a)
	histAfter, _ := os.ReadFile(history)
	journalAfter, _ := os.ReadFile(journal)
	if g != afterG || !bytes.Equal(before, after) || !bytes.Equal(manual, histAfter) || !bytes.Equal(pending, journalAfter) || backend.activeCalls+backend.checks+backend.starts+backend.stops != 0 {
		t.Fatal("host network operation changed node state, recovered a node transaction, or touched service/history")
	}
}

func TestNetworkCLIRejectsInvalidArgumentsAndOfflineMutations(t *testing.T) {
	a, h, _, writes := networkCLIFixture(t)
	for _, args := range [][]string{{"plan", "--tcp", "not-supported"}, {"apply", "--qdisc", "bad"}, {"apply", "--rmem-max", "9999999999"}, {"restore"}, {"restore", "--snapshot", "../../foreign"}, {"status", "extra"}, {"bbr", "--qdisc", "fq_codel"}} {
		if _, e := wizardOutput(t, func() error { return a.networkWithHost(args, h) }); e == nil {
			t.Fatalf("invalid network command accepted: %v", args)
		}
	}
	a.offline = true
	if e := a.networkWithHost([]string{"bbr"}, h); e == nil {
		t.Fatal("offline mode allowed host mutation")
	}
	if *writes != 0 {
		t.Fatal("invalid args caused partial host mutation")
	}
	if _, e := os.Stat(h.StateDir); !os.IsNotExist(e) {
		t.Fatal("invalid args initialized host state", e)
	}
}
