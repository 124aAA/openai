package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qingnode/internal/node"
)

func TestRealityRankingUsesMedianRejectsFlakyAndStableTies(t *testing.T) {
	samples := map[string][]int{
		"www.microsoft.com": {1, 300, 400},
		"www.apple.com":     {30, 20, 10},
		"www.samsung.com":   {25, 20, 15},
		"www.nvidia.com":    {1, -1, 1},
		"www.sony.com":      {-1},
		"www.bing.com":      {35, 30, 40},
	}
	var mu sync.Mutex
	calls := map[string]int{}
	probe := func(r *node.Reality) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		if r.Target != r.ServerName+":443" || strings.Contains(r.ServerName, "cloudflare") {
			t.Error("invalid candidate", r.ServerName)
		}
		i := calls[r.ServerName]
		calls[r.ServerName]++
		v := samples[r.ServerName][i]
		if v < 0 {
			return 0, errors.New("unreachable")
		}
		return time.Duration(v) * time.Millisecond, nil
	}
	got := rankRealityTargets(probe)
	if got[0].name != "www.apple.com" || got[0].latency != 20*time.Millisecond || got[1].name != "www.samsung.com" || got[2].name != "www.bing.com" || got[3].name != "www.microsoft.com" {
		t.Fatal(got)
	}
	if got[4].err == nil || got[5].err == nil || calls["www.nvidia.com"] != 2 {
		t.Fatal("failed sample was accepted", got)
	}
	var output bytes.Buffer
	printRealityTargets(&output, got, 3)
	if strings.Contains(output.String(), "4. ") || !strings.Contains(output.String(), "排除 www.nvidia.com") || !strings.Contains(output.String(), "20.0 ms") {
		t.Fatal(output.String())
	}
}

func TestAutoEndpointChoosesFastestAndFailsClosed(t *testing.T) {
	for _, fail := range []bool{false, true} {
		p := autoProbes{probeReality: func(r *node.Reality) (time.Duration, error) {
			if fail {
				return 0, errors.New("TLS rejected")
			}
			if r.ServerName == "www.bing.com" {
				return time.Millisecond, nil
			}
			return time.Second, nil
		}}
		_, sni, target, e := autoEndpoint("reality", "203.0.113.1", "", "", p)
		if fail {
			if e == nil {
				t.Fatal("failed probes accepted")
			}
			continue
		}
		if e != nil || sni != "www.bing.com" || target != "www.bing.com:443" {
			t.Fatal(sni, target, e)
		}
	}
	_, _, _, e := autoEndpoint("reality", "203.0.113.1", "WWW.CloudFlare.COM.", "", autoProbes{})
	if e == nil || !strings.Contains(e.Error(), "排除") {
		t.Fatal("excluded explicit target reached probe", e)
	}
}

func TestExcludedManualTargetsLeaveStateUntouched(t *testing.T) {
	a := app{offline: true, store: &node.Store{Root: t.TempDir(), GID: -1, Backend: &autoBackend{}}}
	if e := a.add("init", []string{"--server", "203.0.113.1", "--sni", "www.apple.com", "--quiet"}); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(a.store.Root, "current", "state.json")
	before, _ := os.ReadFile(path)
	for _, edit := range []bool{false, true} {
		var e error
		if edit {
			e = a.edit([]string{"--id", "main", "--sni", "www.cloudflare.com"})
		} else {
			e = a.add("add", []string{"--server", "203.0.113.1", "--sni", "www.cloudflare.com"})
		}
		if e == nil || !strings.Contains(e.Error(), "排除") {
			t.Fatal(e)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("rejected target changed state")
		}
	}
	if e := realityTargets([]string{"--top", "0"}); e == nil {
		t.Fatal("invalid top accepted")
	}
	if e := run([]string{"--offline", "reality-targets"}); e == nil {
		t.Fatal("offline probe accepted")
	}
}
