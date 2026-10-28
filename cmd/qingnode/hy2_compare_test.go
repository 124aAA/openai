package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"qingnode/internal/probe"
)

func TestHY2ControlledCompareUsesSavedPlanAndPreservesRawReportsAndState(t *testing.T) {
	a, _, _ := hy2CLIState(t)
	planPath, plan := hy2CLIPlan(t, a, "custom", "--settings", hy2CLISettings(t, `{"client_mode":"brutal","client_up_mbps":10,"client_down_mbps":20}`))
	if plan.BeforeClientSHA == plan.AfterClientSHA {
		t.Fatal("fixture must change the client configuration")
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	measure := func(digest string) probe.Report {
		r, e := probe.Run(context.Background(), probe.Options{Path: "client-proxy", Mode: "light", TargetURL: target.URL, Family: "ipv4", Timeout: 3 * time.Second, MaxBytes: 4096, Samples: 2, Concurrency: 1, Initiator: "controlled-compare-fixture", NodeID: plan.NodeID, ConfigSHA256: digest, CoreVersion: plan.CoreVersion, ClientVersion: "1.14.3"}, probe.Dependencies{Transport: target.Client().Transport})
		if e != nil {
			t.Fatal(e)
		}
		if r.Status != "completed" {
			t.Fatalf("controlled TLS report failed: %+v", r.Errors)
		}
		return r
	}
	before, after := measure(plan.BeforeClientSHA), measure(plan.AfterClientSHA)
	if probe.Compare(before, after).Comparable {
		t.Fatal("ordinary comparison accepted changed configuration")
	}
	dir := t.TempDir()
	beforePath, afterPath, out := filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json"), filepath.Join(dir, "comparison.json")
	if e := probe.WriteReport(beforePath, before); e != nil {
		t.Fatal(e)
	}
	if e := probe.WriteReport(afterPath, after); e != nil {
		t.Fatal(e)
	}
	rawBefore, _ := os.ReadFile(beforePath)
	rawAfter, _ := os.ReadFile(afterPath)
	g, state := savedBatchState(t, a)
	args := []string{"--plan", planPath, "--before", beforePath, "--after", afterPath, "--out", out}
	if e := a.hy2Compare(args); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var c probe.Comparison
	if e = json.Unmarshal(b, &c); e != nil || !c.Comparable || c.Version != 2 || c.ControlledChange == nil {
		t.Fatal("missing controlled plan comparison", e)
	}
	sha, e := hy2PlanSHA(plan)
	if e != nil || c.ControlledChange.PlanSHA256 != sha {
		t.Fatal("comparison not bound to saved plan", e)
	}
	if e = a.hy2Compare(args); e == nil {
		t.Fatal("existing comparison overwritten")
	}
	currentG, currentState := savedBatchState(t, a)
	currentBefore, _ := os.ReadFile(beforePath)
	currentAfter, _ := os.ReadFile(afterPath)
	if currentG != g || !bytes.Equal(state, currentState) || !bytes.Equal(rawBefore, currentBefore) || !bytes.Equal(rawAfter, currentAfter) {
		t.Fatal("read-only comparison changed raw reports or production State")
	}
	// A changed initiator remains a rejected comparison, even with a plan.
	after.Conditions.Initiator = "another-host"
	badPath := filepath.Join(dir, "changed-initiator.json")
	if e = probe.WriteReport(badPath, after); e != nil {
		t.Fatal(e)
	}
	badOut := filepath.Join(dir, "refused.json")
	if e = a.hy2Compare([]string{"--plan", planPath, "--before", beforePath, "--after", badPath, "--out", badOut}); e == nil {
		t.Fatal("unrelated measurement difference accepted")
	}
	b, _ = os.ReadFile(badOut)
	if e = json.Unmarshal(b, &c); e != nil || c.Comparable || len(c.Reasons) == 0 {
		t.Fatal("rejected comparison lost its reasons", e)
	}
}
