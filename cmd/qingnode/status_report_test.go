package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func statusTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			result[path] = target
			return e
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(data)
		result[path] = string(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStatusJSONReadOnlyRedactedAndUnmeasured(t *testing.T) {
	a, s := dashboardFixture(t)
	pending := filepath.Join(a.store.Root, ".auxiliary-qingnode-monitor.conflict.json")
	if err := os.WriteFile(pending, []byte(`{"original_record":"private-test-material"}`), 0600); err != nil {
		t.Fatal(err)
	}
	before := statusTree(t, a.store.Root)
	var out bytes.Buffer
	if err := a.statusJSON(&out); err != nil {
		t.Fatal(err)
	}
	var report statusReport
	d := json.NewDecoder(&out)
	if err := d.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("stdout was not one JSON document", err)
	}
	if report.Version != 1 || report.ObservationLocation != "server-local" || report.Configured == nil || !*report.Configured || len(report.Nodes) != 1 || report.Nodes[0].ClientVerification.TCP != "unknown" || report.Service.Autostart != nil || report.Service.State != "not-observed-offline" {
		t.Fatalf("false status evidence: %+v", report)
	}
	if len(report.Pending) != 1 || report.Pending[0] != filepath.Base(pending) || len(report.Issues) == 0 || !strings.Contains(report.Issues[0].NextCommand, " --offline --root ") || !strings.HasSuffix(report.Issues[0].NextCommand, " service recover --name qingnode-monitor --help") || !strings.Contains(report.Issues[0].Message, "离线模式不能") {
		t.Fatal("missing precise pending recovery action", report)
	}
	// The offline next step must actually be supported, not a preview that
	// auxiliaryDeployment necessarily rejects before examining any journal.
	if err := a.command([]string{"service", "recover", "--name", "qingnode-monitor", "--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("offline recovery guidance did not reach safe executable help", err)
	}
	raw, _ := json.Marshal(report)
	for _, secret := range []string{s.Nodes[0].Users[0].UUID, s.Nodes[0].Reality.PrivateKey, s.Nodes[0].Reality.ShortID, "private-test-material"} {
		if secret != "" && bytes.Contains(raw, []byte(secret)) {
			t.Fatal("status contained authentication or recovery material")
		}
	}
	if !reflect.DeepEqual(before, statusTree(t, a.store.Root)) {
		t.Fatal("status query mutated managed files")
	}
}

func TestStatusJSONCorruptStateAndAbsentInstall(t *testing.T) {
	a := wizardApp(t, "")
	var out bytes.Buffer
	if err := a.statusJSON(&out); err != nil {
		t.Fatal(err)
	}
	var report statusReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Configured == nil || *report.Configured || len(report.Nodes) != 0 {
		t.Fatal("missing installation looked configured")
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("query created State")
	}
	a, s := dashboardFixture(t)
	state := filepath.Join(a.store.Root, "current", "state.json")
	if err := os.WriteFile(state, []byte(`{"schema":999,"password":"must-stay-private"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.statusJSON(&out); err == nil {
		t.Fatal("corrupt State reported success")
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal("failure did not emit structured status", err)
	}
	if report.Configured != nil || report.CoreVerified != nil || len(report.Issues) == 0 || bytes.Contains(out.Bytes(), []byte("must-stay-private")) {
		t.Fatal("corruption became an empty healthy installation", string(out.Bytes()), s.Schema)
	}
}

func TestStatusJSONHistoricalVerificationStaleAndChanged(t *testing.T) {
	a, s := dashboardFixture(t)
	n := s.Nodes[0]
	for _, tc := range []struct {
		age           time.Duration
		changed       bool
		validity, tcp string
	}{{time.Hour, false, "historical-record", "pass"}, {25 * time.Hour, false, "stale", "unknown"}, {time.Hour, true, "configuration-changed", "unknown"}} {
		record := publicRecord{At: time.Now().Add(-tc.age), Fingerprint: publicFingerprint(s, n), TCP: "pass", UDP: "untested", Source: "controlled-client"}
		if tc.changed {
			record.Fingerprint = "changed"
		}
		if err := a.updateHistory(func(h *dashboardHistory) { h.Public = map[string]publicRecord{n.ID: record} }); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := a.statusJSON(&out); err != nil {
			t.Fatal(err)
		}
		var report statusReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		v := report.Nodes[0].ClientVerification
		if v.Validity != tc.validity || v.TCP != tc.tcp || v.UDP == "pass" {
			t.Fatal("stale or unrelated evidence counted as passed", v)
		}
	}
}

func TestMachineCommandsAndBoundedPrompt(t *testing.T) {
	for _, args := range [][]string{{"help", "--json"}, {"version", "--json"}} {
		out, err := wizardOutput(t, func() error { return run(args) })
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(out), &value); err != nil || value["version"] != float64(1) {
			t.Fatal("invalid machine help/version", err, out)
		}
		if args[0] == "help" {
			commands, ok := value["json_commands"].([]any)
			if !ok {
				t.Fatal("machine help did not list JSON commands")
			}
			for _, want := range []string{"network status --json", "egress health --json", "doctor --json", "diagnose --json", "ports --json", "dns show --json", "hy2 show --json", "endpoint list --json", "egress list --json", "forward list --json", "device list --json", "expiration list --json", "subscription status --json"} {
				found := false
				for _, command := range commands {
					if command == want {
						found = true
					}
				}
				if !found {
					t.Fatalf("machine help missing %s", want)
				}
			}
		}
	}
	for _, input := range []string{strings.Repeat("x", 8192) + "\n", "hello\x1b[31m\n", "name\u202eevil\n"} {
		a := wizardApp(t, input)
		if _, err := a.prompt("name", ""); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	a := wizardApp(t, ":cancel\n")
	if _, err := a.prompt("name", ""); !errors.Is(err, errMenuCanceled) {
		t.Fatal("generic form did not cancel")
	}
	a.in = bufio.NewReader(strings.NewReader("unfinished"))
	if _, err := a.prompt("name", ""); !errors.Is(err, io.EOF) {
		t.Fatal("unterminated EOF was committed")
	}
	if commandExitCode(terminalSignalError{syscall.SIGINT}) != 130 || commandExitCode(terminalSignalError{syscall.SIGTERM}) != 143 || commandExitCode(errors.New("failure")) != 1 {
		t.Fatal("unstable secret-input exit codes")
	}
	if got := safeCLIError(`invalid value "pasted-secret" for flag -port: requires a decimal port`); strings.Contains(got, "pasted-secret") || !strings.Contains(got, "-port") {
		t.Fatal("flag parsing exposed pasted input", got)
	}
}
