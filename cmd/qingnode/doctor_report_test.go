package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qingnode/internal/node"
)

func decodeDiagnostic(t *testing.T, b []byte) diagnosticReport {
	t.Helper()
	var report diagnosticReport
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("machine output contains more than one JSON document", err)
	}
	if report.Version != 1 || report.Kind != "qingnode-diagnostic" || report.Location != "server" || report.PublicIngress != "unknown" {
		t.Fatal("incorrect evidence scope")
	}
	return report
}

func TestDoctorJSONOfflinePreservesIdentityAndPendingTransaction(t *testing.T) {
	a := wizardApp(t, "")
	if err := a.command([]string{"init", "--protocol", "ss2022", "--server", "203.0.113.1", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(a.store.Root, "current", "state.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := a.store.Load()
	journal := filepath.Join(a.store.Root, "transaction.json")
	original := []byte("interrupted transaction: preserve exact recovery evidence")
	if err := os.WriteFile(journal, original, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := a.doctorJSON(&output); err == nil {
		t.Fatal("missing verified core must be reported as a failure")
	}
	report := decodeDiagnostic(t, output.Bytes())
	if !report.Offline || report.Status != "failed" {
		t.Fatal("offline failure misreported")
	}
	checks := map[string]diagnosticCheck{}
	for _, check := range report.Checks {
		if _, duplicate := checks[check.ID]; duplicate {
			t.Fatal("duplicate diagnostic identity", check.ID)
		}
		checks[check.ID] = check
	}
	if checks["pending/transaction.json"].Status != "degraded" || checks["service"].Status != "unknown" || checks["dns"].Status != "unknown" || checks["public-egress"].Status != "unknown" {
		t.Fatal("pending, skipped or outbound observations reported incorrectly")
	}
	after, _ := os.ReadFile(statePath)
	retained, _ := os.ReadFile(journal)
	if !bytes.Equal(before, after) || !bytes.Equal(original, retained) {
		t.Fatal("read-only diagnosis mutated State or recovery evidence")
	}
	for _, user := range state.Nodes[0].Users {
		for _, secret := range []string{user.UUID, user.Password, state.Nodes[0].Shadowsocks.ServerKey} {
			if secret != "" && bytes.Contains(output.Bytes(), []byte(secret)) {
				t.Fatal("diagnostic JSON exposed authentication")
			}
		}
	}
}

type diagnosticNoActions struct{}

func (diagnosticNoActions) Check(node.State, string) error { panic("unexpected core check") }
func (diagnosticNoActions) Active() bool                   { panic("unexpected service observation") }
func (diagnosticNoActions) Activate(node.State) error      { panic("unexpected activation") }
func (diagnosticNoActions) Stop() error                    { panic("unexpected stop") }

func TestDoctorJSONUnreadableStateAndBusyLockStillProduceSingleReport(t *testing.T) {
	for _, cause := range []string{"unknown-format", "invalid-current-state", "held-lock"} {
		t.Run(cause, func(t *testing.T) {
			a := wizardApp(t, "")
			if err := a.command([]string{"init", "--protocol", "ss2022", "--server", "203.0.113.1", "--quiet"}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(a.store.Root, "current", "state.json")
			before, _ := os.ReadFile(path)
			if cause == "unknown-format" {
				before = []byte(`{"schema":999,"unknown-private-sentinel-token":"must-not-be-displayed"}`)
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			} else if cause == "invalid-current-state" {
				state, err := a.store.Load()
				if err != nil {
					t.Fatal(err)
				}
				state.Nodes[0].Protocol = "unknown-private-protocol-sentinel"
				before, err = json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				file, err := os.OpenFile(filepath.Join(a.store.Root, ".lock"), os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			}
			a.offline = false
			a.store.Backend = diagnosticNoActions{}
			var output bytes.Buffer
			if err := a.doctorJSON(&output); err == nil {
				t.Fatal("failed inspection reported success")
			}
			report := decodeDiagnostic(t, output.Bytes())
			if report.Status != "failed" || len(report.Checks) != 2 || report.Checks[1].Status != "unknown" {
				t.Fatal("failed view caused fabricated checks")
			}
			if bytes.Contains(output.Bytes(), []byte("sentinel-token")) || bytes.Contains(output.Bytes(), []byte("must-not-be-displayed")) {
				t.Fatal("unrecognized private State data exposed in an error")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("failed diagnosis rewrote original evidence")
			}
		})
	}
}

func TestDiagnosticUnknownAndWarningsCannotBecomeHealthy(t *testing.T) {
	report := diagnosticReport{}
	report.finish()
	if report.Status != "unknown" {
		t.Fatal("empty report became a success")
	}
	report.Checks = []diagnosticCheck{{Status: "healthy"}, {Status: "unknown"}}
	report.finish()
	if report.Status != "unknown" {
		t.Fatal("unmeasured checks became success")
	}
	report.Issues = []string{"result history could not be saved"}
	report.finish()
	if report.Status != "degraded" {
		t.Fatal("result persistence warning was hidden")
	}
}

func TestDoctorJSONMissingStateDoesNotInitializeOrInventCoreResults(t *testing.T) {
	a := wizardApp(t, "")
	var output bytes.Buffer
	if err := a.doctorJSON(&output); err == nil {
		t.Fatal("unconfigured diagnostic returned complete success")
	}
	report := decodeDiagnostic(t, output.Bytes())
	if report.Status != "unknown" || len(report.Checks) != 2 || report.Checks[0].Status != "unknown" {
		t.Fatal("unconfigured host was inspected as a default node")
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("read-only query initialized a directory", err)
	}
}

func TestDoctorAndDiagnoseJSONCommandRoutesAreStructured(t *testing.T) {
	for _, command := range []string{"doctor", "diagnose"} {
		t.Run(command, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "not-initialized")
			text, err := wizardOutput(t, func() error { return run([]string{"--offline", "--root", root, command, "--json"}) })
			if err == nil {
				t.Fatal("unconfigured CLI diagnosis returned success")
			}
			report := decodeDiagnostic(t, []byte(text))
			if report.Status != "unknown" {
				t.Fatal("CLI did not route to the structured diagnostic")
			}
		})
	}
}
