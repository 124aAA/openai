package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"qingnode/internal/node"
)

func readExecutionResult(t *testing.T, dir, name string) executionResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var result executionResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.Kind != "qingnode-command-result" || result.Started.IsZero() {
		t.Fatal("invalid execution receipt identity")
	}
	if !strings.Contains(result.ExitCodeScope, "actual process exit code") {
		t.Fatal("operation exit code was confused with final publication success")
	}
	return result
}

func TestExecutionResultGlobalEntryPreservesJSONAndRequiresExplicitCommand(t *testing.T) {
	for _, args := range [][]string{{"version", "--json"}, {"help", "--json"}, {"install", "--help"}, {"validate-install", "--protocol", "ss2022", "--server", "203.0.113.8"}} {
		dir := filepath.Join(t.TempDir(), "receipt")
		out, err := wizardOutput(t, func() error { return run(append([]string{"--result-dir", dir}, args...)) })
		if err != nil {
			t.Fatal(err)
		}
		result := readExecutionResult(t, dir, "result.json")
		started := readExecutionResult(t, dir, "started.json")
		if result.Status != "completed" || result.ExitCode == nil || *result.ExitCode != 0 || result.ApplyCount != 0 || started.Status != "running" || started.ExitCode != nil || started.Finished != nil {
			t.Fatal("incorrect running or completion receipt")
		}
		if len(args) > 1 && args[1] == "--json" && !json.Valid([]byte(out)) {
			t.Fatal("execution receipt polluted machine stdout")
		}
		for _, name := range []string{"started.json", "result.json"} {
			i, e := os.Stat(filepath.Join(dir, name))
			if e != nil || i.Mode().Perm() != 0600 {
				t.Fatal("receipt file is not private", e)
			}
		}
		i, e := os.Stat(dir)
		if e != nil || i.Mode().Perm() != 0700 {
			t.Fatal("receipt directory is not private", e)
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 2 {
			t.Fatal("staging file retained on successful publication", e)
		}
	}
	dir := filepath.Join(t.TempDir(), "no-command")
	if err := run([]string{"--result-dir", dir}); err == nil {
		t.Fatal("receipt mode entered interactive menu")
	}
	if result := readExecutionResult(t, dir, "result.json"); result.Status != "failed" {
		t.Fatal("unspecified command reported success")
	}
}

func TestExecutionResultRealMutationAndNoOpDoNotExposePrivateOutputs(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "state")
	var firstGeneration string
	for index, dirname := range []string{"create", "repeat"} {
		dir := filepath.Join(base, dirname)
		_, err := wizardOutput(t, func() error {
			return run([]string{"--result-dir", dir, "--offline", "--root", root, "init", "--protocol", "ss2022", "--server", "203.0.113.8", "--quiet"})
		})
		if err != nil {
			t.Fatal(err)
		}
		result := readExecutionResult(t, dir, "result.json")
		if result.Status != "completed" || result.ApplyCount != 1 || len(result.ApplyConfirmations) != 1 || result.ApplyConfirmations[0].Generation == nil {
			t.Fatal("actual Apply was not confirmed")
		}
		if index == 0 {
			firstGeneration = *result.ApplyConfirmations[0].Generation
		} else if firstGeneration != *result.ApplyConfirmations[0].Generation {
			t.Fatal("repeated initialization changed identity/generation")
		}
	}
	store := &node.Store{Root: root, Backend: node.OfflineBackend{}, GID: -1}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	before, err := wizardOutput(t, func() error {
		return run([]string{"--offline", "--root", root, "export", "--id", state.Nodes[0].ID, "--format", "uri"})
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "explicit-export")
	after, err := wizardOutput(t, func() error {
		return run([]string{"--result-dir", dir, "--offline", "--root", root, "export", "--id", state.Nodes[0].ID, "--format", "uri"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if before != after || !strings.HasPrefix(after, "ss://") {
		t.Fatal("receipt altered explicit private export bytes")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{state.Nodes[0].Shadowsocks.ServerKey, state.Nodes[0].Users[0].Password, strings.TrimSpace(after)} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("execution receipt captured authentication or exported stdout")
		}
	}
}

func TestExecutionResultFailedInputNeverClaimsUnchangedAndDoesNotCreateState(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "absent")
	dir := filepath.Join(base, "failure")
	if _, err := wizardOutput(t, func() error {
		return run([]string{"--result-dir", dir, "--offline", "--root", root, "add", "--protocol", "ss2022", "--port", "bad-private-input"})
	}); err == nil {
		t.Fatal("invalid input succeeded")
	}
	result := readExecutionResult(t, dir, "result.json")
	if result.Status != "failed" || result.ExitCode == nil || *result.ExitCode != 1 || result.ApplyCount != 0 || !strings.HasPrefix(result.SideEffects, "unknown") {
		t.Fatal("failed command fabricated transaction safety")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("invalid input initialized State", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	if bytes.Contains(raw, []byte("bad-private-input")) {
		t.Fatal("receipt exposed input value")
	}
}

func TestExecutionResultRecordsCommittedConfigurationWhenPublisherFails(t *testing.T) {
	a, state := batchFixture(t)
	dir := filepath.Join(t.TempDir(), "publisher-failure")
	report, err := beginExecutionReport(dir, a.store.Root, []string{"edit"})
	if err != nil {
		t.Fatal(err)
	}
	a.store.AfterCommit = func(node.State) error { return errors.New("private-publisher-error-value") }
	report.wrapApplyHook(a.store)
	err = a.command([]string{"edit", "--id", state.Nodes[0].ID, "--name", "committed-name"})
	if err == nil {
		t.Fatal("publisher failure hidden")
	}
	if e := report.finish(err); e != nil {
		t.Fatal(e)
	}
	result := readExecutionResult(t, dir, "result.json")
	current, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	if current.Nodes[0].Name != "committed-name" || result.Status != "failed" || result.ApplyCount != 1 || result.ApplyConfirmations[0].DerivedHook != "failed" {
		t.Fatal("post-commit failure was mistaken for uncommitted configuration")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	if bytes.Contains(raw, []byte("private-publisher-error-value")) {
		t.Fatal("receipt exposed raw publisher error")
	}
}

func TestExecutionResultRefusesExistingAndManagedPathsBeforeMutation(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "absent")
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{existing, filepath.Join(root, "receipt")} {
		if err := run([]string{"--result-dir", dir, "--offline", "--root", root, "init", "--protocol", "ss2022", "--server", "203.0.113.8"}); err == nil {
			t.Fatal("unsafe report destination allowed mutation")
		}
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("report failure initialized State")
	}
}

func TestExecutionResultPublicationCollisionKeepsForeignFile(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "state")
	dir := filepath.Join(base, "receipt")
	report, err := beginExecutionReport(dir, root, []string{"add"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := []byte("externally-created-result: do not replace")
	if err = os.WriteFile(filepath.Join(dir, "result.json"), foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if err = report.finish(nil); err == nil {
		t.Fatal("publication collision returned success")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	if !bytes.Equal(foreign, after) {
		t.Fatal("foreign result overwritten")
	}
	if started := readExecutionResult(t, dir, "started.json"); started.Status != "running" || started.Finished != nil {
		t.Fatal("original running evidence rewritten")
	}
}

func TestExecutionResultRefusesReplacedDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "receipt")
	moved := dir + "-moved"
	foreign := filepath.Join(base, "foreign")
	report, err := beginExecutionReport(dir, filepath.Join(base, "state"), []string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(foreign, dir); err != nil {
		t.Fatal(err)
	}
	if err = report.finish(nil); err == nil {
		t.Fatal("replaced directory accepted")
	}
	for _, path := range []string{moved, foreign} {
		if _, err = os.Lstat(filepath.Join(path, "result.json")); !os.IsNotExist(err) {
			t.Fatal("wrote a final result after replacement", err)
		}
	}
}

func TestExecutionResultCancellationHelpAndSignalsAreNotCompletion(t *testing.T) {
	for _, item := range []struct {
		err    error
		status string
		code   int
	}{{errMenuCanceled, "canceled", 0}, {context.Canceled, "canceled", 1}, {flag.ErrHelp, "help", 0}, {terminalSignalError{syscall.SIGINT}, "interrupted", 130}, {terminalSignalError{syscall.SIGTERM}, "interrupted", 143}} {
		dir := filepath.Join(t.TempDir(), "receipt")
		report, err := beginExecutionReport(dir, filepath.Join(t.TempDir(), "state"), []string{"wizard"})
		if err != nil {
			t.Fatal(err)
		}
		if err = report.finish(item.err); err != nil {
			t.Fatal(err)
		}
		result := readExecutionResult(t, dir, "result.json")
		if result.Status != item.status || result.ExitCode == nil || *result.ExitCode != item.code || result.Finished == nil {
			t.Fatal("cancel/help/signal misreported as completed")
		}
	}
}

func TestExecutionResultConcurrentApplyHistoryIsBoundedAndMissingGenerationUnknown(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "receipt")
	root := filepath.Join(base, "absent")
	report, err := beginExecutionReport(dir, root, []string{"monitor"})
	if err != nil {
		t.Fatal(err)
	}
	store := &node.Store{Root: root}
	report.wrapApplyHook(store)
	var wg sync.WaitGroup
	for range 80 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := store.AfterCommit(node.NewState()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err = report.finish(nil); err != nil {
		t.Fatal(err)
	}
	result := readExecutionResult(t, dir, "result.json")
	if result.ApplyCount != 80 || !result.Truncated || len(result.ApplyConfirmations) != 64 {
		t.Fatal("apply history count or bound incorrect")
	}
	for _, event := range result.ApplyConfirmations {
		if event.Generation != nil || event.DerivedHook != "not-configured" {
			t.Fatal("missing generation or absent hook fabricated")
		}
	}
}
