//go:build linux

package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var testCoreANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var testCoreStartedLine = regexp.MustCompile(`(?m)^INFO\[[0-9]{4,}\] sing-box started \([0-9]+(?:\.[0-9]+)?s\)\r?\n`)

func testCoreStartupLogConfig(config []byte) ([]byte, error) {
	var owned M
	if err := json.Unmarshal(config, &owned); err != nil || owned == nil {
		return nil, errors.New("cannot decode owned core fixture configuration")
	}
	logging, ok := owned["log"].(map[string]any)
	if !ok {
		logging = M{}
		owned["log"] = logging
	}
	logging["level"] = "info"
	logging["timestamp"] = false
	logging["disabled"] = false
	// All startup evidence belongs in this fixture's captured standard error.
	delete(logging, "output")
	return json.Marshal(owned)
}

func hasTestCoreStarted(log []byte) bool {
	return testCoreStartedLine.Match(testCoreANSI.ReplaceAll(log, nil))
}

// One caller-owned deadline covers both observations. The official 1.14.0 and
// 1.14.3 Box.Start logs this exact untagged INFO message only after all startup
// stages return. This is stronger than an opened mixed listener; it does not
// claim that later asynchronous interface updates cannot interrupt a session.
func waitCoreStartup(ctx context.Context, pid int, config []byte, exited <-chan struct{}, logPath string) error {
	required, err := coreListenerRequirements(config)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var missing []coreListener
	var procErr, logErr error
	var started bool
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("owned test core startup ended: %w; missing=%v; started=%t; proc=%v; log=%v", err, missing, started, procErr, logErr)
		}
		select {
		case <-exited:
			return errors.New("owned test core exited during startup")
		default:
		}
		ready, err := coreOwnedListeners("/proc", pid)
		procErr = err
		missing = missing[:0]
		for _, listener := range required {
			if !ready[listener] {
				missing = append(missing, listener)
			}
		}
		log, err := os.ReadFile(logPath)
		logErr = err
		started = err == nil && hasTestCoreStarted(log)
		if procErr == nil && len(missing) == 0 && started {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("owned test core startup ended: %w", err)
			}
			select {
			case <-exited:
				return errors.New("owned test core exited as startup became ready")
			default:
				return nil
			}
		}
		select {
		case <-ctx.Done():
		case <-exited:
			return errors.New("owned test core exited during startup")
		case <-ticker.C:
		}
	}
}

func TestCoreStartupFixtureChangesOnlyLogging(t *testing.T) {
	original := []byte(`{"log":{"level":"warn","timestamp":true,"disabled":true,"output":"owned.log"},"inbounds":[{"type":"mixed","listen_port":12080}],"outbounds":[{"type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":24443,"password":"private-fixture"}],"route":{"final":"proxy"}}`)
	updated, err := testCoreStartupLogConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	var before, after M
	if json.Unmarshal(original, &before) != nil || json.Unmarshal(updated, &after) != nil {
		t.Fatal("fixture JSON changed shape")
	}
	log := after["log"].(map[string]any)
	if !reflect.DeepEqual(log, M{"level": "info", "timestamp": false, "disabled": false}) {
		t.Fatal("fixture startup logging is not observable")
	}
	delete(before, "log")
	delete(after, "log")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("startup observation changed transport or routing")
	}
	for _, invalid := range []string{`null`, `[]`, `{`} {
		if _, err := testCoreStartupLogConfig([]byte(invalid)); err == nil {
			t.Fatal("invalid fixture configuration accepted")
		}
	}
}

func TestCoreStartupMarkerRequiresCompleteUntaggedInfo(t *testing.T) {
	for _, log := range []string{
		"INFO[0000] sing-box started (0.00s)\n",
		"\x1b[36mINFO\x1b[0m[0001] sing-box started (1.025s)\r\n",
	} {
		if !hasTestCoreStarted([]byte(log)) {
			t.Fatal("complete official startup line rejected")
		}
	}
	for _, log := range []string{
		"ERROR[0000] sing-box started (0.00s)\n",
		"ERROR[0000] failed: INFO[0000] sing-box started (0.00s)\n",
		"INFO[0000] outbound/hysteria2[proxy]: sing-box started (0.00s)\n",
		"INFO[0000] [42 1ms] sing-box started (0.00s)\n",
		"INFO[0000] sing-box pre-started (0.00s)\n",
		"INFO[0000] sing-box started (0.00s)",
		"INFO[0000] sing-box started (0.00s) extra\n",
	} {
		if hasTestCoreStarted([]byte(log)) {
			t.Fatal("error, component, or partial line mistaken for completed startup")
		}
	}
}

func TestCoreStartupRequiresOwnedListenerAndMarkerWithinOneBudget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	config := []byte(fmt.Sprintf(`{"inbounds":[{"type":"mixed","listen_port":%d}]}`, port))
	logPath := filepath.Join(t.TempDir(), "startup.log")
	writeLog := func(text string) {
		t.Helper()
		if err := os.WriteFile(logPath, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []struct {
		name, log string
		config    []byte
	}{
		{"listener-only", "INFO[0000] mixed listener started\n", config},
		{"error-is-not-started", "ERROR[0000] sing-box started (0.00s)\n", config},
		{"marker-without-listener", "INFO[0000] sing-box started (0.00s)\n", []byte(fmt.Sprintf(`{"inbounds":[{"type":"mixed","listen_port":%d}]}`, freePort(t)))},
	} {
		t.Run(entry.name, func(t *testing.T) {
			writeLog(entry.log)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			if err := waitCoreStartup(ctx, os.Getpid(), entry.config, make(chan struct{}), logPath); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("incomplete startup escaped its single deadline", err)
			}
		})
	}
	writeLog("INFO[0000] sing-box started (0.00s)\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitCoreStartup(ctx, os.Getpid(), config, make(chan struct{}), logPath); err != nil {
		t.Fatal("owned listener and completed startup were not accepted", err)
	}
	cancel()
	t.Run("already-exited-with-stale-ready-evidence", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		exited := make(chan struct{})
		close(exited)
		if err := waitCoreStartup(ctx, os.Getpid(), config, exited, logPath); err == nil || !strings.Contains(err.Error(), "exited") {
			t.Fatal("exited process was accepted using a leftover listener/marker", err)
		}
	})
	t.Run("cancelled-even-with-ready-evidence", func(t *testing.T) {
		cancelled, stop := context.WithCancel(context.Background())
		stop()
		if err := waitCoreStartup(cancelled, os.Getpid(), config, make(chan struct{}), logPath); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled startup became ready", err)
		}
	})
	writeLog("")
	t.Run("cancellation-during-startup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		waiting, stop := context.WithCancel(ctx)
		defer stop()
		trigger := time.AfterFunc(20*time.Millisecond, stop)
		defer trigger.Stop()
		if err := waitCoreStartup(waiting, os.Getpid(), config, make(chan struct{}), logPath); !errors.Is(err, context.Canceled) {
			t.Fatal("startup ignored cancellation", err)
		}
	})
	t.Run("early-exit-during-startup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		exited := make(chan struct{})
		trigger := time.AfterFunc(20*time.Millisecond, func() { close(exited) })
		defer trigger.Stop()
		if err := waitCoreStartup(ctx, os.Getpid(), config, exited, logPath); err == nil || !strings.Contains(err.Error(), "exited") {
			t.Fatal("startup ignored early process death", err)
		}
	})
}
