package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/platform"
)

// Only implements structured, read-only native queries and the exact actions
// expected by the tests. Unknown commands fail rather than reporting success.
func auxiliaryCLIManager(t *testing.T, directory string, actions *[]string, onStart func()) platform.Manager {
	t.Helper()
	active, enabled := map[string]bool{}, map[string]bool{}
	return platform.Manager{Kind: platform.InitSystemd, DefinitionRoot: directory, Execute: func(_ time.Duration, command string, args ...string) ([]byte, error) {
		if command != "systemctl" || len(args) < 2 {
			t.Fatalf("unexpected command %s %v", command, args)
		}
		unit := args[1]
		if args[0] == "show" {
			property := ""
			for _, arg := range args {
				if strings.HasPrefix(arg, "--property=") {
					property = strings.TrimPrefix(arg, "--property=")
				}
			}
			if property == "" {
				t.Fatal("query without bounded properties", args)
			}
			path := filepath.Join(directory, unit)
			_, err := os.Lstat(path)
			present := err == nil
			values := map[string]string{"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "UnitFileState": "", "FragmentPath": "", "DropInPaths": ""}
			if present {
				values["LoadState"], values["FragmentPath"], values["UnitFileState"] = "loaded", path, "disabled"
				if unit == "qingnode-monitor.service" {
					values["UnitFileState"] = "static"
				}
				if enabled[unit] {
					values["UnitFileState"] = "enabled"
				}
				if active[unit] {
					values["ActiveState"], values["SubState"] = "active", "waiting"
				}
			}
			var out strings.Builder
			for _, key := range strings.Split(property, ",") {
				value, exists := values[key]
				if !exists {
					t.Fatal("unexpected native property", key)
				}
				fmt.Fprintf(&out, "%s=%s\n", key, value)
			}
			return []byte(out.String()), nil
		}
		*actions = append(*actions, args[0]+" "+unit)
		switch args[0] {
		case "enable":
			enabled[unit] = true
		case "disable":
			enabled[unit] = false
		case "start", "restart":
			if unit == "qingnode-monitor.service" {
				if onStart != nil {
					onStart()
				}
			} else {
				active[unit] = true
			}
		case "stop":
			active[unit] = false
		default:
			t.Fatal("unexpected native action", command, args)
		}
		return nil, nil
	}}
}

func TestAuxiliaryCLIPreviewNeedsExplicitIntentAndDoesNotCreateRecoveryFiles(t *testing.T) {
	a, _ := batchFixture(t)
	a.offline = false
	var actions []string
	manager := auxiliaryCLIManager(t, t.TempDir(), &actions, nil)
	generation, before := savedBatchState(t, a)
	entries, err := os.ReadDir(a.store.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []struct{ action, name, url string }{{"install", "qingnode-monitor", ""}, {"remove", "qingnode-monitor", ""}, {"recover", "qingnode-monitor", ""}, {"install", "qingnode-subscription", "https://sub.example.test"}} {
		if err := a.auxiliaryDeployment(manager, command.action, command.name, command.url, false, false); err == nil {
			t.Fatal("unconfirmed service mutation accepted", command)
		}
		out, err := wizardOutput(t, func() error {
			return a.auxiliaryDeployment(manager, command.action, command.name, command.url, true, false)
		})
		if err != nil {
			t.Fatal(command, err)
		}
		var preview node.AuxiliaryServicePreview
		if err := json.Unmarshal([]byte(out), &preview); err != nil || preview.Version != 1 || preview.Name != command.name || preview.Pending {
			t.Fatal("invalid preview", command, out, err)
		}
	}
	after, err := os.ReadDir(a.store.Root)
	if err != nil || len(entries) != len(after) || len(actions) != 0 {
		t.Fatal("preview created files or ran a native action", len(entries), len(after), actions, err)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) {
		t.Fatal("preview changed proxy State")
	}
	for _, name := range []string{"qingnode", "sshd", "qingnode-monitor.timer", "../qingnode-monitor"} {
		if err := a.auxiliaryDeployment(manager, "install", name, "", true, false); err == nil {
			t.Fatal("foreign or core service accepted as auxiliary", name)
		}
	}
}

func TestAuxiliaryCLIMonitorControlsWholePairAndReportsTimerEnablement(t *testing.T) {
	a, _ := batchFixture(t)
	directory := t.TempDir()
	var actions []string
	runs := 0
	manager := auxiliaryCLIManager(t, directory, &actions, func() {
		runs++
		if err := a.store.InspectExisting(func() error { _, err := a.store.Load(); return err }); err != nil {
			t.Fatal("oneshot startup retained the State lock", err)
		}
	})
	plan, err := node.NewAuxiliaryServicePlan(manager, "qingnode-monitor", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range plan.Definitions {
		if err := os.WriteFile(filepath.Join(directory, file.Name), file.Contents, file.Mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"enable", "start"} {
		if err := a.controlAuxiliaryService(manager, action, plan.Name, []byte(monitorSystemdService)); err != nil {
			t.Fatal(action, err)
		}
	}
	out, err := wizardOutput(t, func() error { return showAuxiliaryService(manager, plan.Name) })
	if err != nil || !strings.Contains(out, "UnitFileState=enabled\n") || !strings.Contains(out, "SchedulerActiveState=active\n") || !strings.Contains(out, "MainPID=0\n") {
		t.Fatal("oneshot/timer states were conflated", out, err)
	}
	for _, action := range []string{"stop", "disable", "restart"} {
		if err := a.controlAuxiliaryService(manager, action, plan.Name, []byte(monitorSystemdService)); err != nil {
			t.Fatal(action, err)
		}
	}
	want := []string{"enable qingnode-monitor.timer", "start qingnode-monitor.timer", "start qingnode-monitor.service", "stop qingnode-monitor.timer", "stop qingnode-monitor.service", "disable qingnode-monitor.timer", "restart qingnode-monitor.timer", "start qingnode-monitor.service"}
	if !reflect.DeepEqual(actions, want) || runs != 2 {
		t.Fatal("scheduler/oneshot actions differ", actions, runs)
	}
}

func TestAuxiliaryCLILogsRedactProxyAPIDNSAndNotificationSecrets(t *testing.T) {
	a, state := batchFixture(t)
	apiSecret, dnsSecret := strings.Repeat("api-private-", 4), "private-dns-api-token"
	state.Observability = &node.CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: 19090, Secret: apiSecret}
	state.Certificates = append(state.Certificates, node.CertificateResource{ID: "ffffffffffffffff", Name: "unused-private-dns", Certificate: node.Certificate{Mode: "acme", ServerName: "logs.example.test", Email: "owner@example.test", ACME: &node.ACMESettings{Challenge: "dns-01", KeyType: "p256", DNS01: &node.ACMEDNS01{Provider: "cloudflare", APIToken: dnsSecret}}}})
	if err := a.store.WithLock(func() error { return a.store.Apply(state) }); err != nil {
		t.Fatal(err)
	}
	config := monitorCLIConfig(state)
	config.Notifications.Enabled, config.Notifications.Kind = true, "telegram"
	config.Notifications.Endpoint, config.Notifications.Token, config.Notifications.ChatID = "https://api.telegram.org", "123456:private-notification-token", "-1001234567890"
	if err := a.monitorStore().SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	a.offline = false
	secrets := []string{state.Nodes[0].Users[0].Password, apiSecret, dnsSecret, config.Notifications.Token, config.Notifications.Endpoint, config.Notifications.ChatID}
	manager := platform.Manager{Kind: platform.InitSystemd, Execute: func(_ time.Duration, command string, args ...string) ([]byte, error) {
		if command != "journalctl" || strings.Join(args, " ") != "-u qingnode-monitor.service -n 40 --no-pager" {
			t.Fatal("unexpected log query", command, args)
		}
		return []byte("safe diagnostic " + strings.Join(secrets, " ")), nil
	}}
	generation, before := savedBatchState(t, a)
	out, err := wizardOutput(t, func() error { return a.serviceLogs(manager, "qingnode-monitor", 40) })
	if err != nil || !strings.Contains(out, "safe diagnostic") {
		t.Fatal(out, err)
	}
	for _, secret := range secrets {
		if secret == "" || strings.Contains(out, secret) {
			t.Fatal("secret not exercised or leaked")
		}
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) {
		t.Fatal("logs changed State")
	}
	if err := os.WriteFile(filepath.Join(a.monitorStore().Root, "config.json"), []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = wizardOutput(t, func() error { return a.serviceLogs(manager, "qingnode-monitor", 40) })
	if err == nil || out != "" {
		t.Fatal("logs exposed raw output without readable notification secrets", out, err)
	}
}

func TestAuxiliaryCLIFlagsAndTopLevelLogSelection(t *testing.T) {
	a, state := batchFixture(t)
	a.offline = false
	oldFactory := auxiliaryManager
	t.Cleanup(func() { auxiliaryManager = oldFactory })
	queries := 0
	auxiliaryManager = func() platform.Manager {
		return platform.Manager{Kind: platform.InitSystemd, Execute: func(_ time.Duration, command string, args ...string) ([]byte, error) {
			if command != "journalctl" || len(args) != 5 || args[1] != "qingnode-subscription.service" {
				t.Fatal("invalid CLI flags reached native control", command, args)
			}
			queries++
			return []byte("selected log " + state.Nodes[0].Users[0].Password), nil
		}}
	}
	for _, args := range [][]string{
		{"install", "--name", "qingnode-monitor", "--yes", "--preview"},
		{"install", "--name", "qingnode", "--yes"},
		{"remove", "--name", "qingnode-monitor", "--lines", "1", "--yes"},
		{"start", "--name", "qingnode-monitor", "--preview"},
		{"recover", "--name", "qingnode-subscription", "--public-url", "https://sub.example.test", "--yes"},
		{"logs", "--name", "sshd"},
		{"logs", "--name", "qingnode-monitor", "--lines", "0"},
		{"install", "--name", "qingnode-monitor", "--unit-json", "arbitrary.json", "--yes"},
	} {
		if err := a.service(args); err == nil {
			t.Fatal("invalid CLI action accepted", args)
		}
	}
	out, err := wizardOutput(t, func() error { return a.operation("logs", []string{"--name", "qingnode-subscription"}) })
	if err != nil || queries != 1 || !strings.Contains(out, "selected log") || strings.Contains(out, state.Nodes[0].Users[0].Password) {
		t.Fatal("top-level log selection bypassed bounded/redacted path", out, err, queries)
	}
}

func TestFullBackupRejectsPendingAuxiliaryTransactionWithoutRepair(t *testing.T) {
	a, _ := batchFixture(t)
	journal := filepath.Join(a.store.Root, ".auxiliary-qingnode-monitor.journal.json")
	raw := []byte("{\"version\":999}\n")
	if err := os.WriteFile(journal, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := wizardOutput(t, func() error { return a.backupFull("", "", true, false, false, true) }); err == nil || !strings.Contains(err.Error(), "service recover") {
		t.Fatal("full backup accepted pending auxiliary transaction", err)
	}
	if after, err := os.ReadFile(journal); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("backup preview repaired or removed the pending journal", err)
	}
}

func TestAuxiliarySubscriptionOnlyDeploymentMakesFullMigrationExplicitlyLimited(t *testing.T) {
	a, state := batchFixture(t)
	if _, err := os.Lstat(a.monitorStore().Root); !os.IsNotExist(err) {
		t.Fatal("test unexpectedly has independent monitor assets", err)
	}
	// A versioned private receipt is a fixture of persisted deployment data,
	// not evidence of a real service installation on this test host.
	receipt := []byte(`{"version":1,"settings":{"name":"qingnode-subscription","manager":"systemd","public_url":"https://deployment.example.test/private-base"}}`)
	path := filepath.Join(a.store.Root, ".auxiliary-qingnode-subscription.installed.json")
	if err := os.WriteFile(path, receipt, 0600); err != nil {
		t.Fatal(err)
	}
	_, external, err := a.migrationInventory(state)
	if err != nil || len(external) != 1 || !strings.Contains(external[0], "qingnode-subscription") || strings.Contains(external[0], "deployment.example.test") {
		t.Fatal("subscription deployment was omitted or public URL exposed", external, err)
	}
	snapshot, err := a.snapshot(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.captureFull(state, snapshot, false, false); err == nil || !strings.Contains(err.Error(), "allow-incomplete") {
		t.Fatal("full migration claimed complete without optional service deployment", err)
	}
	migration, err := a.captureFull(state, snapshot, false, true)
	if err != nil || migration.Mode != "limited" || len(migration.External) != 1 {
		t.Fatal("explicit limited migration did not preserve deployment gap", migration.Mode, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, receipt) {
		t.Fatal("inventory altered the private deployment receipt", err)
	}
}
