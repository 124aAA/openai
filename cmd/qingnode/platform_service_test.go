package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
	"qingnode/internal/platform"
)

func TestPlatformServiceRendererKeepsCoreAndSubscriptionPrivilegesSeparate(t *testing.T) {
	core, err := wizardOutput(t, func() error { return renderServiceDefinition(nil) })
	if err != nil || core != node.ServiceUnit {
		t.Fatal("default systemd definition changed", err)
	}
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		t.Run(string(kind), func(t *testing.T) {
			out, err := wizardOutput(t, func() error {
				return renderServiceDefinition([]string{"--manager", string(kind), "--name", "qingnode-subscription", "--public-url", "https://sub.example.test"})
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, wanted := range []string{"# Managed by QingNode\n", "qingnode-sub", "--listen 127.0.0.1:8389", "--public-url https://sub.example.test", "--reverse-proxy"} {
				if !strings.Contains(out, wanted) {
					t.Fatal("missing restricted subscription contract", wanted)
				}
			}
			if strings.Contains(out, "CAP_NET_BIND_SERVICE") || strings.Contains(out, `command_user="root:root"`) || strings.Contains(out, "User=root") || strings.Contains(out, "--root") {
				t.Fatal("read-only subscription gained proxy or management privileges", out)
			}
			expected, err := auxiliaryServiceDefinition(kind, "qingnode-subscription", "https://sub.example.test")
			if err != nil || expected != out {
				t.Fatal("control and renderer definitions differ", err)
			}
		})
	}
	for _, publicURL := range []string{"", "http://sub.example.test", "https://name:password@sub.example.test", "https://sub.example.test?token=secret", "https://sub.example.test/#secret", "https://sub.example.test/$(id)", "https://sub.example.test/%n"} {
		if _, err := auxiliaryServiceDefinition(platform.InitOpenRC, "qingnode-subscription", publicURL); err == nil {
			t.Fatal("unsafe or secret URL accepted", publicURL)
		}
	}
	for _, name := range []string{"sshd", "qingnode-other", "../qingnode", "qingnode-subscription.timer"} {
		if _, err := auxiliaryServiceDefinition(platform.InitOpenRC, name, ""); err == nil {
			t.Fatal("foreign auxiliary service accepted", name)
		}
	}
}

func TestPlatformMonitorMaterialsMatchExactManagedDefinitions(t *testing.T) {
	a := wizardApp(t, "")
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		t.Run(string(kind), func(t *testing.T) {
			dir := t.TempDir()
			_, err := wizardOutput(t, func() error { return a.monitorTimerFor(dir, kind) })
			if err != nil {
				t.Fatal(err)
			}
			name := "qingnode-monitor"
			if kind == platform.InitSystemd {
				name += ".service"
			}
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := auxiliaryServiceDefinition(kind, "qingnode-monitor", "")
			if err != nil || string(body) != expected {
				t.Fatal("installed control contract differs from generated monitor", err)
			}
			if kind == platform.InitOpenRC {
				if !strings.Contains(string(body), `command_args="monitor watch"`) || !strings.Contains(string(body), `respawn_max=5`) {
					t.Fatal("OpenRC monitor is not bounded/supervised", string(body))
				}
			} else {
				timer, err := os.ReadFile(filepath.Join(dir, "qingnode-monitor.timer"))
				if err != nil || string(timer) != monitorSystemdTimer {
					t.Fatal("timer changed", err)
				}
				if !strings.Contains(string(body), "Type=oneshot") || !strings.Contains(string(body), "monitor run\n") {
					t.Fatal("existing systemd scheduling semantics changed")
				}
			}
			if _, err := wizardOutput(t, func() error { return a.monitorTimerFor(dir, kind) }); err == nil {
				t.Fatal("existing material overwritten")
			}
		})
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("material generation created State", err)
	}
	if err := a.monitor([]string{"watch", "--cycles", "2"}); err == nil {
		t.Fatal("watch accepted finite cycles flag")
	}
	if err := a.monitor([]string{"watch"}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatal("offline watch ran network or lifecycle", err)
	}
}

func TestPlatformAuxiliaryOwnershipRejectsRetainedMarkerAfterCommandChange(t *testing.T) {
	for _, name := range []string{"qingnode-monitor", "qingnode-subscription"} {
		t.Run(name, func(t *testing.T) {
			url := ""
			if name == "qingnode-subscription" {
				url = "https://sub.example.test"
			}
			expected, err := auxiliaryServiceDefinition(platform.InitOpenRC, name, url)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err = os.WriteFile(path, []byte(expected), 0755); err != nil {
				t.Fatal(err)
			}
			manager := platform.Manager{Kind: platform.InitOpenRC, DefinitionRoot: dir, ConfigRoot: t.TempDir()}
			if err = manager.VerifyOwnership(name, []byte(expected)); err != nil {
				t.Fatal(err)
			}
			modified := strings.Replace(expected, `/usr/local/bin/qingnode`, `/usr/local/bin/external`, 1)
			if modified == expected || !platform.ManagedDefinition([]byte(modified)) {
				t.Fatal("bad retained-marker fixture")
			}
			if err = os.WriteFile(path, []byte(modified), 0755); err != nil {
				t.Fatal(err)
			}
			if manager.VerifyOwnership(name, []byte(expected)) == nil {
				t.Fatal("retained marker hid externally changed auxiliary command")
			}
		})
	}
}

func TestPlatformCapabilitiesJSONSupplementsExistingReadOnlyRuntimeFields(t *testing.T) {
	a := wizardApp(t, "")
	out, err := wizardOutput(t, func() error { return a.capabilities([]string{"--json", "--skip-loopback"}) })
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Version  int                             `json:"version"`
		Source   string                          `json:"source"`
		Host     platform.HostCapabilities       `json:"host"`
		Loopback map[string]node.CapabilityCheck `json:"loopback"`
		Paths    []node.CapabilityPath           `json:"paths"`
	}
	if err = json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Version != 1 || report.Source != "qingnode-local-capabilities" || report.Host.Version != 1 || report.Host.Init.Reason == "" || len(report.Paths) != 4 {
		t.Fatal("host report replaced or hid runtime facts", out)
	}
	for _, p := range report.Loopback {
		if p.ExchangeSucceeded != nil && *p.ExchangeSucceeded {
			t.Fatal("skipped loopback was reported as success")
		}
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("read-only capability report created State", err)
	}
}

func TestPlatformOpenRCMigrationManifestKeepsSchema8Identity(t *testing.T) {
	a, st := batchFixture(t)
	old := st.Clone()
	old.Schema = 8
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := node.DecodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Schema != 9 || !reflect.DeepEqual(migrated.Nodes, st.Nodes) {
		t.Fatal("schema8 identity changed during in-memory platform migration")
	}
	snap, err := a.snapshot(migrated)
	if err != nil {
		t.Fatal(err)
	}
	m, err := node.CaptureMigration(snap, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	m.Manifest.ServiceManager = "openrc"
	before, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Validate(); err != nil {
		t.Fatal("new source manager rejected", err)
	}
	after, _ := json.Marshal(m)
	if string(after) != string(before) {
		t.Fatal("source manager validation changed recovery evidence")
	}
	m.Manifest.ServiceManager = "unrecognized-init"
	if m.Validate() == nil {
		t.Fatal("unknown source manager accepted")
	}
}
