package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

func TestTaskMenuListsSevenUserJobs(t *testing.T) {
	for _, label := range []string{"1 快速建节点", "2 节点与用户", "3 导出与订阅", "4 测速与诊断", "5 证书与备份", "6 进阶网络", "7 系统维护", "8 刷新总览", "9 检查更新"} {
		if !strings.Contains(ui.Text("main"), label) {
			t.Fatal("missing task entry", label)
		}
	}
}
func TestGuidanceUsesPrerequisitesNotSpeedClaims(t *testing.T) {
	for _, tc := range []struct {
		c    protocolConditions
		want string
	}{
		{protocolConditions{Client: "other", Certificate: "none", UDP: "unknown"}, "ss-aead"},
		{protocolConditions{Client: "sing-box", Certificate: "none", UDP: "no"}, "reality"},
		{protocolConditions{Client: "mihomo", Certificate: "pem", UDP: "unknown"}, "trojan"},
		{protocolConditions{Client: "mihomo", Certificate: "acme", UDP: "yes", Resources: "limited"}, "trojan"},
		{protocolConditions{Client: "sing-box", Certificate: "pem", UDP: "yes", Resources: "normal"}, "hysteria2"},
		{protocolConditions{Client: "sing-box", Certificate: "pem", TCP: "no", UDP: "yes", Resources: "limited"}, "hysteria2"},
		{protocolConditions{Client: "sing-box", Certificate: "none", TCP: "no", UDP: "yes"}, ""},
	} {
		got, reason := recommendProtocol(tc.c)
		if got != tc.want || reason == "" || strings.Contains(reason, "一定更快") {
			t.Fatal(got, reason)
		}
	}
}
func TestGuidanceCancelAtEveryQuestionNeverCreatesState(t *testing.T) {
	answers := []string{"1", "1", "1", "1", "2", "1", "hysteria2"}
	for i := range answers {
		for _, ending := range []string{":cancel\n", ""} {
			a := wizardApp(t, strings.Join(answers[:i], "\n")+func() string {
				if i > 0 {
					return "\n"
				}
				return ""
			}()+ending)
			_, err := a.guidedProtocol()
			if !errors.Is(err, errMenuCanceled) && !errors.Is(err, io.EOF) {
				t.Fatal("guidance did not cancel", i, err)
			}
			if _, err := os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancel wrote root", err)
			}
		}
	}
}
func TestGuidancePreservesNATAndAllowsChangingRecommendation(t *testing.T) {
	a := wizardApp(t, "1\n3\n1\n2\n2\n2\nss-aead\n")
	selected, err := a.guidedProtocol()
	if err != nil || selected.Protocol != "ss-aead" || !selected.NAT {
		t.Fatal(selected, err)
	}
	a = wizardApp(t, "1\n1\n1\n2\n1\n1\nhysteria2\ntrojan\n")
	selected, err = a.guidedProtocol()
	if err != nil || selected.Protocol != "trojan" {
		t.Fatal("TCP-only condition allowed UDP carrier", selected, err)
	}
}
func TestMenuFieldCancelControlsAndBlankRefuseBeforeMutation(t *testing.T) {
	for _, input := range []string{":cancel\n", "bad\x1b]52;clipboard\a\n", "bad\tvalue\n", strings.Repeat("x", 4097) + "\n"} {
		a := wizardApp(t, input)
		if _, err := a.wizardPrompt("value", ""); err == nil {
			t.Fatal("unsafe/cancel field accepted")
		}
		if _, err := os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("input wrote State", err)
		}
	}
	a := wizardApp(t, "\n")
	if _, err := a.menuRequired("path"); err == nil {
		t.Fatal("empty required field accepted")
	}
}
func TestMenuMutationPreviewMatchesOneCommittedIdentity(t *testing.T) {
	a := wizardApp(t, "phone\n203.0.113.11\n9443\n")
	text, err := captureProtocolMenuStderr(t, func() error { return a.installWizard(true, "ss2022", true) })
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes) != 1 || strings.Count(text, "本次实际影响") != 1 || !strings.Contains(text, s.Nodes[0].ID) {
		t.Fatal("preview identity or count differs", text)
	}
	if !strings.Contains(text, "203.0.113.11:9443") || strings.Contains(text, s.Nodes[0].Users[0].Password) {
		t.Fatal("preview endpoint wrong or exposed password")
	}
	if a.menuPreview || a.menuPreviewDone {
		t.Fatal("interactive preview leaked into later script command")
	}
	before := s.Nodes[0]
	text, err = captureProtocolMenuStderr(t, func() error { return a.menuCommand([]string{"edit", "--id", before.ID, "--name", "renamed"}) })
	if err != nil {
		t.Fatal(err)
	}
	s, err = a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "无需重启核心") || s.Nodes[0].ID != before.ID || !reflect.DeepEqual(s.Nodes[0].Users, before.Users) {
		t.Fatal("metadata preview changed identity or runtime contract", text)
	}
}
func TestMenuInvalidWizardFieldsDoNotInstallCoreOrCreateGeneration(t *testing.T) {
	a := wizardApp(t, "bad\n203.0.113.8\n0\n")
	if err := a.installWizard(true, "ss2022", true); err == nil {
		t.Fatal("invalid port accepted")
	}
	if _, err := os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid fields created core/State", err)
	}
	// Online + NAT avoids public-IP detection. An invalid long name reaches
	// real candidate validation before any core installation/download.
	a = wizardApp(t, strings.Repeat("x", 300)+"\n127.0.0.1\n127.0.0.1\n39337\n30000\n")
	a.offline = false
	if err := a.installWizardOptions(true, "ss2022", true, true); err == nil || !strings.Contains(err.Error(), "节点名称") {
		t.Fatal("invalid online candidate did not reach name validation", err)
	}
	if _, err := os.Lstat(node.CorePath(a.store.Root, node.DefaultCore)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid online fields installed a core", err)
	}
	if matches, err := filepath.Glob(filepath.Join(a.store.Root, "generations", "g-*")); err != nil || len(matches) != 0 {
		t.Fatal("invalid online candidate created a generation", err, matches)
	}
}
func TestTaskSubmenusCancelBeforeAnyWrites(t *testing.T) {
	for _, call := range []func(*app) error{func(a *app) error { return a.quickMenu() }, func(a *app) error { return a.exportTaskMenu() }, func(a *app) error { return a.diagnosticTaskMenu() }, func(a *app) error { return a.certificateTaskMenu() }, func(a *app) error { return a.advancedTaskMenu() }, func(a *app) error { return a.maintenanceTaskMenu() }} {
		a := wizardApp(t, "0\n")
		if err := call(a); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(a.store.Root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("return created root", err)
		}
	}
}
func TestListAndImpactJSONDoNotContainCredentialsOrProgress(t *testing.T) {
	a, n := menuFixture(t, "")
	before, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"list", "--json"}, {"edit", "--id", n.ID, "--name", "next", "--preview", "--json"}} {
		out, err := wizardOutput(t, func() error { return a.command(args) })
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err = json.Unmarshal([]byte(out), &decoded); err != nil {
			t.Fatal("JSON mixed human output", err, out)
		}
		if decoded["version"] != float64(1) || strings.Contains(out, n.Users[0].Password) || strings.Contains(out, "password") || strings.Contains(out, "配置已应用") {
			t.Fatal("unsafe JSON", out)
		}
	}
	for _, args := range [][]string{{"edit", "--id", n.ID, "--name", "wrong", "--json"}, {"batch", "--file", "absent.json", "--json"}} {
		if err := a.command(args); err == nil {
			t.Fatal("ignored invalid --json combination")
		}
	}
	after, err := a.store.Load()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("query modified State", err)
	}
}
