package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func TestProtocolMenuUsesObservedBuildTagsNotCoreVersionAlone(t *testing.T) {
	observed := protocolMenuCore{version: "1.14.3", installed: true}
	if reason := observed.unavailableReason("ss-aead"); !strings.Contains(reason, "尚未核实") {
		t.Fatal("unchecked custom core was accepted without real build evidence:", reason)
	}
	observed.verified = true
	if reason := observed.unavailableReason("tuic"); !strings.Contains(reason, "with_quic") {
		t.Fatal("version string was treated as QUIC build evidence:", reason)
	}
	observed.tags = []string{"with_quic"}
	if reason := observed.unavailableReason("tuic"); reason != "" {
		t.Fatal("actually observed QUIC tag was rejected:", reason)
	}
	observed.checkErr = errors.New("已安装核心摘要不匹配")
	if reason := observed.unavailableReason("ss-aead"); !strings.Contains(reason, "摘要不匹配") {
		t.Fatal("failed artifact verification was hidden:", reason)
	}
	observed.installed = false
	observed.checkErr = nil
	if reason := observed.unavailableReason("tuic"); reason != "" {
		t.Fatal("first installation must remain available:", reason)
	}
	observed.offline = true
	observed.installed = true
	observed.checkErr = errors.New("offline configuration has no usable core")
	if reason := observed.unavailableReason("tuic"); reason != "" {
		t.Fatal("offline generation was blocked by a runtime check:", reason)
	}
}

func TestProtocolMenuIsReadOnlyAndExplainsClientBoundary(t *testing.T) {
	a := wizardApp(t, "7\n")
	printed, err := captureProtocolMenuStderr(t, func() error {
		protocol, err := a.selectProtocol()
		if err == nil && protocol != "tuic" {
			t.Fatalf("selected %q, expected tuic", protocol)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"离线配置可生成；运行能力未验证", "sing-box 1.14.0/1.14.3", "Mihomo 1.19.30", "分享URI未核验"} {
		if !strings.Contains(printed, wanted) {
			t.Fatalf("menu hid %q", wanted)
		}
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("read-only protocol menu created the state directory", err)
	}
}

func TestProtocolMenuAllowsFirstInstallWithoutCreatingState(t *testing.T) {
	a := wizardApp(t, "7\n")
	a.offline = false
	printed, err := captureProtocolMenuStderr(t, func() error {
		protocol, err := a.selectProtocol()
		if err == nil && protocol != "tuic" {
			t.Fatalf("first-install menu selected %q", protocol)
		}
		return err
	})
	if err != nil || !strings.Contains(printed, "核心尚未安装；向导完成参数后安装并校验") {
		t.Fatal("first installation was blocked or presented as verified", err, printed)
	}
	if _, err := os.Lstat(a.store.Root); !os.IsNotExist(err) {
		t.Fatal("first-install menu created State before user entered parameters", err)
	}
}

func TestProtocolMenuRejectsInvalidInstalledCoreBeforeWizardInput(t *testing.T) {
	a := wizardApp(t, "7\n0\n")
	a.offline = false
	if err := a.store.WithLock(func() error {
		path := node.CorePath(a.store.Root, node.DefaultCore)
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("not a verified core"), 0755)
	}); err != nil {
		t.Fatal(err)
	}
	printed, err := captureProtocolMenuStderr(t, func() error {
		protocol, err := a.selectProtocol()
		if err == nil && protocol != "" {
			t.Fatalf("invalid installed core selected %q", protocol)
		}
		return err
	})
	if err != nil || !strings.Contains(printed, "摘要不匹配") || !strings.Contains(printed, "当前不可用") {
		t.Fatal("invalid installed core reason was not shown", err, printed)
	}
	if err := a.installWizard(false, "tuic", true); err == nil || !strings.Contains(err.Error(), "摘要不匹配") {
		t.Fatal("explicit protocol wizard bypassed observed core failure", err)
	}
	if _, err := os.Lstat(filepath.Join(a.store.Root, "current")); !os.IsNotExist(err) {
		t.Fatal("rejected wizard changed current generation", err)
	}
}

func TestTUICExportMenuOffersFullConfigAfterUnsupportedURI(t *testing.T) {
	a, _ := protocolMenuFixture(t, "tuic", 35512)
	path := filepath.Join(t.TempDir(), "tuic-client.json")
	a.in = bufio.NewReader(strings.NewReader("1\n1\n4\n" + path + "\n"))
	printed, err := captureProtocolMenuStderr(t, a.exportWizard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed, "尚未验证通用TUIC分享URI") || !strings.Contains(printed, "目标客户端版本：1.14.0") {
		t.Fatal("export menu hid the unsupported URI or actual full-config target", printed)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), `"type": "tuic"`) {
		t.Fatal("menu did not export a full TUIC client config", err)
	}
}

func TestTraditionalSSRejectsTLSArgumentsWithItsOwnProtocolName(t *testing.T) {
	a := wizardApp(t, "")
	err := a.add("add", []string{"--protocol", "ss-aead", "--server", "127.0.0.1", "--listen", "127.0.0.1", "--port", "35513", "--sni", "wrong.example.test", "--quiet"})
	if err == nil || !strings.Contains(err.Error(), "ss-aead 不使用 SNI、REALITY 或 TLS 参数") {
		t.Fatal("traditional SS error named a different protocol", err)
	}
}
