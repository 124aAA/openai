package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func captureProtocolMenuStderr(t *testing.T, call func() error) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = old; f.Close() }()
	err = call()
	if _, seekErr := f.Seek(0, 0); seekErr != nil {
		t.Fatal(seekErr)
	}
	b, readErr := io.ReadAll(f)
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), err
}

func protocolMenuFixture(t *testing.T, protocol string, port int) (*app, node.Node) {
	t.Helper()
	a := wizardApp(t, "")
	args := []string{"--protocol", protocol, "--name", "protocol-menu", "--server", "127.0.0.1", "--listen", "127.0.0.1", "--port", strconv.Itoa(port), "--quiet"}
	if node.ProtocolRequiresCertificate(protocol) {
		args = append(args, "--sni", "proxy.example.test", "--acme-email", "owner@example.test")
	}
	if err := a.add("add", args); err != nil {
		t.Fatal(err)
	}
	s, err := a.store.Load()
	if err != nil || len(s.Nodes) != 1 {
		t.Fatal(err)
	}
	return a, s.Nodes[0]
}

func TestProtocolMenuExportsUseVerifiedClientVersion(t *testing.T) {
	for i, protocol := range []string{"anytls", "trojan", "ss-aead", "tuic", "ss2022"} {
		t.Run(protocol, func(t *testing.T) {
			a, n := protocolMenuFixture(t, protocol, 35500+i)
			for _, tc := range []struct{ selection, version string }{
				{"3", "1.19.30"}, // Mihomo full config
				{"4", "1.14.0"},  // sing-box full config
				{"5", "1.19.30"}, // Mihomo provider
			} {
				path := filepath.Join(t.TempDir(), "client-"+tc.selection)
				a.in = bufio.NewReader(strings.NewReader("1\n" + tc.selection + "\n" + path + "\n"))
				stderr, err := captureProtocolMenuStderr(t, a.exportWizard)
				if err != nil {
					t.Fatalf("menu choice %s rejected the verified client export: %v", tc.selection, err)
				}
				b, err := os.ReadFile(path)
				if err != nil || len(b) == 0 {
					t.Fatalf("menu choice %s did not save the selected client's configuration: %v", tc.selection, err)
				}
				if protocol == "ss2022" {
					if strings.Contains(stderr, "目标客户端版本：") {
						t.Fatal("legacy export was given a new client-version policy")
					}
				} else if !strings.Contains(stderr, "目标客户端版本："+tc.version) {
					t.Fatal("menu omitted the actual fixed target version", tc.selection)
				}
			}
			out, err := wizardOutput(t, func() error { return a.info([]string{"--id", n.ID}) })
			if err != nil {
				t.Fatal(err)
			}
			want := "--format sing-box --user " + n.Users[0].ID
			if protocol != "ss2022" {
				want += " --client-version 1.14.0"
			}
			if !strings.Contains(out, want+" --out client.json") {
				t.Fatal("info printed a non-executable or changed legacy export command")
			}
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(line, "导出配置：qingnode export --id ") {
					continue
				}
				args := strings.Fields(strings.TrimPrefix(line, "导出配置：qingnode "))
				path := filepath.Join(t.TempDir(), "from-info.json")
				args[len(args)-1] = path
				if err := a.command(args); err != nil {
					t.Fatal("copying the info export command failed", err)
				}
				if b, err := os.ReadFile(path); err != nil || len(b) == 0 {
					t.Fatal("info export command saved no configuration", err)
				}
				return
			}
			t.Fatal("info did not show a complete export command")
		})
	}
}

func TestTraditionalSSUserMenuOmitsSS2022ServiceKeyAction(t *testing.T) {
	a, n := protocolMenuFixture(t, "ss-aead", 35510)
	a.in = bufio.NewReader(strings.NewReader("4\n"))
	stderr, err := captureProtocolMenuStderr(t, func() error { return a.userMenu(n) })
	if err == nil || !strings.Contains(err.Error(), "仅用于 SS2022") || strings.Contains(stderr, "轮换 SS2022 服务密钥") {
		t.Fatal("traditional SS offered a service-key action", err)
	}
	s, err := a.store.Load()
	if err != nil || len(s.Nodes) != 1 || s.Nodes[0].Shadowsocks.ServerKey != "" || s.Nodes[0].Users[0].Password != n.Users[0].Password {
		t.Fatal("rejected menu action changed traditional SS credentials", err)
	}
	legacy, old := protocolMenuFixture(t, "ss2022", 35511)
	legacy.in = bufio.NewReader(strings.NewReader("0\n"))
	stderr, err = captureProtocolMenuStderr(t, func() error { return legacy.userMenu(old) })
	if err != nil && !errors.Is(err, errMenuCanceled) {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "轮换 SS2022 服务密钥") {
		t.Fatal("existing SS2022 action disappeared")
	}
}
