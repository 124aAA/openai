package main

import (
	"bufio"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func TestTransportCreateEditAndReexportPreserveIdentity(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			a := wizardApp(t, "")
			args := []string{"--protocol", protocol, "--server", "2001:db8::2", "--listen", "127.0.0.1", "--port", "35440", "--connect-port", "443", "--sni", "proxy.example.test", "--acme-email", "owner@example.test", "--transport", "ws", "--transport-path", "/proxy", "--transport-host", "cdn.example.test", "--quiet"}
			if err := a.add("add", args); err != nil {
				t.Fatal(err)
			}
			before, err := a.store.Load()
			if err != nil || len(before.Nodes) != 1 {
				t.Fatal(err)
			}
			n := before.Nodes[0]
			if n.Transport == nil || n.Transport.Path != "/proxy" || n.Transport.Host != "cdn.example.test" || node.EffectiveConnectPort(n) != 443 {
				t.Fatal("create lost transport or NAT settings")
			}
			if err := a.edit([]string{"--id", n.ID, "--transport", "grpc"}); err != nil {
				t.Fatal(err)
			}
			after, _ := a.store.Load()
			updated := after.Nodes[0]
			if !reflect.DeepEqual(updated.Users, n.Users) || updated.ID != n.ID || updated.Transport.Type != "grpc" || updated.Transport.ServiceName != "qingnode" || updated.Transport.Path != "" || updated.Transport.Host != "" {
				t.Fatal("transport edit lost credentials or retained incompatible fields")
			}
			out, err := wizardOutput(t, func() error {
				return a.command([]string{"export", "--id", n.ID, "--format", "uri"})
			})
			if err != nil || strings.TrimSpace(out) != node.URI(updated, updated.Users[0]) || strings.TrimSpace(out) == node.URI(n, n.Users[0]) {
				t.Fatal("re-export did not use the new transport", err)
			}
			if err := a.edit([]string{"--id", n.ID, "--transport-host", "wrong.example.test"}); err == nil {
				t.Fatal("accepted WebSocket Host on gRPC")
			}
			unchanged, _ := a.store.Load()
			if !reflect.DeepEqual(after, unchanged) {
				t.Fatal("failed edit changed saved state")
			}
			if err := a.edit([]string{"--id", n.ID, "--transport", "tcp"}); err != nil {
				t.Fatal(err)
			}
			after, _ = a.store.Load()
			if after.Nodes[0].Transport != nil || !reflect.DeepEqual(after.Nodes[0].Users, n.Users) {
				t.Fatal("restoring direct TLS lost credentials or retained transport")
			}
		})
	}
}

func TestTransportWizardReusesCertificateAndCancelsBeforeSaving(t *testing.T) {
	a, original := protocolMenuFixture(t, "hysteria2", 35441)
	a.in = bufio.NewReader(strings.NewReader("vless-web\n203.0.113.4\n35442\n2\n/proxy\n\n\n"))
	printed, err := captureProtocolMenuStderr(t, func() error { return a.installWizard(false, "vless", true) })
	if err != nil {
		t.Fatal(err)
	}
	st, _ := a.store.Load()
	if len(st.Nodes) != 2 || st.Nodes[1].CertificateID != original.CertificateID || st.Nodes[1].Transport == nil || st.Nodes[1].Transport.Type != "ws" || st.Nodes[1].Transport.Path != "/proxy" {
		t.Fatal("wizard did not reuse certificate and selected transport")
	}
	if strings.Contains(printed, "ACME 邮箱") || strings.Contains(printed, "证书域名（") || strings.Contains(printed, "私钥 PEM 路径") {
		t.Fatal("reusing a certificate asked for duplicate certificate input")
	}
	for _, extra := range []string{":cancel\n", "2\n:cancel\n", "3\n:cancel\n"} {
		canceled := wizardApp(t, "new\n203.0.113.4\n35443\n"+extra)
		if err := canceled.installWizard(true, "vless", true); !errors.Is(err, errMenuCanceled) {
			t.Fatal("canceling transport form did not stop creation", err)
		}
		if _, err := os.Stat(canceled.store.Root); !os.IsNotExist(err) {
			t.Fatal("canceling transport form wrote state", err)
		}
	}
}

func TestTransportInstallPreflightRejectsInapplicableFields(t *testing.T) {
	for _, flags := range [][]string{
		{"--protocol", "ss2022", "--transport", "tcp"},
		{"--protocol", "anytls", "--transport", "ws"},
		{"--protocol", "vless", "--transport", "tcp", "--transport-path", "/proxy"},
		{"--protocol", "vmess", "--transport", "grpc", "--transport-host", "example.test"},
	} {
		if err := (&app{}).add("validate-install", append([]string{"--auto"}, flags...)); err == nil {
			t.Fatal("preflight accepted incompatible transport fields", flags)
		}
	}
}
