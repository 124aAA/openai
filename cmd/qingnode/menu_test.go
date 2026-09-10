package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func wizardApp(t *testing.T, input string) *app {
	t.Helper()
	return &app{offline: true, store: &node.Store{Root: filepath.Join(t.TempDir(), "state"), Backend: node.OfflineBackend{}, GID: -1}, in: bufio.NewReader(strings.NewReader(input))}
}

func wizardOutput(t *testing.T, call func() error) (string, error) {
	t.Helper()
	f, e := os.CreateTemp(t.TempDir(), "stdout")
	if e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old; f.Close() }()
	err := call()
	if _, e = f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e != nil {
		t.Fatal(e)
	}
	return string(b), err
}

func TestWizardSelectionCancelAndEOFDoNotCreateState(t *testing.T) {
	for _, input := range []string{"0\n", "", "\n9\n0\n"} {
		a := wizardApp(t, input)
		out, e := wizardOutput(t, func() error { return a.installWizard(true, "", false) })
		if e != nil && !errors.Is(e, io.EOF) {
			t.Fatal(e)
		}
		if out != "" {
			t.Fatal("cancelled wizard printed a result")
		}
		if _, e := os.Stat(a.store.Root); !os.IsNotExist(e) {
			t.Fatal("cancelled selection touched State", e)
		}
	}
}

func TestWizardSelectedProtocolAndResultMatchState(t *testing.T) {
	for _, tc := range []struct{ choice, protocol, extra string }{
		{"1", "reality", "example.com\n"},
		{"2", "ss2022", ""},
		{"3", "hysteria2", "node.example.com\nacme\nadmin@example.com\n"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			a := wizardApp(t, "9\n"+tc.choice+"\nmy-node\n203.0.113.9\n9443\n"+tc.extra)
			out, e := wizardOutput(t, func() error { return a.installWizard(true, "", false) })
			if e != nil {
				t.Fatal(e)
			}
			s, e := a.store.Load()
			if e != nil || len(s.Nodes) != 1 {
				t.Fatal(s, e)
			}
			n := s.Nodes[0]
			if n.Protocol != tc.protocol || n.Host != "203.0.113.9" || n.Port != 9443 {
				t.Fatal("wizard created different parameters")
			}
			for _, want := range []string{"客户端端口：9443", "--id " + n.ID, node.URI(n, n.Users[0])} {
				if !strings.Contains(out, want) {
					t.Fatalf("result missing %q", want)
				}
			}
			if strings.Count(out, "分享链接：") != 1 {
				t.Fatal("result should appear once")
			}
			if tc.protocol == "hysteria2" && !strings.Contains(out, "SNI：node.example.com\n证书方式：acme") {
				t.Fatal("missing Hysteria2 TLS details")
			}
		})
	}
}

func TestWizardQuietAndFailureDoNotPrintCredentials(t *testing.T) {
	for _, port := range []string{"9443", "0"} {
		a := wizardApp(t, "my-node\n203.0.113.9\n"+port+"\n")
		out, e := wizardOutput(t, func() error { return a.command([]string{"wizard", "--protocol", "ss2022", "--quiet"}) })
		if out != "" || (e == nil) != (port == "9443") {
			t.Fatal("quiet or failed wizard exposed a result", e)
		}
	}
}

func TestWizardAddSuggestsUnusedNameAndExportsSpecificUser(t *testing.T) {
	a := wizardApp(t, "\n203.0.113.9\n9443\n\n203.0.113.9\n9444\n")
	for _, first := range []bool{true, false} {
		if e := a.installWizard(first, "ss2022", true); e != nil {
			t.Fatal(e)
		}
	}
	s, _ := a.store.Load()
	if len(s.Nodes) != 2 || s.Nodes[0].Name != "main" || s.Nodes[1].Name != "main-2" {
		t.Fatal("default name collides with existing node")
	}
	if e := a.command([]string{"user-add", "--id", "main", "--name", "phone"}); e != nil {
		t.Fatal(e)
	}
	out, e := wizardOutput(t, func() error { return a.info([]string{"--id", "main"}) })
	if e != nil {
		t.Fatal(e)
	}
	s, _ = a.store.Load()
	for _, u := range s.Nodes[0].Users {
		cmd := "export --id " + s.Nodes[0].ID + " --format uri --user " + u.ID
		if !strings.Contains(out, cmd) {
			t.Fatal("missing command for specific credential")
		}
		uri, e := wizardOutput(t, func() error { return a.command(strings.Fields(cmd)) })
		if e != nil || strings.TrimSpace(uri) != node.URI(s.Nodes[0], u) {
			t.Fatal("displayed export command does not work", e)
		}
	}
}
