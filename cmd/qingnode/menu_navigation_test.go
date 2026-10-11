package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func menuFixture(t *testing.T, input string) (*app, node.Node) {
	t.Helper()
	a := wizardApp(t, input)
	if e := a.add("init", []string{"--protocol", "ss2022", "--server", "203.0.113.8", "--quiet"}); e != nil {
		t.Fatal(e)
	}
	s, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	return a, s.Nodes[0]
}

func TestSelectionRetriesAndCancellation(t *testing.T) {
	a, n := menuFixture(t, "wrong\n9\n1\n")
	selected, e := a.selectNode()
	if e != nil || selected.ID != n.ID {
		t.Fatal("invalid selection did not retry", e)
	}
	a.in = bufio.NewReader(strings.NewReader("0\n"))
	if _, e = a.selectNode(); !errors.Is(e, errMenuCanceled) {
		t.Fatal("node return is not cancellation", e)
	}
	n.Users = append(n.Users, node.NewUser("phone", "ss2022"))
	a.in = bufio.NewReader(strings.NewReader("bad\n3\n2\n"))
	if id, e := a.selectUser(n); e != nil || id != n.Users[1].ID {
		t.Fatal("credential selection did not retry", e)
	}
	a.in = bufio.NewReader(strings.NewReader("0\n"))
	if _, e = a.selectUser(n); !errors.Is(e, errMenuCanceled) {
		t.Fatal("credential return is not cancellation", e)
	}
	for _, input := range []string{"3\n", "8\n1\n", "9\n1\n"} {
		a.in = bufio.NewReader(strings.NewReader(input))
		if e = a.nodeMenu(); !errors.Is(e, io.EOF) {
			t.Fatal("subflow did not propagate EOF", e)
		}
	}
}

func TestWizardCancelAtEveryInputDoesNotCreateState(t *testing.T) {
	for protocol, fields := range map[string][]string{
		"ss2022":    {"main", "203.0.113.8", "9443"},
		"reality":   {"main", "203.0.113.8", "9443", "example.com"},
		"hysteria2": {"main", "203.0.113.8", "9443", "node.example.com", "pem", "cert.pem", "key.pem"},
	} {
		for i := range fields {
			input := append(append([]string{}, fields[:i]...), ":cancel")
			a := wizardApp(t, strings.Join(input, "\n")+"\n")
			out, e := wizardOutput(t, func() error { return a.installWizard(true, protocol, false) })
			if !errors.Is(e, errMenuCanceled) || out != "" {
				t.Fatalf("%s input %d did not cancel cleanly: %v", protocol, i, e)
			}
			if _, e = os.Lstat(a.store.Root); !os.IsNotExist(e) {
				t.Fatal("canceled wizard wrote state")
			}
		}
	}
}

func TestWizardCancelAtACMEEmailDoesNotCreateState(t *testing.T) {
	a := wizardApp(t, "main\n203.0.113.8\n9443\nnode.example.com\nacme\n:cancel\n")
	out, e := wizardOutput(t, func() error { return a.installWizard(true, "hysteria2", false) })
	if !errors.Is(e, errMenuCanceled) || out != "" {
		t.Fatal("ACME email did not cancel cleanly", e)
	}
	if _, e = os.Lstat(a.store.Root); !os.IsNotExist(e) {
		t.Fatal("canceled ACME wizard wrote state")
	}
}

func TestUnterminatedEOFDoesNotCreateNodeOrConfirm(t *testing.T) {
	a := wizardApp(t, "main\n203.0.113.8\n9443")
	if e := a.installWizard(true, "ss2022", true); !errors.Is(e, io.EOF) {
		t.Fatal("unterminated input was accepted", e)
	}
	if _, e := os.Lstat(a.store.Root); !os.IsNotExist(e) {
		t.Fatal("EOF created a node")
	}
	a.in = bufio.NewReader(strings.NewReader("yes"))
	if a.confirm("delete_warning") {
		t.Fatal("EOF confirmed a destructive action")
	}
}

func TestExportWizardNumericAndLegacyFormatsPreserveCredentials(t *testing.T) {
	for _, tc := range []struct {
		format  string
		choices []string
	}{
		{"uri", []string{"1", "uri", ""}},
		{"qr", []string{"2", "qr"}},
		{"mihomo", []string{"3", "mihomo"}},
		{"sing-box", []string{"4", "sing-box"}},
		{"provider", []string{"5", "provider"}},
		{"base64", []string{"6", "base64"}},
	} {
		for _, choice := range tc.choices {
			a, n := menuFixture(t, "1\ninvalid\n"+choice+"\n\n")
			out, e := wizardOutput(t, a.exportWizard)
			if e != nil {
				t.Fatalf("format %q failed: %v", choice, e)
			}
			want, e := node.Export(n, n.Users[0], tc.format)
			if e != nil || strings.TrimRight(out, "\n") != strings.TrimRight(string(want), "\n") {
				t.Fatalf("choice %q did not export %s: %v", choice, tc.format, e)
			}
			s, e := a.store.Load()
			if e != nil || !reflect.DeepEqual(s.Nodes[0], n) {
				t.Fatal("export changed credentials or node", e)
			}
		}
	}
	a, _ := menuFixture(t, "1\n0\n")
	if out, e := wizardOutput(t, a.exportWizard); !errors.Is(e, errMenuCanceled) || out != "" {
		t.Fatal("canceled export produced secrets", e)
	}
}
