package main

import (
	"bytes"
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

func TestOrdinaryNodeQueriesCleanLegacyDisplayWithoutChangingState(t *testing.T) {
	a, s := dashboardFixture(t)
	n := &s.Nodes[0]
	n.Name = "旧名\u202e" + strings.Repeat("中文", 24) + "😀"
	n.Users[0].Name = "设备\u2066" + n.Users[0].UUID
	n.Host = "2001:db8:1234:5678:90ab:cdef:1234:5678"
	n.AdditionalEndpoints = []node.ConnectionEndpoint{{ID: "domain", Host: strings.Repeat("long-domain.", 12) + "example.com", Port: 30000}}
	if err := a.store.Apply(s); err != nil {
		t.Fatal(err)
	}
	before := statusTree(t, a.store.Root)
	for _, command := range [][]string{{"list"}, {"info"}, {"status"}} {
		out, err := wizardOutput(t, func() error { return a.command(command) })
		if err != nil || strings.ContainsAny(out, "\u202e\u2066") || strings.Contains(out, n.Users[0].UUID) || strings.Contains(out, n.Reality.PrivateKey) {
			t.Fatal("ordinary query exposed control or credential bytes", command, err)
		}
		if command[0] != "status" && (!strings.Contains(out, "中文") || !strings.Contains(out, n.Host)) {
			t.Fatal("ordinary query lost node display data", command)
		}
	}
	if !reflect.DeepEqual(before, statusTree(t, a.store.Root)) {
		t.Fatal("display cleanup changed saved State or derived files")
	}
	private, err := wizardOutput(t, func() error { return a.info([]string{"--id", n.ID, "--show-secrets", "--show-private"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{"UUID：" + n.Users[0].UUID + "\n", "Short ID：" + n.Reality.ShortID + "\n", "Reality Private Key：" + n.Reality.PrivateKey + "\n", node.URI(*n, n.Users[0]) + "\n"} {
		if !strings.Contains(private, exact) {
			t.Fatal("explicit private bytes changed")
		}
	}
}

type failedHumanSink struct{ err error }

func (w failedHumanSink) Write([]byte) (int, error) { return 0, w.err }

func TestStateHumanWriterRedactsBeforeWrappingAndPreservesExplicitBytes(t *testing.T) {
	s := node.NewState()
	n := node.Node{Users: []node.User{node.NewUser("default", "ss2022")}}
	s.Nodes = []node.Node{n}
	secret := n.Users[0].Password
	var out bytes.Buffer
	w := newStateTextWriter(&out, s)
	w.human = ui.NewTextWriter(&out, 12)
	for _, part := range []string{"中文\u202e😀 ", secret[:len(secret)/2], secret[len(secret)/2:], " remains"} {
		if _, err := io.WriteString(w, part); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	joined := strings.ReplaceAll(out.String(), "\n", "")
	if strings.Contains(joined, secret) || strings.Contains(out.String(), "\u202e") || !strings.Contains(joined, "中文") {
		t.Fatal("split secret or display control escaped human writer")
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if ui.DisplayWidth(line) > 12 {
			t.Fatal("human line exceeded configured width")
		}
	}
	raw := "\nss://" + strings.Repeat("encoded-private", 20) + "\n"
	if err := w.Raw(raw); err != nil || !strings.HasSuffix(out.String(), raw) {
		t.Fatal("explicit private line was wrapped or redacted", err)
	}
	failure := errors.New("fixture output failure")
	for _, raw := range []bool{false, true} {
		w = newStateTextWriter(failedHumanSink{failure}, s)
		if raw {
			if !errors.Is(w.Raw("private\n"), failure) {
				t.Fatal("raw output failure hidden")
			}
		} else if _, err := io.WriteString(w, "final unterminated line"); err != nil {
			t.Fatal("failure should be observed at Flush", err)
		}
		if !errors.Is(w.Flush(), failure) {
			t.Fatal("final Flush failure reported success")
		}
	}
}

func TestOrdinaryQueriesReturnOutputFailure(t *testing.T) {
	a, _ := dashboardFixture(t)
	for _, command := range [][]string{{"list"}, {"info"}, {"status"}, {"info", "--show-secrets", "--show-private"}} {
		func() {
			closed, err := os.Create(filepath.Join(t.TempDir(), "closed-output"))
			if err != nil {
				t.Fatal(err)
			}
			closed.Close()
			previous := os.Stdout
			os.Stdout = closed
			defer func() { os.Stdout = previous }()
			if err := a.command(command); err == nil {
				t.Fatal("ordinary query succeeded despite failed output", command)
			}
		}()
	}
}
