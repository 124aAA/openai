package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"qingnode/internal/node"
)

func TestProtocolExpansionCLISharedCertificateAndStableIdentity(t *testing.T) {
	a, base := batchFixture(t)
	for i, protocol := range []string{"anytls", "trojan"} {
		args := []string{"--protocol", protocol, "--name", protocol, "--server", "[2001:db8::7]", "--listen", "127.0.0.1", "--port", strconv.Itoa(33443 + i), "--connect-port", "30000", "--quiet"}
		if i == 0 {
			args = append(args, "--sni", "proxy.example.test", "--acme-email", "owner@example.test")
		} else {
			s, e := a.store.Load()
			if e != nil {
				t.Fatal(e)
			}
			args = append(args, "--certificate-id", s.Nodes[len(s.Nodes)-1].CertificateID)
		}
		if e := a.add("add", args); e != nil {
			t.Fatal(e)
		}
	}
	s, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Nodes) != len(base.Nodes)+2 || s.Nodes[len(base.Nodes)].CertificateID != s.Nodes[len(base.Nodes)+1].CertificateID {
		t.Fatal("shared resource not retained")
	}
	n := s.Nodes[len(base.Nodes)]
	identity, _ := json.Marshal(n.Users)
	if e := a.users("user-add", []string{"--id", n.ID, "--name", "设备二"}); e != nil {
		t.Fatal(e)
	}
	if e := a.edit([]string{"--id", n.ID, "--name", "改名后", "--connect-port", "30001"}); e != nil {
		t.Fatal(e)
	}
	updated, e := a.store.Load()
	if e != nil {
		t.Fatal(e)
	}
	now, _ := updated.Find(n.ID)
	first, _ := json.Marshal(now.Users[:1])
	if !bytes.Equal(first, identity) {
		t.Fatal("ordinary edit rotated password")
	}
	if _, e := node.Export(*now, now.Users[0], "sing-box"); e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(t.TempDir(), "options.json")
	if e := os.WriteFile(input, []byte(`{"version":1,"node_id":"`+n.ID+`","anytls":{"idle_session_min_keep":0,"idle_session_timeout":"30s"}}`), 0600); e != nil {
		t.Fatal(e)
	}
	_, saved := savedBatchState(t, a)
	if e := a.protocols([]string{"options", "--file", input, "--preview"}); e != nil {
		t.Fatal(e)
	}
	if _, raw := savedBatchState(t, a); !bytes.Equal(raw, saved) {
		t.Fatal("preview changed State")
	}
	if e := a.protocols([]string{"options", "--file", input, "--yes"}); e != nil {
		t.Fatal(e)
	}
	updated, _ = a.store.Load()
	now, _ = updated.Find(n.ID)
	if _, e := node.Export(*now, now.Users[0], "uri"); e == nil {
		t.Fatal("URI silently lost pool options")
	}
}

func TestProtocolsListSeparatesClientExportAndServerEgress(t *testing.T) {
	output, err := wizardOutput(t, func() error { return (&app{}).protocols([]string{"list"}) })
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version            int  `json:"version"`
		CoreBinaryVerified bool `json:"core_binary_verified"`
		Protocols          []struct {
			Protocol       string `json:"protocol"`
			Server         bool   `json:"server"`
			Outbound       bool   `json:"outbound"`
			ClientOutbound bool   `json:"client_outbound"`
			ServerEgress   bool   `json:"server_egress"`
		} `json:"protocols"`
	}
	if err = json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.CoreBinaryVerified || len(result.Protocols) != len(node.Protocols()) {
		t.Fatalf("unexpected CLI capability response: %s", output)
	}
	remote := map[string]bool{"reality": true, "ss2022": true, "hysteria2": true}
	for _, capability := range result.Protocols {
		if !capability.Server || !capability.Outbound || !capability.ClientOutbound || capability.ServerEgress != remote[capability.Protocol] {
			t.Fatalf("CLI conflated client export with server Egress: %+v", capability)
		}
	}
}
