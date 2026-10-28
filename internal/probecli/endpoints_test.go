package probecli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"qingnode/internal/probe"
)

func TestEndpointProfileSelectionAndPortableProfileBoundary(t *testing.T) {
	raw := []byte(`{"type":"shadowsocks","tag":"proxy","server":"127.0.0.1","server_port":30000,"method":"2022-blake3-aes-256-gcm","password":"private-credential"}`)
	p, err := probe.NewProfile("node", "1.14.0", raw)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	calls := 0
	h := Hooks{Out: &out, SelectEndpointProfile: func(id, user, endpoint string) (probe.Profile, error) {
		calls++
		if id != "node" || user != "phone" || endpoint != "relay" {
			t.Fatal("endpoint selector lost", id, user, endpoint)
		}
		return p, nil
	}}
	path := filepath.Join(t.TempDir(), "private.json")
	if err = Execute(context.Background(), []string{"profile", "--id", "node", "--user", "phone", "--endpoint", "relay", "--out", path}, h); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("selector not called exactly once")
	}
	if err = Execute(context.Background(), []string{"run", "--path", "client-proxy", "--profile", path, "--endpoint", "relay", "--target", "https://example.test"}, h); err == nil {
		t.Fatal("portable profile allowed hidden endpoint override")
	}
	if calls != 1 {
		t.Fatal("invalid request read manager state")
	}
	h.SelectEndpointProfile = nil
	h.SelectProfile = func(string, string) (probe.Profile, error) {
		t.Fatal("legacy hook silently accepted extra endpoint")
		return p, nil
	}
	if err = Execute(context.Background(), []string{"profile", "--id", "node", "--endpoint", "relay", "--out", filepath.Join(t.TempDir(), "other.json")}, h); err == nil {
		t.Fatal("unsupported endpoint selection silently dropped")
	}
}
