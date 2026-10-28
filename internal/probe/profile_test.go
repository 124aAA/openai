package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testProfile(t *testing.T) Profile {
	t.Helper()
	p, err := NewProfile("test-node", "1.14.0", []byte(`{"type":"shadowsocks","tag":"proxy","server":"127.0.0.1","server_port":1443,"method":"2022-blake3-aes-256-gcm","password":"private-client-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestProfileRejectsFallbackServerSecretsAndUnknownFormats(t *testing.T) {
	p := testProfile(t)
	for _, raw := range []string{
		strings.Replace(string(p.Outbound), `"type":"shadowsocks"`, `"type":"direct"`, 1),
		strings.Replace(string(p.Outbound), `"tag":"proxy"`, `"tag":"proxy","detour":"direct"`, 1),
		strings.Replace(string(p.Outbound), `"tag":"proxy"`, `"tag":"proxy","private_key":"server-secret"`, 1),
		strings.Replace(string(p.Outbound), `"tag":"proxy"`, `"tag":"proxy","tag":"proxy"`, 1),
		`{"type":"selector","tag":"proxy","outbounds":["proxy","direct"]}`,
	} {
		if _, err := NewProfile("id", "1.14.0", []byte(raw)); err == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
	for _, v := range []int{0, 2} {
		p.Version = v
		if p.Validate() == nil {
			t.Fatal("unsupported version accepted")
		}
	}
}
func TestPrivateProfileRoundtripAndNoOverwrite(t *testing.T) {
	p := testProfile(t)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := WriteProfile(path, p); err != nil {
		t.Fatal(err)
	}
	got, err := ReadProfile(path)
	if err != nil || got.ConfigSHA256 != p.ConfigSHA256 {
		t.Fatal(err)
	}
	if err = WriteProfile(path, p); err == nil {
		t.Fatal("existing profile overwritten")
	}
	b, _ := os.ReadFile(path)
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	obj["future"] = true
	b, _ = json.Marshal(obj)
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadProfile(path); err == nil {
		t.Fatal("unknown profile field accepted")
	}
}
func TestSandboxConfigContainsExactlySelectedOutbound(t *testing.T) {
	p := testProfile(t)
	b, err := SandboxConfig(p, 10001)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Outbounds []map[string]any
		Inbounds  []map[string]any
		Route     map[string]any
	}
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Outbounds) != 1 || c.Outbounds[0]["type"] != "shadowsocks" || c.Route["final"] != "proxy" || len(c.Inbounds) != 1 || c.Inbounds[0]["listen"] != "127.0.0.1" {
		t.Fatal("sandbox route/listener escaped its isolation")
	}
}

func TestCoreFileBoundsAndCanceledHashDoNotStartProcess(t *testing.T) {
	p := testProfile(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "core")
	data := []byte("must never execute")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	opts := SandboxOptions{CoreBinary: path, SHA256: hex.EncodeToString(digest[:]), TempParent: dir}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StartSandbox(ctx, p, opts); err != context.Canceled {
		t.Fatalf("canceled hash proceeded: %v", err)
	}
	if err := os.Truncate(path, (256<<20)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := StartSandbox(context.Background(), p, opts); err == nil {
		t.Fatal("oversized core accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("core validation left temp credentials/process", err)
	}
}
