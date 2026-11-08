package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func graphTestRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func graphTestSOCKS(tag, detour string) map[string]any {
	o := map[string]any{"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": 1080, "version": "5", "username": "remote-user", "password": "remote-password"}
	if detour != "" {
		o["detour"] = detour
	}
	return o
}

func graphTestWG() map[string]any {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	return map[string]any{"type": "wireguard", "tag": "wg", "system": false, "address": []string{"10.79.0.1/32"}, "private_key": key, "mtu": 1408, "peers": []any{map[string]any{"address": "127.0.0.1", "port": 51820, "public_key": key, "allowed_ips": []string{"0.0.0.0/0"}}}}
}

func TestGraphProfileStrictPathAndNoDirectFallback(t *testing.T) {
	p, err := NewGraphProfile("chain-test", "1.14.0", "second", []json.RawMessage{graphTestRaw(t, graphTestSOCKS("first", "")), graphTestRaw(t, graphTestSOCKS("second", "first"))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.SupportsNetwork("tcp") || !p.SupportsNetwork("udp") {
		t.Fatal("valid SOCKS5 chain must support both")
	}
	b, err := graphSandboxConfig(p, 2080, "local-user", "local-password")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg["outbounds"].([]any)) != 2 || cfg["route"].(map[string]any)["final"] != "second" || strings.Contains(string(b), `"type": "direct"`) || strings.Contains(string(b), "selector") {
		t.Fatalf("unexpected path: %s", b)
	}
	if cfg["inbounds"].([]any)[0].(map[string]any)["listen"] != "127.0.0.1" {
		t.Fatal("temporary mixed must remain loopback")
	}
	if _, err = NewGraphProfile("chain-test", "1.14.3", "second", append(p.Outbounds, graphTestRaw(t, graphTestSOCKS("unused", ""))), nil); err == nil {
		t.Fatal("unused alternative path accepted")
	}
	p.Outbounds[0] = graphTestRaw(t, graphTestSOCKS("first", "second"))
	p.ConfigSHA256 = p.digest()
	if p.Validate() == nil {
		t.Fatal("detour cycle accepted")
	}
}

func TestGraphProfileRejectsInjectionAndInvalidMembers(t *testing.T) {
	cases := map[string]func(map[string]any){
		"direct":           func(o map[string]any) { o["type"] = "direct" },
		"selector":         func(o map[string]any) { o["type"] = "selector"; o["outbounds"] = []string{"direct"} },
		"unknown":          func(o map[string]any) { o["command"] = "bad" },
		"case alias":       func(o map[string]any) { o["Type"] = "direct" },
		"bind ignored":     func(o map[string]any) { o["detour"] = "other"; o["bind_interface"] = "wg0" },
		"DNS ignored":      func(o map[string]any) { o["detour"] = "other"; o["domain_resolver"] = "system" },
		"foreign resolver": func(o map[string]any) { o["domain_resolver"] = "proxy" },
		"IPv6 bracket":     func(o map[string]any) { o["server"] = "[::1]" },
		"endpoint URL":     func(o map[string]any) { o["server"] = "https://example.com" },
		"version4":         func(o map[string]any) { o["version"] = "4" },
		"partial auth":     func(o map[string]any) { delete(o, "password") },
		"unknown network":  func(o map[string]any) { o["network"] = "both" },
		"HY2 on SOCKS":     func(o map[string]any) { o["bbr_profile"] = "standard" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o := graphTestSOCKS("a", "")
			change(o)
			if _, err := NewGraphProfile("test", "1.14.0", "a", []json.RawMessage{graphTestRaw(t, o)}, nil); err == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
	duplicate := json.RawMessage(`{"type":"socks","type":"direct","tag":"a"}`)
	if _, err := NewGraphProfile("test", "1.14.0", "a", []json.RawMessage{duplicate}, nil); err == nil {
		t.Fatal("duplicate field accepted")
	}
	for _, version := range []string{"1.13.9", "1.15.0", "1.14.3-beta.1"} {
		if _, err := NewGraphProfile("test", version, "a", []json.RawMessage{graphTestRaw(t, graphTestSOCKS("a", ""))}, nil); err == nil {
			t.Fatal("unsupported compatibility line accepted")
		}
	}
}

func TestGraphWGAndDNSAreBoundedAndHashed(t *testing.T) {
	p, err := NewGraphProfile("test", "1.14.3", "wg", nil, []json.RawMessage{graphTestRaw(t, graphTestWG())})
	if err != nil || !p.SupportsNetwork("tcp") || !p.SupportsNetwork("udp") {
		t.Fatal(err)
	}
	q, err := SetGraphResolver(p, "udp", "127.0.0.1", 5353)
	if err != nil || q.ConfigSHA256 == p.ConfigSHA256 {
		t.Fatal("resolver not bound by digest", err)
	}
	b, err := graphSandboxConfig(q, 2080, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	dns := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if dns["server"] != "127.0.0.1" || dns["server_port"] != float64(5353) {
		t.Fatalf("wrong bootstrap: %s", b)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["action"] != "reject" {
		t.Fatal("WG unsolicited landing traffic must be rejected")
	}
	for _, v := range []struct {
		kind, host string
		port       int
	}{{"https", "1.1.1.1", 443}, {"udp", "example.com", 53}, {"udp", "::", 53}, {"udp", "::1", 0}, {"system", "1.1.1.1", 53}} {
		if _, err = SetGraphResolver(p, v.kind, v.host, v.port); err == nil {
			t.Fatal("invalid resolver accepted", v)
		}
	}
	for name, change := range map[string]func(map[string]any){"system interface": func(o map[string]any) { o["system"] = true }, "interface name": func(o map[string]any) { o["name"] = "wg0" }, "listen detour": func(o map[string]any) { o["listen_port"] = 51820; o["detour"] = "first" }, "bad key": func(o map[string]any) { o["private_key"] = "wrong" }, "bad MTU": func(o map[string]any) { o["mtu"] = 65535 }, "bad allowed IP": func(o map[string]any) { o["peers"].([]any)[0].(map[string]any)["allowed_ips"] = []string{"not-CIDR"} }} {
		t.Run(name, func(t *testing.T) {
			o := graphTestWG()
			change(o)
			if _, err := NewGraphProfile("test", "1.14.0", "wg", nil, []json.RawMessage{graphTestRaw(t, o)}); err == nil {
				t.Fatal("invalid WG accepted")
			}
		})
	}
	q.Resolver.Port++
	if q.Validate() == nil {
		t.Fatal("tampered resolver accepted")
	}
}

func TestGraphNetworkIncludesProxyTransport(t *testing.T) {
	tcpOnly := graphTestSOCKS("first", "")
	tcpOnly["network"] = "tcp"
	last := graphTestSOCKS("last", "first")
	p, err := NewGraphProfile("test", "1.14.0", "last", []json.RawMessage{graphTestRaw(t, tcpOnly), graphTestRaw(t, last)}, nil)
	if err != nil || !p.SupportsNetwork("tcp") || p.SupportsNetwork("udp") {
		t.Fatal("TCP-only SOCKS incorrectly used for UDP", err)
	}
	wg := graphTestWG()
	wg["detour"] = "first"
	w, err := NewGraphProfile("test", "1.14.0", "wg", []json.RawMessage{graphTestRaw(t, tcpOnly)}, []json.RawMessage{graphTestRaw(t, wg)})
	if err != nil {
		t.Fatal(err)
	}
	if w.SupportsNetwork("tcp") || w.SupportsNetwork("udp") {
		t.Fatal("WireGuard carrier UDP escaped TCP-only validation")
	}
}

func TestGraphCanceledOrInvalidCoreLeavesNoPrivateFiles(t *testing.T) {
	p, err := NewGraphProfile("test", "1.14.0", "one", []json.RawMessage{graphTestRaw(t, graphTestSOCKS("one", ""))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err = StartGraphSandbox(context.Background(), p, SandboxOptions{CoreBinary: "relative", SHA256: strings.Repeat("0", 64), TempParent: dir}); err == nil {
		t.Fatal("untrusted core accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed graph startup left files", err)
	}
}

func TestGraphCoreCapabilitiesKeepVersionsAndTagsSeparate(t *testing.T) {
	all := map[string]bool{"with_quic": true, "with_utls": true, "with_wireguard": true, "with_gvisor": true}
	for _, version := range []string{"1.14.0", "1.14.3"} {
		if err := checkProbeCoreCapabilities(version, all, []string{"vless", "hysteria2", "wireguard"}); err != nil {
			t.Fatal(version, err)
		}
	}
	for _, tag := range []string{"with_quic", "with_utls", "with_wireguard", "with_gvisor"} {
		tags := map[string]bool{}
		for key, value := range all {
			tags[key] = value
		}
		delete(tags, tag)
		if err := checkProbeCoreCapabilities("1.14.3", tags, []string{"vless", "hysteria2", "wireguard"}); err == nil {
			t.Fatal("accepted version masked missing feature tag", tag)
		}
	}
	if err := checkProbeCoreCapabilities("1.15.0", all, []string{"wireguard"}); err == nil {
		t.Fatal("feature tags allowed an unverified compatibility line")
	}
	if err := checkProbeCoreCapabilities("1.14.0", nil, []string{"socks", "shadowsocks"}); err != nil {
		t.Fatal("unrelated tags became mandatory", err)
	}
}
