package probe

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func expansionOutbound(kind string) map[string]any {
	o := map[string]any{"type": kind, "tag": "proxy", "server": "127.0.0.1", "server_port": 1443, "password": "private-client-secret"}
	if kind == "shadowsocks" {
		o["method"] = "aes-256-gcm"
	} else {
		o["tls"] = map[string]any{"enabled": true, "server_name": "fixture.example"}
	}
	if kind == "tuic" {
		o["uuid"] = "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f"
		o["congestion_control"], o["udp_relay_mode"], o["zero_rtt_handshake"], o["heartbeat"] = "bbr", "quic", false, "1500ms"
		o["tls"].(map[string]any)["alpn"] = []string{"h3"}
	}
	return o
}

func TestProtocolExpansionProfilesAndSandbox(t *testing.T) {
	for _, version := range []string{"1.14.0", "1.14.3"} {
		for _, kind := range []string{"anytls", "trojan", "shadowsocks", "tuic"} {
			t.Run(version+"/"+kind, func(t *testing.T) {
				o := expansionOutbound(kind)
				if kind == "anytls" {
					o["idle_session_check_interval"], o["idle_session_timeout"], o["min_idle_session"] = "6s", "24h", 0
				}
				p, err := NewProfile("stable-id", version, graphTestRaw(t, o))
				if err != nil {
					t.Fatal(err)
				}
				b, err := sandboxConfig(p, 2080, "local", "local-only-password")
				if err != nil {
					t.Fatal(err)
				}
				var config struct {
					Outbounds []json.RawMessage `json:"outbounds"`
					Route     struct {
						Final string `json:"final"`
					} `json:"route"`
				}
				if json.Unmarshal(b, &config) != nil || len(config.Outbounds) != 1 || config.Route.Final != "proxy" || !bytes.Equal(config.Outbounds[0], p.Outbound) && !jsonEqual(config.Outbounds[0], p.Outbound) {
					t.Fatal("sandbox did not retain the single selected outbound")
				}
				if kind == "anytls" && !bytes.Contains(p.Outbound, []byte(`"min_idle_session":0`)) {
					t.Fatal("explicit zero idle retention was omitted")
				}
			})
		}
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		o := expansionOutbound("shadowsocks")
		o["method"] = method
		if _, err := NewProfile("id", "1.14.0", graphTestRaw(t, o)); err != nil {
			t.Fatal(method, err)
		}
	}
}

func jsonEqual(a, b []byte) bool {
	var ca, cb bytes.Buffer
	return json.Compact(&ca, a) == nil && json.Compact(&cb, b) == nil && bytes.Equal(ca.Bytes(), cb.Bytes())
}

func TestProtocolExpansionRejectsMisplacedAndUnmodeledFields(t *testing.T) {
	cases := map[string]struct {
		kind   string
		mutate func(map[string]any)
	}{
		"anytls interval silently defaulted": {"anytls", func(o map[string]any) { o["idle_session_check_interval"] = "5s" }},
		"anytls fractional seconds":          {"anytls", func(o map[string]any) { o["idle_session_timeout"] = "6.5s" }},
		"anytls timeout bound":               {"anytls", func(o map[string]any) { o["idle_session_timeout"] = "24h1s" }},
		"anytls retention bound":             {"anytls", func(o map[string]any) { o["min_idle_session"] = 1025 }},
		"anytls negative retention":          {"anytls", func(o map[string]any) { o["min_idle_session"] = -1 }},
		"anytls metadata unmodeled":          {"anytls", func(o map[string]any) { o["client_metadata"] = "unmodeled" }},
		"trojan wrong pool even null":        {"trojan", func(o map[string]any) { o["min_idle_session"] = nil }},
		"trojan wrong TUIC false":            {"trojan", func(o map[string]any) { o["zero_rtt_handshake"] = false }},
		"trojan short credential":            {"trojan", func(o map[string]any) { o["password"] = "short" }},
		"trojan control credential":          {"trojan", func(o map[string]any) { o["password"] = "private-password\u0085" }},
		"trojan arbitrary transport":         {"trojan", func(o map[string]any) { o["transport"] = map[string]any{"type": "ws"} }},
		"trojan insecure":                    {"trojan", func(o map[string]any) { o["tls"].(map[string]any)["insecure"] = true }},
		"trojan extra ALPN null":             {"trojan", func(o map[string]any) { o["tls"].(map[string]any)["alpn"] = nil }},
		"anytls UTLS": {"anytls", func(o map[string]any) {
			o["tls"].(map[string]any)["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}},
		"tuic 0RTT":                     {"tuic", func(o map[string]any) { o["zero_rtt_handshake"] = true }},
		"tuic unknown CC":               {"tuic", func(o map[string]any) { o["congestion_control"] = "unknown" }},
		"tuic unknown relay":            {"tuic", func(o map[string]any) { o["udp_relay_mode"] = "unknown" }},
		"tuic UoT unmodeled":            {"tuic", func(o map[string]any) { o["udp_over_stream"] = true }},
		"tuic client server auth field": {"tuic", func(o map[string]any) { o["auth_timeout"] = "3s" }},
		"tuic HY2 mixing":               {"tuic", func(o map[string]any) { o["bbr_profile"] = "standard" }},
		"tuic pool empty":               {"tuic", func(o map[string]any) { o["idle_session_timeout"] = "" }},
		"tuic UUID":                     {"tuic", func(o map[string]any) { o["uuid"] = "invalid" }},
		"tuic short heartbeat":          {"tuic", func(o map[string]any) { o["heartbeat"] = "999ms" }},
		"tuic heartbeat bound":          {"tuic", func(o map[string]any) { o["heartbeat"] = "121s" }},
		"tuic heartbeat precision":      {"tuic", func(o map[string]any) { o["heartbeat"] = "1000000001ns" }},
		"tuic ALPN":                     {"tuic", func(o map[string]any) { o["tls"].(map[string]any)["alpn"] = []string{"h2"} }},
		"SS none":                       {"shadowsocks", func(o map[string]any) { o["method"] = "none" }},
		"SS stream":                     {"shadowsocks", func(o map[string]any) { o["method"] = "aes-128-cfb" }},
		"SS plugin":                     {"shadowsocks", func(o map[string]any) { o["plugin"] = "obfs" }},
		"SS TUIC option null":           {"shadowsocks", func(o map[string]any) { o["congestion_control"] = nil }},
		"field case alias":              {"trojan", func(o map[string]any) { o["Password"] = "other-password-value" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := expansionOutbound(tc.kind)
			tc.mutate(o)
			if _, err := NewProfile("id", "1.14.3", graphTestRaw(t, o)); err == nil {
				t.Fatal("unsafe portable profile accepted")
			}
			o["tag"] = "remote"
			if _, err := NewGraphProfile("id", "1.14.3", "remote", []json.RawMessage{graphTestRaw(t, o)}, nil); err == nil {
				t.Fatal("unsafe graph profile accepted")
			}
		})
	}
}

func TestProtocolExpansionGraphTransportRequirements(t *testing.T) {
	for _, kind := range []string{"anytls", "trojan", "shadowsocks", "tuic"} {
		o := expansionOutbound(kind)
		o["tag"], o["detour"] = "remote", "first"
		first := graphTestSOCKS("first", "")
		first["network"] = "tcp"
		p, err := NewGraphProfile("id", "1.14.3", "remote", []json.RawMessage{graphTestRaw(t, first), graphTestRaw(t, o)}, nil)
		if err != nil {
			t.Fatal(kind, err)
		}
		wantTCP := kind != "tuic"
		wantUDP := kind == "anytls" || kind == "trojan"
		if p.SupportsNetwork("tcp") != wantTCP || p.SupportsNetwork("udp") != wantUDP {
			t.Fatalf("%s confused listener carrier and business UDP", kind)
		}
	}
	for _, name := range []string{"min_idle_session", "zero_rtt_handshake"} {
		o := graphTestSOCKS("remote", "")
		o[name] = nil
		if _, err := NewGraphProfile("id", "1.14.3", "remote", []json.RawMessage{graphTestRaw(t, o)}, nil); err == nil {
			t.Fatal("SOCKS accepted foreign protocol field", name)
		}
	}
	if checkProbeCoreCapabilities("1.14.0", nil, []string{"anytls", "trojan", "shadowsocks"}) != nil || checkProbeCoreCapabilities("1.14.3", nil, []string{"tuic"}) == nil || checkProbeCoreCapabilities("1.14.3", map[string]bool{"with_quic": true}, []string{"tuic"}) != nil {
		t.Fatal("protocol build tags were not checked correctly")
	}
}

func TestProtocolExpansionPreservesLegacyHY2CanonicalBytes(t *testing.T) {
	const legacy = `{"up_mbps":10,"down_mbps":20,"disable_chrome_parrot":false,"type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":1443,"password":"private-client-secret","tls":{"enabled":true,"server_name":"fixture.example"}}`
	p, err := NewProfile("id", "1.14.0", []byte(legacy))
	if err != nil || string(p.Outbound) != legacy {
		t.Fatalf("legacy canonical bytes changed: %v, %s", err, p.Outbound)
	}
	for _, key := range []string{"idle_session", "min_idle_session", "congestion_control", "udp_relay_mode", "zero_rtt_handshake", "heartbeat", "alpn"} {
		if strings.Contains(string(p.Outbound), key) {
			t.Fatal("new omitted field changed legacy canonical form", key)
		}
	}
}
