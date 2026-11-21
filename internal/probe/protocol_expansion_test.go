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
	for _, key := range []string{"idle_session", "min_idle_session", "congestion_control", "udp_relay_mode", "zero_rtt_handshake", "heartbeat", "alpn", "security", "alter_id", "global_padding", "authenticated_length", "packet_encoding", "transport"} {
		if strings.Contains(string(p.Outbound), key) {
			t.Fatal("new omitted field changed legacy canonical form", key)
		}
	}
}

func v040Outbound(kind, transportKind string) map[string]any {
	const testUUID = "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f"
	tls := map[string]any{"enabled": true, "server_name": "fixture.example"}
	var o map[string]any
	switch kind {
	case "vless-tls":
		o = map[string]any{
			"type":            "vless",
			"tag":             "proxy",
			"server":          "127.0.0.1",
			"server_port":     1443,
			"uuid":            testUUID,
			"packet_encoding": "xudp",
			"tls":             tls,
		}
	case "vmess-tls":
		o = map[string]any{
			"type":                 "vmess",
			"tag":                  "proxy",
			"server":               "127.0.0.1",
			"server_port":          1443,
			"uuid":                 testUUID,
			"security":             "auto",
			"alter_id":             0,
			"global_padding":       true,
			"authenticated_length": true,
			"packet_encoding":      "xudp",
			"tls":                  tls,
		}
	case "trojan":
		o = expansionOutbound("trojan")
		tls = o["tls"].(map[string]any)
	}
	switch transportKind {
	case "ws":
		tls["alpn"] = []string{"http/1.1"}
		o["transport"] = map[string]any{"type": "ws", "path": "/ws", "headers": map[string]any{"Host": "cdn.fixture.example"}}
	case "grpc":
		tls["alpn"] = []string{"h2"}
		o["transport"] = map[string]any{"type": "grpc", "service_name": "grpc_svc.1"}
	case "httpupgrade":
		tls["alpn"] = []string{"http/1.1"}
		o["transport"] = map[string]any{"type": "httpupgrade", "path": "/upgrade", "host": "cdn.fixture.example"}
	}
	return o
}

func TestProtocolV040TransportAndTLSProfiles(t *testing.T) {
	for _, version := range []string{"1.14.0", "1.14.3"} {
		for _, kind := range []string{"vless-tls", "vmess-tls", "trojan"} {
			for _, tr := range []string{"tcp", "ws", "grpc", "httpupgrade"} {
				t.Run(version+"/"+kind+"/"+tr, func(t *testing.T) {
					o := v040Outbound(kind, tr)
					p, err := NewProfile("stable-id", version, graphTestRaw(t, o))
					if err != nil {
						t.Fatal(err)
					}
					if kind == "vmess-tls" && !bytes.Contains(p.Outbound, []byte(`"alter_id":0`)) {
						t.Fatal("explicit zero alter_id was omitted")
					}
					if _, err := sandboxConfig(p, 2080, "local", "local-only-password"); err != nil {
						t.Fatal(err)
					}
					goOut := v040Outbound(kind, tr)
					goOut["tag"], goOut["detour"] = "remote", "first"
					first := graphTestSOCKS("first", "")
					first["network"] = "tcp"
					gp, err := NewGraphProfile("id", version, "remote", []json.RawMessage{graphTestRaw(t, first), graphTestRaw(t, goOut)}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if !gp.SupportsNetwork("tcp") || !gp.SupportsNetwork("udp") {
						t.Fatalf("%s/%s did not report TCP+UDP over TCP SOCKS detour", kind, tr)
					}
				})
			}
		}
	}

	var parsedVLESSTLS outbound
	_ = json.Unmarshal(graphTestRaw(t, v040Outbound("vless-tls", "ws")), &parsedVLESSTLS)
	if probeCoreKind(parsedVLESSTLS) != "vless-tls" || checkProbeCoreCapabilities("1.14.3", nil, []string{probeCoreKind(parsedVLESSTLS), "vmess"}) != nil {
		t.Fatal("standard TLS VLESS/VMess unexpectedly required with_utls")
	}

	rejectCases := map[string]struct {
		base   func() map[string]any
		mutate func(map[string]any)
	}{
		"vless-tls vision flow without reality": {
			func() map[string]any { return v040Outbound("vless-tls", "tcp") },
			func(o map[string]any) { o["flow"] = "xtls-rprx-vision" },
		},
		"vless-tls zero uuid": {
			func() map[string]any { return v040Outbound("vless-tls", "tcp") },
			func(o map[string]any) { o["uuid"] = "00000000-0000-0000-0000-000000000000" },
		},
		"vless-tls utls": {
			func() map[string]any { return v040Outbound("vless-tls", "tcp") },
			func(o map[string]any) {
				o["tls"].(map[string]any)["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			},
		},
		"vless-tls unknown packet_encoding": {
			func() map[string]any { return v040Outbound("vless-tls", "tcp") },
			func(o map[string]any) { o["packet_encoding"] = "packetaddr-unknown" },
		},
		"reality with transport": {
			func() map[string]any {
				return map[string]any{
					"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": 1443,
					"uuid": "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f", "flow": "xtls-rprx-vision",
					"tls": map[string]any{
						"enabled": true, "server_name": "fixture.example",
						"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
						"reality": map[string]any{"enabled": true, "public_key": "pub", "short_id": "0102"},
					},
				}
			},
			func(o map[string]any) { o["transport"] = map[string]any{"type": "ws", "path": "/ws"} },
		},
		"vmess non-zero alter_id": {
			func() map[string]any { return v040Outbound("vmess-tls", "tcp") },
			func(o map[string]any) { o["alter_id"] = 1 },
		},
		"vmess security none": {
			func() map[string]any { return v040Outbound("vmess-tls", "tcp") },
			func(o map[string]any) { o["security"] = "none" },
		},
		"vmess security zero": {
			func() map[string]any { return v040Outbound("vmess-tls", "tcp") },
			func(o map[string]any) { o["security"] = "zero" },
		},
		"vmess global_padding false": {
			func() map[string]any { return v040Outbound("vmess-tls", "tcp") },
			func(o map[string]any) { o["global_padding"] = false },
		},
		"vmess authenticated_length false": {
			func() map[string]any { return v040Outbound("vmess-tls", "tcp") },
			func(o map[string]any) { o["authenticated_length"] = false },
		},
		"vmess without tls": {
			func() map[string]any { return v040Outbound("vmess-tls", "tcp") },
			func(o map[string]any) { delete(o, "tls") },
		},
		"trojan with vmess alter_id": {
			func() map[string]any { return v040Outbound("trojan", "tcp") },
			func(o map[string]any) { o["alter_id"] = 0 },
		},
		"trojan tcp with http/1.1 alpn": {
			func() map[string]any { return v040Outbound("trojan", "tcp") },
			func(o map[string]any) { o["tls"].(map[string]any)["alpn"] = []string{"http/1.1"} },
		},
		"ws with h2 alpn": {
			func() map[string]any { return v040Outbound("vless-tls", "ws") },
			func(o map[string]any) { o["tls"].(map[string]any)["alpn"] = []string{"h2"} },
		},
		"grpc with http/1.1 alpn": {
			func() map[string]any { return v040Outbound("vmess-tls", "grpc") },
			func(o map[string]any) { o["tls"].(map[string]any)["alpn"] = []string{"http/1.1"} },
		},
		"ws lowercase host header key": {
			func() map[string]any { return v040Outbound("trojan", "ws") },
			func(o map[string]any) {
				o["transport"].(map[string]any)["headers"] = map[string]any{"host": "cdn.fixture.example"}
			},
		},
		"ws extra header": {
			func() map[string]any { return v040Outbound("trojan", "ws") },
			func(o map[string]any) {
				o["transport"].(map[string]any)["headers"] = map[string]any{"Host": "cdn.fixture.example", "X-Forwarded-For": "1.2.3.4"}
			},
		},
		"ws query in path": {
			func() map[string]any { return v040Outbound("trojan", "ws") },
			func(o map[string]any) { o["transport"].(map[string]any)["path"] = "/ws?ed=2048" },
		},
		"httpupgrade empty host": {
			func() map[string]any { return v040Outbound("vless-tls", "httpupgrade") },
			func(o map[string]any) { o["transport"].(map[string]any)["host"] = "" },
		},
		"grpc invalid service_name": {
			func() map[string]any { return v040Outbound("vmess-tls", "grpc") },
			func(o map[string]any) { o["transport"].(map[string]any)["service_name"] = "/invalid" },
		},
		"anytls with ws transport": {
			func() map[string]any { return expansionOutbound("anytls") },
			func(o map[string]any) { o["transport"] = map[string]any{"type": "ws", "path": "/ws"} },
		},
		"transport null": {
			func() map[string]any { return v040Outbound("trojan", "tcp") },
			func(o map[string]any) { o["transport"] = nil },
		},
	}
	for name, tc := range rejectCases {
		t.Run(name, func(t *testing.T) {
			o := tc.base()
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
