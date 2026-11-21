package probe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func round3KeyBase64(size int) string {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestRound3HY2ObfsAndServerPortsProfileAndGraph(t *testing.T) {
	validHY2 := map[string]any{
		"type":          "hysteria2",
		"tag":           "proxy",
		"server":        "127.0.0.1",
		"server_ports":  []string{"20000:30000"},
		"hop_interval":  "30s",
		"password":      "hy2-user-secret-1234",
		"obfs":          map[string]any{"type": "salamander", "password": "hy2-obfs-secret-5678"},
		"tls":           map[string]any{"enabled": true, "server_name": "fixture.example"},
		"up_mbps":       50,
		"down_mbps":     200,
	}
	p, err := NewProfile("hy2-hop-node", "1.14.0", graphTestRaw(t, validHY2))
	if err != nil {
		t.Fatalf("valid HY2 server_ports + salamander profile rejected: %v", err)
	}
	if bytes.Contains(p.Outbound, []byte(`"server_port"`)) || !bytes.Contains(p.Outbound, []byte(`"server_ports":["20000:30000"]`)) {
		t.Fatalf("unexpected canonical HY2 outbound: %s", p.Outbound)
	}

	gHop := map[string]any{
		"type":         "hysteria2",
		"tag":          "remote-hy2",
		"server":       "198.51.100.10",
		"server_ports": []string{"25000:26000"},
		"hop_interval": "15s",
		"password":     "hy2-user-secret-1234",
		"obfs":         map[string]any{"type": "salamander", "password": "hy2-obfs-secret-5678"},
		"tls":          map[string]any{"enabled": true, "server_name": "fixture.example"},
	}
	gp, err := NewGraphProfile("egress-hy2", "1.14.0", "remote-hy2", []json.RawMessage{graphTestRaw(t, gHop)}, nil)
	if err != nil || !gp.SupportsNetwork("tcp") || !gp.SupportsNetwork("udp") {
		t.Fatalf("valid HY2 server_ports graph profile failed: %v", err)
	}

	badMutations := map[string]func(map[string]any){
		"conflicting server_port": func(o map[string]any) { o["server_port"] = 8443 },
		"explicit zero port":      func(o map[string]any) { delete(o, "server_ports"); delete(o, "hop_interval"); o["server_port"] = 0 },
		"obfs same as user pw":    func(o map[string]any) { o["obfs"] = map[string]any{"type": "salamander", "password": "hy2-user-secret-1234"} },
		"obfs unsupported type":   func(o map[string]any) { o["obfs"] = map[string]any{"type": "xor", "password": "hy2-obfs-secret-5678"} },
		"obfs extra field":        func(o map[string]any) { o["obfs"] = map[string]any{"type": "salamander", "password": "hy2-obfs-secret-5678", "extra": 1} },
		"hop_interval no ports":   func(o map[string]any) { delete(o, "server_ports"); o["server_port"] = 8443 },
		"hop low port < 1024":     func(o map[string]any) { o["server_ports"] = []string{"80:2000"} },
		"hop reversed range":      func(o map[string]any) { o["server_ports"] = []string{"30000:20000"} },
		"hop span > 20001":        func(o map[string]any) { o["server_ports"] = []string{"10000:40000"} },
		"hop interval < 5s":       func(o map[string]any) { o["hop_interval"] = "4s" },
	}
	for name, mutate := range badMutations {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(validHY2)
			var clone map[string]any
			_ = json.Unmarshal(raw, &clone)
			mutate(clone)
			if _, err := NewProfile("id", "1.14.0", graphTestRaw(t, clone)); err == nil {
				t.Fatalf("accepted invalid HY2 portable profile (%s)", name)
			}
			clone["tag"] = "remote-hy2"
			if _, err := NewGraphProfile("id", "1.14.0", "remote-hy2", []json.RawMessage{graphTestRaw(t, clone)}, nil); err == nil {
				t.Fatalf("accepted invalid HY2 graph profile (%s)", name)
			}
		})
	}
}

func TestRound3TransportsEarlyDataHTTP2RealityGRPCAndMultiplex(t *testing.T) {
	uuid := "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f"
	realityPub := round3KeyBase64(32)
	realityPub = strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(realityPub, "+", "-"), "/", "_"), "=")

	// 1. WS Early Data (default & custom header) + HTTP/2 transport + packetaddr.
	wsValid := map[string]any{
		"type":            "vmess",
		"tag":             "proxy",
		"server":          "127.0.0.1",
		"server_port":     443,
		"uuid":            uuid,
		"security":        "aes-128-gcm",
		"packet_encoding": "packetaddr",
		"tls":             map[string]any{"enabled": true, "server_name": "fixture.example", "alpn": []string{"http/1.1"}},
		"transport": map[string]any{
			"type":                   "ws",
			"path":                   "/ws",
			"headers":                map[string]any{"Host": "fixture.example"},
			"max_early_data":         2048,
			"early_data_header_name": "X-Early-Data",
		},
	}
	if _, err := NewProfile("vmess-ws-ed", "1.14.0", graphTestRaw(t, wsValid)); err != nil {
		t.Fatalf("valid VMess WS early-data + packetaddr rejected: %v", err)
	}

	for _, kind := range []string{"vless", "vmess", "trojan"} {
		h2 := map[string]any{
			"type":        kind,
			"tag":         "proxy",
			"server":      "127.0.0.1",
			"server_port": 443,
			"tls":         map[string]any{"enabled": true, "server_name": "fixture.example", "alpn": []string{"h2"}},
			"transport":   map[string]any{"type": "http", "path": "/h2", "host": []string{"fixture.example"}},
		}
		if kind == "trojan" {
			h2["password"] = "trojan-secret-password"
		} else {
			h2["uuid"] = uuid
		}
		if kind == "vmess" {
			h2["security"] = "auto"
		}
		if _, err := NewProfile(kind+"-h2", "1.14.0", graphTestRaw(t, h2)); err != nil {
			t.Fatalf("valid %s HTTP/2 profile rejected: %v", kind, err)
		}
	}

	// Reject invalid WS early data and HTTP/2 host/ALPN mismatches.
	for name, bad := range map[string]map[string]any{
		"ws forbidden header Host": {
			"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": 443, "password": "trojan-secret-password",
			"tls":       map[string]any{"enabled": true, "server_name": "fixture.example"},
			"transport": map[string]any{"type": "ws", "path": "/ws", "max_early_data": 2048, "early_data_header_name": "Host"},
		},
		"ws header without max_early_data": {
			"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": 443, "password": "trojan-secret-password",
			"tls":       map[string]any{"enabled": true, "server_name": "fixture.example"},
			"transport": map[string]any{"type": "ws", "path": "/ws", "early_data_header_name": "Sec-WebSocket-Protocol"},
		},
		"h2 scalar host string": {
			"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": 443, "password": "trojan-secret-password",
			"tls":       map[string]any{"enabled": true, "server_name": "fixture.example", "alpn": []string{"h2"}},
			"transport": map[string]any{"type": "http", "path": "/h2", "host": "fixture.example"},
		},
		"h2 wrong ALPN http/1.1": {
			"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": 443, "password": "trojan-secret-password",
			"tls":       map[string]any{"enabled": true, "server_name": "fixture.example", "alpn": []string{"http/1.1"}},
			"transport": map[string]any{"type": "http", "path": "/h2", "host": []string{"fixture.example"}},
		},
	} {
		if _, err := NewProfile("bad", "1.14.0", graphTestRaw(t, bad)); err == nil {
			t.Fatalf("accepted invalid transport case %q", name)
		}
	}

	// 2. REALITY + gRPC (flow omitted) + all 10 extended fingerprints.
	for _, fp := range []string{"chrome", "firefox", "safari", "ios", "edge", "random", "randomized", "qq", "android", "360"} {
		realityGRPC := map[string]any{
			"type":        "vless",
			"tag":         "proxy",
			"server":      "127.0.0.1",
			"server_port": 443,
			"uuid":        uuid,
			"transport":   map[string]any{"type": "grpc", "service_name": "reality_svc"},
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "www.microsoft.com",
				"utls":        map[string]any{"enabled": true, "fingerprint": fp},
				"reality":     map[string]any{"enabled": true, "public_key": realityPub, "short_id": "01020304"},
			},
		}
		if _, err := NewProfile("reality-"+fp, "1.14.0", graphTestRaw(t, realityGRPC)); err != nil {
			t.Fatalf("REALITY+gRPC with fingerprint %s rejected: %v", fp, err)
		}
	}
	// REALITY + gRPC + vision flow or REALITY + ws must be rejected.
	realityBadVision := map[string]any{
		"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": 443, "uuid": uuid,
		"flow":      "xtls-rprx-vision",
		"transport": map[string]any{"type": "grpc", "service_name": "reality_svc"},
		"tls": map[string]any{
			"enabled": true, "server_name": "www.microsoft.com",
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": realityPub, "short_id": "01020304"},
		},
	}
	if _, err := NewProfile("reality-bad-flow", "1.14.0", graphTestRaw(t, realityBadVision)); err == nil {
		t.Fatal("accepted REALITY+gRPC with TCP-only xtls-rprx-vision flow")
	}

	// 3. Multiplex on compatible TCP protocols & rejection on REALITY / QUIC / AnyTLS.
	for _, proto := range []string{"h2mux", "smux", "yamux"} {
		muxTrojan := map[string]any{
			"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": 443, "password": "trojan-secret-password",
			"tls":       map[string]any{"enabled": true, "server_name": "fixture.example"},
			"multiplex": map[string]any{"enabled": true, "protocol": proto, "max_connections": 4, "min_streams": 8, "padding": true},
		}
		if _, err := NewProfile("mux-"+proto, "1.14.0", graphTestRaw(t, muxTrojan)); err != nil {
			t.Fatalf("valid Trojan multiplex (%s) rejected: %v", proto, err)
		}
	}
	for _, badKind := range []string{"anytls", "hysteria2", "tuic"} {
		o := expansionOutbound(badKind)
		o["multiplex"] = map[string]any{"enabled": true, "protocol": "h2mux"}
		if _, err := NewProfile("bad-mux-"+badKind, "1.14.0", graphTestRaw(t, o)); err == nil {
			t.Fatalf("accepted multiplex on incompatible protocol %s", badKind)
		}
	}
}

func TestRound3SS2022MultiCipherAndHTTPProxyGraph(t *testing.T) {
	key16 := round3KeyBase64(16)
	key32 := round3KeyBase64(32)

	// 1. SS2022 16B & 32B ciphers (single and colon-joined server:user keys).
	for _, tc := range []struct {
		method string
		good   string
		bad    string
	}{
		{"2022-blake3-aes-128-gcm", key16, key32},
		{"2022-blake3-aes-128-gcm", key16 + ":" + key16, key16 + ":" + key32},
		{"2022-blake3-chacha20-poly1305", key32, key16},
		{"2022-blake3-chacha20-poly1305", key32 + ":" + key32, key32 + ":" + key16},
	} {
		goodSS := map[string]any{
			"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": 8388,
			"method": tc.method, "password": tc.good,
		}
		if _, err := NewProfile("ss-ok", "1.14.0", graphTestRaw(t, goodSS)); err != nil {
			t.Fatalf("valid %s rejected: %v", tc.method, err)
		}
		badSS := map[string]any{
			"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": 8388,
			"method": tc.method, "password": tc.bad,
		}
		if _, err := NewProfile("ss-bad", "1.14.0", graphTestRaw(t, badSS)); err == nil {
			t.Fatalf("accepted wrong-length key for %s", tc.method)
		}
	}

	// 2. HTTP / HTTPS CONNECT proxy in GraphProfile & SupportsNetwork chain semantics.
	httpHop := map[string]any{
		"type":        "http",
		"tag":         "corp-proxy",
		"server":      "198.51.100.5",
		"server_port": 8443,
		"username":    "alice",
		"password":    "secret-pass",
		"tls":         map[string]any{"enabled": true, "server_name": "proxy.example.com"},
	}
	httpGraph, err := NewGraphProfile("http-only", "1.14.0", "corp-proxy", []json.RawMessage{graphTestRaw(t, httpHop)}, nil)
	if err != nil {
		t.Fatalf("valid HTTPS CONNECT proxy graph rejected: %v", err)
	}
	if !httpGraph.SupportsNetwork("tcp") || httpGraph.SupportsNetwork("udp") {
		t.Fatal("HTTP CONNECT proxy must support TCP only (not UDP)")
	}

	// Multiplexed Shadowsocks over HTTP CONNECT proxy supports BOTH TCP and UDP (sing-mux over TCP)!
	ssMuxOverHTTP := map[string]any{
		"type":        "shadowsocks",
		"tag":         "ss-mux",
		"detour":      "corp-proxy",
		"server":      "198.51.100.99",
		"server_port": 8388,
		"method":      "2022-blake3-aes-128-gcm",
		"password":    key16,
		"multiplex":   map[string]any{"enabled": true, "protocol": "yamux"},
	}
	chainedMux, err := NewGraphProfile("chain-mux", "1.14.0", "ss-mux", []json.RawMessage{graphTestRaw(t, httpHop), graphTestRaw(t, ssMuxOverHTTP)}, nil)
	if err != nil {
		t.Fatalf("SS2022+mux over HTTPS CONNECT graph rejected: %v", err)
	}
	if !chainedMux.SupportsNetwork("tcp") || !chainedMux.SupportsNetwork("udp") {
		t.Fatal("multiplexed Shadowsocks detoured over HTTP CONNECT must support both TCP and UDP")
	}

	// Un-multiplexed Shadowsocks over HTTP CONNECT supports TCP but NOT UDP!
	ssRawOverHTTP := map[string]any{
		"type":        "shadowsocks",
		"tag":         "ss-raw",
		"detour":      "corp-proxy",
		"server":      "198.51.100.99",
		"server_port": 8388,
		"method":      "2022-blake3-aes-128-gcm",
		"password":    key16,
	}
	chainedRaw, err := NewGraphProfile("chain-raw", "1.14.0", "ss-raw", []json.RawMessage{graphTestRaw(t, httpHop), graphTestRaw(t, ssRawOverHTTP)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !chainedRaw.SupportsNetwork("tcp") || chainedRaw.SupportsNetwork("udp") {
		t.Fatal("non-multiplexed Shadowsocks over HTTP CONNECT cannot tunnel raw UDP")
	}
}
