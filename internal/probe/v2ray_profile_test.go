package probe

import (
	"bytes"
	"encoding/json"
	"testing"
)

func v2rayProfileOutbound(kind, transport string) map[string]any {
	o := expansionOutbound(kind)
	if kind != "trojan" {
		delete(o, "password")
		o["uuid"] = "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f"
	}
	if kind == "vmess" {
		o["security"], o["alter_id"] = "auto", 0
	}
	if transport != "tcp" {
		tr := map[string]any{"type": transport}
		alpn := "http/1.1"
		switch transport {
		case "grpc":
			tr["service_name"], alpn = "qingnode.Test-v2", "h2"
		case "ws":
			tr["path"], tr["headers"] = "/连接+:@&=", map[string]string{"Host": "cdn.example.test:8443"}
		case "httpupgrade":
			tr["path"], tr["host"] = "/连接+:@&=", "cdn.example.test:8443"
		}
		o["transport"] = tr
		o["tls"].(map[string]any)["alpn"] = []string{alpn}
	}
	return o
}

func TestV2RayProfilesKeepNativeTLSAndTransport(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		for _, transport := range []string{"tcp", "ws", "grpc", "httpupgrade"} {
			if transport == "httpupgrade" && kind != "vless" {
				continue
			}
			t.Run(kind+"/"+transport, func(t *testing.T) {
				o := v2rayProfileOutbound(kind, transport)
				p, err := NewProfile("id", "1.14.0", graphTestRaw(t, o))
				if err != nil {
					t.Fatal(err)
				}
				var parsed outbound
				if err = json.Unmarshal(p.Outbound, &parsed); err != nil || parsed.coreKind() != kind || checkProbeCoreCapabilities("1.14.0", nil, []string{parsed.coreKind()}) != nil {
					t.Fatal("native TLS incorrectly requires uTLS or QUIC", err)
				}
				if kind == "vmess" && !bytes.Contains(p.Outbound, []byte(`"alter_id":0`)) {
					t.Fatal("VMess AEAD explicit zero was omitted")
				}
				if _, err = sandboxConfig(p, 2080, "local", "local-password"); err != nil {
					t.Fatal(err)
				}
				o["tag"], o["detour"] = "remote", "first"
				first := graphTestSOCKS("first", "")
				first["network"] = "tcp"
				g, err := NewGraphProfile("id", "1.14.3", "remote", []json.RawMessage{graphTestRaw(t, o), graphTestRaw(t, first)}, nil)
				if err != nil || !g.SupportsNetwork("tcp") || !g.SupportsNetwork("udp") {
					t.Fatal("native TLS transport lost carried UDP over TCP", err)
				}
			})
		}
	}
}

func TestV2RayProfilesRejectMissingAndMisplacedParameters(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"legacy authentication": func(o map[string]any) { o["alter_id"] = 1 },
		"missing AEAD mode":     func(o map[string]any) { delete(o, "security") },
		"missing UUID":          func(o map[string]any) { o["uuid"] = "bad" },
		"misplaced flow":        func(o map[string]any) { o["flow"] = "xtls-rprx-vision" },
		"missing ALPN":          func(o map[string]any) { delete(o["tls"].(map[string]any), "alpn") },
		"wrong ALPN":            func(o map[string]any) { o["tls"].(map[string]any)["alpn"] = []string{"h2"} },
		"extra headers": func(o map[string]any) {
			o["transport"].(map[string]any)["headers"] = map[string]string{"Host": "cdn.example.test", "Authorization": "private"}
		},
		"hidden wrong field": func(o map[string]any) { o["transport"].(map[string]any)["service_name"] = nil },
		"escaped path":       func(o map[string]any) { o["transport"].(map[string]any)["path"] = "/wrong%20path" },
	} {
		t.Run(name, func(t *testing.T) {
			o := v2rayProfileOutbound("vmess", "ws")
			change(o)
			if _, err := NewProfile("id", "1.14.3", graphTestRaw(t, o)); err == nil {
				t.Fatal("incomplete or silently reinterpreted profile accepted")
			}
		})
	}
	legacy := outbound{Type: "vless", TLS: &clientTLS{UTLS: &clientUTLS{Enabled: true}}}
	if legacy.coreKind() != "reality" || checkProbeCoreCapabilities("1.14.3", nil, []string{legacy.coreKind()}) == nil {
		t.Fatal("REALITY lost its uTLS requirement")
	}
}
