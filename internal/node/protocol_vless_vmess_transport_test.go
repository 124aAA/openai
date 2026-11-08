package node

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeProtocolAndTransportAliases(t *testing.T) {
	cases := []struct {
		rawProto    string
		rawTr       string
		path        string
		host        string
		serviceName string
		wantProto   string
		wantTrType  string
		wantPath    string
		wantSN      string
		wantNilTr   bool
	}{
		{rawProto: "vless-tls", wantProto: "vless-tls", wantNilTr: true},
		{rawProto: "vmess-tls", wantProto: "vmess-tls", wantNilTr: true},
		{rawProto: "vless-ws-tls", wantProto: "vless-tls", wantTrType: "ws", wantPath: "/ws"},
		{rawProto: "vless-grpc-tls", wantProto: "vless-tls", wantTrType: "grpc", wantSN: "grpc"},
		{rawProto: "vless-httpupgrade-tls", wantProto: "vless-tls", wantTrType: "httpupgrade", wantPath: "/upgrade"},
		{rawProto: "vmess-ws-tls", path: "/custom-ws", host: "cdn.example.com", wantProto: "vmess-tls", wantTrType: "ws", wantPath: "/custom-ws"},
		{rawProto: "vmess-grpc-tls", serviceName: "tun.Service", wantProto: "vmess-tls", wantTrType: "grpc", wantSN: "tun.Service"},
		{rawProto: "trojan-ws-tls", wantProto: "trojan", wantTrType: "ws", wantPath: "/ws"},
		{rawProto: "trojan-grpc-tls", wantProto: "trojan", wantTrType: "grpc", wantSN: "grpc"},
		{rawProto: "trojan", rawTr: "httpupgrade", path: "/up", wantProto: "trojan", wantTrType: "httpupgrade", wantPath: "/up"},
	}
	for _, tc := range cases {
		proto, tr, err := NormalizeProtocolAndTransport(tc.rawProto, tc.rawTr, tc.path, tc.host, tc.serviceName)
		if err != nil {
			t.Fatalf("%s/%s unexpected error: %v", tc.rawProto, tc.rawTr, err)
		}
		if proto != tc.wantProto {
			t.Fatalf("%s got proto %q, want %q", tc.rawProto, proto, tc.wantProto)
		}
		if tc.wantNilTr {
			if tr != nil {
				t.Fatalf("%s expected nil transport for default TCP, got %+v", tc.rawProto, tr)
			}
			continue
		}
		if tr == nil || tr.Type != tc.wantTrType || tr.Path != tc.wantPath || tr.ServiceName != tc.wantSN {
			t.Fatalf("%s got transport %+v, want type=%q path=%q sn=%q", tc.rawProto, tr, tc.wantTrType, tc.wantPath, tc.wantSN)
		}
	}

	// Reject conflicting alias + explicit transport or unsupported protocol transport
	if _, _, err := NormalizeProtocolAndTransport("vless-ws-tls", "grpc", "", "", ""); err == nil {
		t.Fatal("expected error for conflicting transport alias and explicit --transport")
	}
	if _, _, err := NormalizeProtocolAndTransport("reality", "ws", "/ws", "", ""); err == nil {
		t.Fatal("expected error for reality with ws transport")
	}
	if _, _, err := NormalizeProtocolAndTransport("vless-tls", "ws", "relative-path", "", ""); err == nil {
		t.Fatal("expected error for path without leading slash")
	}
}

func TestVLESSTLSAndVMessTLSAndTrojanTransportsConsistency(t *testing.T) {
	connectPort := 2096
	combos := []struct {
		name      string
		protocol  string
		transport *TransportOptions
	}{
		{name: "vless-tls-tcp", protocol: "vless-tls", transport: nil},
		{name: "vless-ws-tls", protocol: "vless-tls", transport: &TransportOptions{Type: "ws", Path: "/vless-ws", Host: "ws.example.com"}},
		{name: "vless-grpc-tls", protocol: "vless-tls", transport: &TransportOptions{Type: "grpc", ServiceName: "vless.Tun"}},
		{name: "vless-httpupgrade-tls", protocol: "vless-tls", transport: &TransportOptions{Type: "httpupgrade", Path: "/vless-up", Host: "up.example.com"}},
		{name: "vmess-tls-tcp", protocol: "vmess-tls", transport: nil},
		{name: "vmess-ws-tls", protocol: "vmess-tls", transport: &TransportOptions{Type: "ws", Path: "/vmess-ws", Host: "cdn.example.com"}},
		{name: "vmess-grpc-tls", protocol: "vmess-tls", transport: &TransportOptions{Type: "grpc", ServiceName: "vmess.Tun"}},
		{name: "vmess-httpupgrade-tls", protocol: "vmess-tls", transport: &TransportOptions{Type: "httpupgrade", Path: "/vmess-up"}},
		{name: "trojan-ws-tls", protocol: "trojan", transport: &TransportOptions{Type: "ws", Path: "/trojan-ws", Host: "trojan.example.com"}},
		{name: "trojan-grpc-tls", protocol: "trojan", transport: &TransportOptions{Type: "grpc", ServiceName: "trojan.Tun"}},
		{name: "trojan-httpupgrade-tls", protocol: "trojan", transport: &TransportOptions{Type: "httpupgrade", Path: "/trojan-up"}},
	}

	for _, tc := range combos {
		t.Run(tc.name, func(t *testing.T) {
			u := NewUser("dev#1", tc.protocol)
			n := Node{
				ID:          Token(8),
				Name:        "HK Node #1",
				Protocol:    tc.protocol,
				Transport:   tc.transport,
				Host:        "2001:db8::1",
				Listen:      "::",
				Port:        8443,
				ConnectPort: &connectPort,
				Enabled:     true,
				Users:       []User{u},
				Certificate: &Certificate{
					Mode:       "acme",
					ServerName: "edge.example.com",
					Email:      "ops@example.com",
				},
			}

			st := NewState()
			st.Nodes = []Node{n}
			if err := st.Validate(); err != nil {
				t.Fatalf("State.Validate failed: %v", err)
			}

			// 1. Server config check
			srvBytes, err := Server(st, "/var/lib/qingnode")
			if err != nil {
				t.Fatalf("Server config render failed: %v", err)
			}
			var srv map[string]any
			if err := json.Unmarshal(srvBytes, &srv); err != nil {
				t.Fatalf("Server JSON unmarshal failed: %v", err)
			}
			inbounds := srv["inbounds"].([]any)
			ib := inbounds[0].(map[string]any)
			if int(ib["listen_port"].(float64)) != 8443 {
				t.Fatalf("server listen_port = %v, want 8443", ib["listen_port"])
			}

			// 2. sing-box client export check (uses ConnectPort 2096 and matching transport)
			sbRes, err := ExportWithCapabilities(n, u, "sing-box", "1.14.0", nil, false)
			if err != nil {
				t.Fatalf("sing-box export failed: %v", err)
			}
			var sb map[string]any
			if err := json.Unmarshal(sbRes.Data, &sb); err != nil {
				t.Fatalf("sing-box client JSON unmarshal failed: %v", err)
			}
			ob := sb["outbounds"].([]any)[0].(map[string]any)
			if int(ob["server_port"].(float64)) != connectPort {
				t.Fatalf("client server_port = %v, want ConnectPort %d", ob["server_port"], connectPort)
			}
			if ob["server"] != "2001:db8::1" {
				t.Fatalf("client server = %v, want 2001:db8::1", ob["server"])
			}
			if tc.transport != nil {
				ibTr, ok1 := ib["transport"].(map[string]any)
				obTr, ok2 := ob["transport"].(map[string]any)
				if !ok1 || !ok2 || ibTr["type"] != tc.transport.Type || obTr["type"] != tc.transport.Type {
					t.Fatalf("transport mismatch between server (%v) and client (%v)", ib["transport"], ob["transport"])
				}
			}

			// 3. Mihomo export check
			mhRes, err := ExportWithCapabilities(n, u, "mihomo", "1.19.30", nil, false)
			if err != nil {
				t.Fatalf("mihomo export failed: %v", err)
			}
			mhText := string(mhRes.Data)
			if !strings.Contains(mhText, "port: 2096") || !strings.Contains(mhText, "edge.example.com") {
				t.Fatalf("mihomo config missing ConnectPort or SNI:\n%s", mhText)
			}

			// 4. URI & QR & Base64 check
			uriRes, err := ExportWithCapabilities(n, u, "uri", "", nil, false)
			if err != nil {
				t.Fatalf("URI export failed: %v", err)
			}
			parsedURI, err := url.Parse(string(uriRes.Data))
			if err != nil {
				t.Fatalf("URI parse failed: %v", err)
			}
			if parsedURI.Host != "[2001:db8::1]:2096" {
				t.Fatalf("URI host = %q, want [2001:db8::1]:2096", parsedURI.Host)
			}
			q := parsedURI.Query()
			if q.Get("sni") != "edge.example.com" {
				t.Fatalf("URI sni = %q, want edge.example.com", q.Get("sni"))
			}
			if tc.transport != nil {
				if q.Get("type") != tc.transport.Type {
					t.Fatalf("URI type = %q, want %q", q.Get("type"), tc.transport.Type)
				}
				if tc.transport.Path != "" && q.Get("path") != tc.transport.Path {
					t.Fatalf("URI path = %q, want %q", q.Get("path"), tc.transport.Path)
				}
				if tc.transport.ServiceName != "" && q.Get("serviceName") != tc.transport.ServiceName {
					t.Fatalf("URI serviceName = %q, want %q", q.Get("serviceName"), tc.transport.ServiceName)
				}
			}

			// 5. VMess V2RayN Base64 JSON format check
			if tc.protocol == "vmess-tls" {
				v2Res, err := ExportWithCapabilities(n, u, "vmess-v2rayn", "", nil, false)
				if err != nil {
					t.Fatalf("vmess-v2rayn export failed: %v", err)
				}
				raw := strings.TrimPrefix(string(v2Res.Data), "vmess://")
				decoded, err := base64.StdEncoding.DecodeString(raw)
				if err != nil {
					t.Fatalf("vmess-v2rayn base64 decode failed: %v", err)
				}
				var v2 map[string]any
				if err := json.Unmarshal(decoded, &v2); err != nil {
					t.Fatalf("vmess-v2rayn json decode failed: %v", err)
				}
				if v2["id"] != u.UUID || v2["port"] != "2096" || v2["sni"] != "edge.example.com" || v2["tls"] != "tls" {
					t.Fatalf("vmess-v2rayn fields mismatch: %+v", v2)
				}
			}
		})
	}
}
