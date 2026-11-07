package node

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestV2RayTLSFormatsPreserveTransportAndEndpoint(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, transport := range []string{"tcp", "ws", "grpc", "httpupgrade"} {
			if transport == "httpupgrade" && protocol != "vless" {
				continue
			}
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				n := tlsProtocolFixture(t, protocol)
				if protocol != "trojan" {
					n.Users = []User{NewUser("用户 / #+%", protocol)}
				}
				p, _ := Protocol(protocol)
				n.Transport = NormalizeV2RayTransport(&V2RayTransport{Type: transport})
				if transport == "ws" || transport == "httpupgrade" {
					n.Transport.Path, n.Transport.Host = "/连接+:@&=", "cdn.example.test:8443"
					if transport == "ws" {
						n.Transport.Path = "/ws+:@&="
					}
				}
				if transport == "grpc" {
					n.Transport.ServiceName = "qingnode.Test-v2"
				}
				connectPort := 3443
				n.ConnectPort = &connectPort
				u := n.Users[0]
				if err := p.Validate(n); err != nil {
					t.Fatal(err)
				}
				server, client, mihomo := p.Inbound(n, t.TempDir()), Outbound(n, u), MihomoProxy(n, u)
				if client["server"] != n.Host || client["server_port"] != connectPort || mihomo["server"] != n.Host || mihomo["port"] != connectPort || n.Port != 1443 {
					t.Fatal("public NAT endpoint replaced the local listen port")
				}
				if !reflect.DeepEqual(server["transport"], client["transport"]) || !reflect.DeepEqual(server["tls"].(M)["alpn"], client["tls"].(M)["alpn"]) {
					t.Fatal("server and client disagree on transport or TLS ALPN")
				}
				if _, present := client["flow"]; present {
					t.Fatal("plain TLS protocol acquired REALITY Vision flow")
				}
				if transport == "tcp" && (server["transport"] != nil || client["tls"].(M)["alpn"] != nil) {
					t.Fatal("plain TCP acquired transport settings")
				}
				if transport == "grpc" && (mihomo["grpc-opts"].(M)["grpc-service-name"] != n.Transport.ServiceName || !reflect.DeepEqual(client["tls"].(M)["alpn"], []string{"h2"})) {
					t.Fatal("gRPC lost service name or h2")
				}
				if transport == "ws" || transport == "httpupgrade" {
					ws := mihomo["ws-opts"].(M)
					if ws["path"] != n.Transport.Path || ws["headers"].(M)["Host"] != n.Transport.Host || mihomo["network"] != "ws" {
						t.Fatal("Mihomo lost path, Host, or websocket transport")
					}
					if transport == "httpupgrade" && ws["v2ray-http-upgrade"] != true {
						t.Fatal("HTTPUpgrade silently became WebSocket")
					}
				}
				raw := URI(n, u)
				if transport == "httpupgrade" {
					if raw != "" || len(ProtocolExportWarnings(n, "qr")) == 0 {
						t.Fatal("unsupported importer received a misleading URI")
					}
				} else if protocol == "vmess" {
					decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "vmess://"))
					var share map[string]string
					if err != nil || json.Unmarshal(decoded, &share) != nil || share["id"] != u.UUID || share["add"] != n.Host || share["port"] != "3443" || share["ps"] != n.Name+" / "+u.Name || share["aid"] != "0" || share["net"] != transport {
						t.Fatal("VMess JSON share lost credentials, display name, or NAT endpoint")
					}
					if transport == "grpc" && share["path"] != n.Transport.ServiceName || transport == "ws" && (share["path"] != n.Transport.Path || share["host"] != n.Transport.Host) {
						t.Fatal("VMess share lost transport parameters")
					}
				} else {
					parsed, err := url.Parse(raw)
					if err != nil || parsed.Hostname() != n.Host || parsed.Port() != "3443" || parsed.Query().Get("sni") != n.Certificate.ServerName || parsed.Query().Get("type") != transport || parsed.Fragment != n.Name+" / "+u.Name {
						t.Fatal("URI lost TLS, endpoint, transport, or escaped name")
					}
					if transport == "grpc" && parsed.Query().Get("serviceName") != n.Transport.ServiceName || transport == "ws" && (parsed.Query().Get("path") != n.Transport.Path || parsed.Query().Get("host") != n.Transport.Host) {
						t.Fatal("URI lost transport parameters")
					}
				}
				state := NewState()
				state.Nodes = []Node{n}
				data, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				restored, err := DecodeState(data)
				if err != nil || len(restored.Nodes) != 1 || !reflect.DeepEqual(restored.Nodes[0].Users, n.Users) || !reflect.DeepEqual(restored.Nodes[0].Transport, n.Transport) || URI(restored.Nodes[0], u) != raw {
					t.Fatal("state round trip changed credentials or transport", err)
				}
			})
		}
	}
}

func TestV2RayTransportDefaultsDoNotDiscardOrMutateInput(t *testing.T) {
	for _, tc := range []struct {
		input V2RayTransport
		want  *V2RayTransport
	}{
		{V2RayTransport{Type: "tcp"}, nil},
		{V2RayTransport{Type: "ws"}, &V2RayTransport{Type: "ws", Path: "/"}},
		{V2RayTransport{Type: "grpc"}, &V2RayTransport{Type: "grpc", ServiceName: "qingnode"}},
	} {
		before := tc.input
		if got := NormalizeV2RayTransport(&tc.input); !reflect.DeepEqual(got, tc.want) || tc.input != before || ValidateV2RayTransport("vless", &tc.input) != nil {
			t.Fatal("default changed input or could not be validated")
		}
	}
	for _, tc := range []struct {
		protocol string
		input    V2RayTransport
	}{
		{"anytls", V2RayTransport{Type: "tcp"}},
		{"vless", V2RayTransport{Type: "tcp", Path: "/ignored"}},
		{"vless", V2RayTransport{Type: "grpc", Host: "ignored.test"}},
		{"vless", V2RayTransport{Type: "grpc", ServiceName: "service/path"}},
		{"vless", V2RayTransport{Type: "ws", ServiceName: "ignored"}},
		{"vless", V2RayTransport{Type: "ws", Path: "/path%20different"}},
		{"vless", V2RayTransport{Type: "ws", Path: "/连接+:@&="}},
		{"vless", V2RayTransport{Type: "ws", Host: "bad.test\r\nHeader: x"}},
		{"trojan", V2RayTransport{Type: "httpupgrade"}},
	} {
		if ValidateV2RayTransport(tc.protocol, &tc.input) == nil {
			t.Fatal("unsupported or silently dropped transport parameters accepted", tc.protocol, tc.input.Type)
		}
	}
}

func TestV2RayCredentialRotationUsesUUIDOnly(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		p, _ := Protocol(protocol)
		u := User{Password: "previous-password"}
		p.Credential(&u)
		if !uuidRE.MatchString(u.UUID) || u.Password != "" {
			t.Fatal("UUID generation retained a password")
		}
		old := u.UUID
		p.Credential(&u)
		if u.UUID == old || !uuidRE.MatchString(u.UUID) {
			t.Fatal("credential rotation did not generate a fresh UUID")
		}
	}
}
