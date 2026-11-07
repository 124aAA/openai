//go:build linux

package node

import "testing"

// Reuse the existing isolated core/client and payload helpers. This is an
// opt-in loopback transport check, not public reachability or service evidence.
func TestOfficialCoreV2RayTLSAndMihomoTransportPayloads(t *testing.T) {
	core, version, mihomo := protocolExpansionInputs(t, true)
	cert, key := makeCert(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, transport := range []string{"tcp", "ws", "grpc", "httpupgrade"} {
			if transport == "httpupgrade" && protocol != "vless" {
				continue
			}
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				n := Node{ID: Token(8), Name: protocol + "-" + transport, Protocol: protocol,
					Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
					Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key},
					Users:       []User{NewUser("transport-user", protocol)},
					Transport:   NormalizeV2RayTransport(&V2RayTransport{Type: transport})}
				if transport == "ws" || transport == "httpupgrade" {
					n.Transport.Path, n.Transport.Host = "/连接+:@&=", "localhost"
					if transport == "ws" {
						n.Transport.Path = "/ws+:@&="
					}
				}
				state := NewState()
				state.CoreVersion, state.Nodes = version, []Node{n}
				server, err := Server(state, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				stopServer := protocolExpansionStartCore(t, core, server)
				defer stopServer()
				target := protocolExpansionTarget(t)
				for _, format := range []string{"sing-box", "mihomo"} {
					t.Run(format, func(t *testing.T) {
						port, client, stop := protocolExpansionClient(t, core, mihomo, version, format, n, n.Users[0], cert, "")
						defer stop()
						protocolExpansionExchange(t, port, client, target, true)
					})
				}
			})
		}
	}
}
