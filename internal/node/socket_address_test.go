package node

import "testing"

func TestSocketsReadyComparesIPAddresses(t *testing.T) {
	tests := []struct {
		name, listen, observed string
		owned                  bool
		want                   bool
	}{
		{"expanded IPv6 wildcard", "0:0:0:0:0:0:0:0", "::", true, true},
		{"expanded IPv6 address", "2001:0db8:0:0:0:0:0:1", "2001:db8::1", true, true},
		{"IPv4 address", "127.0.0.1", "127.0.0.1", true, true},
		{"different IPv6 address", "2001:db8::1", "2001:db8::2", true, false},
		{"IPv4 and IPv6 wildcards differ", "0.0.0.0", "::", true, false},
		{"IPv6 and IPv4 wildcards differ", "::", "0.0.0.0", true, false},
		{"wildcard and concrete address differ", "::", "::1", true, false},
		{"unowned equivalent IPv6", "0:0:0:0:0:0:0:0", "::", false, false},
		{"invalid addresses", "invalid", "invalid", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewState()
			s.Nodes = []Node{{Protocol: "reality", Listen: tt.listen, Port: 23456, Enabled: true}}
			sockets := []Socket{{Network: "tcp", Address: tt.observed, Port: 23456, Owned: tt.owned}}
			if got := SocketsReady(s, sockets); got != tt.want {
				t.Fatalf("SocketsReady=%v, want %v", got, tt.want)
			}
			if tt.want {
				sockets[0].Network = "udp"
				if SocketsReady(s, sockets) {
					t.Fatal("wrong transport accepted")
				}
				sockets[0].Network = "tcp"
				sockets[0].Port++
				if SocketsReady(s, sockets) {
					t.Fatal("wrong port accepted")
				}
			}
		})
	}
}
