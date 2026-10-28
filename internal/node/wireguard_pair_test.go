package node

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"
)

func TestWireGuardPairPreservesDirectionsAndOwnKeys(t *testing.T) {
	p, err := NewWireGuardPair(WireGuardPairOptions{ID: "pair1", EntryTunnel: "10.66.0.1/32", LandingTunnel: "10.66.0.2/32", LandingHost: "[2001:db8::8]", ConnectPort: 30001, ListenPort: 51820, AllowedIPs: []string{"0.0.0.0/0"}, Keepalive: 25})
	if err != nil {
		t.Fatal(err)
	}
	a, b := p.Entry.WireGuard, p.Landing.WireGuard
	if a.ListenPort != 0 || a.ReceiveEgressID != "" || b.ListenPort != 51820 || b.ReceiveEgressID != "direct" || a.Peers[0].Port != 30001 || a.Peers[0].Address != "2001:db8::8" || b.Peers[0].Address != "" || b.Peers[0].Port != 0 || b.Peers[0].AllowedIPs[0] != "10.66.0.1/32" {
		t.Fatal("配对方向、内外端口或接收范围错误")
	}
	for _, pair := range []struct{ private, public string }{{a.PrivateKey, b.Peers[0].PublicKey}, {b.PrivateKey, a.Peers[0].PublicKey}} {
		raw, e := base64.StdEncoding.DecodeString(pair.private)
		if e != nil {
			t.Fatal(e)
		}
		k, e := ecdh.X25519().NewPrivateKey(raw)
		if e != nil || base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()) != pair.public {
			t.Fatal("两端公私钥不配对")
		}
	}
	if a.PrivateKey == b.PrivateKey || a.Peers[0].PreSharedKey != b.Peers[0].PreSharedKey {
		t.Fatal("两端私钥须独立，预共享密钥须一致")
	}
}

func TestWireGuardPairRejectsAmbiguousInputs(t *testing.T) {
	base := WireGuardPairOptions{ID: "pair1", EntryTunnel: "10.66.0.1/32", LandingTunnel: "10.66.0.2/32", LandingHost: "example.org", ConnectPort: 30001, ListenPort: 51820, AllowedIPs: []string{"0.0.0.0/0"}}
	for name, edit := range map[string]func(*WireGuardPairOptions){
		"same-address":       func(o *WireGuardPairOptions) { o.LandingTunnel = o.EntryTunnel },
		"network-not-host":   func(o *WireGuardPairOptions) { o.EntryTunnel = "10.66.0.1/24" },
		"mixed-family":       func(o *WireGuardPairOptions) { o.LandingTunnel = "fd00::2/128" },
		"no-targets":         func(o *WireGuardPairOptions) { o.AllowedIPs = nil },
		"invalid-target":     func(o *WireGuardPairOptions) { o.AllowedIPs = []string{"https://example.org"} },
		"bad-id":             func(o *WireGuardPairOptions) { o.ID = "../escape" },
		"bad-port":           func(o *WireGuardPairOptions) { o.ListenPort = 0 },
		"large-mtu":          func(o *WireGuardPairOptions) { o.MTU = 9000 },
		"negative-keepalive": func(o *WireGuardPairOptions) { o.Keepalive = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			edit(&o)
			if _, err := NewWireGuardPair(o); err == nil {
				t.Fatal("无效配对被接受")
			}
		})
	}
}
