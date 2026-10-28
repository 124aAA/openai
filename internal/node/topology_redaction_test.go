package node

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTopologyRedactionCoversWireGuardIPCRepresentationsAndSOCKSAuth(t *testing.T) {
	s := NewState()
	wg := topologyWG(t)
	psk := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xab", 32)))
	wg.WireGuard.Peers[0].PreSharedKey = psk
	s.Egresses = []Egress{wg, topologySOCKS("3333333333333333", "remote")}
	privateBytes, _ := base64.StdEncoding.DecodeString(wg.WireGuard.PrivateKey)
	pskBytes, _ := base64.StdEncoding.DecodeString(psk)
	privateHex, pskHex := hex.EncodeToString(privateBytes), hex.EncodeToString(pskBytes)
	values := []string{wg.WireGuard.PrivateKey, psk, privateHex, pskHex, strings.ToUpper(privateHex), strings.ToUpper(pskHex), s.Egresses[1].Socks.Username, s.Egresses[1].Socks.Password}
	for _, value := range values {
		if out := Redact("upstream IPC failed while processing "+value, s); strings.Contains(out, value) {
			t.Fatal("remote secret representation remained in an embedded error")
		}
	}
	for _, label := range []string{"private_key", "preshared_key", "pre_shared_key"} {
		out := Redact("upstream IPC error (" + label + "=" + pskHex + ")")
		if strings.Contains(out, pskHex) || !strings.Contains(out, "upstream IPC error") {
			t.Fatal("state-free embedded IPC key was not safely redacted")
		}
	}
	for _, label := range []string{"pre_shared_key", "preshared key", "username"} {
		out := Redact(label + ": fixture-secret\nnext error is retained")
		if strings.Contains(out, "fixture-secret") || !strings.Contains(out, "next error is retained") {
			t.Fatal("remote key/account label or following diagnostic was mishandled")
		}
	}
	public := wg.WireGuard.Peers[0].PublicKey
	if got := Redact("public_key="+public, s); !strings.Contains(got, public) {
		t.Fatal("a public peer key was unexpectedly treated as private")
	}
}
