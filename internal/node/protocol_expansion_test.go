package node

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
)

func TestProtocolExpansionSchema7MemoryMigrationAndNewFieldsRefused(t *testing.T) {
	old := NewState()
	old.Schema = 7
	old.Nodes = []Node{ssFixture()}
	old.Observability = &CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: 19090, Secret: Token(24)}
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeState(raw)
	if err != nil || got.Schema != Schema {
		t.Fatal(err)
	}
	got.Schema = 7
	back, err := json.Marshal(got)
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatal("migration changed identity or choices", err)
	}
	for _, field := range []string{"anytls", "AnyTLS", "tuic", "TUIC"} {
		bad := []byte(`{"schema":7,"core_version":"1.14.0","nodes":[{"` + field + `":null}]}`)
		if _, err := DecodeState(bad); err == nil {
			t.Fatal("old version accepted extension", field)
		}
	}
	for _, protocol := range []string{"anytls", "trojan", "ss-aead", "tuic"} {
		if _, err := DecodeState([]byte(`{"schema":7,"nodes":[{"protocol":"` + protocol + `"}]}`)); err == nil {
			t.Fatal("new protocol hidden in old state")
		}
	}
	if _, err := DecodeState([]byte(`{"schema":` + strconv.Itoa(Schema+1) + `,"nodes":[]}`)); err == nil {
		t.Fatal("future State accepted")
	}
}

func TestProtocolExpansionCapabilitySeparatesSocketsAndBusiness(t *testing.T) {
	for _, name := range []string{"reality", "anytls", "trojan"} {
		c, ok := ProtocolCapabilities(name)
		if !ok || len(c.ListenerNetworks) != 1 || c.ListenerNetworks[0] != "tcp" || !topologyHasNetwork(c.BusinessNetworks, "udp") {
			t.Fatal("socket and carried UDP conflated", name)
		}
	}
	for _, name := range []string{"anytls", "trojan"} {
		if !ProtocolRequiresCertificate(name) {
			t.Fatal("missing shared TLS requirement")
		}
	}
	if ProtocolRequiresCertificate("ss2022") {
		t.Fatal("old SS2022 acquired TLS")
	}
}
