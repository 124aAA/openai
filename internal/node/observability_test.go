package node

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func observationFixture() *CoreObservation {
	return &CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: 19090, Secret: strings.Repeat("private-observation-", 3)}
}

func TestCoreObservationRequiresExplicitLoopbackPortAndPrivateAuthentication(t *testing.T) {
	if err := ValidateCoreObservation(nil); err != nil {
		t.Fatal("default observation was not disabled", err)
	}
	for _, listen := range []string{"127.0.0.1", "::1"} {
		c := observationFixture()
		c.Listen = listen
		if err := ValidateCoreObservation(c); err != nil {
			t.Fatal("explicit supported loopback refused", err)
		}
		if want := map[string]string{"127.0.0.1": "http://127.0.0.1:19090", "::1": "http://[::1]:19090"}[listen]; c.Endpoint() != want {
			t.Fatal("observation endpoint changed family/port", c.Endpoint())
		}
	}
	for _, listen := range []string{"", "localhost", "0.0.0.0", "::", "127.0.0.2", "::ffff:127.0.0.1", "192.168.0.1", "203.0.113.8"} {
		c := observationFixture()
		c.Listen = listen
		if err := ValidateCoreObservation(c); err == nil {
			t.Fatalf("noncanonical/public API address accepted: %q", listen)
		}
	}
	for _, port := range []int{-1, 0, 1023, 65536} {
		c := observationFixture()
		c.Port = port
		if err := ValidateCoreObservation(c); err == nil {
			t.Fatal("invalid/privileged observation port accepted", port)
		}
	}
	for _, secret := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 257), strings.Repeat("a", 32) + " ", strings.Repeat("a", 32) + "\n", strings.Repeat("a", 32) + "\x00", strings.Repeat("a", 32) + "\v", strings.Repeat("a", 32) + "\u00a0"} {
		c := observationFixture()
		c.Secret = secret
		if err := ValidateCoreObservation(c); err == nil {
			t.Fatal("missing/short/long/whitespace authentication accepted")
		}
	}
}

func TestCoreObservationDisabledDefaultPreservesServerAndBindings(t *testing.T) {
	s := fixture(t)
	s.Firewall = "ufw"
	base, err := Server(s, "/var/lib/qingnode")
	if err != nil {
		t.Fatal(err)
	}
	bindings, rules := StateBindings(s), RequiredRules(s)
	if bytes.Contains(base, []byte(`"services"`)) {
		t.Fatal("default server enabled observation service")
	}
	s.Observability = observationFixture()
	s.Observability.Enabled = false
	disabled, err := Server(s, "/var/lib/qingnode")
	if err != nil || !bytes.Equal(base, disabled) || !reflect.DeepEqual(bindings, StateBindings(s)) || !reflect.DeepEqual(rules, RequiredRules(s)) {
		t.Fatal("disabled observation changed runtime config, reservations or firewall", err)
	}
	if bytes.Contains(disabled, []byte(s.Observability.Secret)) {
		t.Fatal("disabled API secret entered runnable core config")
	}
}

func TestCoreObservationEnabledRendersOnlyOwnedLocalServiceAndNoPublicFirewallRule(t *testing.T) {
	s := fixture(t)
	s.Firewall = "ufw"
	beforeBindings, beforeRules := StateBindings(s), RequiredRules(s)
	s.Observability = observationFixture()
	rendered, err := Server(s, "/var/lib/qingnode")
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(rendered, &config); err != nil {
		t.Fatal(err)
	}
	services, ok := config["services"].([]any)
	if !ok || len(services) != 1 {
		t.Fatal("missing/unexpected core service count")
	}
	service, ok := services[0].(map[string]any)
	want := map[string]any{"type": "api", "tag": "qingnode-api", "listen": "127.0.0.1", "listen_port": float64(19090), "secret": s.Observability.Secret}
	if !ok || !reflect.DeepEqual(service, want) {
		t.Fatal("API service is not bound to exact private configuration")
	}
	bindings := StateBindings(s)
	if len(bindings) != len(beforeBindings)+1 || bindings[len(beforeBindings)] != (LocalBinding{NodeID: "qingnode-api", Network: "tcp", Address: "127.0.0.1", Port: 19090}) {
		t.Fatal("enabled API not included in local TCP conflict checks")
	}
	if !reflect.DeepEqual(beforeRules, RequiredRules(s)) {
		t.Fatal("local observation opened or changed public firewall rules")
	}
}

func TestCoreObservationListenerConflictsAreRejectedBeforeApply(t *testing.T) {
	for _, listen := range []string{"127.0.0.1", "0.0.0.0", "::"} {
		s := fixture(t)
		s.Nodes[0].Listen, s.Nodes[0].Port = listen, 19090
		s.Observability = observationFixture()
		err := s.Validate()
		if listen == "::" && err == nil {
			// Cross-family wildcard overlap is deliberately uncertain in the
			// pure State validator. The existing pre-apply path binds candidates
			// together using the core's actual Go dual-stack listener semantics.
			_, err = ProbeLocalBindings(context.Background(), StateBindings(s), BindingProbeOptions{})
		}
		if err == nil {
			t.Fatalf("API/TCP listener overlap accepted on %q", listen)
		}
	}
	s := fixture(t)
	s.Nodes[0].Listen, s.Nodes[0].Port = "::1", 19090
	s.Observability = observationFixture()
	if err := s.Validate(); err != nil {
		t.Fatal("distinct concrete address families were rejected", err)
	}
	s.Nodes[0].Listen = "127.0.0.1"
	s.Observability.Enabled = false
	if err := s.Validate(); err != nil {
		t.Fatal("disabled API reserved listener port", err)
	}
}

func TestCoreObservationSecretIsRedactedIncludingDisabledConfiguration(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := NewState()
		s.Observability = observationFixture()
		s.Observability.Enabled = enabled
		input := `{"endpoint":"http://127.0.0.1:19090","secret":"` + s.Observability.Secret + `","diagnostic":"connection refused"}`
		redacted := Redact(input, s)
		if !json.Valid([]byte(redacted)) || strings.Contains(redacted, s.Observability.Secret) || !strings.Contains(redacted, "已隐藏") || !strings.Contains(redacted, "connection refused") || !strings.Contains(redacted, "127.0.0.1:19090") {
			t.Fatal("observation error redaction leaked secret or lost useful diagnostics")
		}
	}
}

func TestStateCloneOwnsObservationCredentialsAndExpiryRecords(t *testing.T) {
	s := fixture(t)
	s.Observability = observationFixture()
	e := CredentialExpiration{ID: "4444444444444444", NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[0].ID, ExpiresAt: "2030-01-02T03:04:05Z"}
	s.CredentialExpirations = []CredentialExpiration{e}
	cloned := s.Clone()
	cloned.Observability.Secret = strings.Repeat("replacement", 4)
	cloned.CredentialExpirations[0].ExpiresAt = "2040-01-01T00:00:00Z"
	if s.Observability.Secret != observationFixture().Secret || s.CredentialExpirations[0] != e {
		t.Fatal("candidate/inspection clone shared observation credential pointer or deadline slice with input")
	}
}
