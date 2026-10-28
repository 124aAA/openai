package node

import (
	"bytes"
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
)

func TestAnyTLSDefaultAndExplicitClientOptions(t *testing.T) {
	n := tlsProtocolFixture(t, "anytls")
	u := n.Users[0]
	defaultOut := anytlsOutbound(n, u)
	defaultMihomo := anytlsMihomo(n, u)
	if !reflect.DeepEqual(defaultOut, M{"type": "anytls", "password": u.Password, "tls": M{"enabled": true, "server_name": "localhost"}}) || defaultMihomo["udp"] != true || defaultMihomo["skip-cert-verify"] != false {
		t.Fatal("default client settings force idle sessions or weaken TLS")
	}
	n.AnyTLS = &AnyTLSOptions{}
	if AnyTLSClientSettingsPresent(n.AnyTLS) || !reflect.DeepEqual(defaultOut, anytlsOutbound(n, u)) || !reflect.DeepEqual(defaultMihomo, anytlsMihomo(n, u)) {
		t.Fatal("empty options changed conservative defaults")
	}
	zero := 0
	n.AnyTLS = &AnyTLSOptions{IdleSessionCheckInterval: "1m30s", IdleSessionTimeout: "24h", IdleSessionMinKeep: &zero}
	if err := validateAnyTLS(n); err != nil {
		t.Fatal(err)
	}
	out, mihomo := anytlsOutbound(n, u), anytlsMihomo(n, u)
	if out["idle_session_check_interval"] != "1m30s" || out["idle_session_timeout"] != "24h" || out["min_idle_session"] != 0 || mihomo["idle-session-check-interval"] != 90 || mihomo["idle-session-timeout"] != 86400 || mihomo["min-idle-session"] != 0 {
		t.Fatal("client field names, units, or explicit zero were lost")
	}
	if in := anytlsInbound(n, "/owned/root"); len(in) != 3 {
		t.Fatal("client session reuse settings leaked into the server")
	}
	raw, err := json.Marshal(n.AnyTLS)
	if err != nil {
		t.Fatal(err)
	}
	var round AnyTLSOptions
	if err = json.Unmarshal(raw, &round); err != nil || round.IdleSessionMinKeep == nil || *round.IdleSessionMinKeep != 0 || !reflect.DeepEqual(n.AnyTLS, &round) {
		t.Fatal("persisted explicit zero became unset", err)
	}
	if anytlsURI(n, u) != "" {
		t.Fatal("basic URI silently discarded advanced client settings")
	}
}

func TestAnyTLSOptionBoundsPreventClientReinterpretation(t *testing.T) {
	for _, raw := range []string{"0s", "-1s", "5s", "5.999s", "6.5s", "24h1s", "garbage", "999999999999999999999999s"} {
		for _, p := range []*AnyTLSOptions{{IdleSessionCheckInterval: raw}, {IdleSessionTimeout: raw}} {
			if validateAnyTLSOptions(p) == nil {
				t.Fatal("unrepresentable or reinterpreted duration accepted", raw)
			}
		}
	}
	for _, raw := range []string{"6s", "30s", "1m", "24h"} {
		if err := validateAnyTLSOptions(&AnyTLSOptions{IdleSessionCheckInterval: raw, IdleSessionTimeout: raw}); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, keep := range []int{-1, 1025} {
		if validateAnyTLSOptions(&AnyTLSOptions{IdleSessionMinKeep: &keep}) == nil {
			t.Fatal("unbounded idle session reservation accepted")
		}
	}
	for _, keep := range []int{0, 1024} {
		if err := validateAnyTLSOptions(&AnyTLSOptions{IdleSessionMinKeep: &keep}); err != nil {
			t.Fatal(err)
		}
	}
	n := tlsProtocolFixture(t, "anytls")
	n.AnyTLS = &AnyTLSOptions{IdleSessionTimeout: "1s"}
	for _, format := range []string{"sing-box", "mihomo", "provider"} {
		if _, err := Export(n, n.Users[0], format); err == nil {
			t.Fatal("public export let a client reinterpret an invalid explicit duration", format)
		}
		if _, err := ExportWithCapabilities(n, n.Users[0], format, "1.14.3", nil, true); err == nil {
			t.Fatal("capability export bypassed option validation", format)
		}
	}
}

func TestAnyTLSBasicURIUsesOfficialFieldsAndConnectEndpoint(t *testing.T) {
	n := tlsProtocolFixture(t, "anytls")
	port := 2443
	n.ConnectPort = &port
	u := n.Users[0]
	raw := anytlsURI(n, u)
	got, err := url.Parse(raw)
	if err != nil || got.Scheme != "anytls" || got.Hostname() != "2001:db8::1" || got.Port() != "2443" || got.User.Username() != u.Password || got.Path != "/" || got.Fragment != n.Name+" / "+u.Name {
		t.Fatal("URI lost an IPv6 endpoint, secret escaping, or display name", err)
	}
	if _, hasPassword := got.User.Password(); hasPassword || !reflect.DeepEqual(got.Query(), url.Values{"sni": {"localhost"}, "insecure": {"0"}}) {
		t.Fatal("URI invented an auth pair or unsupported fields")
	}
}

func TestAnyTLSManagedCertificateRoundTripAndPublicExportGate(t *testing.T) {
	n := tlsProtocolFixture(t, "anytls")
	zero := 0
	n.AnyTLS = &AnyTLSOptions{IdleSessionTimeout: "45s", IdleSessionMinKeep: &zero}
	s := NewState()
	s.Nodes = []Node{n}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	n = decoded.Nodes[0]
	if n.CertificateID == "" || len(decoded.Certificates) != 1 || n.AnyTLS == nil || n.AnyTLS.IdleSessionMinKeep == nil || *n.AnyTLS.IdleSessionMinKeep != 0 {
		t.Fatal("managed certificate identity or explicit client choice was lost")
	}
	server, err := Server(decoded, "/owned/root")
	if err != nil || !bytes.Contains(server, []byte(`"type": "anytls"`)) || bytes.Contains(server, []byte("idle_session")) {
		t.Fatal("server rendering lost its adapter or included client-only options", err)
	}
	for _, format := range []string{"uri", "qr", "base64"} {
		if _, err := Export(n, n.Users[0], format); err == nil {
			t.Fatal("public export silently discarded explicit client settings", format)
		}
		if _, err := ExportWithCapabilities(n, n.Users[0], format, "1.14.3", nil, true); err == nil {
			t.Fatal("lossy export returned an empty URI as successful output", format)
		}
	}
	for _, format := range []string{"sing-box", "mihomo", "provider"} {
		data, err := Export(n, n.Users[0], format)
		if err != nil || !bytes.Contains(data, []byte(n.Users[0].Password)) {
			t.Fatal("complete client configuration did not preserve the credential", format, err)
		}
	}
}
