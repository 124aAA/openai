package node

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func tuicFixture(t *testing.T) Node {
	t.Helper()
	n := tlsProtocolFixture(t, "tuic")
	n.Users[0].UUID = "11111111-1111-4111-8111-111111111111"
	n.Users[1].UUID = "22222222-2222-4222-8222-222222222222"
	return n
}

func TestTUICCredentialsAndConservativeDefaults(t *testing.T) {
	n := tuicFixture(t)
	if err := validateTUIC(n); err != nil {
		t.Fatal(err)
	}
	u := n.Users[0]
	out, mihomo := tuicOutbound(n, u), tuicMihomo(n, u)
	wantTLS := M{"enabled": true, "server_name": "localhost", "alpn": []string{"h3"}}
	if !reflect.DeepEqual(out, M{"type": "tuic", "uuid": u.UUID, "password": u.Password, "tls": wantTLS, "zero_rtt_handshake": false}) {
		t.Fatal("default TUIC client changed TLS, authentication, or enabled 0-RTT")
	}
	if !reflect.DeepEqual(mihomo, M{"type": "tuic", "uuid": u.UUID, "password": u.Password, "sni": "localhost", "skip-cert-verify": false, "alpn": []string{"h3"}, "reduce-rtt": false}) {
		t.Fatal("Mihomo default TUIC client has unsafe or unsupported fields")
	}
	defaultIn := tuicInbound(n, "/owned/root")
	if defaultIn["zero_rtt_handshake"] != false || !reflect.DeepEqual(defaultIn["tls"].(M)["alpn"], []string{"h3"}) {
		t.Fatal("server and client did not agree on safe TLS/QUIC defaults")
	}
	wantUsers := []any{M{"name": n.Users[0].ID, "uuid": n.Users[0].UUID, "password": n.Users[0].Password}, M{"name": n.Users[1].ID, "uuid": n.Users[1].UUID, "password": n.Users[1].Password}}
	if !reflect.DeepEqual(defaultIn["users"], wantUsers) {
		t.Fatal("TUIC users lost stable attribution or independent UUID/password pairs")
	}
	n.TUIC = &TUICOptions{}
	if !reflect.DeepEqual(defaultIn, tuicInbound(n, "/owned/root")) || !reflect.DeepEqual(out, tuicOutbound(n, u)) || !reflect.DeepEqual(mihomo, tuicMihomo(n, u)) {
		t.Fatal("empty options changed the fixed clients' defaults")
	}
	generated := User{Password: "old-password"}
	tuicCredential(&generated)
	if !uuidRE.MatchString(generated.UUID) || generated.UUID[14] != '4' || len(generated.Password) != 48 || generated.Password == u.Password {
		t.Fatal("TUIC did not generate a fresh UUID and independent password")
	}
	if tuicURI(n, u) != "" {
		t.Fatal("TUIC invented an unchecked sharing URI")
	}
}

func TestTUICServerClientDirectionsAndExactMihomoUnits(t *testing.T) {
	n := tuicFixture(t)
	zeroRTT := false
	n.TUIC = &TUICOptions{ServerCongestionControl: "bbr", ClientCongestionControl: "new_reno", AuthTimeout: "1500ms", ServerHeartbeat: "2500ms", ClientHeartbeat: "1500ms", UDPRelayMode: "quic", ZeroRTTHandshake: &zeroRTT}
	if err := validateTUIC(n); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(n)
	in, out, mihomo := tuicInbound(n, "/owned/root"), tuicOutbound(n, n.Users[0]), tuicMihomo(n, n.Users[0])
	if in["congestion_control"] != "bbr" || in["auth_timeout"] != "1500ms" || in["heartbeat"] != "2500ms" || in["udp_relay_mode"] != nil {
		t.Fatal("client relay or congestion settings leaked into the TUIC server")
	}
	if out["congestion_control"] != "new_reno" || out["heartbeat"] != "1500ms" || out["udp_relay_mode"] != "quic" || out["auth_timeout"] != nil {
		t.Fatal("TUIC client lost its settings or inherited server authentication timeout")
	}
	if mihomo["congestion-controller"] != "new_reno" || mihomo["heartbeat-interval"] != 1500 || mihomo["udp-relay-mode"] != "quic" || mihomo["reduce-rtt"] != false {
		t.Fatal("Mihomo field names, millisecond units, or safe handshake choice changed")
	}
	after, _ := json.Marshal(n)
	if string(before) != string(after) {
		t.Fatal("TUIC rendering mutated persisted credentials or options")
	}
	var round Node
	if err := json.Unmarshal(before, &round); err != nil || round.TUIC == nil || round.TUIC.ZeroRTTHandshake == nil || *round.TUIC.ZeroRTTHandshake {
		t.Fatal("explicit false was not preserved in persisted settings", err)
	}
}

func TestTUICOptionsRejectLossyOrUnsafeChoices(t *testing.T) {
	trueValue := true
	for _, p := range []*TUICOptions{
		{ServerCongestionControl: "newreno"}, {ClientCongestionControl: "magic"},
		{AuthTimeout: "0s"}, {AuthTimeout: "999ms"}, {AuthTimeout: "60.001s"}, {AuthTimeout: "bad"},
		{ServerHeartbeat: "999ms"}, {ClientHeartbeat: "120.001s"}, {ClientHeartbeat: "1.000001s"}, {ClientHeartbeat: "bad"},
		{UDPRelayMode: "udp_over_stream"}, {ZeroRTTHandshake: &trueValue},
	} {
		if validateTUICOptions(p) == nil {
			t.Fatalf("unsupported or unsafe TUIC settings accepted: %+v", p)
		}
	}
	for _, cc := range []string{"cubic", "new_reno", "bbr"} {
		for _, relay := range []string{"native", "quic"} {
			for _, heartbeat := range []string{"1s", "1500ms", "2m"} {
				if err := validateTUICOptions(&TUICOptions{ServerCongestionControl: cc, ClientCongestionControl: cc, AuthTimeout: "60s", ServerHeartbeat: heartbeat, ClientHeartbeat: heartbeat, UDPRelayMode: relay}); err != nil {
					t.Fatal("supported exact settings rejected", err)
				}
			}
		}
	}
}

func TestTUICValidationRestoreAndUUIDCollisions(t *testing.T) {
	for _, change := range []func(*Node){
		func(n *Node) { n.Certificate = nil },
		func(n *Node) { n.Certificate.ServerName = "wrong.example.test" },
		func(n *Node) { n.Reality = &Reality{} },
		func(n *Node) { n.Shadowsocks = &Shadowsocks{} },
		func(n *Node) { n.AnyTLS = &AnyTLSOptions{} },
		func(n *Node) { n.HY2 = &HY2Performance{} },
		func(n *Node) { n.Users[0].UUID = "" },
		func(n *Node) { n.Users[0].Password = "too-short" },
		func(n *Node) { n.Users[0].Password = "password-with-\n-control" },
		func(n *Node) {
			n.Users[0].UUID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
			n.Users[1].UUID = strings.ToUpper(n.Users[0].UUID)
		},
	} {
		n := tuicFixture(t)
		change(&n)
		if validateTUICCertificate(n, false) == nil {
			t.Fatal("restore bypassed a TUIC authentication, certificate, or protocol rule")
		}
	}
	n := tuicFixture(t)
	n.Certificate = &Certificate{Mode: "file", ServerName: "localhost", CertificatePath: filepath.Join(t.TempDir(), "missing-cert.pem"), KeyPath: filepath.Join(t.TempDir(), "missing-key.pem")}
	if err := validateTUICCertificate(n, false); err != nil {
		t.Fatal("restore did not defer destination file access", err)
	}
	if validateTUIC(n) == nil {
		t.Fatal("runnable TUIC accepted unavailable external certificate files")
	}
	n.TUIC = &TUICOptions{ClientHeartbeat: "1.1ms"}
	if validateTUICCertificate(n, false) == nil {
		t.Fatal("restore skipped client option validation")
	}
	cert, key := certificateTestPair(t, time.Now(), false, true)
	n.Certificate = &Certificate{Mode: "pem", ServerName: "hy2.example.test", CertPEM: cert, KeyPEM: key}
	n.TUIC = nil
	if err := validateTUIC(n); err != nil {
		t.Fatal("native TUIC TLS inherited a Chrome-specific certificate restriction", err)
	}
}
