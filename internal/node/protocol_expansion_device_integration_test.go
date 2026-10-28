//go:build linux

package node

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// This checks complete mixed-device configurations with the actual official
// parsers. The documented IPv6 endpoints are not dialled and no core is run.
func TestProtocolExpansionOfficialMixedDeviceParsers(t *testing.T) {
	core, version, mihomo := deviceOfficialInputs(t)
	s, p := protocolExpansionDeviceFixture(t)
	zero, zeroRTT := 0, false
	for i := range s.Nodes {
		switch s.Nodes[i].Protocol {
		case "anytls":
			s.Nodes[i].AnyTLS = &AnyTLSOptions{IdleSessionCheckInterval: "30s", IdleSessionTimeout: "45s", IdleSessionMinKeep: &zero}
		case "tuic":
			s.Nodes[i].TUIC = &TUICOptions{ServerCongestionControl: "bbr", ClientCongestionControl: "new_reno", AuthTimeout: "3s", ServerHeartbeat: "2s", ClientHeartbeat: "1500ms", UDPRelayMode: "quic", ZeroRTTHandshake: &zeroRTT}
		}
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	before := s.Clone()
	for _, format := range []string{"sing-box", "mihomo"} {
		t.Run(format, func(t *testing.T) {
			clientVersion := version
			if format == "mihomo" {
				clientVersion = "1.19.30"
			}
			r, err := ExportDeviceProfile(s, p, format, clientVersion, false)
			if err != nil || len(r.NodeIDs) != 5 {
				t.Fatal("complete mixed-device export failed or omitted a protocol", err)
			}
			private := t.TempDir()
			path := filepath.Join(private, "mixed-device.config")
			if err = os.WriteFile(path, r.Content, 0600); err != nil {
				t.Fatal(err)
			}
			ca := filepath.Join(private, "fixture-ca.pem")
			if err = os.WriteFile(ca, []byte(s.Certificates[0].Certificate.CertPEM), 0600); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(r.Content, []byte(s.Certificates[0].Certificate.KeyPEM)) || bytes.Contains(r.Content, []byte(`"insecure": true`)) || bytes.Contains(r.Content, []byte("skip-cert-verify: true")) {
				t.Fatal("parser fixture exported a server private key or disabled certificate verification")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, core, "check", "-c", path)
			if format == "mihomo" {
				cmd = exec.CommandContext(ctx, mihomo, "-t", "-d", private, "-f", path)
			}
			// Trust only the fixture's public CA in the child process; the host
			// trust store and generated client TLS verification stay unchanged.
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+private, "DISABLE_SYSTEM_CA=false")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("official %s parser rejected mixed device configuration: %v\n%s", format, err, Redact(string(output)))
			}
			t.Logf("official %s parser accepted all five selected nodes; parse-only, no endpoint dial or transport claim", format)
		})
	}
	if !reflect.DeepEqual(s, before) {
		t.Fatal("official parser fixture changed the source State")
	}
}
