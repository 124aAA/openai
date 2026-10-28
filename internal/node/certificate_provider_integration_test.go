//go:build linux

package node

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This is configuration-parser evidence only. It never runs the core or asks
// a CA/DNS provider to issue a certificate; all credentials below are fixtures.
func TestOfficialCoreCertificateACMEProviderSchemas(t *testing.T) {
	core := os.Getenv("SING_BOX_BIN")
	if core == "" {
		t.Skip("SING_BOX_BIN is unset; official ACME provider parser validation was not run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	versionOutput, err := exec.CommandContext(ctx, core, "version").CombinedOutput()
	cancel()
	fields := strings.Fields(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if err != nil || len(fields) != 3 || fields[0] != "sing-box" || fields[1] != "version" || (fields[2] != "1.14.0" && fields[2] != "1.14.3") {
		t.Fatalf("requires separately verified official sing-box 1.14.0 or 1.14.3: %v %s", err, versionOutput)
	}
	withACME := false
	for _, tag := range CoreBuildTags(string(versionOutput)) {
		withACME = withACME || tag == "with_acme"
	}
	if !withACME {
		t.Fatal("official core lacks the exact with_acme build tag")
	}
	version := fields[2]
	commonDNS := func(d ACMEDNS01) *ACMEDNS01 {
		d.TTL = "60s"
		d.PropagationDelay = "2s"
		d.PropagationTimeout = "2m"
		d.Resolvers = []string{"192.0.2.53:53", "[2001:db8::53]:53"}
		d.OverrideDomain = "_acme-challenge.delegated.example.test"
		return &d
	}
	cases := []struct {
		name     string
		settings ACMESettings
	}{
		{"http-01", ACMESettings{Challenge: "http-01", KeyType: "p256", AlternativeHTTPPort: 18080}},
		{"tls-alpn-01", ACMESettings{Challenge: "tls-alpn-01", KeyType: "rsa2048", AlternativeTLSPort: 18443}},
		{"dns-01-alidns", ACMESettings{Challenge: "dns-01", KeyType: "p256", DNS01: commonDNS(ACMEDNS01{Provider: "alidns", AccessKeyID: "fixture-access-id", AccessKeySecret: "fixture-access-secret", RegionID: "cn-hangzhou", SecurityToken: "fixture-security-token"})}},
		{"dns-01-cloudflare", ACMESettings{Challenge: "dns-01", KeyType: "p256", DNS01: commonDNS(ACMEDNS01{Provider: "cloudflare", APIToken: "fixture-api-token", ZoneToken: "fixture-zone-token"})}},
		{"dns-01-acmedns", ACMESettings{Challenge: "dns-01", KeyType: "p256", DNS01: commonDNS(ACMEDNS01{Provider: "acmedns", Username: "fixture-username", Password: "fixture-password", Subdomain: "fixture-subdomain", ServerURL: "https://auth.example.test"})}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			resource := CertificateResource{ID: "1111111111111111", Name: "parser-certificate", Certificate: Certificate{Mode: "acme", ServerName: "hy2.example.test", Email: "fixture@example.test", ACME: &tc.settings}}
			state := NewState()
			state.CoreVersion = version
			state.Certificates = []CertificateResource{resource}
			state.Nodes = []Node{{ID: "2222222222222222", Name: "parser-node", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 24443, Enabled: true, CertificateID: resource.ID, Users: []User{{ID: "3333333333333333", Name: "parser-user", Password: "fixture-hy2-password"}}}}
			if err := ResolveCertificates(&state); err != nil {
				t.Fatal("resolve production certificate reference", err)
			}
			if err := state.Validate(); err != nil {
				t.Fatal("complete production State fixture must pass validation", err)
			}
			generated, err := Server(state, dir)
			if err != nil {
				t.Fatal("production resource/server renderer", err)
			}
			var config M
			if err := json.Unmarshal(generated, &config); err != nil {
				t.Fatal(err)
			}
			providers, ok := config["certificate_providers"].([]any)
			if !ok || len(providers) != 1 {
				t.Fatal("production renderer did not emit exactly one shared certificate provider")
			}
			provider := providers[0].(map[string]any)
			inbound := config["inbounds"].([]any)[0].(map[string]any)
			if provider["type"] != "acme" || provider["tag"] != "certificate-"+resource.ID || inbound["tls"].(map[string]any)["certificate_provider"] != provider["tag"] || provider["data_directory"] != CertificateACMEDirectory(dir, resource) {
				t.Fatal("stable resource reference or owned ACME storage was not rendered")
			}
			switch tc.settings.Challenge {
			case "http-01":
				if provider["alternative_http_port"] != float64(18080) || provider["disable_tls_alpn_challenge"] != true || provider["disable_http_challenge"] == true {
					t.Fatal("HTTP-01 challenge selection or alternative port was lost")
				}
			case "tls-alpn-01":
				if provider["alternative_tls_port"] != float64(18443) || provider["disable_http_challenge"] != true || provider["disable_tls_alpn_challenge"] != false {
					t.Fatal("TLS-ALPN challenge selection or alternative port was lost")
				}
			case "dns-01":
				dnsBytes, err := json.Marshal(tc.settings.DNS01)
				if err != nil {
					t.Fatal(err)
				}
				var expectedDNS M
				if err := json.Unmarshal(dnsBytes, &expectedDNS); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(provider["dns01_challenge"], map[string]any(expectedDNS)) || provider["disable_http_challenge"] != true || provider["disable_tls_alpn_challenge"] != true {
					t.Fatal("DNS provider fields, propagation controls or challenge selection were lost")
				}
			}
			path := filepath.Join(dir, "provider.json")
			if err := os.WriteFile(path, generated, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, core, "check", "-c", path)
			cmd.Dir = dir
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("official %s parser rejected production %s configuration: %v\n%s", version, tc.name, err, Redact(string(output), state))
			}
			t.Logf("official %s accepted production %s configuration; parser evidence only, no issuance or public reachability asserted", version, tc.name)
		})
	}
}
