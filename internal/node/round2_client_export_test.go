package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSchema9MigrationLosslessAndRejectsSmuggledSchema10Fields(t *testing.T) {
	raw, err := os.ReadFile("testdata/state-v9-devices.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := ReadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Validate(); err != nil {
		t.Fatal(err)
	}
	if st.Schema != Schema || st.Firewall != "firewalld" || len(st.Devices) != 1 {
		t.Fatalf("unexpected migrated state: %+v", st)
	}
	dev := st.Devices[0]
	if dev.Routing != "basic" || dev.TUN || dev.Controller != nil || dev.DefaultSubscriptionFormat != "" {
		t.Fatalf("legacy device defaults mutated during migration: %+v", dev)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, raw) {
		t.Fatal("read-only ReadState mutated schema-9 file on disk")
	}

	// Reject schema 1..9 smuggling any schema-10 DeviceProfile fields (including null, uppercase, or Unicode SimpleFold aliases) or new routing presets.
	smuggled := []string{
		`"default_subscription_format": "mihomo",`,
		`"default_subscription_format": null,`,
		`"default_ſubscription_format": "mihomo",`,
		`"tun": true,`,
		`"tun": false,`,
		`"tun": null,`,
		`"TUN": false,`,
		`"controller": {"enabled": true, "port": 9090, "secret": "0123456789abcdef"},`,
		`"controller": null,`,
		`"Controller": null,`,
	}
	for _, field := range smuggled {
		bad := bytes.Replace(raw, []byte(`"routing": "basic"`), []byte(field+` "routing": "basic"`), 1)
		if _, err = DecodeState(bad); err == nil {
			t.Fatalf("schema 9 accepted smuggled schema-10 field: %s", field)
		}
	}
	for _, preset := range []string{"cn-direct", "global-secure-dns"} {
		bad := bytes.Replace(raw, []byte(`"routing": "basic"`), []byte(`"routing": "`+preset+`"`), 1)
		if _, err = DecodeState(bad); err == nil {
			t.Fatalf("schema 9 accepted schema-10 routing preset %s", preset)
		}
	}

	// Schema 10 accepts all new fields and redacts Controller.Secret.
	st.Devices[0].Routing = "cn-direct"
	st.Devices[0].DefaultSubscriptionFormat = "sing-box"
	st.Devices[0].TUN = true
	st.Devices[0].Controller = &ClientController{Enabled: true, Port: 9090, Secret: "super-secret-controller-token"}
	if err = st.Validate(); err != nil {
		t.Fatalf("schema 10 valid device rejected: %v", err)
	}
	encoded, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(encoded)
	if err != nil || !decoded.Devices[0].TUN || decoded.Devices[0].Controller == nil || decoded.Devices[0].DefaultSubscriptionFormat != "sing-box" {
		t.Fatalf("schema 10 round-trip failed: %v %+v", err, decoded.Devices)
	}
	redactedLog := Redact("controller token=super-secret-controller-token", decoded)
	if strings.Contains(redactedLog, "super-secret-controller-token") || !strings.Contains(redactedLog, "[API凭据已隐藏]") {
		t.Fatalf("controller secret leaked through Redact: %q", redactedLog)
	}
	if decoded.Devices[0].Controller.Secret != "super-secret-controller-token" {
		t.Fatal("Redact mutated original state")
	}
}

func TestSemanticClientVersionGates(t *testing.T) {
	for _, okVer := range []string{"1.14.0", "1.14.3", "1.14.99"} {
		if !SupportedVersion(okVer) {
			t.Fatalf("sing-box %s should be supported", okVer)
		}
	}
	for _, badVer := range []string{"", "1.13.9", "1.15.0", "1.14", "1.14.01", "1.14.3-beta.1"} {
		if SupportedVersion(badVer) {
			t.Fatalf("sing-box %s should be rejected", badVer)
		}
	}
	for _, okMihomo := range []string{"1.19.0", "1.19.30", "1.19.99", "1.20.1", "2.0.0"} {
		if !SupportedMihomoVersion(okMihomo) {
			t.Fatalf("mihomo %s should be supported", okMihomo)
		}
	}
	for _, badMihomo := range []string{"", "1.18.9", "0.19.0", "1.19", "01.19.0", "1.19.0-alpha"} {
		if SupportedMihomoVersion(badMihomo) {
			t.Fatalf("mihomo %s should be rejected", badMihomo)
		}
	}
}

func TestClientExportPresetsTUNAndControllerStructure(t *testing.T) {
	s, p := deviceFixture(t)
	// Reject invalid controller port collisions, disabled-with-secret, or short secrets.
	for _, bad := range []*ClientController{
		{Enabled: true, Port: 2080, Secret: "0123456789abcdef"},
		{Enabled: true, Port: 7890, Secret: "0123456789abcdef"},
		{Enabled: true, Port: 9090, Secret: "short"},
		{Enabled: true, Port: 9090, Secret: "0123456789abcdef\n"},
		{Enabled: false, Port: 9090, Secret: "0123456789abcdef"},
	} {
		q := p
		q.Controller = bad
		if err := ValidateDeviceProfile(s, q); err == nil {
			t.Fatalf("accepted invalid controller %+v", bad)
		}
	}

	p.Routing = "cn-direct"
	p.TUN = true
	p.Controller = &ClientController{Enabled: true, Port: 9090, Secret: "0123456789abcdef0123456789abcdef"}
	p.DefaultSubscriptionFormat = "mihomo"
	if err := ValidateDeviceProfile(s, p); err != nil {
		t.Fatal(err)
	}

	sbRes, err := ExportDeviceProfile(s, p, "sing-box", "1.14.0", false)
	if err != nil {
		t.Fatal(err)
	}
	var sbDoc map[string]any
	if err = json.Unmarshal(sbRes.Content, &sbDoc); err != nil {
		t.Fatal(err)
	}
	if len(sbDoc["inbounds"].([]any)) != 2 {
		t.Fatalf("expected mixed + tun inbounds, got %v", sbDoc["inbounds"])
	}
	tunInbound := sbDoc["inbounds"].([]any)[1].(map[string]any)
	if tunInbound["type"] != "tun" || tunInbound["auto_route"] != true || tunInbound["strict_route"] != true {
		t.Fatalf("unexpected sing-box tun inbound: %v", tunInbound)
	}
	exp := sbDoc["experimental"].(map[string]any)["clash_api"].(map[string]any)
	if exp["external_controller"] != "127.0.0.1:9090" || exp["secret"] != p.Controller.Secret {
		t.Fatalf("unexpected sing-box clash_api: %v", exp)
	}
	dnsDoc := sbDoc["dns"].(map[string]any)
	if dnsDoc["independent_cache"] != nil || len(dnsDoc["servers"].([]any)) != 3 {
		t.Fatalf("unexpected sing-box cn-direct dns: %v", dnsDoc)
	}
	routeDoc := sbDoc["route"].(map[string]any)
	if routeDoc["auto_detect_interface"] != true || len(routeDoc["rule_set"].([]any)) != 2 {
		t.Fatalf("unexpected sing-box cn-direct route: %v", routeDoc)
	}

	mhRes, err := ExportDeviceProfile(s, p, "mihomo", "1.19.0", false)
	if err != nil {
		t.Fatal(err)
	}
	var mhDoc map[string]any
	if err = yaml.Unmarshal(mhRes.Content, &mhDoc); err != nil {
		t.Fatal(err)
	}
	if mhDoc["external-controller"] != "127.0.0.1:9090" || mhDoc["secret"] != p.Controller.Secret {
		t.Fatalf("unexpected mihomo controller: %v", mhDoc["external-controller"])
	}
	tunMap := mhDoc["tun"].(map[string]any)
	if tunMap["enable"] != true || tunMap["stack"] != "mixed" || tunMap["auto-route"] != true || tunMap["auto-detect-interface"] != true {
		t.Fatalf("unexpected mihomo tun: %v", tunMap)
	}
	mhDNS := mhDoc["dns"].(map[string]any)
	if mhDNS["enable"] != true || mhDNS["enhanced-mode"] != "fake-ip" {
		t.Fatalf("unexpected mihomo dns: %v", mhDNS)
	}

	// Single-node ExportWithClientOptions also supports presets, TUN, and controller while plain Export preserves legacy defaults.
	legacySB, err := Export(s.Nodes[0], s.Nodes[0].Users[0], "sing-box")
	if err != nil || bytes.Contains(legacySB, []byte(`"tun"`)) || bytes.Contains(legacySB, []byte(`"clash_api"`)) {
		t.Fatalf("legacy single-node export changed default behavior: %v", err)
	}
	optSB, err := ExportWithClientOptions(s.Nodes[0], s.Nodes[0].Users[0], "sing-box", "1.14.9", nil, false, ClientOptions{
		Routing:    "global-secure-dns",
		TUN:        true,
		Controller: &ClientController{Enabled: true, Port: 19090, Secret: "abcdef0123456789abcdef0123456789"},
	})
	if err != nil || !bytes.Contains(optSB.Data, []byte(`"tun"`)) || !bytes.Contains(optSB.Data, []byte(`"127.0.0.1:19090"`)) || !bytes.Contains(optSB.Data, []byte(`"dns-remote"`)) {
		t.Fatalf("single-node ExportWithClientOptions failed: %v\n%s", err, optSB.Data)
	}
}

func TestVMessBase64DeviceSubscriptionAndOfficialCoreValidation(t *testing.T) {
	vm := tlsProtocolFixture(t, "vmess-tls")
	vm.ID = "7777777777777777"
	vm.Name = "vmess-ws"
	vm.Host = "vmess.example.test"
	vm.Users[0].UUID = "33333333-3333-4333-8333-333333333333"
	vm.Users[1].UUID = "44444444-4444-4444-8444-444444444444"
	vm.Users[0].Password, vm.Users[1].Password = "", ""
	vm.Transport = &TransportOptions{Type: "ws", Path: "/ws", Host: "vmess.example.test"}
	tu := tuicFixture(t)
	tu.ID = "8888888888888888"
	tu.Name = "tuic-h3"
	tu.Host = "tuic.example.test"

	s := NewState()
	s.Nodes = []Node{vm, tu}
	p := DeviceProfile{
		ID:       "9999999999999999",
		Name:     "mixed-sub",
		Bindings: []DeviceBinding{{NodeID: vm.ID, UserID: vm.Users[0].ID}, {NodeID: tu.ID, UserID: tu.Users[0].ID}},
		Strategy: "manual",
		Routing:  "cn-direct",
		TUN:      true,
		Controller: &ClientController{
			Enabled: true,
			Port:    9090,
			Secret:  "0123456789abcdef0123456789abcdef",
		},
	}
	b64Res, err := ExportDeviceProfile(s, p, "base64", "", false)
	if err != nil {
		t.Fatal(err)
	}
	rawSub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64Res.Content)))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(rawSub)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "vmess://") || !strings.HasPrefix(lines[1], "tuic://") {
		t.Fatalf("unexpected base64 subscription lines: %v", lines)
	}
	vmJSON, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines[0], "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var vmMap map[string]string
	if err = json.Unmarshal(vmJSON, &vmMap); err != nil || vmMap["ps"] != deviceExportName(vm, vm.Users[0], p.Bindings[0]) || vmMap["net"] != "ws" || vmMap["tls"] != "tls" {
		t.Fatalf("unexpected vmess base64 payload: %v (%v)", vmMap, err)
	}
	tuURL, err := url.Parse(lines[1])
	if err != nil || tuURL.Fragment != deviceExportName(tu, tu.Users[0], p.Bindings[1]) {
		t.Fatalf("unexpected tuic base64 line: %s (%v)", lines[1], err)
	}

	core, mihomo := os.Getenv("SING_BOX_BIN"), os.Getenv("MIHOMO_BIN")
	if core == "" || mihomo == "" {
		t.Skip("SING_BOX_BIN or MIHOMO_BIN unset; official parser validation skipped")
	}
	for _, routing := range []string{"global", "basic", "global-secure-dns", "cn-direct"} {
		for _, tun := range []bool{false, true} {
			q := p
			q.Routing = routing
			q.TUN = tun
			sbOut, err := ExportDeviceProfile(s, q, "sing-box", "1.14.0", false)
			if err != nil {
				t.Fatalf("sing-box %s tun=%v export failed: %v", routing, tun, err)
			}
			dir := t.TempDir()
			sbPath := filepath.Join(dir, "client.json")
			if err = os.WriteFile(sbPath, sbOut.Content, 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(core, "check", "-c", sbPath).CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "" {
				t.Fatalf("official sing-box check failed or emitted warning for %s tun=%v: %v\n%s", routing, tun, err, out)
			}

			mhOut, err := ExportDeviceProfile(s, q, "mihomo", "1.19.30", false)
			if err != nil {
				t.Fatalf("mihomo %s tun=%v export failed: %v", routing, tun, err)
			}
			mhPath := filepath.Join(dir, "client.yaml")
			if err = os.WriteFile(mhPath, mhOut.Content, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err = exec.Command(mihomo, "-t", "-d", dir, "-f", mhPath).CombinedOutput(); err != nil {
				t.Fatalf("official mihomo -t failed for %s tun=%v: %v\n%s", routing, tun, err, out)
			}
		}
	}

	// Verify official Mihomo parses our base64 subscription containing both vmess:// and NEP-408 tuic://!
	provDir := t.TempDir()
	if err = os.WriteFile(filepath.Join(provDir, "sub.b64"), b64Res.Content, 0600); err != nil {
		t.Fatal(err)
	}
	provYAML := []byte("mixed-port: 7890\nproxy-providers:\n  p:\n    type: file\n    path: ./sub.b64\nproxy-groups:\n  - name: PROXY\n    type: select\n    use:\n      - p\nrules:\n  - MATCH,PROXY\n")
	provPath := filepath.Join(provDir, "prov.yaml")
	if err = os.WriteFile(provPath, provYAML, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(mihomo, "-t", "-d", provDir, "-f", provPath).CombinedOutput(); err != nil {
		t.Fatalf("official mihomo rejected base64 vmess+tuic subscription: %v\n%s", err, out)
	}
}
