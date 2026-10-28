package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func deviceFixture(t *testing.T) (State, DeviceProfile) {
	t.Helper()
	s := fixture(t)
	s.Nodes[0].ID = "1111111111111111"
	s.Nodes[0].Users = append(s.Nodes[0].Users, NewUser("另一台设备", "reality"))
	h := hyFixture(t).Nodes[0]
	h.ID = "3333333333333333"
	h.Users = append(h.Users, NewUser("另一台设备", "hysteria2"))
	ss := ssFixture()
	ss.ID = "5555555555555555"
	s.Nodes = append(s.Nodes, h, ss)
	p := DeviceProfile{ID: "7777777777777777", Name: "我的手机 / # : true"}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		n.Name = []string{"重名 / 中文", "重名", "独立 : true #"}[i]
		n.Users[0].Name = []string{"特殊 : true #", "中文 / 特殊 : true #", "手机 / 特殊 #"}[i]
		n.Users[1].Name = "另一台 / #"
		n.Tags = []string{"手机", "旅途"}
		n.ConnectPort = endpointPort(30000 + i)
		n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "v6", Host: "2001:0db8::9", Port: 31000 + i}}
		p.Bindings = append(p.Bindings, DeviceBinding{NodeID: n.ID, UserID: n.Users[0].ID, EndpointID: "v6"})
	}
	if err := s.Validate(); err != nil {
		t.Fatal("invalid device test fixture", err)
	}
	return s, p
}

func TestDeviceExportExplicitCredentialsEndpointsUniqueNamesAndOrdering(t *testing.T) {
	s, p := deviceFixture(t)
	before := s.Clone()
	for _, format := range []string{"uri", "base64", "sing-box", "sing-box-outbounds", "mihomo", "provider"} {
		t.Run(format, func(t *testing.T) {
			version := "1.14.0"
			if format == "mihomo" || format == "provider" {
				version = "1.19.30"
			}
			r, err := ExportDeviceProfile(s, p, format, version, false)
			if err != nil {
				t.Fatal(err)
			}
			data := r.Content
			if format == "base64" {
				data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, n := range s.Nodes {
				if bytes.Contains(data, []byte(n.Users[1].Password)) && n.Users[1].Password != "" || bytes.Contains(data, []byte(n.Users[1].UUID)) && n.Users[1].UUID != "" {
					t.Fatal("unselected credential leaked")
				}
				if n.Reality != nil && bytes.Contains(data, []byte(n.Reality.PrivateKey)) || n.Certificate != nil && bytes.Contains(data, []byte(n.Certificate.KeyPEM)) {
					t.Fatal("server key leaked")
				}
			}
			if format == "uri" || format == "base64" {
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				seen := map[string]bool{}
				if len(lines) != 3 {
					t.Fatal("wrong binding count")
				}
				for i, line := range lines {
					u, err := url.Parse(line)
					if err != nil || u.Hostname() != "2001:0db8::9" || u.Port() != []string{"31000", "31001", "31002"}[i] || seen[u.Fragment] {
						t.Fatal("IPv6, NAT external port or unique label was lost")
					}
					seen[u.Fragment] = true
				}
			} else if format == "mihomo" || format == "provider" {
				var doc struct{ Proxies []map[string]any }
				if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Proxies) != 3 {
					t.Fatal("invalid YAML collection", err)
				}
				seen := map[string]bool{}
				for _, proxy := range doc.Proxies {
					name := proxy["name"].(string)
					if seen[name] || proxy["server"] != "2001:0db8::9" {
						t.Fatal("display-name collision or wrong endpoint")
					}
					seen[name] = true
				}
			} else {
				var doc struct{ Outbounds []map[string]any }
				if err := json.Unmarshal(data, &doc); err != nil || len(doc.Outbounds) < 3 {
					t.Fatal("invalid JSON collection", err)
				}
				seen := map[string]bool{}
				for _, out := range doc.Outbounds {
					tag := out["tag"].(string)
					if seen[tag] || out["type"] == "direct" {
						t.Fatal("tag collision or hidden direct")
					}
					seen[tag] = true
				}
			}
			// Reverse every source collection; stable IDs, never first user,
			// determine the output. Ordered fallback is tested separately.
			reversed := s.Clone()
			for i := range reversed.Nodes {
				reversed.Nodes[i].Users[0], reversed.Nodes[i].Users[1] = reversed.Nodes[i].Users[1], reversed.Nodes[i].Users[0]
			}
			reversed.Nodes[0], reversed.Nodes[2] = reversed.Nodes[2], reversed.Nodes[0]
			q := p
			q.Bindings = append([]DeviceBinding(nil), p.Bindings...)
			q.Bindings[0], q.Bindings[2] = q.Bindings[2], q.Bindings[0]
			again, err := ExportDeviceProfile(reversed, q, format, version, false)
			if err != nil || !bytes.Equal(r.Content, again.Content) {
				t.Fatal("source order changed stable export", err)
			}
		})
	}
	if !reflect.DeepEqual(s, before) {
		t.Fatal("read-only export mutated State")
	}
}

func TestDeviceProfilesRefuseImplicitCredentialAndDanglingReferences(t *testing.T) {
	s, p := deviceFixture(t)
	for name, change := range map[string]func(*DeviceProfile){
		"missing user":   func(p *DeviceProfile) { p.Bindings[0].UserID = "" },
		"user name":      func(p *DeviceProfile) { p.Bindings[0].UserID = s.Nodes[0].Users[0].Name },
		"wrong user":     func(p *DeviceProfile) { p.Bindings[0].UserID = "ffffffffffffffff" },
		"wrong node":     func(p *DeviceProfile) { p.Bindings[0].NodeID = "ffffffffffffffff" },
		"wrong endpoint": func(p *DeviceProfile) { p.Bindings[0].EndpointID = "missing" },
		"duplicate":      func(p *DeviceProfile) { p.Bindings = append(p.Bindings, p.Bindings[0]) },
		"empty":          func(p *DeviceProfile) { p.Bindings = nil },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			q.Bindings = append([]DeviceBinding(nil), p.Bindings...)
			change(&q)
			if err := ValidateDeviceProfile(s, q); err == nil {
				t.Fatal("invalid saved binding accepted")
			}
			if _, err := ExportDeviceProfile(s, q, "uri", "", false); err == nil {
				t.Fatal("invalid binding silently exported another user")
			}
		})
	}
	q := p
	q.Bindings = []DeviceBinding{p.Bindings[0], p.Bindings[0]}
	q.Bindings[0].EndpointID, q.Bindings[1].EndpointID = "", "default"
	if ValidateDeviceProfile(s, q) == nil {
		t.Fatal("default endpoint aliases allowed duplicate bindings")
	}
	p.Disabled = true
	s.Nodes = nil
	if err := ValidateDeviceProfile(s, p); err != nil {
		t.Fatal("disabled profile lost recoverable historical bindings", err)
	}
	if _, err := ExportDeviceProfile(s, p, "uri", "", false); err == nil {
		t.Fatal("disabled device exported")
	}
}

func TestDeviceTagFilterNeverAddsCredentialsAndDisabledNodeCanBeSaved(t *testing.T) {
	s, p := deviceFixture(t)
	s.Nodes[0].Tags = []string{"chosen"}
	p.NodeTags = []string{"chosen"}
	r, err := ExportDeviceProfile(s, p, "uri", "", false)
	if err != nil || len(r.NodeIDs) != 1 || r.NodeIDs[0] != s.Nodes[0].ID {
		t.Fatal("tag filter selected wrong nodes", err)
	}
	p.NodeTags = []string{"none"}
	if _, err := ExportDeviceProfile(s, p, "uri", "", false); err == nil {
		t.Fatal("empty selection became an empty client group")
	}
	p.NodeTags = nil
	s.Nodes[0].Enabled = false
	if err := ValidateDeviceProfile(s, p); err != nil {
		t.Fatal("profile prevented node stop", err)
	}
	if _, err := ExportDeviceProfile(s, p, "uri", "", false); err == nil {
		t.Fatal("disabled selected node exported")
	}
}

func TestDeviceClientStrategiesVersionGatesAndBuiltinRules(t *testing.T) {
	s, p := deviceFixture(t)
	p.Strategy, p.TestURL = "auto", "https://controlled.example.test/health"
	for _, version := range []string{"1.14.0", "1.14.3"} {
		r, err := ExportDeviceProfile(s, p, "sing-box", version, false)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.Unmarshal(r.Content, &doc)
		groups := doc["outbounds"].([]any)
		group := groups[len(groups)-1].(map[string]any)
		if group["type"] != "urltest" || group["interval"] != "300s" || group["tolerance"] != float64(50) || group["timeout"] != nil || group["interrupt_exist_connections"] != false {
			t.Fatal("sing-box URLTest used guessed Mihomo fields")
		}
	}
	p.TimeoutMS = 5000
	if _, err := ExportDeviceProfile(s, p, "sing-box", "1.14.3", false); err == nil {
		t.Fatal("unsupported sing-box timeout accepted")
	}
	p.TimeoutMS = 0
	if _, err := ExportDeviceProfile(s, p, "sing-box", "1.15.0", false); err == nil {
		t.Fatal("untested sing-box version guessed")
	}
	if _, err := ExportDeviceProfile(s, p, "mihomo", "1.19.31", false); err == nil {
		t.Fatal("untested Mihomo version guessed")
	}
	p.Strategy, p.Routing = "fallback", "basic"
	p.Bindings[0], p.Bindings[2] = p.Bindings[2], p.Bindings[0]
	if _, err := ExportDeviceProfile(s, p, "sing-box", "1.14.0", false); err == nil {
		t.Fatal("sing-box was given a fake fallback strategy")
	}
	r, err := ExportDeviceProfile(s, p, "mihomo", "1.19.30", false)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal(r.Content, &doc); err != nil {
		t.Fatal(err)
	}
	group := doc["proxy-groups"].([]any)[0].(map[string]any)
	if group["type"] != "fallback" || group["empty-fallback"] != "REJECT" || group["timeout"] != 5000 || group["tolerance"] != nil || group["proxies"].([]any)[0] != deviceExportName(s.Nodes[2], s.Nodes[2].Users[0], p.Bindings[0]) {
		t.Fatal("fallback priority, fail-closed behavior or client timeout lost")
	}
	if len(doc["rules"].([]any)) != 5 || r.RuleSource.ID != "private-rfc1918-rfc4193-v1" || !strings.Contains(r.RuleSource.CacheStatus, "no external") {
		t.Fatal("minimal built-in split source or cache provenance lost")
	}
	p.Strategy, p.TestURL = "manual", ""
	r, err = ExportDeviceProfile(s, p, "sing-box", "1.14.3", false)
	if err != nil || !bytes.Contains(r.Content, []byte(`"DIRECT"`)) || !bytes.Contains(r.Content, []byte(`"fc00::/7"`)) {
		t.Fatal("explicit basic split missing", err)
	}
}

func TestDeviceHY2LossExplicitAndNoInternalEgressCredentialExport(t *testing.T) {
	s, p := deviceFixture(t)
	s.Nodes[1].HY2 = &HY2Performance{Client: &HY2Transport{QUIC: &HY2QUIC{IdleTimeout: "45s"}}}
	s.Egresses = []Egress{{ID: "9999999999999999", Name: "internal", Protocol: "socks", Server: "internal.test", Port: 1080, Socks: &RemoteSOCKS{Username: "not-for-phone", Password: "internal-landing-secret"}}}
	s.Nodes[0].EgressID = s.Egresses[0].ID
	for _, format := range []string{"uri", "base64", "mihomo", "provider"} {
		version := "1.19.30"
		if format == "uri" || format == "base64" {
			version = ""
		}
		if _, err := ExportDeviceProfile(s, p, format, version, false); err == nil {
			t.Fatal("loss of HY2 selection was silent", format)
		}
		r, err := ExportDeviceProfile(s, p, format, version, true)
		if err != nil || len(r.Warnings) == 0 {
			t.Fatal("explicit lossy export missing warning", format, err)
		}
		if bytes.Contains(r.Content, []byte("internal-landing-secret")) || bytes.Contains(r.Content, []byte("not-for-phone")) || bytes.Contains(r.Content, []byte("internal.test")) {
			t.Fatal("internal path authentication leaked")
		}
	}
	r, err := ExportDeviceProfile(s, p, "sing-box", "1.14.0", false)
	if err != nil || !bytes.Contains(r.Content, []byte(`"idle_timeout": "45s"`)) {
		t.Fatal("complete sing-box configuration lost HY2 fields", err)
	}
}

func TestDeviceMihomoAutoDefaultRefusalAndExplicitDegradation(t *testing.T) {
	s, p := deviceFixture(t)
	p.Strategy, p.TestURL = "auto", "https://controlled.example.test/health"
	if _, err := ExportDeviceProfile(s, p, "mihomo", "1.19.30", false); err == nil || !strings.Contains(err.Error(), "首成员容差缺陷") {
		t.Fatal("known fixed-version tolerance defect was not refused by default", err)
	}
	// Collections contain no URLTest group; they must not acquire the full
	// configuration restriction or silently claim to preserve its policy.
	for _, format := range []string{"uri", "base64", "provider"} {
		if r, err := ExportDeviceProfile(s, p, format, "1.19.30", false); err != nil || len(r.Content) == 0 || len(r.Warnings) == 0 {
			t.Fatal("collection export was incorrectly blocked by a group defect", format, err)
		}
	}
	p.AllowDegradedAuto = true
	for attempt := 0; attempt < 2; attempt++ {
		r, err := ExportDeviceProfile(s, p, "mihomo", "1.19.30", false)
		if err != nil || !strings.Contains(strings.Join(r.Warnings, "\n"), "不能保证容差防抖") {
			t.Fatal("explicit opt-in did not retain a warning on every export", err)
		}
		var doc map[string]any
		if err = yaml.Unmarshal(r.Content, &doc); err != nil {
			t.Fatal(err)
		}
		group := doc["proxy-groups"].([]any)[0].(map[string]any)
		if group["type"] != "url-test" || group["tolerance"] != 50 {
			t.Fatal("degraded opt-in altered the real client field")
		}
	}
	encoded, err := json.Marshal(p)
	if err != nil || !bytes.Contains(encoded, []byte(`"allow_degraded_auto":true`)) {
		t.Fatal("explicit acceptance did not survive serialization", err)
	}
	for _, strategy := range []string{"manual", "fallback"} {
		q := p
		q.Strategy = strategy
		if err := ValidateDeviceProfile(s, q); err == nil || !strings.Contains(err.Error(), "只允许用于 auto") {
			t.Fatal("degradation flag was accepted outside auto", strategy, err)
		}
	}
	p.AllowDegradedAuto = false
	encoded, err = json.Marshal(p)
	if err != nil || bytes.Contains(encoded, []byte("allow_degraded_auto")) {
		t.Fatal("false opt-in should remain absent from the saved profile", err)
	}
}

func TestDeviceProfileBoundsAndProfileIdentity(t *testing.T) {
	s, p := deviceFixture(t)
	for name, mutate := range map[string]func(*DeviceProfile){
		"interval":           func(p *DeviceProfile) { p.IntervalSeconds = 1 },
		"timeout":            func(p *DeviceProfile) { p.TimeoutMS = 20000 },
		"negative tolerance": func(p *DeviceProfile) { p.ToleranceMS = -1 },
		"url credentials":    func(p *DeviceProfile) { p.TestURL = "https://secret:secret@example.test/health" },
		"public default":     func(p *DeviceProfile) { p.TestURL = "" },
		"http":               func(p *DeviceProfile) { p.TestURL = "http://controlled.test/health" },
		"url port":           func(p *DeviceProfile) { p.TestURL = "https://controlled.test:65536/health" },
		"url fragment":       func(p *DeviceProfile) { p.TestURL = "https://controlled.test/health#secret" },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			q.Strategy, q.TestURL = "auto", "https://controlled.test/health"
			mutate(&q)
			if ValidateDeviceProfile(s, q) == nil {
				t.Fatal("invalid automation accepted")
			}
		})
	}
	s.Devices = []DeviceProfile{p, p}
	if ValidateDeviceProfiles(s) == nil {
		t.Fatal("duplicate profile identity accepted")
	}
	s.Devices[1].ID = "8888888888888888"
	if ValidateDeviceProfiles(s) == nil {
		t.Fatal("duplicate display name accepted")
	}
	s.Devices[1].Name = "second"
	if err := ValidateDeviceProfiles(s); err != nil {
		t.Fatal(err)
	}
}
