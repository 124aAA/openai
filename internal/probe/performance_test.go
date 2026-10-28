package probe

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHY2PrivateProfilePreservesPerformanceAndRejectsForeignFields(t *testing.T) {
	base := `{"type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":443,"password":"test-secret","tls":{"enabled":true,"server_name":"example.invalid"}`
	valid := `,"up_mbps":12,"down_mbps":34,"bbr_profile":"conservative","stream_receive_window":1048576,"connection_receive_window":4194304,"idle_timeout":"40s","keep_alive_period":"10s","max_concurrent_streams":64,"initial_packet_size":1280,"disable_path_mtu_discovery":false,"brutal_debug":false,"disable_chrome_parrot":false}`
	for _, version := range []string{"1.14.0", "1.14.3"} {
		p, err := NewProfile("hy2-node", version, []byte(base+valid))
		if err != nil {
			t.Fatal(err)
		}
		b, err := SandboxConfig(p, 10001)
		if err != nil {
			t.Fatal(err)
		}
		var c struct{ Outbounds []map[string]any }
		if err = json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		o := c.Outbounds[0]
		if len(c.Outbounds) != 1 || o["up_mbps"] != float64(12) || o["down_mbps"] != float64(34) || o["disable_chrome_parrot"] != false || o["connection_receive_window"] != float64(4194304) {
			t.Fatal("private profile lost explicit performance settings")
		}
	}
	for _, fields := range []string{
		`,"up_mbps":1}`, `,"up_mbps":0,"down_mbps":1}`, `,"up_mbps":1,"down_mbps":1000001}`,
		`,"bbr_profile":"invented"}`, `,"stream_receive_window":4194304,"connection_receive_window":1048576}`,
		`,"idle_timeout":"10s","keep_alive_period":"20s"}`, `,"max_concurrent_streams":4097}`,
		`,"initial_packet_size":9000}`, `,"http2":{"max_concurrent_streams":10}}`, `,"quic":{"idle_timeout":"30s"}}`,
		`,"detour":"direct"}`, `,"up_mbps":1,"up_mbps":2,"down_mbps":1}`,
	} {
		if _, err := NewProfile("hy2", "1.14.3", []byte(base+fields)); err == nil {
			t.Fatalf("unsafe HY2 profile accepted: %s", fields)
		}
	}
	if _, err := NewProfile("hy2", "1.15.0", []byte(base+valid)); err == nil {
		t.Fatal("untested core line accepted")
	}
	ss := strings.Replace(string(testProfile(t).Outbound), `"tag":"proxy"`, `"tag":"proxy","bbr_profile":"conservative"`, 1)
	if _, err := NewProfile("ss", "1.14.3", []byte(ss)); err == nil {
		t.Fatal("QUIC parameters accepted on TCP/SS")
	}
}

func performanceReport(t *testing.T, digest string) Report {
	t.Helper()
	o := testOptions("https://example.invalid/object")
	o.Path, o.NodeID, o.ConfigSHA256 = "client-proxy", "hy2-node", digest
	o, err := NormalizeOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	v, code := 10.0, 200
	r := Report{Version: 1, Source: "qingnode-automatic-probe", Status: "completed", StartedAt: time.Now().UTC(), Conditions: conditions(o), DNS: Stage{Status: "unknown"}, Connection: Stage{Status: "unknown"}, TLS: Stage{Status: "unknown"}}
	r.FinishedAt = r.StartedAt.Add(time.Second)
	for i := 1; i <= o.Samples; i++ {
		r.Samples = append(r.Samples, Sample{Sequence: i, Kind: "idle", Status: "success", HTTPStatus: &code, ElapsedMS: &v})
	}
	r.Statistics = statistics(r.Samples)
	if err := ValidateReport(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestControlledComparisonAllowsOnlyDeclaredConfigDifference(t *testing.T) {
	one, two := strings.Repeat("a", 64), strings.Repeat("b", 64)
	a, b := performanceReport(t, one), performanceReport(t, two)
	change := ControlledChange{1, strings.Repeat("c", 64), "hy2-node", one, two, strings.Repeat("d", 64), strings.Repeat("e", 64)}
	if Compare(a, b).Comparable {
		t.Fatal("ordinary comparison loosened")
	}
	c := CompareControlled(a, b, change)
	if !c.Comparable || c.Version != 2 || c.ControlledChange == nil || len(c.Limitations) < 4 {
		t.Fatalf("valid controlled comparison rejected: %+v", c)
	}
	if a.Conditions.ConfigSHA256 != one || b.Conditions.ConfigSHA256 != two {
		t.Fatal("raw report mutated")
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Conditions.Initiator = "other-machine" },
		func(r *Report) { r.Conditions.NodeID = "other-node" },
		func(r *Report) { r.Conditions.ConfigSHA256 = strings.Repeat("f", 64) },
		func(r *Report) { r.Conditions.Limits.MaxPayloadBytes++ },
		func(r *Report) { r.Conditions.CoreVersion = "1.14.3" },
		func(r *Report) { r.Status = "canceled" },
		func(r *Report) {
			r.StartedAt = r.StartedAt.Add(25 * time.Hour)
			r.FinishedAt = r.StartedAt.Add(time.Second)
		},
	} {
		x := b
		mutate(&x)
		if CompareControlled(a, x, change).Comparable {
			t.Fatal("unrelated difference accepted")
		}
	}
	bad := change
	bad.Version = 2
	if CompareControlled(a, b, bad).Comparable {
		t.Fatal("unknown plan version accepted")
	}
	bad = change
	bad.PlanSHA256 = ""
	if CompareControlled(a, b, bad).Comparable {
		t.Fatal("missing plan binding accepted")
	}
	// Server-only performance changes retain the same exported client hash.
	b = a
	change.AfterClientSHA256 = one
	if !CompareControlled(a, b, change).Comparable {
		t.Fatal("server-only change rejected")
	}
	change.AfterServerSHA256 = change.BeforeServerSHA256
	if CompareControlled(a, b, change).Comparable {
		t.Fatal("no-op plan accepted as a tuning change")
	}
}
