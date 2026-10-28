package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dnsPort(v int) *int { return &v }

func TestDNSDefaultRenderingIsIdenticalAndOnlyServerChanges(t *testing.T) {
	expected := M{"servers": []any{M{"type": "local", "tag": "system"}}}
	if !reflect.DeepEqual(ProjectDNS(nil), expected) || !reflect.DeepEqual(ProjectDNS(&DNSSettings{Type: "system"}), expected) {
		t.Fatal("legacy default DNS rendering changed")
	}
	s := fixture(t)
	s.DNS = nil
	dir := t.TempDir()
	original, e := Server(s, dir)
	if e != nil {
		t.Fatal(e)
	}
	clientBefore := Client(s.Nodes[0], s.Nodes[0].Users[0], 1080)
	s.DNS = &DNSSettings{Type: "system"}
	explicit, e := Server(s, dir)
	if e != nil || !bytes.Equal(original, explicit) {
		t.Fatal("explicit system DNS changed legacy server bytes", e)
	}
	s.DNS = &DNSSettings{Type: "udp", Server: "127.0.0.1", Port: dnsPort(5353)}
	changed, e := Server(s, dir)
	if e != nil {
		t.Fatal(e)
	}
	var before, after M
	json.Unmarshal(original, &before)
	json.Unmarshal(changed, &after)
	after["dns"] = before["dns"]
	if !reflect.DeepEqual(before, after) {
		t.Fatal("DNS selection changed non-DNS server fields")
	}
	if !reflect.DeepEqual(clientBefore, Client(s.Nodes[0], s.Nodes[0].Users[0], 1080)) {
		t.Fatal("server DNS silently changed client bootstrap configuration")
	}
	got := ProjectDNS(s.DNS)["servers"].([]any)[0].(M)
	if got["type"] != "udp" || got["server"] != "127.0.0.1" || got["server_port"] != 5353 || got["tag"] != "system" {
		t.Fatal("server resolver interface mismatched", got)
	}
	withoutPort := ProjectDNS(&DNSSettings{Type: "udp", Server: "::1"})["servers"].([]any)[0].(M)
	if _, exists := withoutPort["server_port"]; exists {
		t.Fatal("omitted default resolver port was materialized as an explicit choice")
	}
}

func TestDNSSettingsRejectUnsupportedAndAmbiguousResolvers(t *testing.T) {
	for _, d := range []*DNSSettings{nil, {Type: "system"}, {Type: "udp", Server: "127.0.0.1"}, {Type: "udp", Server: "::1", Port: dnsPort(65535)}} {
		if e := ValidateDNS(d); e != nil {
			t.Fatalf("supported resolver rejected: %#v %v", d, e)
		}
	}
	for _, d := range []*DNSSettings{{Type: ""}, {Type: "tcp", Server: "127.0.0.1"}, {Type: "https", Server: "https://example.com/dns-query"}, {Type: "system", Server: "127.0.0.1"}, {Type: "system", Port: dnsPort(53)}, {Type: "udp", Server: "dns.example.com"}, {Type: "udp", Server: "udp://127.0.0.1:53"}, {Type: "udp", Server: "[::1]"}, {Type: "udp", Server: "127.0.0.1", Port: dnsPort(0)}, {Type: "udp", Server: "127.0.0.1", Port: dnsPort(65536)}, {Type: "udp", Server: "127.0.0.1\n"}} {
		if e := ValidateDNS(d); e == nil {
			t.Fatalf("unsupported/ambiguous resolver accepted: %#v", d)
		}
	}
}

func TestDNSDiagnosticValidationRunsBeforeLookup(t *testing.T) {
	base := DNSDiagnosticOptions{Name: "controlled.invalid", Family: "ipv4", Samples: 1, Timeout: time.Second}
	cases := []DNSDiagnosticOptions{base, base, base, base, base, base, base, base, base, base, base}
	cases[0].Name = "127.0.0.1"
	cases[1].Name = "https://controlled.invalid"
	cases[2].Family = "auto"
	cases[3].Samples = 9
	cases[4].Samples = -1
	cases[5].Timeout = time.Nanosecond
	cases[6].Timeout = 11 * time.Second
	cases[7].Samples = 8
	cases[7].Timeout = 5 * time.Second
	cases[8].Expected = []string{"not-an-ip"}
	cases[9].Expected = make([]string, 33)
	for i := range cases[9].Expected {
		cases[9].Expected[i] = "192.0.2.1"
	}
	cases[10].Resolver = &DNSSettings{Type: "udp", Server: "resolver.invalid"}
	calls := 0
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}
	for _, o := range cases {
		if _, e := DiagnoseDNS(context.Background(), o, lookup); e == nil {
			t.Fatalf("invalid diagnosis accepted: %#v", o)
		}
	}
	if calls != 0 {
		t.Fatal("invalid diagnosis performed a lookup")
	}
}

// The controlled server constructs standard DNS packets itself, keeping these
// tests independent from public resolvers and external network availability.
func controlledDNSServer(t *testing.T, rcode uint16, ip4, ip6 net.IP, drop bool) (*DNSSettings, *atomic.Int32) {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			n, addr, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			count.Add(1)
			if drop {
				continue
			}
			if n < 17 {
				continue
			}
			end := 12
			for end < n && b[end] != 0 {
				size := int(b[end])
				end += 1 + size
			}
			end += 5
			if end > n {
				continue
			}
			qtype := binary.BigEndian.Uint16(b[end-4 : end-2])
			response := append([]byte(nil), b[:end]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180|rcode)
			for i := 6; i < 12; i++ {
				response[i] = 0
			}
			if rcode == 0 {
				var answer net.IP
				switch qtype {
				case 1:
					answer = ip4.To4()
				case 28:
					answer = ip6.To16()
				}
				if answer != nil {
					binary.BigEndian.PutUint16(response[6:8], 1)
					rr := []byte{0xc0, 0x0c, byte(qtype >> 8), byte(qtype), 0, 1, 0, 0, 0, 1, 0, byte(len(answer))}
					response = append(response, rr...)
					response = append(response, answer...)
				}
			}
			_, _ = c.WriteTo(response, addr)
		}
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("controlled DNS endpoint leaked")
		}
	})
	return &DNSSettings{Type: "udp", Server: "127.0.0.1", Port: dnsPort(c.LocalAddr().(*net.UDPAddr).Port)}, count
}

func TestDNSRealControlledUDPAnswersExpectedCIDRAndIPv6(t *testing.T) {
	resolver, count := controlledDNSServer(t, 0, net.ParseIP("192.0.2.42"), net.ParseIP("2001:db8::42"), false)
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			expected := []string{"192.0.2.0/24"}
			address := "192.0.2.42"
			if family == "ipv6" {
				expected = []string{"2001:db8::/32"}
				address = "2001:db8::42"
			}
			r, e := DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "controlled.invalid", Family: family, Resolver: resolver, Expected: expected, Samples: 2, Timeout: time.Second}, nil)
			if e != nil || r.Status != "completed" || r.Source != "qingnode-dns-diagnostic" || r.Initiator == "" || r.Version != 1 || len(r.Samples) != 2 {
				t.Fatalf("controlled UDP resolver failed: %#v %v", r, e)
			}
			for _, s := range r.Samples {
				if s.ErrorCategory != "" || s.Correct == nil || !*s.Correct || !reflect.DeepEqual(s.Addresses, []string{address}) || s.ElapsedMS < 0 {
					t.Fatalf("family/content check failed: %#v", s)
				}
			}
		})
	}
	if count.Load() < 4 {
		t.Fatal("diagnostic did not contact controlled UDP endpoint")
	}
}

func TestDNSWrongAnswerAndNXDOMAINAreDifferent(t *testing.T) {
	resolver, _ := controlledDNSServer(t, 0, net.ParseIP("198.51.100.9"), nil, false)
	r, e := DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "wrong.controlled.invalid", Resolver: resolver, Expected: []string{"192.0.2.0/24"}, Samples: 1, Timeout: time.Second}, nil)
	if e != nil || r.Status != "failed" || r.Samples[0].ErrorCategory != "dns_unexpected_answer" || r.Samples[0].Correct == nil || *r.Samples[0].Correct || len(r.Samples[0].Addresses) != 1 {
		t.Fatalf("wrong DNS content treated as network success: %#v %v", r, e)
	}
	nxdomain, _ := controlledDNSServer(t, 3, nil, nil, false)
	r, e = DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "missing.controlled.invalid", Resolver: nxdomain, Samples: 1, Timeout: time.Second}, nil)
	if e != nil || r.Status != "failed" || r.Samples[0].ErrorCategory != "dns_nxdomain_or_nodata" || r.Samples[0].Correct != nil || len(r.Samples[0].Addresses) != 0 {
		t.Fatalf("NXDOMAIN mistaken for content mismatch or zero elapsed: %#v %v", r, e)
	}
}

func TestDNSCancellationAndTimeoutKeepFailedSamples(t *testing.T) {
	resolver, _ := controlledDNSServer(t, 0, nil, nil, true)
	r, e := DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "timeout.controlled.invalid", Resolver: resolver, Samples: 1, Timeout: 30 * time.Millisecond}, nil)
	if e != nil || r.Status != "failed" || len(r.Samples) != 1 || r.Samples[0].ErrorCategory != "timeout" || r.Samples[0].Correct != nil {
		t.Fatalf("timeout was reported as success: %#v %v", r, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	r, e = DiagnoseDNS(ctx, DNSDiagnosticOptions{Name: "cancel.controlled.invalid", Resolver: resolver, Samples: 8, Timeout: time.Second}, nil)
	if e != nil || r.Status != "canceled" || len(r.Samples) != 1 || r.Samples[0].ErrorCategory != "canceled" || time.Since(start) > time.Second {
		t.Fatalf("cancellation retried all samples or passed: %#v %v", r, e)
	}
}

func TestDNSUnknownCorrectnessSmallSamplesAndAddressNormalization(t *testing.T) {
	calls := 0
	r, e := DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "controlled.invalid", Samples: 1}, func(_ context.Context, network, name string) ([]net.IP, error) {
		calls++
		if network != "ip4" || name != "controlled.invalid" {
			t.Error("lookup family/name differs", network, name)
		}
		return []net.IP{net.ParseIP("192.0.2.9"), net.ParseIP("::ffff:192.0.2.1"), net.ParseIP("192.0.2.9")}, nil
	})
	if e != nil || r.Status != "completed" || len(r.Samples) != 1 || calls != 1 || r.Samples[0].Correct != nil || !reflect.DeepEqual(r.Samples[0].Addresses, []string{"192.0.2.1", "192.0.2.9"}) {
		t.Fatalf("single sample invented correctness/aggregate or failed normalization: %#v %v", r, e)
	}
	if !strings.Contains(FormatDNSDiagnostic(r), "正确性未知") || len(r.Limitations) == 0 {
		t.Fatal("single sample concealed missing correctness evidence")
	}
	r, e = DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "controlled.invalid", Family: "ipv6", Expected: []string{"2001:db8::/32"}, Samples: 1}, func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	})
	if e != nil || r.Status != "failed" || len(r.Samples[0].Addresses) != 0 || r.Samples[0].Correct == nil || *r.Samples[0].Correct {
		t.Fatalf("wrong address family escaped requested filter: %#v %v", r, e)
	}
}

func TestDNSFailuresDoNotExposeResolverErrorsAndDoNotWriteHostFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf-sentinel")
	before := []byte("nameserver 192.0.2.1\n")
	os.WriteFile(path, before, 0600)
	r, e := DiagnoseDNS(context.Background(), DNSDiagnosticOptions{Name: "controlled.invalid", Samples: 1}, func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("resolver password=private-token vless://secret")
	})
	if e != nil || r.Status != "failed" || r.Samples[0].ErrorCategory != "dns_failed" {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte("private-token")) || bytes.Contains(b, []byte("vless://secret")) {
		t.Fatal("raw resolver errors leaked into report")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("DNS diagnostic wrote host resolver sentinel")
	}
}
