package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRealityTargetExclusions(t *testing.T) {
	for _, host := range []string{"cloudflare.com", "WWW.CloudFlare.COM.", "x.workers.dev", "x.pages.dev", "104.16.1.1", "2606:4700::1", "::ffff:104.16.1.1", "one.one.one.one", "1.1.1.1", "1.0.0.1", "::ffff:1.1.1.1"} {
		for _, sniOnly := range []bool{false, true} {
			r := &Reality{ServerName: "www.example.com", Target: "www.example.com:443"}
			if sniOnly {
				r.ServerName = host
			} else {
				r.Target = net.JoinHostPort(host, "443")
			}
			if RealityTargetPolicy(r) == nil {
				t.Fatal("not excluded", host, sniOnly)
			}
		}
	}
	for _, host := range []string{"notcloudflare.com", "cloudflare.com.example.org", "127.0.0.1", "www.apple.com", "2001:db8::1"} {
		if e := RealityTargetPolicy(&Reality{ServerName: host, Target: net.JoinHostPort(host, "443")}); e != nil {
			t.Fatal(e)
		}
	}
	if RealityTargetPolicy(nil) == nil || RealityTargetPolicy(&Reality{Target: "bad"}) == nil {
		t.Fatal("invalid target accepted")
	}
}

func TestRealityCNAMEDenyAndAlternateFamily(t *testing.T) {
	lookupCNAME := func(context.Context, string) (string, error) { return "alias.pages.dev.", nil }
	lookupIP := func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("excluded CNAME reached address lookup")
		return nil, nil
	}
	if _, e := resolveRealityWith(context.Background(), "custom.example.org", lookupCNAME, lookupIP); e == nil {
		t.Fatal("CNAME exclusion bypassed")
	}
	var calls []string
	resolve := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}, {IP: net.ParseIP("192.0.2.3")}, {IP: net.ParseIP("2001:db8::1")}}, nil
	}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		calls = append(calls, address)
		return nil, errors.New("unreachable")
	}
	_, _ = probeReality(context.Background(), &Reality{ServerName: "example.com", Target: "example.com:443"}, resolve, dial, nil)
	if len(calls) != 4 || calls[1] != "[2001:db8::1]:443" {
		t.Fatal("IPv6 fallback starved by IPv4 addresses", calls)
	}
}

func TestRealityProbeHandshakeHonorsDeadline(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	resolve := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := probeReality(ctx, &Reality{ServerName: "example.com", Target: "example.com:443"}, resolve, dial, nil)
	if e == nil || !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("TLS handshake ignored deadline", e)
	}
}

func TestRealityDNSExclusionChecksEveryAddressBeforeDial(t *testing.T) {
	r := &Reality{ServerName: "alias.example.org", Target: "alias.example.org:443"}
	for _, blocked := range []string{"104.16.1.1", "2606:4700::1", "::ffff:104.16.1.1"} {
		resolve := func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP(blocked)}}, nil
		}
		dial := func(context.Context, string, string) (net.Conn, error) {
			t.Error("dial before policy completed")
			return nil, errors.New("unexpected")
		}
		if _, e := probeReality(context.Background(), r, resolve, dial, nil); e == nil || !strings.Contains(e.Error(), "Cloudflare") {
			t.Fatal(e)
		}
	}
	resolve := func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("DNS unavailable") }
	if _, e := probeReality(context.Background(), r, resolve, nil, nil); e == nil || !strings.Contains(e.Error(), "DNS") {
		t.Fatal(e)
	}
}

func TestRealityProbeVerifiesTLSAndDialsCheckedIP(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-sni", "untrusted", "no-h2", "old-tls", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			server.EnableHTTP2 = mode != "no-h2"
			if mode == "old-tls" {
				server.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
			}
			server.StartTLS()
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			if mode == "untrusted" {
				pool = x509.NewCertPool()
			}
			host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			r := &Reality{ServerName: "example.com", Target: "alias.example.org:" + port}
			// httptest's certificate includes example.com, independently of the dial hostname.
			if mode == "wrong-sni" {
				r.ServerName = "wrong.invalid"
			}
			resolve := func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: net.ParseIP(host)}}, nil }
			d := &net.Dialer{}
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != server.Listener.Addr().String() {
					t.Error("unchecked hostname dialed", address)
				}
				return d.DialContext(ctx, network, address)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			duration, e := probeReality(ctx, r, resolve, dial, pool)
			if mode == "valid" {
				if e != nil || duration <= 0 {
					t.Fatal(duration, e)
				}
			} else if e == nil {
				t.Fatal("bad TLS accepted", mode)
			}
		})
	}
}
