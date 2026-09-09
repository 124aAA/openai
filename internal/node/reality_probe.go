package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Cloudflare's published proxy networks, verified 2026-09-09:
// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
// This is a known-provider exclusion, not a complete shared-CDN detector.
var realityExcludedPrefixes = func() []netip.Prefix {
	var result []netip.Prefix
	for _, cidr := range strings.Fields(`173.245.48.0/20 103.21.244.0/22 103.22.200.0/22
103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14
172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32
2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`) {
		result = append(result, netip.MustParsePrefix(cidr))
	}
	return result
}()

func excludedRealityHost(host string) error {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, suffix := range []string{"cloudflare.com", "cloudflare.net", "cloudflare-dns.com", "cloudflareclient.com", "one.one.one.one", "workers.dev", "pages.dev", "cfargotunnel.com", "r2.dev", "r2.cloudflarestorage.com"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return fmt.Errorf("REALITY 目标 %s 已排除：Cloudflare/共享代理服务可能被借道消耗流量", host)
		}
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		ip = ip.WithZone("").Unmap()
		// Public Cloudflare resolver endpoints are outside its proxy-network list.
		if ip.String() == "1.1.1.1" || ip.String() == "1.0.0.1" {
			return fmt.Errorf("REALITY 目标 %s 是已排除的 Cloudflare DNS 服务", ip)
		}
		for _, prefix := range realityExcludedPrefixes {
			if prefix.Contains(ip) {
				return fmt.Errorf("REALITY 目标地址 %s 命中已排除的 Cloudflare 网段", ip)
			}
		}
	}
	return nil
}

// RealityTargetPolicy is usable offline and does not invalidate stored identities.
func RealityTargetPolicy(r *Reality) error {
	if r == nil {
		return errors.New("缺少 REALITY 参数")
	}
	host, _, e := net.SplitHostPort(r.Target)
	if e != nil {
		return errors.New("REALITY 目标应为主机:端口")
	}
	if e = excludedRealityHost(r.ServerName); e != nil {
		return e
	}
	return excludedRealityHost(host)
}

func resolveReality(ctx context.Context, host string) ([]net.IPAddr, error) {
	return resolveRealityWith(ctx, host, net.DefaultResolver.LookupCNAME, net.DefaultResolver.LookupIPAddr)
}

func resolveRealityWith(ctx context.Context, host string, lookupCNAME func(context.Context, string) (string, error), lookupIP func(context.Context, string) ([]net.IPAddr, error)) ([]net.IPAddr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		return []net.IPAddr{{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}}, nil
	}
	cname, e := lookupCNAME(ctx, host)
	if e != nil {
		return nil, e
	}
	if e = excludedRealityHost(cname); e != nil {
		return nil, e
	}
	return lookupIP(ctx, host)
}

// ProbeReality measures DNS + TCP + verified TLS, never application throughput.
func ProbeReality(r *Reality) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	d := &net.Dialer{Timeout: 2 * time.Second}
	return probeReality(ctx, r, resolveReality, d.DialContext, nil)
}

func probeReality(ctx context.Context, r *Reality, resolve func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (time.Duration, error) {
	started := time.Now()
	if e := RealityTargetPolicy(r); e != nil {
		return 0, e
	}
	host, port, _ := net.SplitHostPort(r.Target)
	ips, e := resolve(ctx, host)
	if e != nil {
		return 0, fmt.Errorf("目标 DNS/排除检查失败：%w", e)
	}
	if len(ips) == 0 {
		return 0, errors.New("目标没有可用 IP 地址")
	}
	for _, ip := range ips {
		if e = excludedRealityHost(ip.String()); e != nil {
			return 0, e
		}
	}
	// Dial only the addresses just checked; do not resolve the hostname again.
	// Alternate families so several broken IPv4 routes cannot starve IPv6.
	var v4, v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	ips = nil
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			ips = append(ips, v4[i])
		}
		if i < len(v6) {
			ips = append(ips, v6[i])
		}
	}
	var raw net.Conn
	for _, ip := range ips {
		raw, e = dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			break
		}
	}
	if e != nil {
		return 0, fmt.Errorf("目标 TCP 连接失败：%w", e)
	}
	c := tls.Client(raw, &tls.Config{ServerName: r.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	defer c.Close()
	if e = c.HandshakeContext(ctx); e != nil {
		return 0, fmt.Errorf("目标 TLS 握手失败（检查网络、SNI、证书）：%w", e)
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		return 0, errors.New("目标未协商 HTTP/2")
	}
	return time.Since(started), nil
}
