package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Run returns parameter errors directly. Operational failures are preserved in
// a report, including cancellation and timeout, so partial samples can be saved.
func Run(parent context.Context, input Options, deps Dependencies) (Report, error) {
	o, err := NormalizeOptions(input)
	if err != nil {
		return Report{}, err
	}
	if o.Path == "client-proxy" && deps.Transport == nil {
		return Report{}, errors.New("客户端经代理测试必须明确提供隔离代理连接；不会回落直连")
	}
	if o.Path == "client-proxy" && o.UDPAddress != "" && o.UDPProxyAddress == "" && deps.UDPProbe == nil {
		return Report{}, errors.New("客户端UDP测试必须明确提供代理转发路径")
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	r := Report{Version: ReportVersionFor(o), Source: "qingnode-automatic-probe", StartedAt: time.Now().UTC(), Status: "completed", Conditions: conditions(o), DNS: Stage{Status: "unknown"}, Connection: Stage{Status: "unknown"}, TLS: Stage{Status: "unknown"}, Samples: []Sample{}, Statistics: map[string]Statistics{}, Limitations: []string{
		"请求往返时间包含HTTPS请求、代理与目标处理；它不是独立的网络RTT。",
		"首字节时间从请求发起算起；独立的代理认证与握手耗时未知。",
		"完整网络流量包含TLS/HTTP头等开销，目前未知；字节硬上限只涵盖收到的HTTP内容与发送、收到的UDP内容。",
		"CPU占用百分比未知；能读取/proc时记录CPU累计计数与RSS内存。UDP内核计数属于本机网络空间总量，不能当成所选节点丢包。",
	}, Traffic: Traffic{Accounting: "HTTP内容与UDP内容；TLS/HTTP/代理封装开销未知"}}
	if o.ServerPathSHA256 != "" {
		r.Limitations = append(r.Limitations, ServerPathLimitation)
	}
	metric := deps.Metrics
	if metric == nil {
		metric = func() Metrics { return ReadMetrics(deps.MetricsPID) }
	}
	r.MetricsBefore = metric()
	finish := func() {
		r.FinishedAt = time.Now().UTC()
		r.MetricsAfter = metric()
		r.Statistics = statistics(r.Samples)
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				r.Status = "canceled"
			} else {
				r.Status = "timeout"
			}
			r.Errors = append(r.Errors, Failure{r.Status, "测试被取消或超过总时间预算，尚未完成"})
		}
		for k, s := range r.Statistics {
			if s.Values < 20 {
				r.Limitations = append(r.Limitations, k+" 的有效样本少于20个；p95只描述本次样本，不代表高置信结论。")
			}
		}
	}
	if o.Path == "local" {
		r.DNS.Status = "not-requested"
		r.Connection.Status = "not-requested"
		r.TLS.Status = "not-requested"
		r.Limitations = append(r.Limitations, "本机诊断不访问外部目标，也不验证代理可用性。")
		finish()
		return r, nil
	}
	u, _ := url.Parse(o.TargetURL)
	var addresses []net.IPAddr
	if o.Path == "client-proxy" {
		r.Limitations = append(r.Limitations, "经代理时看不到目标端域名解析及独立TCP/TLS阶段；失败可能同时涉及路由与认证。")
	} else {
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			addresses = []net.IPAddr{{IP: ip}}
			r.DNS.Status = "not-applicable"
		} else {
			resolver := deps.Resolve
			if resolver == nil {
				resolver = net.DefaultResolver.LookupIPAddr
			}
			start := time.Now()
			addresses, err = resolver(ctx, u.Hostname())
			v := milliseconds(time.Since(start))
			r.DNS.ElapsedMS = &v
			if err != nil {
				cat := errorCategory(ctx, err, false)
				if cat != "canceled" && cat != "timeout" {
					cat = "dns_failed"
				}
				r.DNS.Status = "failed"
				r.DNS.Category = cat
				r.DNS.Detail = "目标域名无法解析"
				r.Status = "failed"
				r.Errors = append(r.Errors, Failure{cat, r.DNS.Detail})
				finish()
				return r, nil
			}
			r.DNS.Status = "success"
		}
		filtered := addresses[:0]
		for _, a := range addresses {
			if (o.Family == "ipv4" && a.IP.To4() == nil) || (o.Family == "ipv6" && a.IP.To4() != nil) {
				continue
			}
			filtered = append(filtered, a)
		}
		addresses = filtered
		if len(addresses) == 0 {
			r.DNS.Status = "failed"
			r.DNS.Category = "address_family_unavailable"
			r.Status = "failed"
			r.Errors = append(r.Errors, Failure{"address_family_unavailable", "目标没有所要求的IPv4或IPv6地址"})
			finish()
			return r, nil
		}
	}
	transport, closeTransport := buildTransport(o, deps.Transport, u.Hostname(), addresses)
	defer closeTransport()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := 0; i < o.Samples; i++ {
		if ctx.Err() != nil {
			break
		}
		s, conn, tlsStage := request(ctx, client, o, "idle", i+1, 0)
		r.Samples = append(r.Samples, s)
		if o.Path != "client-proxy" && i == 0 {
			r.Connection = conn
			r.TLS = tlsStage
		}
		if s.Status != "success" {
			r.Status = "failed"
		}
	}
	if o.Mode == "download" && ctx.Err() == nil {
		budget := o.MaxBytes
		if o.UDPAddress != "" {
			budget -= int64(o.Samples) * 129
		}
		if budget < 1 {
			r.Status = "failed"
			r.Errors = append(r.Errors, Failure{"byte_limit", "预留UDP流量后，已无剩余HTTP下载额度"})
		} else {
			var mu sync.Mutex
			var workers sync.WaitGroup
			var started sync.WaitGroup
			var activeDownloads atomic.Int64
			active := make(chan struct{})
			loadDone := make(chan struct{})
			// One bounded GET per worker. Every GET has its own fixed share of
			// the total budget, preventing concurrent requests from overspending.
			for i := 0; i < o.Concurrency; i++ {
				workers.Add(1)
				started.Add(1)
				allocation := budget / int64(o.Concurrency)
				if int64(i) < budget%int64(o.Concurrency) {
					allocation++
				}
				go func(seq int, cap int64) {
					defer workers.Done()
					if cap == 0 {
						started.Done()
						return
					}
					activeDownloads.Add(1)
					started.Done()
					s, _, _ := request(ctx, client, o, "download", seq, cap)
					activeDownloads.Add(-1)
					mu.Lock()
					r.Samples = append(r.Samples, s)
					r.Traffic.PayloadBytesReceived += s.PayloadBytes
					if s.Status != "success" {
						r.Status = "failed"
					}
					mu.Unlock()
				}(i+1, allocation)
			}
			go func() { workers.Wait(); close(active) }()
			go func() {
				defer close(loadDone)
				started.Wait()
				for i := 0; i < o.Samples; i++ {
					select {
					case <-active:
						return
					case <-ctx.Done():
						return
					default:
					}
					if activeDownloads.Load() == 0 {
						return
					}
					s, _, _ := request(ctx, client, o, "load", i+1, 0)
					if activeDownloads.Load() == 0 {
						s.Kind = "load_partial_overlap"
					}
					mu.Lock()
					r.Samples = append(r.Samples, s)
					if s.Status != "success" {
						r.Status = "failed"
					}
					mu.Unlock()
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case <-active:
						timer.Stop()
						return
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
			}()
			<-active
			<-loadDone
		}
	}
	if o.UDPAddress != "" && ctx.Err() == nil {
		runUDP := deps.UDPProbe
		if runUDP == nil {
			runUDP = RunUDP
		}
		result, udpErr := runUDP(ctx, UDPOptions{Target: o.UDPAddress, ProxyAddress: o.UDPProxyAddress, ProxyUsername: o.UDPProxyUsername, ProxyPassword: o.UDPProxyPassword, Family: o.Family, Samples: o.Samples, PayloadBytes: 64, Interval: 10 * time.Millisecond, Timeout: o.UDPTimeout, MaxBytes: int64(o.Samples) * 129})
		r.UDP = &result
		// Counters are copied after a complete UDP run; its result also retains
		// all received/dropped datagrams and non-loss termination reasons.
		r.Traffic.UDPPayloadBytesSent = result.SentBytes
		r.Traffic.UDPPayloadBytesReceived = result.ReceivedBytes + result.DiscardedBytes
		if udpErr != nil {
			r.Status = "failed"
			category := result.Error
			if category == "" {
				category = "udp_probe_failed"
			}
			if category == "cancelled" {
				category = "canceled"
			}
			r.Errors = append(r.Errors, Failure{category, "UDP请求回包测试未完成；详细类别见UDP结果"})
		}
	}
	sort.SliceStable(r.Samples, func(i, j int) bool {
		a, b := r.Samples[i], r.Samples[j]
		if a.Kind == b.Kind {
			return a.Sequence < b.Sequence
		}
		return a.Kind < b.Kind
	})
	for _, s := range r.Samples {
		if s.ElapsedMS == nil {
			r.Limitations = append(r.Limitations, "有请求快于当前计时精度，耗时与吞吐保留为未知。")
		}
		if s.Kind == "load_partial_overlap" {
			r.Limitations = append(r.Limitations, "有请求仅与部分下载时间重叠；保留原样本，但不计入下载期间请求往返统计。")
		}
		if s.Status != "success" {
			r.Errors = append(r.Errors, Failure{s.ErrorCategory, s.Error})
		}
	}
	finish()
	return r, nil
}

func buildTransport(o Options, supplied http.RoundTripper, hostname string, ips []net.IPAddr) (http.RoundTripper, func()) {
	var t *http.Transport
	if supplied != nil {
		if v, ok := supplied.(*http.Transport); ok {
			t = v.Clone()
		} else {
			return supplied, func() {}
		}
	} else {
		t = http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
	}
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	// Clone may inherit ALPN protocols initialized on an earlier use of the
	// transport. Disabling the HTTP/2 handler alone does not remove "h2" from
	// the TLS offer; negotiating it and then sending HTTP/1.1 breaks valid
	// HTTPS targets. Keep this bounded single-connection probe on HTTP/1.1.
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	connections := o.Concurrency + 1
	if connections > MaxConcurrency {
		connections = MaxConcurrency
	}
	t.MaxConnsPerHost = connections
	t.MaxIdleConnsPerHost = connections
	t.DisableCompression = true
	if o.Path != "client-proxy" {
		dialer := &net.Dialer{}
		network := "tcp"
		if o.Family == "ipv4" {
			network = "tcp4"
		} else if o.Family == "ipv6" {
			network = "tcp6"
		}
		t.DialContext = func(ctx context.Context, _ string, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if host != hostname {
				return nil, errors.New("unexpected destination outside the selected target")
			}
			var last error
			for _, a := range ips {
				conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
				if e == nil {
					return conn, nil
				}
				last = e
			}
			if last == nil {
				last = errors.New("no destination address")
			}
			return nil, last
		}
	}
	return t, t.CloseIdleConnections
}

func request(ctx context.Context, client *http.Client, o Options, kind string, seq int, cap int64) (Sample, Stage, Stage) {
	s := Sample{Sequence: seq, Kind: kind, Status: "failed"}
	conn, tlsStage := Stage{Status: "unknown"}, Stage{Status: "unknown"}
	start := time.Now()
	var connectStart, tlsStart time.Time
	var traceMu sync.Mutex
	var observedTTFB *float64
	trace := &httptrace.ClientTrace{ConnectStart: func(string, string) { traceMu.Lock(); connectStart = time.Now(); traceMu.Unlock() }, ConnectDone: func(_, _ string, err error) {
		traceMu.Lock()
		defer traceMu.Unlock()
		if !connectStart.IsZero() {
			v := milliseconds(time.Since(connectStart))
			conn.ElapsedMS = &v
			conn.Status = "success"
			if err != nil {
				conn.Status = "failed"
			}
		}
	}, TLSHandshakeStart: func() { traceMu.Lock(); tlsStart = time.Now(); traceMu.Unlock() }, TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
		traceMu.Lock()
		defer traceMu.Unlock()
		if !tlsStart.IsZero() {
			v := milliseconds(time.Since(tlsStart))
			tlsStage.ElapsedMS = &v
			tlsStage.Status = "success"
			if err != nil {
				tlsStage.Status = "failed"
			}
		}
	}, GotFirstResponseByte: func() {
		traceMu.Lock()
		defer traceMu.Unlock()
		d := time.Since(start)
		if d > 0 {
			v := milliseconds(d)
			observedTTFB = &v
		}
	}}
	method := http.MethodHead
	if kind == "download" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, o.TargetURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "QingNode-probe/1")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Cache-Control", "no-cache")
		if cap > 0 {
			req.Header.Set("Range", rangeHeader(cap))
		}
		var resp *http.Response
		resp, err = client.Do(req)
		if resp != nil {
			code := resp.StatusCode
			s.HTTPStatus = &code
			if err == nil && code >= 200 && code < 400 {
				if cap > 0 {
					s.PayloadBytes, err = io.CopyN(io.Discard, resp.Body, cap)
					if errors.Is(err, io.EOF) {
						err = nil
					}
					s.BudgetLimited = s.PayloadBytes == cap && (resp.ContentLength < 0 || resp.ContentLength > cap)
				}
				if err == nil {
					s.Status = "success"
				}
			} else if err == nil {
				err = errors.New("HTTP status outside accepted range")
				s.ErrorCategory = "http_status"
			}
			resp.Body.Close()
		}
	}
	d := time.Since(start)
	if d > 0 {
		v := milliseconds(d)
		s.ElapsedMS = &v
	}
	if s.Status == "success" && kind == "download" && s.PayloadBytes > 0 && d > 0 {
		rate := float64(s.PayloadBytes) * 8 / d.Seconds() / 1e6
		s.ThroughputMbps = &rate
	}
	if err != nil {
		if s.ErrorCategory == "" {
			s.ErrorCategory = errorCategory(ctx, err, o.Path == "client-proxy")
		}
		s.Error = safeError(s.ErrorCategory)
	}
	traceMu.Lock()
	s.TTFBMS = observedTTFB
	observedConn, observedTLS := conn, tlsStage
	traceMu.Unlock()
	return s, observedConn, observedTLS
}

func rangeHeader(cap int64) string         { return "bytes=0-" + strconv.FormatInt(cap-1, 10) }
func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func errorCategory(ctx context.Context, err error, proxy bool) string {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if proxy {
		return "proxy_transport_or_auth_unknown"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_failed"
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return "tls_failed"
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return "connection_failed"
	}
	return "https_failed"
}

func safeError(category string) string {
	switch category {
	case "canceled":
		return "请求已取消"
	case "timeout":
		return "请求超过时间上限"
	case "dns_failed":
		return "目标域名解析失败"
	case "tls_failed":
		return "HTTPS证书校验失败"
	case "connection_failed":
		return "目标连接失败"
	case "http_status":
		return "目标返回了不成功的HTTP状态"
	case "proxy_transport_or_auth_unknown":
		return "所选代理连接失败；目前无法可靠区分路由问题与认证问题"
	default:
		return "HTTPS请求失败"
	}
}
