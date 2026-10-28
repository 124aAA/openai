package probe

// The SOCKS5 UDP framing here follows RFC 1928, section 7. No proxy protocol is
// implemented: the selected official sing-box client handles node transport.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	MaxUDPSamples      = 64
	MaxUDPPayloadBytes = 1200
	udpHeaderBytes     = 28
)

var udpMagic = []byte("QNUDP02!")

type UDPOptions struct {
	Target        string
	Family        string // auto (default), ipv4, ipv6; a forced family requires a literal IP.
	ProxyAddress  string // Empty only for an explicitly selected direct path.
	ProxyUsername string `json:"-"`
	ProxyPassword string `json:"-"`
	Samples       int
	PayloadBytes  int   // Includes the 28-byte version/token/sequence envelope.
	MaxBytes      int64 // Payload send + receive budget, including rejected replies; 0 uses a bounded default.
	Interval      time.Duration
	Timeout       time.Duration // Per sample, and initial SOCKS negotiation.
}

type UDPSample struct {
	Sequence  int      `json:"sequence"`
	RTTMS     *float64 `json:"rtt_ms"`
	Error     string   `json:"error,omitempty"`
	Discarded int      `json:"discarded_packets"`
}

type UDPResult struct {
	Status         string      `json:"status"`
	Error          string      `json:"error,omitempty"`
	Path           string      `json:"path"`
	Target         string      `json:"target"`
	AddressFamily  string      `json:"address_family"`
	Samples        []UDPSample `json:"samples"`
	Sent           int         `json:"sent"`
	Received       int         `json:"received"`
	Lost           int         `json:"lost"`
	Unfinished     int         `json:"unfinished"`
	SentBytes      int64       `json:"sent_bytes"`
	ReceivedBytes  int64       `json:"received_bytes"`
	DiscardedBytes int64       `json:"discarded_bytes"`
	LossPercent    *float64    `json:"loss_percent"`
	MedianRTTMS    *float64    `json:"median_rtt_ms"`
	P95RTTMS       *float64    `json:"p95_rtt_ms"`
	JitterMS       *float64    `json:"jitter_ms"`
	DurationMS     float64     `json:"duration_ms"`
	LimitNote      string      `json:"limit_note,omitempty"`
}

// Datagram preserves one connected UDP flow. A SOCKS implementation also keeps
// the TCP association alive until Close; closing it ends the UDP relay session.
type Datagram interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetDeadline(time.Time) error
	Close() error
}

func validateUDPOptions(o UDPOptions) error {
	if err := validateUDPProxyAuth(o.ProxyAddress, o.ProxyUsername, o.ProxyPassword); err != nil {
		return err
	}
	if o.Family != "" && o.Family != "auto" && o.Family != "ipv4" && o.Family != "ipv6" {
		return errors.New("UDP 地址族只能选 auto、ipv4 或 ipv6")
	}
	if o.Family == "ipv4" || o.Family == "ipv6" {
		host, _, err := net.SplitHostPort(o.Target)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || (o.Family == "ipv4" && ip.To4() == nil) || (o.Family == "ipv6" && ip.To4() != nil) {
			return errors.New("指定 UDP 地址族时，目标必须直接填写匹配的 IPv4 或 IPv6 地址")
		}
	}
	if o.Samples < 1 || o.Samples > MaxUDPSamples {
		return fmt.Errorf("UDP 样本数必须在 1 到 %d 之间", MaxUDPSamples)
	}
	if o.PayloadBytes < udpHeaderBytes || o.PayloadBytes > MaxUDPPayloadBytes {
		return fmt.Errorf("UDP 每次请求大小必须在 %d 到 %d 字节之间", udpHeaderBytes, MaxUDPPayloadBytes)
	}
	if o.Timeout <= 0 || o.Timeout > 5*time.Second || o.Interval < 0 || o.Interval > time.Second {
		return errors.New("UDP 单次等待时间必须大于 0 且不超过 5 秒；请求间隔必须在 0 到 1 秒之间")
	}
	if time.Duration(o.Samples)*(o.Timeout+o.Interval) > 120*time.Second {
		return errors.New("UDP 全部样本的最长等待时间超过 120 秒，请减少样本数或单次等待时间")
	}
	if o.MaxBytes < 0 || o.MaxBytes > MaxUDPSamples*(2*MaxUDPPayloadBytes+1) {
		return errors.New("UDP 总字节预算不能为负，也不能超过硬上限")
	}
	return validateUDPTarget(o.Target)
}

func validateUDPProxyAuth(proxy, username, password string) error {
	if (username == "") != (password == "") || len(username) > 255 || len(password) > 255 {
		return errors.New("本机 UDP 代理的用户名和密码须一起提供，每项长度为 1 到 255 字节")
	}
	if proxy == "" && username != "" {
		return errors.New("直接 UDP 测试不能携带代理用户名或密码")
	}
	return nil
}

func validateUDPTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || len(host) > 253 || bytes.ContainsAny([]byte(host), "\x00\r\n\t /@") {
		return errors.New("UDP 目标必须明确填写 主机:端口，不能带凭据、路径或控制字符")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("UDP 目标端口必须在 1 到 65535 之间")
	}
	return nil
}

func udpError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "udp_no_response"
	}
	return "udp_transport"
}

// RunUDP measures request-response RTT and RTT variation, not one-way latency.
// Missing responses are counted only for requests actually sent. Cancellation
// and exhausted budgets remain failures, rather than zero RTT or success.
func RunUDP(ctx context.Context, o UDPOptions) (result UDPResult, err error) {
	start := time.Now()
	result = UDPResult{Status: "failed", AddressFamily: "unknown", Path: "direct", Samples: []UDPSample{}}
	defer func() { result.DurationMS = float64(time.Since(start)) / float64(time.Millisecond) }()
	if o.ProxyAddress != "" {
		result.Path = "proxy_socks5_udp"
	}
	if err = validateUDPOptions(o); err != nil {
		result.Error = "invalid_input"
		return
	}
	result.Target = o.Target
	if o.MaxBytes == 0 {
		o.MaxBytes = int64(o.Samples * (2*o.PayloadBytes + 1))
	}
	host, _, _ := net.SplitHostPort(o.Target)
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			result.AddressFamily = "ipv4"
		} else {
			result.AddressFamily = "ipv6"
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	d, connectErr := ConnectDatagramWithAuth(ctx, o.Target, o.ProxyAddress, o.ProxyUsername, o.ProxyPassword, o.Timeout)
	if connectErr != nil {
		result.Error = udpError(connectErr)
		return result, connectErr
	}
	defer d.Close()
	stop := context.AfterFunc(ctx, func() { _ = d.Close() })
	defer stop()
	payload := make([]byte, o.PayloadBytes)
	copy(payload, udpMagic)
	if _, err = rand.Read(payload[8:24]); err != nil {
		result.Error = "random_source"
		return
	}
	buf := make([]byte, o.PayloadBytes+1)
	rtts := []float64{}
	differences := []float64{}
	previous := 0.0
	previousSeq := -1
	for i := 0; i < o.Samples; i++ {
		if ctx.Err() != nil {
			err = ctx.Err()
			result.Error = udpError(err)
			break
		}
		remaining := o.MaxBytes - result.SentBytes - result.ReceivedBytes - result.DiscardedBytes
		if remaining < int64(2*o.PayloadBytes+1) {
			result.Error = "byte_limit"
			break
		}
		if i > 0 && o.Interval > 0 {
			timer := time.NewTimer(o.Interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				err = ctx.Err()
			case <-timer.C:
			}
			if err != nil {
				result.Error = udpError(err)
				break
			}
		}
		binary.BigEndian.PutUint32(payload[24:28], uint32(i))
		sample := UDPSample{Sequence: i}
		sentAt := time.Now()
		deadline := sentAt.Add(o.Timeout)
		if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
			deadline = outer
		}
		_ = d.SetDeadline(deadline)
		n, writeErr := d.Write(payload)
		result.SentBytes += int64(n)
		if writeErr != nil || n != len(payload) {
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			sample.Error = udpError(writeErr)
			if ctx.Err() != nil {
				err = ctx.Err()
				sample.Error = udpError(err)
			} else {
				err = writeErr
			}
			result.Error = sample.Error
			result.Samples = append(result.Samples, sample)
			break
		}
		result.Sent++
		for {
			remaining = o.MaxBytes - result.SentBytes - result.ReceivedBytes - result.DiscardedBytes
			if remaining < int64(o.PayloadBytes+1) {
				sample.Error = "byte_limit"
				result.Error = sample.Error
				break
			}
			n, readErr := d.Read(buf)
			if readErr != nil {
				if ctx.Err() != nil {
					err = ctx.Err()
					sample.Error = udpError(err)
				} else {
					sample.Error = udpError(readErr)
				}
				break
			}
			if n != len(payload) || !bytes.Equal(buf[:n], payload) {
				sample.Discarded++
				result.DiscardedBytes += int64(n)
				continue
			}
			rtt := float64(time.Since(sentAt)) / float64(time.Millisecond)
			sample.RTTMS = &rtt
			result.Received++
			result.ReceivedBytes += int64(n)
			rtts = append(rtts, rtt)
			if previousSeq >= 0 && previousSeq == i-1 {
				delta := rtt - previous
				if delta < 0 {
					delta = -delta
				}
				differences = append(differences, delta)
			}
			previous, previousSeq = rtt, i
			break
		}
		result.Samples = append(result.Samples, sample)
		if err != nil {
			result.Error = sample.Error
			break
		}
	}
	for _, sample := range result.Samples {
		if sample.Error == "udp_no_response" {
			result.Lost++
		}
	}
	result.Unfinished = result.Sent - result.Received - result.Lost
	if result.Sent > 0 && result.Unfinished == 0 && result.Error != "cancelled" && result.Error != "timeout" && result.Error != "byte_limit" {
		loss := float64(result.Lost) * 100 / float64(result.Sent)
		result.LossPercent = &loss
	}
	if len(rtts) > 0 {
		sort.Float64s(rtts)
		m := medianUDP(rtts)
		p := rtts[(len(rtts)*95+99)/100-1]
		result.MedianRTTMS = &m
		result.P95RTTMS = &p
	}
	if len(differences) > 0 {
		sum := 0.0
		for _, v := range differences {
			sum += v
		}
		j := sum / float64(len(differences))
		result.JitterMS = &j
	}
	if result.Sent < 10 || result.Received < 10 {
		result.LimitNote = "样本较少：丢包比例和往返耗时分位数只描述本次测量，不能据此下高置信结论"
	}
	if result.Error == "" {
		if result.Received == o.Samples {
			result.Status = "passed"
		} else {
			result.Error = "udp_no_response"
			result.Status = "failed"
		}
	}
	if result.Error != "" && err == nil {
		err = fmt.Errorf("UDP 请求回复测试未完成（原因编码：%s）", result.Error)
	}
	return
}

func medianUDP(v []float64) float64 {
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}

// ConnectDatagram never falls back from SOCKS to direct. RFC 1928 associates
// the relay lifetime with its TCP control connection, retained in socksDatagram.
func ConnectDatagram(ctx context.Context, target, proxy string, timeout time.Duration) (Datagram, error) {
	return ConnectDatagramWithAuth(ctx, target, proxy, "", "", timeout)
}

// ConnectDatagramWithAuth offers only RFC 1929 username/password when private
// session credentials are supplied. It never accepts an unauthenticated method
// as a fallback. This authenticates the client, not the listening process:
// process ownership/readiness must be checked separately by the sandbox.
func ConnectDatagramWithAuth(ctx context.Context, target, proxy, username, password string, timeout time.Duration) (Datagram, error) {
	if err := validateUDPProxyAuth(proxy, username, password); err != nil {
		return nil, err
	}
	if err := validateUDPTarget(target); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > 5*time.Second {
		return nil, errors.New("UDP 建连等待时间必须大于 0 且不超过 5 秒")
	}
	if proxy == "" {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", target)
	}
	if err := validateUDPTarget(proxy); err != nil {
		return nil, err
	}
	control, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (Datagram, error) {
		control.Close()
		if ctx.Err() != nil {
			e = ctx.Err()
		}
		return nil, e
	}
	deadline := time.Now().Add(timeout)
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	control.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	method := byte(0)
	if username != "" {
		method = 2
	}
	if _, err = control.Write([]byte{5, 1, method}); err != nil {
		return fail(err)
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(control, greeting); err != nil {
		return fail(err)
	}
	if !bytes.Equal(greeting, []byte{5, method}) {
		return fail(errors.New("本机 SOCKS5 代理拒绝了测试连接方式"))
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(username))}, []byte(username)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err = control.Write(auth); err != nil {
			return fail(err)
		}
		response := make([]byte, 2)
		if _, err = io.ReadFull(control, response); err != nil {
			return fail(err)
		}
		if !bytes.Equal(response, []byte{1, 0}) {
			return fail(errors.New("本机 SOCKS5 代理的测试会话身份验证失败"))
		}
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(control, head); err != nil {
		return fail(err)
	}
	if head[0] != 5 || head[1] != 0 || head[2] != 0 {
		return fail(errors.New("本机 SOCKS5 代理拒绝建立 UDP 转发会话"))
	}
	relay, err := readSOCKSAddress(control, head[3])
	if err != nil {
		return fail(err)
	}
	rhost, rport, err := net.SplitHostPort(relay)
	if err != nil {
		return fail(err)
	}
	if ip := net.ParseIP(rhost); ip != nil && ip.IsUnspecified() {
		rhost, _, _ = net.SplitHostPort(control.RemoteAddr().String())
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", net.JoinHostPort(rhost, rport))
	if err != nil {
		return fail(err)
	}
	address, err := encodeSOCKSAddress(target)
	if err != nil {
		conn.Close()
		return fail(err)
	}
	control.SetDeadline(time.Time{})
	s := &socksDatagram{conn: conn, control: control, address: address}
	go func() { buf := make([]byte, 1); _, _ = control.Read(buf); _ = conn.Close() }()
	return s, nil
}

func readSOCKSAddress(r io.Reader, atyp byte) (string, error) {
	size := 0
	switch atyp {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		size = int(b[0])
	default:
		return "", errors.New("SOCKS5 返回了不支持的地址类型")
	}
	b := make([]byte, size+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	host := string(b[:size])
	if atyp != 3 {
		host = net.IP(b[:size]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(b[size:])))), nil
}

func encodeSOCKSAddress(target string) ([]byte, error) {
	host, port, _ := net.SplitHostPort(target)
	p, _ := strconv.Atoi(port)
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS5 目标主机名过长")
		}
		b = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	return append(b, byte(p>>8), byte(p)), nil
}

type socksDatagram struct {
	conn    net.Conn
	control net.Conn
	address []byte
	once    sync.Once
}

func (s *socksDatagram) Close() error {
	var err error
	s.once.Do(func() { err = s.conn.Close(); s.control.Close() })
	return err
}
func (s *socksDatagram) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }
func (s *socksDatagram) Write(b []byte) (int, error) {
	packet := append([]byte{0, 0, 0}, s.address...)
	packet = append(packet, b...)
	n, e := s.conn.Write(packet)
	if n < len(packet) {
		if e == nil {
			e = io.ErrShortWrite
		}
		return 0, e
	}
	return len(b), e
}
func (s *socksDatagram) Read(b []byte) (int, error) {
	packet := make([]byte, len(b)+262)
	n, err := s.conn.Read(packet)
	if err != nil {
		return 0, err
	}
	if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, errors.New("SOCKS5 UDP 回复格式损坏，或使用了本测试不支持的分片")
	}
	r := bytes.NewReader(packet[4:n])
	source, err := readSOCKSAddress(r, packet[3])
	if err != nil {
		return 0, err
	}
	_ = source // Per-run token + exact payload reject unsolicited/mismatched replies.
	// Preserve a one-byte oversized marker; the caller rejects payloads that
	// differ from the request and charges this bounded read to its byte budget.
	if r.Len() > len(b) {
		return copy(b, packet[n-r.Len():n]), nil
	}
	return r.Read(b)
}

type EchoOptions struct {
	MaxPackets  int
	MaxBytes    int64
	IdleTimeout time.Duration
}
type EchoResult struct {
	Received      int   `json:"received"`
	Replied       int   `json:"replied"`
	ReceivedBytes int64 `json:"received_bytes"`
	SentBytes     int64 `json:"sent_bytes"`
	Rejected      int   `json:"rejected"`
}

// ServeUDPEcho is a bounded, explicitly started measurement endpoint, not a
// production daemon. It handles only QingNode's versioned sequence envelope.
// MaxBytes counts received plus sent payload bytes; malformed data is counted.
func ServeUDPEcho(ctx context.Context, conn net.PacketConn, o EchoOptions) (result EchoResult, err error) {
	if o.MaxPackets < 1 || o.MaxPackets > 4096 || o.MaxBytes < udpHeaderBytes || o.MaxBytes > 8*1024*1024 || o.IdleTimeout <= 0 || o.IdleTimeout > 120*time.Second {
		return result, errors.New("受控 UDP 回复端点的请求数、字节数或等待时间超出允许范围")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, MaxUDPPayloadBytes+1)
	for result.Received < o.MaxPackets {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		remaining := o.MaxBytes - result.ReceivedBytes - result.SentBytes
		if remaining <= 0 {
			return result, nil
		}
		readBuffer := buf
		if int64(len(readBuffer)) > remaining {
			readBuffer = readBuffer[:int(remaining)]
		}
		deadline := time.Now().Add(o.IdleTimeout)
		if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
			deadline = outer
		}
		_ = conn.SetReadDeadline(deadline)
		// Cancellation may set an immediate deadline just before this call
		// overwrites it. Re-check after setting the deadline so that ordering
		// cannot leave the endpoint blocked for its full idle timeout.
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		n, addr, e := conn.ReadFrom(readBuffer)
		if e != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return result, e
		}
		result.Received++
		result.ReceivedBytes += int64(n)
		if n < udpHeaderBytes || n > MaxUDPPayloadBytes || !bytes.Equal(buf[:8], udpMagic) {
			result.Rejected++
			if result.ReceivedBytes+result.SentBytes >= o.MaxBytes {
				return result, nil
			}
			continue
		}
		if result.ReceivedBytes+result.SentBytes+int64(n) > o.MaxBytes {
			return result, nil
		}
		written, e := conn.WriteTo(buf[:n], addr)
		result.SentBytes += int64(written)
		if e != nil {
			return result, e
		}
		result.Replied++
		if result.ReceivedBytes+result.SentBytes >= o.MaxBytes {
			return result, nil
		}
	}
	return result, nil
}
