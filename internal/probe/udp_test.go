package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func udpTestEndpoint(t *testing.T, handle func([]byte) [][]byte) (string, *atomic.Int32) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, e := c.ReadFrom(buf)
			if e != nil {
				return
			}
			count.Add(1)
			for _, response := range handle(append([]byte(nil), buf[:n]...)) {
				_, _ = c.WriteTo(response, addr)
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP fixture did not exit")
		}
	})
	return c.LocalAddr().String(), count
}

func udpDefaults(target string) UDPOptions {
	return UDPOptions{Target: target, Samples: 4, PayloadBytes: 64, Timeout: 100 * time.Millisecond}
}

func TestUDPControlledSequenceDelayLossAndJitter(t *testing.T) {
	target, count := udpTestEndpoint(t, func(b []byte) [][]byte {
		seq := binary.BigEndian.Uint32(b[24:28])
		if seq == 1 {
			return nil
		}
		time.Sleep(time.Duration(5+seq*5) * time.Millisecond)
		return [][]byte{b}
	})
	o := udpDefaults(target)
	r, err := RunUDP(context.Background(), o)
	if err == nil || r.Status != "failed" || r.Error != "udp_no_response" || r.Sent != 4 || r.Received != 3 || r.Lost != 1 || count.Load() != 4 {
		t.Fatalf("wrong sequence loss: %#v, %v", r, err)
	}
	if r.LossPercent == nil || *r.LossPercent != 25 || r.Samples[1].RTTMS != nil || r.Samples[1].Error != "udp_no_response" {
		t.Fatalf("loss/missing data fabricated: %#v", r)
	}
	if r.MedianRTTMS == nil || *r.MedianRTTMS < 12 || r.P95RTTMS == nil || *r.P95RTTMS < 18 || r.JitterMS == nil || *r.JitterMS <= 0 || r.LimitNote == "" {
		t.Fatalf("controlled delay direction/small sample wrong: %#v", r)
	}
	if r.SentBytes != 256 || r.ReceivedBytes != 192 {
		t.Fatalf("wrong payload accounting: %#v", r)
	}
}

func TestUDPSingleValidSampleHasNoJitter(t *testing.T) {
	target, _ := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{b} })
	o := udpDefaults(target)
	o.Samples = 1
	r, e := RunUDP(context.Background(), o)
	if e != nil || r.Status != "passed" || r.MedianRTTMS == nil || r.JitterMS != nil || r.LimitNote == "" {
		t.Fatalf("one RTT became a variation/confidence claim: %#v %v", r, e)
	}
}

func TestUDPTokenSequenceCorruptionIsNotSuccess(t *testing.T) {
	target, _ := udpTestEndpoint(t, func(b []byte) [][]byte { b[8] ^= 1; return [][]byte{b} })
	o := udpDefaults(target)
	o.Samples = 1
	o.MaxBytes = 193 // Permit one corrupt response plus waiting for a valid reply.
	r, err := RunUDP(context.Background(), o)
	if err == nil || r.Received != 0 || r.Lost != 1 || r.Samples[0].Discarded != 1 || r.DiscardedBytes != 64 || r.Samples[0].RTTMS != nil || r.JitterMS != nil {
		t.Fatalf("corrupted echo accepted: %#v %v", r, err)
	}
}

func TestUDPByteLimitAndCancellation(t *testing.T) {
	target, count := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{b} })
	o := udpDefaults(target)
	o.MaxBytes = 129
	r, err := RunUDP(context.Background(), o)
	if err == nil || r.Error != "byte_limit" || count.Load() != 1 || r.SentBytes+r.ReceivedBytes+r.DiscardedBytes > o.MaxBytes || r.LossPercent != nil {
		t.Fatalf("UDP budget bypass: %#v %v", r, err)
	}
	blackhole, _ := udpTestEndpoint(t, func(b []byte) [][]byte { return nil })
	o = udpDefaults(blackhole)
	o.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	start := time.Now()
	r, err = RunUDP(ctx, o)
	if !errors.Is(err, context.Canceled) || r.Error != "cancelled" || r.Status == "passed" || r.LossPercent != nil || time.Since(start) > time.Second {
		t.Fatalf("UDP cancellation fabricated success or blocked: %#v %v", r, err)
	}
}

func TestUDPValidationHardBounds(t *testing.T) {
	base := udpDefaults("127.0.0.1:9")
	cases := []UDPOptions{base, base, base, base, base, base}
	cases[0].Samples = 65
	cases[1].PayloadBytes = 1201
	cases[2].Timeout = 6 * time.Second
	cases[3].Interval = 2 * time.Second
	cases[4].MaxBytes = 1 << 30
	cases[5].Target = "https://user:secret@example.com:443/path"
	for _, o := range cases {
		r, e := RunUDP(context.Background(), o)
		if e == nil || r.Error != "invalid_input" || r.Sent != 0 {
			t.Fatalf("unbounded UDP input accepted: %#v %#v %v", o, r, e)
		}
	}
}

// This small fixture validates RFC framing and the TCP association lifecycle;
// official sing-box protocol integration uses the same adapter separately.
func udpSOCKSFixture(t *testing.T, target string) (string, <-chan struct{}) {
	return udpSOCKSAuthFixture(t, target, "", "")
}

func udpSOCKSAuthFixture(t *testing.T, target, username, password string) (string, <-chan struct{}) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	u, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	closed := make(chan struct{})
	controlReady := make(chan struct{})
	go func() {
		defer close(closed)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 3)
		if _, e = io.ReadFull(c, b); e != nil {
			return
		}
		method := byte(0)
		if username != "" {
			method = 2
		}
		if !bytes.Equal(b, []byte{5, 1, method}) {
			return
		}
		_, _ = c.Write([]byte{5, method})
		if method == 2 {
			head := make([]byte, 2)
			if _, e = io.ReadFull(c, head); e != nil || head[0] != 1 || head[1] == 0 {
				return
			}
			u := make([]byte, int(head[1]))
			if _, e = io.ReadFull(c, u); e != nil {
				return
			}
			plen := make([]byte, 1)
			if _, e = io.ReadFull(c, plen); e != nil || plen[0] == 0 {
				return
			}
			p := make([]byte, int(plen[0]))
			if _, e = io.ReadFull(c, p); e != nil {
				return
			}
			if string(u) != username || string(p) != password {
				_, _ = c.Write([]byte{1, 1})
				return
			}
			_, _ = c.Write([]byte{1, 0})
		}
		b = make([]byte, 10)
		if _, e = io.ReadFull(c, b); e != nil {
			return
		}
		if b[1] != 3 {
			return
		}
		port := u.LocalAddr().(*net.UDPAddr).Port
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		close(controlReady)
		_, _ = io.Copy(io.Discard, c)
	}()
	go func() {
		select {
		case <-controlReady:
		case <-closed:
			return
		}
		buf := make([]byte, 2048)
		for {
			n, addr, e := u.ReadFrom(buf)
			if e != nil {
				return
			}
			if n < 10 || buf[2] != 0 {
				continue
			}
			header := append([]byte(nil), buf[:10]...)
			if buf[3] != 1 {
				continue
			}
			d, e := net.Dial("udp", target)
			if e != nil {
				return
			}
			d.SetDeadline(time.Now().Add(time.Second))
			_, _ = d.Write(buf[10:n])
			n, e = d.Read(buf[10:])
			d.Close()
			if e == nil {
				response := append(header, buf[10:10+n]...)
				_, _ = u.WriteTo(response, addr)
			}
		}
	}()
	t.Cleanup(func() { l.Close(); u.Close() })
	return l.Addr().String(), closed
}

func TestSOCKSUDPAssociationHeldAndClosed(t *testing.T) {
	target, _ := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{b} })
	proxy, closed := udpSOCKSFixture(t, target)
	o := udpDefaults(target)
	o.ProxyAddress = proxy
	r, err := RunUDP(context.Background(), o)
	if err != nil || r.Status != "passed" || r.Path != "proxy_socks5_udp" || r.Received != 4 {
		t.Fatalf("SOCKS UDP failed: %#v %v", r, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("SOCKS TCP association leaked after probe")
	}
}

func TestSOCKSUDPAuthenticatedAssociationAndWrongPassword(t *testing.T) {
	for _, correct := range []bool{true, false} {
		t.Run(strconv.FormatBool(correct), func(t *testing.T) {
			target, count := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{b} })
			proxy, closed := udpSOCKSAuthFixture(t, target, "probe-user", "private-test-password")
			o := udpDefaults(target)
			o.ProxyAddress = proxy
			o.ProxyUsername = "probe-user"
			o.ProxyPassword = "private-test-password"
			if !correct {
				o.ProxyPassword = "wrong-password"
			}
			r, e := RunUDP(context.Background(), o)
			if correct {
				if e != nil || r.Status != "passed" || r.Received != o.Samples {
					t.Fatalf("authenticated UDP association failed: %#v %v", r, e)
				}
			} else {
				if e == nil || r.Status == "passed" || r.Sent != 0 || count.Load() != 0 {
					t.Fatalf("wrong SOCKS password fell back direct: %#v %v", r, e)
				}
			}
			if e != nil && (strings.Contains(e.Error(), o.ProxyPassword) || strings.Contains(e.Error(), o.ProxyUsername)) {
				t.Fatal("authentication error exposed private session credentials")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("authenticated SOCKS association leaked")
			}
		})
	}
}

func TestSOCKSAuthCannotDowngradeToUnauthenticated(t *testing.T) {
	target, count := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{b} })
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 3)
		if _, e = io.ReadFull(c, buf); e != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		io.Copy(io.Discard, c)
	}()
	o := udpDefaults(target)
	o.ProxyAddress = l.Addr().String()
	o.ProxyUsername = "probe-user"
	o.ProxyPassword = "probe-password"
	r, e := RunUDP(context.Background(), o)
	if e == nil || r.Status == "passed" || count.Load() != 0 || r.Sent != 0 {
		t.Fatalf("private association downgraded: %#v %v", r, e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("downgraded association was not closed")
	}
}

func TestSOCKSAuthInputBoundsAndNoDirectCredentials(t *testing.T) {
	base := udpDefaults("127.0.0.1:9")
	base.ProxyAddress = "127.0.0.1:1080"
	base.ProxyUsername = "user"
	base.ProxyPassword = "password"
	cases := []UDPOptions{base, base, base, base, base}
	cases[0].ProxyUsername = ""
	cases[1].ProxyPassword = ""
	cases[2].ProxyUsername = strings.Repeat("a", 256)
	cases[3].ProxyPassword = strings.Repeat("a", 256)
	cases[4].ProxyAddress = ""
	for _, o := range cases {
		r, e := RunUDP(context.Background(), o)
		if e == nil || r.Error != "invalid_input" || r.Sent != 0 {
			t.Fatalf("invalid proxy authentication accepted: %#v", r)
		}
	}
	base.ProxyUsername = strings.Repeat("a", 255)
	base.ProxyPassword = strings.Repeat("b", 255)
	if e := validateUDPOptions(base); e != nil {
		t.Fatal("RFC1929 boundary rejected", e)
	}
}

func TestSOCKSAuthenticationCancellationClosesControlConnection(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		greeting := make([]byte, 3)
		if _, e = io.ReadFull(c, greeting); e != nil {
			return
		}
		_, _ = c.Write([]byte{5, 2})
		io.Copy(io.Discard, c)
	}()
	o := udpDefaults("127.0.0.1:9")
	o.ProxyAddress = l.Addr().String()
	o.ProxyUsername = "probe-user"
	o.ProxyPassword = "private-test-password"
	o.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	r, e := RunUDP(ctx, o)
	if !errors.Is(e, context.Canceled) || r.Error != "cancelled" || r.Sent != 0 {
		t.Fatalf("auth cancellation misclassified: %#v %v", r, e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled authentication connection leaked")
	}
}

func TestSOCKSFailureNeverFallsBackDirect(t *testing.T) {
	target, count := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{b} })
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	proxy := l.Addr().String()
	l.Close()
	o := udpDefaults(target)
	o.ProxyAddress = proxy
	r, err := RunUDP(context.Background(), o)
	if err == nil || r.Status == "passed" || count.Load() != 0 || r.Sent != 0 {
		t.Fatalf("proxy failure fell back direct: %#v %v", r, err)
	}
}

func TestSOCKSAddressWireForms(t *testing.T) {
	for _, target := range []string{"127.0.0.1:53", "[::1]:5353", "controlled.example:9999"} {
		b, e := encodeSOCKSAddress(target)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := readSOCKSAddress(bytes.NewReader(b[1:]), b[0])
		if e != nil || parsed != target {
			t.Fatalf("SOCKS address differs: %s %s %v", target, parsed, e)
		}
	}
	if _, e := readSOCKSAddress(bytes.NewReader(nil), 2); e == nil {
		t.Fatal("unknown address type accepted")
	}
}

func TestBoundedEchoRejectsUnknownPacketsAndExits(t *testing.T) {
	u, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	done := make(chan EchoResult, 1)
	go func() {
		r, _ := ServeUDPEcho(context.Background(), u, EchoOptions{MaxPackets: 3, MaxBytes: 1000, IdleTimeout: time.Second})
		done <- r
	}()
	c, e := net.Dial("udp", u.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.Write([]byte("not-qingnode"))
	payload := make([]byte, 64)
	copy(payload, udpMagic)
	binary.BigEndian.PutUint32(payload[24:28], uint32(7))
	c.Write(payload)
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, e := c.Read(buf)
	if e != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatal("echo changed sequence", e)
	}
	c.Write([]byte("third-packet"))
	select {
	case r := <-done:
		if r.Received != 3 || r.Replied != 1 || r.Rejected != 2 || r.SentBytes != 64 {
			t.Fatalf("echo bounds/rejections wrong: %#v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("echo did not stop at packet limit")
	}
}

func TestEchoCancellationAndInvalidOptions(t *testing.T) {
	u, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	if _, e = ServeUDPEcho(context.Background(), u, EchoOptions{MaxPackets: 4097, MaxBytes: 1000, IdleTimeout: time.Second}); e == nil {
		t.Fatal("unbounded echo accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	_, e = ServeUDPEcho(ctx, u, EchoOptions{MaxPackets: 2, MaxBytes: 1000, IdleTimeout: time.Second})
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("echo cancellation unknown: %v", e)
	}
}

// Force cancellation's immediate deadline to happen before the main loop's
// idle-deadline write, the ordering that could otherwise postpone cleanup.
type udpDeadlineRace struct {
	net.PacketConn
	calls    atomic.Int32
	first    chan struct{}
	release  chan struct{}
	canceled chan struct{}
	reads    atomic.Int32
	once     sync.Once
}

func (c *udpDeadlineRace) SetReadDeadline(t time.Time) error {
	if c.calls.Add(1) == 1 {
		close(c.first)
		<-c.release
		return c.PacketConn.SetReadDeadline(t)
	}
	e := c.PacketConn.SetReadDeadline(t)
	c.once.Do(func() { close(c.canceled) })
	return e
}
func (c *udpDeadlineRace) ReadFrom(b []byte) (int, net.Addr, error) {
	c.reads.Add(1)
	return c.PacketConn.ReadFrom(b)
}

func TestEchoCancellationCannotBeOverwrittenByIdleDeadline(t *testing.T) {
	u, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	c := &udpDeadlineRace{PacketConn: u, first: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := ServeUDPEcho(ctx, c, EchoOptions{MaxPackets: 1, MaxBytes: 128, IdleTimeout: time.Second})
		done <- e
	}()
	<-c.first
	cancel()
	<-c.canceled
	close(c.release)
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) || c.reads.Load() != 0 {
			t.Fatalf("cancel entered an idle-blocking read: %v reads=%d", e, c.reads.Load())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancellation was postponed by idle deadline")
	}
}

func TestUDPDirectDNSFailureDistinct(t *testing.T) {
	o := udpDefaults(net.JoinHostPort("invalid host", strconv.Itoa(9)))
	r, e := RunUDP(context.Background(), o)
	if e == nil || r.Error != "invalid_input" {
		t.Fatal("invalid target not rejected")
	}
}

func TestUDPDNSReplyDoesNotCountAsSequenceEcho(t *testing.T) {
	target, _ := udpTestEndpoint(t, func(b []byte) [][]byte { return [][]byte{{0x51, 0x4e, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}} })
	o := udpDefaults(target)
	o.Samples = 1
	r, e := RunUDP(context.Background(), o)
	if e == nil || r.Status == "passed" || r.Received != 0 || r.Samples[0].RTTMS != nil || r.JitterMS != nil {
		t.Fatalf("UDP DNS availability mistaken for measured loss/jitter: %#v %v", r, e)
	}
}

func TestUDPForcedFamilyRejectsUnprovenHostname(t *testing.T) {
	for _, target := range []string{"controlled.example:9", "127.0.0.1:9"} {
		o := udpDefaults(target)
		o.Family = "ipv6"
		r, e := RunUDP(context.Background(), o)
		if e == nil || r.Error != "invalid_input" || r.Sent != 0 {
			t.Fatalf("UDP family requirement ignored: %#v %v", r, e)
		}
	}
}

func TestSOCKSHandshakeCancellationClosesAssociation(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	o := udpDefaults("127.0.0.1:9")
	o.ProxyAddress = l.Addr().String()
	o.Timeout = 5 * time.Second
	r, e := RunUDP(ctx, o)
	if !errors.Is(e, context.Canceled) || r.Error != "cancelled" {
		t.Fatalf("SOCKS handshake cancellation misclassified: %#v %v", r, e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled SOCKS handshake leaked association")
	}
}
