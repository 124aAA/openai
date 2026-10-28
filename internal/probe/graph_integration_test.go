package probe

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func graphFreePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp4" {
		c, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Fixture configs are private, freshly created, and never printed on failure:
// WireGuard upstream error strings can include its private IPC key material.
func graphFixtureCore(t *testing.T, bin string, config any, readyPort int) func() {
	t.Helper()
	dir := t.TempDir()
	if err := protectPrivate(dir, true); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture.json")
	if err = writePrivate(path, b); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	check := exec.CommandContext(ctx, bin, "check", "-c", path)
	check.Stdout, check.Stderr = io.Discard, io.Discard
	err = check.Run()
	cancel()
	if err != nil {
		t.Fatalf("official core rejected private graph fixture (logs suppressed): %v", err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	prepareProcess(cmd)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			stopProcess(cmd, true)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("owned graph fixture process did not exit")
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-done:
			t.Fatal("official graph fixture exited before listener readiness")
		default:
		}
		owned, ownErr := ownedListener(cmd.Process.Pid, readyPort)
		if ownErr != nil {
			t.Fatal("graph fixture listener ownership unavailable", ownErr)
		}
		if owned {
			return stop
		}
		if time.Now().After(deadline) {
			t.Fatal("graph fixture listener ownership deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func graphSOCKSServer(port int, source string) map[string]any {
	return map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "remote-socks", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "remote-user", "password": "remote-password"}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "fixture-exit", "inet4_bind_address": source}},
		"route":     map[string]any{"final": "fixture-exit"},
	}
}

func graphUDPTarget(t *testing.T) (string, *atomic.Int64, *atomic.Value) {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int64{}
	source := &atomic.Value{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1201)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			count.Add(1)
			host, _, _ := net.SplitHostPort(a.String())
			source.Store(host)
			_, _ = c.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned graph UDP target leaked")
		}
	})
	return c.LocalAddr().String(), count, source
}

func graphSandbox(t *testing.T, p GraphProfile, bin, digest string) *Sandbox {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	s, err := StartGraphSandbox(ctx, p, SandboxOptions{CoreBinary: bin, SHA256: digest, TempParent: t.TempDir()})
	if err != nil {
		t.Fatal("official graph sandbox failed", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func graphHTTPSClient(t *testing.T, s *Sandbox, target *httptest.Server) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	transport := s.Transport()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DisableKeepAlives = true
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func graphRequireHTTPS(t *testing.T, client *http.Client, url, source string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("QINGNODE_WG_PACKET_OBSERVER") == "1" {
		started := time.Now()
		var mu sync.Mutex
		var events []string
		record := func(label string) {
			mu.Lock()
			defer mu.Unlock()
			if len(events) < 32 {
				events = append(events, fmt.Sprintf("%s after%dms", label, time.Since(started).Milliseconds()))
			}
		}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
			GetConn:           func(string) { record("local-transport-get-connection") },
			ConnectStart:      func(string, string) { record("local-proxy-connect-start") },
			ConnectDone:       func(_, _ string, e error) { record(fmt.Sprintf("local-proxy-connect-done error=%t", e != nil)) },
			TLSHandshakeStart: func() { record("origin-TLS-start") },
			TLSHandshakeDone:  func(_ tls.ConnectionState, e error) { record(fmt.Sprintf("origin-TLS-done error=%t", e != nil)) },
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				record(fmt.Sprintf("origin-request-written error=%t", info.Err != nil))
			},
			GotFirstResponseByte: func() { record("origin-first-response-byte") },
		}))
		defer func() {
			mu.Lock()
			defer mu.Unlock()
			t.Logf("HTTP transport observations (not independent proxy handshake timings): %s", strings.Join(events, "; "))
		}()
	}
	r, err := client.Do(request)
	if err != nil {
		t.Fatal("real graph HTTPS request failed", err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 128))
	if err != nil || r.StatusCode != 200 || string(b) != source {
		t.Fatalf("observed graph exit source %q, wanted %s (status %d, %v)", b, source, r.StatusCode, err)
	}
}

func TestOfficialCoreGraphSOCKSChainNoFallback(t *testing.T) {
	bin, digest, version := portableOfficialCore(t)
	for _, disabled := range []string{"first", "second"} {
		t.Run(disabled, func(t *testing.T) {
			var requests atomic.Int64
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				_, _ = w.Write([]byte(host))
			}))
			defer target.Close()
			udpTarget, udpRequests, udpSource := graphUDPTarget(t)
			firstPort, secondPort := graphFreePort(t, "tcp4"), graphFreePort(t, "tcp4")
			stopFirst := graphFixtureCore(t, bin, graphSOCKSServer(firstPort, "127.0.0.2"), firstPort)
			stopSecond := graphFixtureCore(t, bin, graphSOCKSServer(secondPort, "127.0.0.3"), secondPort)
			first, last := graphTestSOCKS("egress-first", ""), graphTestSOCKS("egress-last", "egress-first")
			first["server_port"], last["server_port"] = firstPort, secondPort
			p, err := NewGraphProfile("two-hop-socks", version, "egress-last", []json.RawMessage{graphTestRaw(t, first), graphTestRaw(t, last)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			s := graphSandbox(t, p, bin, digest)
			client := graphHTTPSClient(t, s, target)
			graphRequireHTTPS(t, client, target.URL, "127.0.0.3")
			r, err := RunUDP(context.Background(), UDPOptions{Target: udpTarget, ProxyAddress: s.Address, ProxyUsername: s.Username, ProxyPassword: s.Password, Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
			if err != nil || r.Sent != 2 || r.Received != 2 || udpRequests.Load() != 2 || udpSource.Load() != "127.0.0.3" {
				t.Fatalf("two-hop actual UDP failed: %+v %v source=%v target=%d", r, err, udpSource.Load(), udpRequests.Load())
			}
			wrong := graphTestSOCKS("egress-last", "egress-first")
			wrong["server_port"] = secondPort
			wrong["password"] = "wrong-credential"
			bad, err := NewGraphProfile("wrong-remote-credential", version, "egress-last", []json.RawMessage{graphTestRaw(t, first), graphTestRaw(t, wrong)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			badSandbox := graphSandbox(t, bad, bin, digest)
			badClient := graphHTTPSClient(t, badSandbox, target)
			before := requests.Load()
			response, err := badClient.Get(target.URL)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || requests.Load() != before {
				t.Fatal("wrong remote credentials bypassed authentication")
			}
			badUDPBefore := udpRequests.Load()
			badUDP, badUDPErr := RunUDP(context.Background(), UDPOptions{Target: udpTarget, ProxyAddress: badSandbox.Address, ProxyUsername: badSandbox.Username, ProxyPassword: badSandbox.Password, Samples: 1, PayloadBytes: 64, Timeout: 700 * time.Millisecond})
			if badUDPErr == nil || badUDP.Received != 0 || udpRequests.Load() != badUDPBefore {
				t.Fatalf("wrong remote SOCKS5 credentials allowed UDP: %+v %v", badUDP, badUDPErr)
			}
			portableAssertClean(t, badSandbox)
			if disabled == "first" {
				stopFirst()
			} else {
				stopSecond()
			}
			before = requests.Load()
			response, err = client.Get(target.URL)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || requests.Load() != before {
				t.Fatal("disabled chain member fell back to direct")
			}
			beforeUDP := udpRequests.Load()
			u, udpErr := RunUDP(context.Background(), UDPOptions{Target: udpTarget, ProxyAddress: s.Address, ProxyUsername: s.Username, ProxyPassword: s.Password, Samples: 1, PayloadBytes: 64, Timeout: 700 * time.Millisecond})
			if udpErr == nil || u.Received != 0 || udpRequests.Load() != beforeUDP {
				t.Fatalf("disabled chain member leaked UDP: %+v %v", u, udpErr)
			}
			// A direct control confirms that proxy failure was not origin failure.
			control, err := target.Client().Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			control.Body.Close()
			portableAssertClean(t, s)
			t.Logf("official %s two-hop SOCKS5 HTTPS+2 sequenced UDP replies observed source127.0.0.3; wrong remote password rejected; stopping %s blocks new HTTPS/UDP while origin stays reachable; owned processes/files cleaned", version, disabled)
		})
	}
}

func graphWGKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// A test-owned datagram relay records only WireGuard's public message type,
// length and time, never packet bytes or keys. It lets a failed first request
// distinguish missing initiation/response from encrypted transport traffic.
type graphWGRelay struct {
	connection net.PacketConn
	target     *net.UDPAddr
	started    time.Time
	mu         sync.Mutex
	closed     bool
	upstreams  map[string]*net.UDPConn
	events     []string
	wg         sync.WaitGroup
	once       sync.Once
}

func graphStartWGRelay(t *testing.T, target string) *graphWGRelay {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	r := &graphWGRelay{connection: c, target: a, started: time.Now(), upstreams: map[string]*net.UDPConn{}}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		buffer := make([]byte, 65536)
		for {
			n, client, err := c.ReadFrom(buffer)
			if err != nil {
				return
			}
			r.record("to-landing", buffer[:n])
			r.mu.Lock()
			if r.closed {
				r.mu.Unlock()
				return
			}
			up := r.upstreams[client.String()]
			if up == nil {
				up, err = net.DialUDP("udp4", nil, r.target)
				if err != nil {
					r.mu.Unlock()
					return
				}
				r.upstreams[client.String()] = up
				r.wg.Add(1)
				go func(up *net.UDPConn, client net.Addr) {
					defer r.wg.Done()
					defer up.Close()
					reply := make([]byte, 65536)
					for {
						n, err := up.Read(reply)
						if err != nil {
							return
						}
						r.record("from-landing", reply[:n])
						if _, err = c.WriteTo(reply[:n], client); err != nil {
							return
						}
					}
				}(up, client)
			}
			r.mu.Unlock()
			if _, err = up.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	t.Cleanup(r.Close)
	return r
}
func (r *graphWGRelay) record(direction string, packet []byte) {
	if len(packet) < 4 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) < 32 {
		r.events = append(r.events, fmt.Sprintf("%s type%d bytes%d after%dms", direction, binary.LittleEndian.Uint32(packet[:4]), len(packet), time.Since(r.started).Milliseconds()))
	}
}
func (r *graphWGRelay) summary() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.events, "; ")
}
func (r *graphWGRelay) Close() {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.connection.Close()
		for _, up := range r.upstreams {
			up.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
}

// This optional Linux observer receives copies of loopback packets through
// AF_PACKET. It never forwards, delays, edits or writes a captured packet. Only
// public WireGuard type, direction, byte lengths and relative times are retained.
// The subprocess is deliberately opt-in: ordinary protocol tests need no raw
// socket privilege and keep precisely their original direct path and deadline.
func graphWGPacketObserver(t *testing.T, port int) func() {
	t.Helper()
	if os.Getenv("QINGNODE_WG_PACKET_OBSERVER") != "1" {
		return func() {}
	}
	if runtime.GOOS != "linux" {
		t.Fatal("explicit AF_PACKET observer requires Linux; not counted as protocol success")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("explicit packet observer requires Python3", err)
	}
	const script = `import json,signal,socket,struct,sys,time
port=int(sys.argv[1]); running=True; events=[]
def stop(signum,frame):
 global running
 running=False
signal.signal(signal.SIGINT,stop)
try:
 sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
 sock.bind(("lo",0));sock.settimeout(0.1)
except Exception as error:
 print("OBSERVER_ERROR="+type(error).__name__,flush=True);raise SystemExit(2)
started=time.monotonic();end=started+12
print("QINGNODE_WG_OBSERVER_READY",flush=True)
while running and time.monotonic()<end:
 try: frame,address=sock.recvfrom(65536)
 except socket.timeout: continue
 if address[2]!=socket.PACKET_HOST or len(frame)<42 or frame[12:14]!=b"\x08\x00": continue
 ip=frame[14:];header=(ip[0]&15)*4
 if ip[0]>>4!=4 or len(ip)<header+8 or ip[9]!=17: continue
 source,destination,length=struct.unpack("!HHH",ip[header:header+6])
 if source!=port and destination!=port: continue
 payload=ip[header+8:]
 if len(payload)<4: continue
 if len(events)<64:
  events.append({"direction":"to-landing" if destination==port else "from-landing","message_type":struct.unpack("<I",payload[:4])[0],"captured_payload_bytes":len(payload),"udp_length":length,"ip_total_length":struct.unpack("!H",ip[2:4])[0],"after_ms":round((time.monotonic()-started)*1000)})
sock.close()
print(json.dumps({"version":1,"interface":"lo","capture":"AF_PACKET receive copies; no forwarding or payload bytes stored","events":events},separators=(",",":")),flush=True)
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, python, "-u", "-c", script, strconv.Itoa(port))
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var output, stderr limitedOutput
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	ready := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		reader := bufio.NewReader(pipe)
		line, err := reader.ReadString('\n')
		ready <- err == nil && strings.TrimSpace(line) == "QINGNODE_WG_OBSERVER_READY"
		_, _ = io.Copy(&output, reader)
		_ = cmd.Wait()
		close(done)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
			}
			cancel()
			t.Logf("WireGuard unchanged-path packet observations: %s", strings.TrimSpace(output.String()))
			if stderr.Len() > 0 {
				t.Log("packet observer diagnostics suppressed; inspect observer readiness/exit")
			}
		})
	}
	t.Cleanup(stop)
	select {
	case okay := <-ready:
		if !okay {
			stop()
			t.Fatal("explicit AF_PACKET observer unavailable before any traffic")
		}
	case <-time.After(3 * time.Second):
		stop()
		t.Fatal("AF_PACKET observer readiness deadline")
	}
	return stop
}

func TestOfficialCoreGraphUserspaceWireGuardDataAndWrongKey(t *testing.T) {
	bin, digest, version := portableOfficialCore(t)
	privateA, publicA := graphWGKeys(t)
	privateB, publicB := graphWGKeys(t)
	listenPort, readyPort := graphFreePort(t, "udp4"), graphFreePort(t, "tcp4")
	landing := graphSOCKSServer(readyPort, "127.0.0.2")
	landing["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "wg-landing", "system": false, "mtu": 1408, "address": []string{"10.79.0.2/32"}, "private_key": privateB, "listen_port": listenPort, "peers": []any{map[string]any{"public_key": publicA, "allowed_ips": []string{"10.79.0.1/32"}}}}}
	landing["route"] = map[string]any{"final": "fixture-exit", "rules": []any{map[string]any{"inbound": []string{"wg-landing"}, "action": "route", "outbound": "fixture-exit"}}}
	stopLanding := graphFixtureCore(t, bin, landing, readyPort)
	peerPort := listenPort
	if os.Getenv("QINGNODE_WG_TRACE_RELAY") == "1" {
		relay := graphStartWGRelay(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
		peerPort = relay.connection.LocalAddr().(*net.UDPAddr).Port
		t.Cleanup(func() { t.Logf("WireGuard public message timing (bounded, no payload/key bytes): %s", relay.summary()) })
	}
	stopObserver := graphWGPacketObserver(t, listenPort)
	var requests atomic.Int64
	var targetConnections, targetActive atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = w.Write([]byte(host))
	}))
	target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			targetConnections.Add(1)
		}
		if state == http.StateActive {
			targetActive.Add(1)
		}
	}
	target.StartTLS()
	t.Cleanup(func() {
		if os.Getenv("QINGNODE_WG_PACKET_OBSERVER") == "1" {
			t.Logf("controlled HTTPS origin TCP connections=%d active HTTP requests=%d handler calls=%d", targetConnections.Load(), targetActive.Load(), requests.Load())
		}
	})
	defer target.Close()
	udpTarget, udpRequests, udpSource := graphUDPTarget(t)
	wg := graphTestWG()
	wg["tag"] = "egress-wg"
	wg["private_key"] = privateA
	wg["peers"] = []any{map[string]any{"address": "127.0.0.1", "port": peerPort, "public_key": publicB, "allowed_ips": []string{"0.0.0.0/0"}}}
	p, err := NewGraphProfile("userspace-wg", version, "egress-wg", nil, []json.RawMessage{graphTestRaw(t, wg)})
	if err != nil {
		t.Fatal(err)
	}
	s := graphSandbox(t, p, bin, digest)
	client := graphHTTPSClient(t, s, target)
	// The peer's interface address is explicitly mapped to its own loopback
	// service by sing-box's WG endpoint. This avoids gVisor treating a requested
	// 127/8 address as the initiating stack's local loopback route.
	wgURL := strings.Replace(target.URL, "127.0.0.1", "10.79.0.2", 1)
	wgUDP := strings.Replace(udpTarget, "127.0.0.1", "10.79.0.2", 1)
	firstRequest := time.Now()
	graphRequireHTTPS(t, client, wgURL, "127.0.0.2")
	t.Logf("WireGuard first HTTPS application response after%dms (unchanged2s request deadline)", time.Since(firstRequest).Milliseconds())
	stopObserver()
	u, err := RunUDP(context.Background(), UDPOptions{Target: wgUDP, ProxyAddress: s.Address, ProxyUsername: s.Username, ProxyPassword: s.Password, Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
	if err != nil || u.Received != 2 || udpRequests.Load() != 2 || udpSource.Load() != "127.0.0.2" {
		t.Fatalf("WG handshake did not produce correct end-to-end UDP: %+v %v source=%v", u, err, udpSource.Load())
	}
	_, wrongPublic := graphWGKeys(t)
	wg["peers"].([]any)[0].(map[string]any)["public_key"] = wrongPublic
	bad, err := NewGraphProfile("wrong-wg-key", version, "egress-wg", nil, []json.RawMessage{graphTestRaw(t, wg)})
	if err != nil {
		t.Fatal(err)
	}
	badSandbox := graphSandbox(t, bad, bin, digest)
	badClient := graphHTTPSClient(t, badSandbox, target)
	before := requests.Load()
	response, err := badClient.Get(wgURL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || requests.Load() != before {
		t.Fatal("wrong WireGuard peer key unexpectedly reached target")
	}
	badUDPBefore := udpRequests.Load()
	badUDP, badUDPErr := RunUDP(context.Background(), UDPOptions{Target: wgUDP, ProxyAddress: badSandbox.Address, ProxyUsername: badSandbox.Username, ProxyPassword: badSandbox.Password, Samples: 1, PayloadBytes: 64, Timeout: 700 * time.Millisecond})
	if badUDPErr == nil || badUDP.Received != 0 || udpRequests.Load() != badUDPBefore {
		t.Fatalf("wrong WireGuard peer key allowed UDP: %+v %v", badUDP, badUDPErr)
	}
	portableAssertClean(t, badSandbox)
	stopLanding()
	before = requests.Load()
	response, err = client.Get(wgURL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || requests.Load() != before {
		t.Fatal("stopped WireGuard landing fell back to direct")
	}
	beforeUDP := udpRequests.Load()
	u, udpErr := RunUDP(context.Background(), UDPOptions{Target: wgUDP, ProxyAddress: s.Address, ProxyUsername: s.Username, ProxyPassword: s.Password, Samples: 1, PayloadBytes: 64, Timeout: 700 * time.Millisecond})
	if udpErr == nil || u.Received != 0 || udpRequests.Load() != beforeUDP {
		t.Fatalf("stopped WG landing leaked UDP: %+v %v", u, udpErr)
	}
	control, err := target.Client().Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	control.Body.Close()
	portableAssertClean(t, s)
	t.Logf("official %s userspace WireGuard system=false: HTTPS+2 sequence UDP replies observed landing source127.0.0.2; wrong key and stopped landing fail, origin stays directly reachable; no host interface or route configured", version)
}

func TestOfficialCoreGraphCancellationAndCrashCleanup(t *testing.T) {
	bin, digest, version := portableOfficialCore(t)
	port := graphFreePort(t, "tcp4")
	graphFixtureCore(t, bin, graphSOCKSServer(port, "127.0.0.1"), port)
	o := graphTestSOCKS("one", "")
	o["server_port"] = port
	p, err := NewGraphProfile("cleanup-graph", version, "one", []json.RawMessage{graphTestRaw(t, o)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"cancel", "crash"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := StartGraphSandbox(ctx, p, SandboxOptions{CoreBinary: bin, SHA256: digest, TempParent: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if kind == "cancel" {
				cancel()
			} else {
				if err = s.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-s.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("graph process failed to exit")
			}
			portableAssertClean(t, s)
		})
	}
}
