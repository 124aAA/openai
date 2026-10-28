//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/probe"
)

// These application-level raw relays model an administrator's controlled port
// translation. They change no firewall, route, namespace or production node.
type natTCPForward struct {
	listener    net.Listener
	target      string
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]bool
	wg          sync.WaitGroup
	once        sync.Once
	accepted    atomic.Int64
	bytesIn     atomic.Int64
}

func startNATTCPForward(network, address, target string) (*natTCPForward, error) {
	l, e := net.Listen(network, address)
	if e != nil {
		return nil, e
	}
	f := &natTCPForward{listener: l, target: target, connections: map[net.Conn]bool{}}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			client, e := l.Accept()
			if e != nil {
				return
			}
			f.mu.Lock()
			if f.closed {
				f.mu.Unlock()
				client.Close()
				return
			}
			f.connections[client] = true
			f.wg.Add(1)
			f.mu.Unlock()
			f.accepted.Add(1)
			go func() {
				defer f.wg.Done()
				defer func() { client.Close(); f.mu.Lock(); delete(f.connections, client); f.mu.Unlock() }()
				up, e := net.DialTimeout("tcp4", f.target, time.Second)
				if e != nil {
					return
				}
				f.mu.Lock()
				if f.closed {
					f.mu.Unlock()
					up.Close()
					return
				}
				f.connections[up] = true
				f.mu.Unlock()
				defer func() { up.Close(); f.mu.Lock(); delete(f.connections, up); f.mu.Unlock() }()
				back := make(chan struct{})
				go func() { io.Copy(client, up); client.Close(); up.Close(); close(back) }()
				n, _ := io.Copy(up, client)
				f.bytesIn.Add(n)
				client.Close()
				up.Close()
				<-back
			}()
		}
	}()
	return f, nil
}
func (f *natTCPForward) Close() {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.listener.Close()
		for c := range f.connections {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
}

type natUDPForward struct {
	listener     net.PacketConn
	target       *net.UDPAddr
	mu           sync.Mutex
	closed       bool
	associations map[string]*net.UDPConn
	wg           sync.WaitGroup
	once         sync.Once
	requests     atomic.Int64
	responses    atomic.Int64
}

func startNATUDPForward(network, address, target string) (*natUDPForward, error) {
	upstream, e := net.ResolveUDPAddr("udp4", target)
	if e != nil {
		return nil, e
	}
	l, e := net.ListenPacket(network, address)
	if e != nil {
		return nil, e
	}
	f := &natUDPForward{listener: l, target: upstream, associations: map[string]*net.UDPConn{}}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		buf := make([]byte, 65536)
		for {
			n, source, e := l.ReadFrom(buf)
			if e != nil {
				return
			}
			f.mu.Lock()
			if f.closed {
				f.mu.Unlock()
				return
			}
			up := f.associations[source.String()]
			if up == nil {
				up, e = net.DialUDP("udp4", nil, f.target)
				if e != nil {
					f.mu.Unlock()
					continue
				}
				f.associations[source.String()] = up
				f.wg.Add(1)
				go func(conn *net.UDPConn, client net.Addr) {
					defer f.wg.Done()
					defer conn.Close()
					response := make([]byte, 65536)
					for {
						size, e := conn.Read(response)
						if e != nil {
							return
						}
						if _, e = f.listener.WriteTo(response[:size], client); e != nil {
							return
						}
						f.responses.Add(1)
					}
				}(up, source)
			}
			f.mu.Unlock()
			if _, e = up.Write(buf[:n]); e == nil {
				f.requests.Add(1)
			}
		}
	}()
	return f, nil
}
func (f *natUDPForward) Close() {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.listener.Close()
		for _, c := range f.associations {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
}

// A stopped UDP forwarder leaves an owned silent sink on its external port.
// An actually closed port may send ICMP port-unreachable, which correctly
// produces a transport error rather than the unanswered-datagram case here.
type natSilentUDPSink struct {
	connection net.PacketConn
	packets    atomic.Int64
	done       chan struct{}
	once       sync.Once
}

func startNATSilentUDPSink(address string) (*natSilentUDPSink, error) {
	connection, err := net.ListenPacket("udp4", address)
	if err != nil {
		return nil, err
	}
	sink := &natSilentUDPSink{connection: connection, done: make(chan struct{})}
	go func() {
		defer close(sink.done)
		buffer := make([]byte, 65536)
		for {
			if _, _, err := connection.ReadFrom(buffer); err != nil {
				return
			}
			sink.packets.Add(1)
		}
	}()
	return sink, nil
}

func (sink *natSilentUDPSink) Close() {
	sink.once.Do(func() {
		sink.connection.Close()
		<-sink.done
	})
}

func natClient(t *testing.T, bin string, n Node, cert string) (*http.Client, int) {
	t.Helper()
	port := freePort(t)
	config := Client(n, n.Users[0], port)
	outbound := config["outbounds"].([]any)[0].(M)
	if outbound["server_port"] != EffectiveConnectPort(n) {
		t.Fatal("客户端未使用声明的外部连接端口")
	}
	if n.Protocol == "hysteria2" {
		outbound["tls"].(M)["certificate"] = []string{cert}
	}
	encoded, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, encoded)
	return &http.Client{Transport: probeTransport(t, port, cert, "", ""), Timeout: 3 * time.Second}, port
}

func natRequireHTTP(t *testing.T, client *http.Client, url string, payload []byte) {
	t.Helper()
	r, e := client.Get(url)
	if e != nil {
		t.Fatal("经受控外部映射的真实代理请求失败", e)
	}
	defer r.Body.Close()
	body, e := io.ReadAll(io.LimitReader(r.Body, 4096))
	if e != nil || r.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("真实代理载荷不一致 status=%d error=%v body=%q", r.StatusCode, e, body)
	}
}

func TestOfficialCoreControlledNATEndpoints(t *testing.T) {
	if os.Getenv("QINGNODE_NAT_DISPOSABLE") != "1" {
		t.Skip("固定443/30000/30001仅在QINGNODE_NAT_DISPOSABLE=1的一次性隔离Linux运行")
	}
	if os.Geteuid() != 0 {
		t.Fatal("一次性NAT固定443验收需要root；不把权限不足算通过")
	}
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("缺少已验证官方核心；真实协议NAT项未执行")
	}
	version, e := exec.Command(bin, "version").Output()
	if e != nil {
		t.Fatal(e)
	}
	fields := strings.Fields(strings.SplitN(string(version), "\n", 2)[0])
	if len(fields) != 3 || !SupportedVersion(fields[2]) {
		t.Fatal("官方核心版本无效")
	}
	cert, key := makeCert(t)
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("controlled reality handshake")) }))
	handshake.EnableHTTP2 = true
	handshake.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	handshake.StartTLS()
	defer handshake.Close()
	var targetRequests atomic.Int64
	payload := []byte("qingnode-controlled-NAT-proxy-payload")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetRequests.Add(1); w.Write(payload) })
	https := httptest.NewUnstartedServer(handler)
	https.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	https.StartTLS()
	defer https.Close()
	httpOrigin := httptest.NewServer(handler)
	defer httpOrigin.Close()
	reality, e := NewReality("localhost", handshake.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	rp, hp := 30000, 30001
	state := NewState()
	state.CoreVersion = fields[2]
	state.Nodes = []Node{
		{ID: Token(8), Name: "TCP NAT REALITY", Protocol: "reality", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 443, ConnectPort: &rp, Enabled: true, Users: []User{NewUser("controlled", "reality")}, Reality: reality},
		{ID: Token(8), Name: "UDP NAT HY2", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: 443, ConnectPort: &hp, Enabled: true, Users: []User{NewUser("controlled", "hysteria2")}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}},
	}
	server, e := Server(state, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, server)
	tcpForward, e := startNATTCPForward("tcp4", "127.0.0.1:30000", "127.0.0.1:443")
	if e != nil {
		t.Fatal(e)
	}
	defer tcpForward.Close()
	udpForward, e := startNATUDPForward("udp4", "127.0.0.1:30001", "127.0.0.1:443")
	if e != nil {
		t.Fatal(e)
	}
	defer udpForward.Close()
	for i, n := range state.Nodes {
		t.Run(n.Protocol, func(t *testing.T) {
			client, localPort := natClient(t, bin, n, cert)
			var udpTarget string
			var udpRequests *atomic.Int32
			var udpSink *natSilentUDPSink
			natRequireHTTP(t, client, https.URL, payload)
			natRequireHTTP(t, client, httpOrigin.URL, payload)
			if n.Protocol == "hysteria2" {
				target, requests := probeTestUDP(t, true)
				udpTarget, udpRequests = target, requests
				// The bounded default includes one extra receive byte per sample
				// to distinguish an oversized reply from a valid 64-byte echo.
				result, e := probe.RunUDP(context.Background(), probe.UDPOptions{Target: target, ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), Samples: 2, PayloadBytes: 64, Timeout: time.Second, Interval: 10 * time.Millisecond})
				if e != nil || result.Sent != 2 || result.Received != 2 || result.Lost != 0 || result.SentBytes != 128 || result.ReceivedBytes != 128 || requests.Load() != 2 {
					t.Fatalf("HY2 NAT UDP真实路径失败: %+v %v target=%d", result, e, requests.Load())
				}
				if udpForward.requests.Load() == 0 || udpForward.responses.Load() == 0 {
					t.Fatal("HY2请求未经过声明的UDP转发")
				}
				udpForward.Close()
				udpSink, e = startNATSilentUDPSink("127.0.0.1:30001")
				if e != nil {
					t.Fatal("无法建立测试自有的外端口静默收包端点", e)
				}
				t.Cleanup(udpSink.Close)
			} else {
				if tcpForward.accepted.Load() == 0 {
					t.Fatal("REALITY请求未经过声明的TCP转发")
				}
				tcpForward.Close()
			}
			before := targetRequests.Load()
			// A fresh official client has no cached QUIC/TCP proxy session. The
			// TCP relay is closed, or UDP forwarding is stopped with a silent
			// external-port sink; the server on local443 stays up in both cases.
			blocked, _ := natClient(t, bin, n, cert)
			response, e := blocked.Get(https.URL)
			if response != nil {
				response.Body.Close()
			}
			if e == nil {
				t.Fatal("停止声明的转发后仍成功，可能错误使用了本地443或direct回落")
			}
			if targetRequests.Load() != before {
				t.Fatal("停止转发后错误请求仍到达受控目标")
			}
			if udpRequests != nil {
				beforeUDP := udpRequests.Load()
				// Isolate this association from the canceled HTTP attempt's
				// upstream session and its still-running handshake retries.
				_, udpBlockedPort := natClient(t, bin, n, cert)
				result, udpErr := probe.RunUDP(context.Background(), probe.UDPOptions{Target: udpTarget, ProxyAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(udpBlockedPort)), Samples: 1, PayloadBytes: 64, Timeout: time.Second})
				if udpErr == nil || result.Sent != 1 || result.Received != 0 || result.Lost != 1 || result.SentBytes != 64 || result.ReceivedBytes != 0 || result.Error != "udp_no_response" || len(result.Samples) != 1 || result.Samples[0].Error != "udp_no_response" || udpRequests.Load() != beforeUDP {
					t.Fatalf("UDP转发已停止且外端口静默收包，但未观察到真实请求超时或目标计数不符: %+v %v", result, udpErr)
				}
				if udpSink == nil || udpSink.packets.Load() == 0 {
					t.Fatal("外端口静默收包端点没有收到真实核心发出的数据，不能证明黑洞路径")
				}
				t.Logf("UDP forwarding stopped; external-port silent sink packets=%d; SOCKS UDP sent1 received0 lost1; HTTP/UDP origin counts unchanged", udpSink.packets.Load())
			}
			t.Logf("official %s %s local443 external%d: authenticated HTTPS+HTTP payload; forwarding stopped => fresh client failed, target count unchanged", state.CoreVersion, n.Protocol, EffectiveConnectPort(n))
			t.Run("additional-ipv6", func(t *testing.T) {
				port := 30002 + i
				address := net.JoinHostPort("::1", strconv.Itoa(port))
				var closeRelay func()
				var counter func() int64
				if n.Protocol == "reality" {
					f, e := startNATTCPForward("tcp6", address, "127.0.0.1:443")
					if e != nil {
						if !natIPv6Available() {
							t.Skipf("IPv6本地绑定不可用，仅跳过额外IPv6端点: %v", e)
						}
						t.Fatal(e)
					}
					closeRelay = f.Close
					counter = f.accepted.Load
				} else {
					f, e := startNATUDPForward("udp6", address, "127.0.0.1:443")
					if e != nil {
						if !natIPv6Available() {
							t.Skipf("IPv6本地绑定不可用，仅跳过额外IPv6端点: %v", e)
						}
						t.Fatal(e)
					}
					closeRelay = f.Close
					counter = f.requests.Load
				}
				defer closeRelay()
				n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "controlled-v6", Host: "::1", Port: port}}
				selected, e := WithEndpoint(n, "controlled-v6")
				if e != nil {
					t.Fatal(e)
				}
				v6client, _ := natClient(t, bin, selected, cert)
				natRequireHTTP(t, v6client, https.URL, payload)
				if counter() == 0 {
					t.Fatal("选择额外IPv6端点却未经过其转发")
				}
			})
		})
	}
	if tcpForward.accepted.Load() == 0 || udpForward.requests.Load() == 0 || udpForward.responses.Load() == 0 {
		t.Fatal("缺少独立TCP/UDP转发路径证据")
	}
	t.Logf("controlled TCP forward connections=%d bytes=%d; UDP forward requests=%d responses=%d; origin authenticated requests=%d", tcpForward.accepted.Load(), tcpForward.bytesIn.Load(), udpForward.requests.Load(), udpForward.responses.Load(), targetRequests.Load())
}

func natIPv6Available() bool {
	l, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		return false
	}
	l.Close()
	return true
}
