//go:build linux

package node

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func deviceOfficialInputs(t *testing.T) (core, version, mihomo string) {
	t.Helper()
	core, mihomo = os.Getenv("SING_BOX_BIN"), os.Getenv("MIHOMO_BIN")
	if core == "" || mihomo == "" {
		t.Skip("requires verified official SING_BOX_BIN and MIHOMO_BIN; batch client parser/data evidence absent")
	}
	output, err := exec.Command(core, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	version = strings.TrimSpace(strings.TrimPrefix(strings.Split(string(output), "\n")[0], "sing-box version "))
	if version != "1.14.0" && version != "1.14.3" {
		t.Fatal("fixture only audits official sing-box 1.14.0/1.14.3")
	}
	mihomoVersion, err := exec.Command(mihomo, "-v").Output()
	if err != nil || !strings.Contains(string(mihomoVersion), "v1.19.30") {
		t.Fatal("fixture requires official Mihomo v1.19.30")
	}
	t.Logf("actual sing-box %s; %s", version, strings.TrimSpace(string(mihomoVersion)))
	return
}

func TestDeviceOfficialClientParserMatrix(t *testing.T) {
	core, version, mihomo := deviceOfficialInputs(t)
	s, p := deviceFixture(t)
	for _, strategy := range []string{"manual", "auto", "fallback"} {
		for _, routing := range []string{"global", "basic"} {
			for _, format := range []string{"sing-box", "mihomo"} {
				t.Run(format+"/"+strategy+"/"+routing, func(t *testing.T) {
					q := p
					q.Strategy, q.Routing = strategy, routing
					if strategy != "manual" {
						q.TestURL = "https://controlled.example.test/health"
					}
					if strategy == "auto" && format == "mihomo" {
						if _, err := ExportDeviceProfile(s, q, format, "1.19.30", false); err == nil {
							t.Fatal("known Mihomo first-member tolerance defect must refuse by default")
						}
						q.AllowDegradedAuto = true
					}
					v := version
					if format == "mihomo" {
						v = "1.19.30"
					}
					r, err := ExportDeviceProfile(s, q, format, v, false)
					if strategy == "fallback" && format == "sing-box" {
						if err == nil {
							t.Fatal("unsupported client strategy must refuse before rendering")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					private := t.TempDir()
					path := filepath.Join(private, "device.config")
					if err = os.WriteFile(path, r.Content, 0600); err != nil {
						t.Fatal(err)
					}
					command := exec.Command(core, "check", "-c", path)
					if format == "mihomo" {
						command = exec.Command(mihomo, "-t", "-d", private, "-f", path)
					}
					if err = command.Run(); err != nil {
						t.Fatal("official client parser rejected generated batch configuration", err)
					}
				})
			}
		}
	}
}

// The normal client export retains public CA verification. A private test CA is
// installed only inside this test's child process, never into production State
// or the host trust store. No skip-cert-verify/insecure fields are introduced.
func deviceStartMihomo(t *testing.T, bin string, cfg M, cert string) func() {
	t.Helper()
	private := t.TempDir()
	path := filepath.Join(private, "client.yaml")
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = exec.Command(bin, "-t", "-d", private, "-f", path).Run(); err != nil {
		t.Fatal("official Mihomo parser rejected batch configuration", err)
	}
	caPath := filepath.Join(private, "fixture-ca.pem")
	if err = os.WriteFile(caPath, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(private, "running")
	readyCommand := "umask 077; printf ready > '" + strings.ReplaceAll(ready, "'", "'\\''") + "'"
	cmd := exec.Command(bin, "-d", private, "-f", path, "-post-up", readyCommand)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath, "SSL_CERT_DIR="+private, "DISABLE_SYSTEM_CA=false")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("owned batch Mihomo did not exit")
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, err := os.ReadFile(ready); err == nil && string(data) == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Mihomo did not complete OnRunning/post-up barrier")
		}
		select {
		case <-done:
			t.Fatal("owned batch Mihomo exited before readiness")
		case <-time.After(20 * time.Millisecond):
		}
	}
	port := cfg["mixed-port"].(int)
	listener, _ := json.Marshal(M{"inbounds": []any{M{"type": "mixed", "listen_port": port}}})
	if err = waitCoreListeners(cmd.Process.Pid, listener, done, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	return stop
}

func deviceHTTPClient(port int) *http.Client {
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: 5 * time.Second}
}

func deviceRequirePayload(t *testing.T, client *http.Client, target, want string) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal("actual batch client TCP request failed", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != want {
		t.Fatalf("actual batch client payload mismatch: status=%d bytes=%d read_error=%v", response.StatusCode, len(body), err)
	}
}

func TestDeviceOfficialFullConfigsTCPUDPAndNoDirectFallback(t *testing.T) {
	core, version, mihomo := deviceOfficialInputs(t)
	cert, key := makeCert(t)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "handshake") }))
	handshake.EnableHTTP2 = true
	handshake.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	handshake.StartTLS()
	defer handshake.Close()
	for _, format := range []string{"sing-box", "mihomo"} {
		for _, protocol := range []string{"reality", "ss2022", "hysteria2"} {
			t.Run(format+"/"+protocol, func(t *testing.T) {
				s, p := deviceFixture(t)
				s.CoreVersion = version
				for i := range s.Nodes {
					n := &s.Nodes[i]
					n.Name = "入口-" + n.Protocol
					n.Users[0].Name, n.Users[1].Name = "selected", "unselected"
					n.Host, n.Listen, n.Port, n.ConnectPort = "127.0.0.1", "127.0.0.1", freePort(t), nil
					n.AdditionalEndpoints = nil
					p.Bindings[i].EndpointID = ""
					if n.Protocol == "reality" {
						n.Reality, err = NewReality("localhost", handshake.Listener.Addr().String())
						if err != nil {
							t.Fatal(err)
						}
					}
					if n.Protocol == "hysteria2" {
						n.Certificate = &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}
					}
				}
				server, err := Server(s, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				stopServer := probeTestCore(t, core, server)
				var hits atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					_, _ = io.WriteString(w, "controlled-batch-device-payload")
				}))
				defer origin.Close()
				v := version
				if format == "mihomo" {
					v = "1.19.30"
				}
				r, err := ExportDeviceProfile(s, p, format, v, false)
				if err != nil {
					t.Fatal(err)
				}
				port := freePort(t)
				if format == "sing-box" {
					var cfg M
					if err = json.Unmarshal(r.Content, &cfg); err != nil {
						t.Fatal(err)
					}
					cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"] = port
					selected := ""
					for _, raw := range cfg["outbounds"].([]any) {
						out := raw.(map[string]any)
						if out["type"] == "hysteria2" {
							out["tls"].(map[string]any)["certificate"] = []string{cert}
						}
						want := protocol
						if protocol == "reality" {
							want = "vless"
						} else if protocol == "ss2022" {
							want = "shadowsocks"
						}
						if out["type"] == want {
							selected = out["tag"].(string)
						}
					}
					for _, raw := range cfg["outbounds"].([]any) {
						out := raw.(map[string]any)
						if out["type"] == "selector" {
							out["default"] = selected
						}
					}
					data, _ := json.Marshal(cfg)
					probeTestCore(t, core, data)
				} else {
					var cfg M
					if err = yaml.Unmarshal(r.Content, &cfg); err != nil {
						t.Fatal(err)
					}
					cfg["mixed-port"] = port
					group := cfg["proxy-groups"].([]any)[0].(map[string]any)
					selected := ""
					for _, raw := range cfg["proxies"].([]any) {
						proxy := raw.(map[string]any)
						want := protocol
						if protocol == "reality" {
							want = "vless"
						} else if protocol == "ss2022" {
							want = "ss"
						}
						if proxy["type"] == want {
							selected = proxy["name"].(string)
						}
					}
					old := group["proxies"].([]any)
					ordered := []any{selected}
					for _, name := range old {
						if name != selected {
							ordered = append(ordered, name)
						}
					}
					group["proxies"] = ordered
					deviceStartMihomo(t, mihomo, cfg, cert)
				}
				client := deviceHTTPClient(port)
				defer client.CloseIdleConnections()
				deviceRequirePayload(t, client, origin.URL, "controlled-batch-device-payload")
				socksUDP(t, port) // A separate actual UDP exchange, not inferred from HTTP.
				if hits.Load() != 1 {
					t.Fatal("unexpected target requests")
				}
				stopServer()
				if response, err := client.Get(origin.URL); err == nil {
					response.Body.Close()
					if response.StatusCode == http.StatusOK {
						t.Fatal("stopped selected proxy passed via hidden direct fallback")
					}
				}
				if hits.Load() != 1 {
					t.Fatal("target reached after all declared entrances stopped")
				}
			})
		}
	}
}

func deviceControlJSON(t *testing.T, controller, path string, output any, secret ...string) {
	t.Helper()
	status := deviceControlStatusJSON(t, controller, path, output, secret...)
	if status != http.StatusOK {
		t.Fatal("owned client controller returned an unexpected status", status)
	}
}

func deviceControlStatusJSON(t *testing.T, controller, path string, output any, secret ...string) int {
	t.Helper()
	client := &http.Client{Timeout: 8 * time.Second}
	request, err := http.NewRequest(http.MethodGet, controller+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) > 0 {
		request.Header.Set("Authorization", "Bearer "+secret[0])
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("owned client controller", err)
	}
	defer response.Body.Close()
	if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(output) != nil {
		t.Fatal("owned client controller returned an invalid bounded response", response.StatusCode)
	}
	return response.StatusCode
}

func TestDeviceMihomoOrderedFallbackRealPrimaryFailure(t *testing.T) {
	core, version, mihomo := deviceOfficialInputs(t)
	s := NewState()
	s.CoreVersion = version
	p := DeviceProfile{ID: Token(8), Name: "受控主备", Strategy: "fallback", TimeoutMS: 1000}
	stops := []func(){}
	for i := 0; i < 2; i++ {
		n := ssFixture()
		n.Name, n.Listen, n.Host, n.Port = fmt.Sprintf("entry-%d", i), "127.0.0.1", "127.0.0.1", freePort(t)
		one := NewState()
		one.CoreVersion, one.Nodes = version, []Node{n}
		server, err := Server(one, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		stops = append(stops, probeTestCore(t, core, server))
		s.Nodes = append(s.Nodes, n)
		p.Bindings = append(p.Bindings, DeviceBinding{NodeID: n.ID, UserID: n.Users[0].ID})
	}
	cert, key := makeCert(t)
	pair, _ := tls.X509KeyPair([]byte(cert), []byte(key))
	var healthRequests atomic.Int32
	health := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthRequests.Add(1)
		// Fixed Mihomo v1.19.30 adapter/adapter.go URLTest truncates elapsed
		// time to integer milliseconds; hub/route/proxies.go getProxyDelay
		// returns 503 for delay == 0 even when the HTTPS request succeeded.
		// Keep this controlled response above that quantization boundary,
		// preserving every status/delay and actual fallback-data assertion.
		// The old 503/0ms log alone cannot prove which cause occurred.
		timer := time.NewTimer(5 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			w.WriteHeader(204)
		}
	}))
	health.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	health.StartTLS()
	defer health.Close()
	p.TestURL = health.URL
	r, err := ExportDeviceProfile(s, p, "mihomo", "1.19.30", false)
	if err != nil {
		t.Fatal(err)
	}
	var cfg M
	if err = yaml.Unmarshal(r.Content, &cfg); err != nil {
		t.Fatal(err)
	}
	port, controlPort := freePort(t), freePort(t)
	cfg["mixed-port"], cfg["external-controller"] = port, "127.0.0.1:"+strconv.Itoa(controlPort)
	secret := Token(32)
	cfg["secret"] = secret
	deviceStartMihomo(t, mihomo, cfg, cert)
	controller := "http://127.0.0.1:" + strconv.Itoa(controlPort)
	names := []string{}
	for i, b := range p.Bindings {
		names = append(names, deviceExportName(s.Nodes[i], s.Nodes[i].Users[0], b))
	}
	forceHealth := func(phase string, alive []bool) {
		t.Helper()
		t.Logf("forced fallback health phase=%s expected_primary_alive=%t expected_backup_alive=%t", phase, alive[0], alive[1])
		query := url.Values{"url": {health.URL}, "timeout": {"2000"}}.Encode()
		for i, name := range names {
			var result struct {
				Delay   uint16 `json:"delay"`
				Message string `json:"message"`
			}
			hitsBefore := healthRequests.Load()
			status := deviceControlStatusJSON(t, controller, "/proxies/"+url.PathEscape(name)+"/delay?"+query, &result, secret)
			hitsAfter := healthRequests.Load()
			if alive[i] {
				if status != http.StatusOK || result.Delay == 0 {
					t.Fatalf("phase=%s member=%d live entrance health failed: status=%d delay_ms=%d message=%q target_hits_before=%d target_hits_after=%d", phase, i, status, result.Delay, Redact(result.Message, s), hitsBefore, hitsAfter)
				}
				if hitsAfter <= hitsBefore {
					t.Fatalf("phase=%s member=%d live entrance health did not reach controlled HTTPS target: target_hits_before=%d target_hits_after=%d", phase, i, hitsBefore, hitsAfter)
				}
			} else if status != http.StatusServiceUnavailable || result.Message != "An error occurred in the delay test" {
				// The owned listener was stopped, so an immediate connection
				// failure is expected, not a masked controller timeout.
				t.Fatalf("phase=%s member=%d stopped entrance did not report the fixed-version unavailable error: status=%d message=%q", phase, i, status, result.Message)
			}
			t.Logf("fallback member health phase=%s member=%d status=%d delay_ms=%d target_hits_before=%d target_hits_after=%d", phase, i, status, result.Delay, hitsBefore, hitsAfter)
		}
		// This native group endpoint explicitly clears a forced selection,
		// tests its declared members, and lets fallback find the first alive.
		if !alive[0] && !alive[1] {
			var result struct {
				Message string `json:"message"`
			}
			status := deviceControlStatusJSON(t, controller, "/group/PROXY/delay?"+query, &result, secret)
			if status != http.StatusGatewayTimeout || result.Message != "get delay: all proxies timeout" {
				t.Fatalf("phase=%s all-dead group did not return the audited native error: status=%d message=%q", phase, status, result.Message)
			}
			t.Logf("fallback group health phase=%s status=504 all declared entrances unavailable; no authorized direct fallback", phase)
			return
		}
		var result map[string]uint16
		deviceControlJSON(t, controller, "/group/PROXY/delay?"+query, &result, secret)
		for i, name := range names {
			measured, exists := result[name]
			if exists != alive[i] || exists && measured == 0 {
				t.Fatalf("phase=%s member=%d group health results disagree with actual entrance availability", phase, i)
			}
		}
	}
	selected := func() string {
		var group struct {
			Now string `json:"now"`
		}
		deviceControlJSON(t, controller, "/group/PROXY", &group, secret)
		return group.Now
	}
	forceHealth("both-alive", []bool{true, true})
	if selected() != deviceExportName(s.Nodes[0], s.Nodes[0].Users[0], p.Bindings[0]) {
		t.Fatal("ordered fallback did not prefer the first healthy entrance")
	}
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "controlled-fallback-payload")
	}))
	defer origin.Close()
	client := deviceHTTPClient(port)
	defer client.CloseIdleConnections()
	deviceRequirePayload(t, client, origin.URL, "controlled-fallback-payload")
	socksUDP(t, port)
	stops[0]()
	forceHealth("primary-stopped", []bool{false, true})
	if selected() != deviceExportName(s.Nodes[1], s.Nodes[1].Users[0], p.Bindings[1]) {
		t.Fatal("failed primary did not choose declared backup")
	}
	deviceRequirePayload(t, client, origin.URL, "controlled-fallback-payload")
	socksUDP(t, port)
	stops[1]()
	forceHealth("both-stopped", []bool{false, false})
	if response, err := client.Get(origin.URL); err == nil {
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("all-dead fallback reached target without a permitted entrance")
		}
	}
	if hits.Load() != 2 {
		t.Fatal("all-dead fallback reached the controlled target")
	}
}

// This fixture adds delay to each new TCP connection before copying any data;
// it is an actual byte relay to the authenticated SS2022 server, not invented
// latency history. It owns every listener, connection, timer and goroutine.
func deviceDelayedRelay(t *testing.T, destination string) (port int, delay *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	delay = &atomic.Int64{}
	owned := map[net.Conn]bool{}
	var mu sync.Mutex
	var copies sync.WaitGroup
	acceptDone, stop := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			owned[incoming] = true
			mu.Unlock()
			copies.Add(1)
			go func() {
				defer copies.Done()
				defer incoming.Close()
				defer func() { mu.Lock(); delete(owned, incoming); mu.Unlock() }()
				timer := time.NewTimer(time.Duration(delay.Load()))
				defer timer.Stop()
				select {
				case <-stop:
					return
				case <-timer.C:
				}
				outgoing, err := net.DialTimeout("tcp4", destination, 2*time.Second)
				if err != nil {
					return
				}
				defer outgoing.Close()
				mu.Lock()
				owned[outgoing] = true
				mu.Unlock()
				defer func() { mu.Lock(); delete(owned, outgoing); mu.Unlock() }()
				select {
				case <-stop:
					return
				default:
				}
				done := make(chan struct{})
				go func() { _, _ = io.Copy(outgoing, incoming); close(done) }()
				_, _ = io.Copy(incoming, outgoing)
				_ = incoming.Close()
				_ = outgoing.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		close(stop)
		_ = listener.Close()
		<-acceptDone
		mu.Lock()
		for connection := range owned {
			_ = connection.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { copies.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("controlled TCP delay relay did not stop all owned copies")
		}
	})
	return listener.Addr().(*net.TCPAddr).Port, delay
}

func TestDeviceOfficialAutoToleranceWithControlledRelayDelays(t *testing.T) {
	core, version, _ := deviceOfficialInputs(t)
	deviceControlledAutoDelayFixture(t, core, version, "", "sing-box")
}

// This is a reproduction of the audited v1.19.30 defect, not a passing
// tolerance guarantee. The production export requires explicit acceptance.
func TestDeviceMihomo11930FirstMemberToleranceDefectAndExplicitOptIn(t *testing.T) {
	core, version, mihomo := deviceOfficialInputs(t)
	deviceControlledAutoDelayFixture(t, core, version, mihomo, "mihomo")
}

func deviceControlledAutoDelayFixture(t *testing.T, core, version, mihomo, format string) {
	t.Helper()
	cert, key := makeCert(t)
	pair, _ := tls.X509KeyPair([]byte(cert), []byte(key))
	health := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	health.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	health.StartTLS()
	defer health.Close()
	private := t.TempDir()
	caPath := filepath.Join(private, "auto-fixture-ca.pem")
	if err := os.WriteFile(caPath, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	// The isolated child core reads this CA. No OS trust file changes.
	t.Setenv("SSL_CERT_FILE", caPath)
	t.Setenv("SSL_CERT_DIR", private)
	s := NewState()
	s.CoreVersion = version
	p := DeviceProfile{ID: Token(8), Name: "受控容差", Strategy: "auto", TestURL: health.URL, ToleranceMS: 300}
	delays := []*atomic.Int64{}
	for i := 0; i < 2; i++ {
		n := ssFixture()
		n.ID = []string{"1111111111111111", "3333333333333333"}[i]
		n.Name, n.Listen, n.Host, n.Port = fmt.Sprintf("auto-entry-%d", i), "127.0.0.1", "127.0.0.1", freePort(t)
		one := NewState()
		one.CoreVersion, one.Nodes = version, []Node{n}
		server, err := Server(one, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		probeTestCore(t, core, server)
		relayPort, delay := deviceDelayedRelay(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(n.Port)))
		n.ConnectPort = &relayPort
		delays = append(delays, delay)
		s.Nodes = append(s.Nodes, n)
		p.Bindings = append(p.Bindings, DeviceBinding{NodeID: n.ID, UserID: n.Users[0].ID})
	}
	delays[0].Store(int64(10 * time.Millisecond))
	delays[1].Store(int64(700 * time.Millisecond))
	clientVersion := version
	if format == "mihomo" {
		clientVersion = "1.19.30"
		if _, err := ExportDeviceProfile(s, p, format, clientVersion, false); err == nil {
			t.Fatal("known first-member tolerance defect was not refused before explicit opt-in")
		}
		p.AllowDegradedAuto = true
	}
	r, err := ExportDeviceProfile(s, p, format, clientVersion, false)
	if err != nil {
		t.Fatal(err)
	}
	if format == "mihomo" && !strings.Contains(strings.Join(r.Warnings, "\n"), "不能保证容差防抖") {
		t.Fatal("real degraded client fixture did not retain the public export warning")
	}
	port, controlPort, secret := freePort(t), freePort(t), Token(32)
	controller := "http://127.0.0.1:" + strconv.Itoa(controlPort)
	if format == "sing-box" {
		var cfg M
		if err = json.Unmarshal(r.Content, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"] = port
		cfg["experimental"] = M{"clash_api": M{"external_controller": "127.0.0.1:" + strconv.Itoa(controlPort), "secret": secret}}
		data, _ := json.Marshal(cfg)
		probeTestCore(t, core, data)
	} else {
		var cfg M
		if err = yaml.Unmarshal(r.Content, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["mixed-port"], cfg["external-controller"], cfg["secret"] = port, "127.0.0.1:"+strconv.Itoa(controlPort), secret
		deviceStartMihomo(t, mihomo, cfg, cert)
	}
	// Readiness only: no test target or proxy traffic is sent here.
	deadline := time.Now().Add(5 * time.Second)
	for {
		request, _ := http.NewRequest(http.MethodGet, controller+"/version", nil)
		request.Header.Set("Authorization", "Bearer "+secret)
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("private authenticated controller was not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	names := []string{}
	for i, b := range p.Bindings {
		name := deviceExportTag(b)
		if format == "mihomo" {
			name = deviceExportName(s.Nodes[i], s.Nodes[i].Users[0], b)
		}
		names = append(names, name)
	}
	forceHealth := func() (int, int) {
		measurements := map[string]uint16{}
		query := url.Values{"url": {health.URL}, "timeout": {"3000"}}.Encode()
		if format == "mihomo" {
			deviceControlJSON(t, controller, "/group/PROXY/delay?"+query, &measurements, secret)
		} else {
			for _, name := range names {
				var result struct {
					Delay uint16 `json:"delay"`
				}
				deviceControlJSON(t, controller, "/proxies/"+url.PathEscape(name)+"/delay?"+query, &result, secret)
				measurements[name] = result.Delay
			}
		}
		first, one := measurements[names[0]]
		second, two := measurements[names[1]]
		if !one || !two || first == 0 || second == 0 {
			t.Fatal("forced health did not return two actual valid delay samples")
		}
		return int(first), int(second)
	}
	selected := func() string {
		if format == "mihomo" {
			// Fixed v1.19.30 caches the selected URLTest result for 10s.
			// Let that exact cache expire before assessing new samples.
			time.Sleep(11 * time.Second)
		}
		var group struct {
			Now string `json:"now"`
		}
		deviceControlJSON(t, controller, "/proxies/PROXY", &group, secret)
		return group.Now
	}
	first, second := forceHealth()
	if second-first <= p.ToleranceMS || selected() != names[0] {
		t.Fatalf("initial controlled difference did not select first: first_ms=%d second_ms=%d tolerance_ms=%d", first, second, p.ToleranceMS)
	}
	t.Logf("initial forced HTTPS samples first_ms=%d second_ms=%d selected=first tolerance_ms=%d", first, second, p.ToleranceMS)
	delays[0].Store(int64(140 * time.Millisecond))
	delays[1].Store(int64(100 * time.Millisecond))
	if format == "mihomo" {
		// urltest.go fast() marks only proxies[1:] as still present.
		// With the first member selected, fastNotExist stays true and
		// bypasses tolerance. Keep this real failure visible.
		first, second = forceHealth()
		if first <= second || first-second >= p.ToleranceMS {
			t.Fatalf("defect fixture did not obtain an inside-tolerance faster second member: first_ms=%d second_ms=%d tolerance_ms=%d", first, second, p.ToleranceMS)
		}
		actual := selected()
		t.Logf("KNOWN v1.19.30 FIRST-MEMBER DEFECT: forced HTTPS first_ms=%d second_ms=%d tolerance_ms=%d expected_without_defect=first actual=%s", first, second, p.ToleranceMS, actual)
		if actual != names[1] {
			t.Fatal("audited fixed-version first-member tolerance defect was not reproduced")
		}
		// Once the second member is current, exercise its actual tolerance
		// rather than claiming the first-member defect has disappeared.
		delays[0].Store(int64(100 * time.Millisecond))
		delays[1].Store(int64(140 * time.Millisecond))
		for round := 1; round <= 3; round++ {
			first, second = forceHealth()
			if second <= first || second-first >= p.ToleranceMS {
				t.Fatalf("second-member tolerance fixture outside its intended range: first_ms=%d second_ms=%d tolerance_ms=%d", first, second, p.ToleranceMS)
			}
			actual = selected()
			t.Logf("second-member inside-tolerance forced HTTPS round=%d first_ms=%d second_ms=%d selected=%s", round, first, second, actual)
			if actual != names[1] {
				t.Fatal("fixed client switched from second member within configured tolerance")
			}
		}
		delays[0].Store(int64(20 * time.Millisecond))
		delays[1].Store(int64(700 * time.Millisecond))
		first, second = forceHealth()
		actual = selected()
		t.Logf("second-member beyond-tolerance forced HTTPS first_ms=%d second_ms=%d selected=%s; default 300s timer not waited; HTTP health does not measure UDP", first, second, actual)
		if second-first <= p.ToleranceMS || actual != names[0] {
			t.Fatal("fixed client did not switch back beyond tolerance")
		}
		return
	}
	for round := 1; round <= 3; round++ {
		first, second = forceHealth()
		if first <= second || first-second >= p.ToleranceMS {
			t.Fatalf("controlled faster backup was not inside tolerance: first_ms=%d second_ms=%d tolerance_ms=%d", first, second, p.ToleranceMS)
		}
		if selected() != names[0] {
			t.Fatal("automatic client switched within its configured delay tolerance")
		}
		t.Logf("within-tolerance forced HTTPS round=%d first_ms=%d second_ms=%d selected=first", round, first, second)
	}
	delays[0].Store(int64(700 * time.Millisecond))
	delays[1].Store(int64(20 * time.Millisecond))
	first, second = forceHealth()
	if first-second <= p.ToleranceMS || selected() != names[1] {
		t.Fatalf("automatic client did not switch beyond tolerance: first_ms=%d second_ms=%d tolerance_ms=%d", first, second, p.ToleranceMS)
	}
	t.Logf("beyond-tolerance forced HTTPS samples first_ms=%d second_ms=%d selected=second; default 300s timer not waited; UDP not measured by HTTP health", first, second)
}
