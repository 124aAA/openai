//go:build linux

package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestProbeLocalBindingsActualDualUDPWildcardConflict(t *testing.T) {
	if err := endpointDualStackPrerequisite(); err != nil {
		t.Skipf("IPv6 dual-stack-specific preflight not verified: %v", err)
	}
	port := freePort(t)
	bindings := []LocalBinding{{Network: "udp", Address: "::", Port: port}, {Network: "udp", Address: "0.0.0.0", Port: port}}
	if overlap, certain := BindingOverlap(bindings[0], bindings[1]); overlap || certain {
		t.Fatal("cross-family socket semantics were guessed")
	}
	if _, err := ProbeLocalBindings(context.Background(), bindings, BindingProbeOptions{}); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("actual dual-stack UDP conflict passed preflight", err)
	}
}

// This is an actual wildcard inbound, not an IPv6 relay to an IPv4 core.
// Host capability is established before starting the official core; every
// subsequent failure is a test failure, including an official IPv6 failure.
func TestOfficialCoreSingleSS2022WildcardDualStackTCPUDP(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("set SING_BOX_BIN to a verified official 1.14.x binary")
	}
	if err := endpointDualStackPrerequisite(); err != nil {
		t.Skipf("this dual-stack-only test requires one local :: socket to exchange IPv4 and IPv6 TCP/UDP: %v", err)
	}
	n := ssFixture()
	n.Listen, n.Host, n.Port = "::", "127.0.0.1", freePort(t)
	n.ConnectPort = &n.Port
	s := NewState()
	s.Nodes = []Node{n}
	config, err := Server(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Inbounds []struct {
			Listen string `json:"listen"`
		} `json:"inbounds"`
	}
	if err = json.Unmarshal(config, &rendered); err != nil || len(rendered.Inbounds) != 1 || rendered.Inbounds[0].Listen != "::" {
		t.Fatal("expected exactly one wildcard IPv6 server inbound", err)
	}
	path := filepath.Join(t.TempDir(), "server.json")
	if err = os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := exec.CommandContext(ctx, bin, "check", "-c", path).CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("official core rejected single :: inbound: %v (%s)", err, Redact(string(out), s))
	}
	logfile, err := os.CreateTemp(t.TempDir(), "dual-stack-core-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = logfile, logfile
	if err = cmd.Start(); err != nil {
		logfile.Close()
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("dual-stack core did not stop")
		}
		logfile.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logfile.Name())
			t.Logf("dual-stack core log: %s", Redact(string(b), s))
		}
	})
	if err = waitCoreListeners(pid, config, done, 5*time.Second); err != nil {
		t.Fatal("official single :: inbound did not become ready", err)
	}
	var hits atomic.Int64
	payload := []byte("qingnode-single-core-dual-stack-payload")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(payload)
	}))
	defer origin.Close()
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			selected := n
			selected.Host = host
			mixedPort := freePort(t)
			clientConfig := Client(selected, selected.Users[0], mixedPort)
			outbound := clientConfig["outbounds"].([]any)
			if len(outbound) != 1 || outbound[0].(M)["server"] != host || outbound[0].(M)["server_port"] != n.Port {
				t.Fatal("client must use only the selected literal address and same server port")
			}
			b, err := json.Marshal(clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, b)
			proxy, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
			before := hits.Load()
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal("first and only HTTP request through selected address failed", err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+1)))
			response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) || hits.Load() != before+1 {
				t.Fatalf("HTTP payload/status/origin count mismatch: status=%d bytes=%d hits=%d error=%v", response.StatusCode, len(body), hits.Load()-before, readErr)
			}
			socksUDP(t, mixedPort)
			if err = waitCoreListeners(pid, config, done, time.Second); err != nil || cmd.Process.Pid != pid {
				t.Fatal("single server PID must still own both TCP and UDP listeners", err)
			}
			t.Logf("same official SS2022 server PID %d, listen [::]:%d, outer address %s: HTTP payload and SOCKS UDP echo passed", pid, n.Port, host)
		})
	}
	if hits.Load() != 2 {
		t.Fatalf("expected exactly two controlled origin requests, got %d", hits.Load())
	}
}

// These sockets are owned by this test and always closed. No sysctl, route or
// firewall change is used to make the host support mapped IPv4 on ::.
func endpointDualStackPrerequisite() error {
	tcp, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		return fmt.Errorf("wildcard TCP bind: %w", err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		return fmt.Errorf("wildcard UDP bind: %w", err)
	}
	defer udp.Close()
	for _, family := range []struct{ suffix, host string }{{"4", "127.0.0.1"}, {"6", "::1"}} {
		if err = endpointDualStackTCP(tcp.(*net.TCPListener), family.suffix, family.host); err != nil {
			return err
		}
		if err = endpointDualStackUDP(udp, family.suffix, family.host); err != nil {
			return err
		}
	}
	return nil
}

func endpointDualStackTCP(listener *net.TCPListener, family, host string) error {
	deadline := time.Now().Add(2 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		return err
	}
	client, err := net.DialTimeout("tcp"+family, net.JoinHostPort(host, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)), time.Until(deadline))
	if err != nil {
		return fmt.Errorf("TCP%s loopback: %w", family, err)
	}
	defer client.Close()
	_ = client.SetDeadline(deadline)
	peer, err := listener.Accept()
	if err != nil {
		return err
	}
	defer peer.Close()
	_ = peer.SetDeadline(deadline)
	if _, err = client.Write([]byte{42}); err != nil {
		return err
	}
	b := make([]byte, 1)
	if _, err = io.ReadFull(peer, b); err != nil || b[0] != 42 {
		return fmt.Errorf("TCP%s receive: byte=%d error=%v", family, b[0], err)
	}
	if _, err = peer.Write(b); err != nil {
		return err
	}
	if _, err = io.ReadFull(client, b); err != nil || b[0] != 42 {
		return fmt.Errorf("TCP%s echo: byte=%d error=%v", family, b[0], err)
	}
	return nil
}

func endpointDualStackUDP(listener net.PacketConn, family, host string) error {
	deadline := time.Now().Add(2 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		return err
	}
	client, err := net.DialTimeout("udp"+family, net.JoinHostPort(host, strconv.Itoa(listener.LocalAddr().(*net.UDPAddr).Port)), time.Until(deadline))
	if err != nil {
		return fmt.Errorf("UDP%s loopback: %w", family, err)
	}
	defer client.Close()
	_ = client.SetDeadline(deadline)
	if _, err = client.Write([]byte{42}); err != nil {
		return err
	}
	b := make([]byte, 1)
	n, source, err := listener.ReadFrom(b)
	if err != nil || n != 1 || b[0] != 42 {
		return fmt.Errorf("UDP%s receive: bytes=%d error=%v", family, n, err)
	}
	if _, err = listener.WriteTo(b, source); err != nil {
		return err
	}
	n, err = client.Read(b)
	if err != nil || n != 1 || b[0] != 42 {
		return fmt.Errorf("UDP%s echo: bytes=%d error=%v", family, n, err)
	}
	return nil
}
