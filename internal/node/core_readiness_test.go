//go:build linux

package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type coreListener struct {
	Network string
	Port    int
}

func coreListenerRequirements(config []byte) ([]coreListener, error) {
	var c struct {
		Inbounds []struct {
			Type       string `json:"type"`
			ListenPort int    `json:"listen_port"`
			Network    string `json:"network"`
		} `json:"inbounds"`
	}
	if e := json.Unmarshal(config, &c); e != nil {
		return nil, errors.New("cannot inspect generated test core listeners")
	}
	var listeners []coreListener
	for _, inbound := range c.Inbounds {
		if inbound.ListenPort < 1 || inbound.ListenPort > 65535 {
			return nil, errors.New("test readiness requires explicit inbound ports")
		}
		var networks []string
		switch inbound.Type {
		case "mixed", "socks", "http", "vless", "anytls", "trojan":
			networks = []string{"tcp"}
		case "hysteria2", "tuic":
			networks = []string{"udp"}
		case "shadowsocks":
			switch inbound.Network {
			case "":
				networks = []string{"tcp", "udp"}
			case "tcp", "udp":
				networks = []string{inbound.Network}
			default:
				return nil, errors.New("unsupported test Shadowsocks listener network")
			}
		default:
			return nil, errors.New("unsupported generated test inbound for listener readiness")
		}
		for _, network := range networks {
			listeners = append(listeners, coreListener{network, inbound.ListenPort})
		}
	}
	if len(listeners) == 0 {
		return nil, errors.New("generated test core has no fixed listeners to verify")
	}
	return listeners, nil
}

// coreOwnedListeners checks the target PID's fd socket inodes against its own
// network namespace tables. Seeing a matching port owned by another process,
// an established TCP connection, or an outbound UDP socket is not readiness.
func coreOwnedListeners(procRoot string, pid int) (map[coreListener]bool, error) {
	root := filepath.Join(procRoot, strconv.Itoa(pid))
	fds, e := os.ReadDir(filepath.Join(root, "fd"))
	if e != nil {
		return nil, e
	}
	owned := map[string]bool{}
	for _, fd := range fds {
		target, e := os.Readlink(filepath.Join(root, "fd", fd.Name()))
		if e != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
	}
	ready := map[coreListener]bool{}
	readTables := 0
	for _, table := range []struct{ name, network, state string }{{"tcp", "tcp", "0A"}, {"tcp6", "tcp", "0A"}, {"udp", "udp", "07"}, {"udp6", "udp", "07"}} {
		b, e := os.ReadFile(filepath.Join(root, "net", table.name))
		if os.IsNotExist(e) {
			continue // An IPv4-only or IPv6-only test kernel may omit one table.
		}
		if e != nil {
			return nil, e
		}
		readTables++
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != table.state || !owned[fields[9]] {
				continue
			}
			colon := strings.LastIndexByte(fields[1], ':')
			if colon < 0 {
				continue
			}
			port, e := strconv.ParseUint(fields[1][colon+1:], 16, 16)
			if e == nil && port > 0 {
				ready[coreListener{table.network, int(port)}] = true
			}
		}
	}
	if readTables == 0 {
		return nil, errors.New("target process network namespace exposes no socket tables")
	}
	return ready, nil
}

// waitCoreListeners is shared with the opt-in netns fixture. A closed exited
// channel aborts immediately; timeout bounds only startup, not protocol I/O.
func waitCoreListeners(pid int, config []byte, exited <-chan struct{}, timeout time.Duration) error {
	required, e := coreListenerRequirements(config)
	if e != nil {
		return e
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	var missing []coreListener
	for {
		select {
		case <-exited:
			return errors.New("owned test core exited during startup")
		default:
		}
		ready, err := coreOwnedListeners("/proc", pid)
		lastErr = err
		missing = missing[:0]
		for _, listener := range required {
			if !ready[listener] {
				missing = append(missing, listener)
			}
		}
		if err == nil && len(missing) == 0 {
			select {
			case <-exited:
				return errors.New("owned test core exited as listeners became ready")
			default:
				return nil
			}
		}
		select {
		case <-exited:
			return errors.New("owned test core exited during startup")
		case <-timer.C:
			return fmt.Errorf("owned test core listeners not ready within %s; missing=%v; proc=%v", timeout, missing, lastErr)
		case <-ticker.C:
		}
	}
}

func TestCoreListenerRequirements(t *testing.T) {
	listeners, e := coreListenerRequirements([]byte(`{"inbounds":[{"type":"mixed","listen_port":10001},{"type":"hysteria2","listen_port":10002},{"type":"shadowsocks","listen_port":10003}]}`))
	if e != nil || len(listeners) != 4 || listeners[0] != (coreListener{"tcp", 10001}) || listeners[1] != (coreListener{"udp", 10002}) || listeners[2] != (coreListener{"tcp", 10003}) || listeners[3] != (coreListener{"udp", 10003}) {
		t.Fatal("actual TCP/UDP inbound requirements lost", listeners, e)
	}
	for _, raw := range []string{`{}`, `{"inbounds":[{"type":"hysteria2","listen_port":0}]}`, `{"inbounds":[{"type":"tun","listen_port":10001}]}`} {
		if _, e = coreListenerRequirements([]byte(raw)); e == nil {
			t.Fatal("unverifiable startup accepted")
		}
	}
}

func TestCoreOwnedListenersRejectsForeignAndConnectedSockets(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "42")
	for _, dir := range []string{"fd", "net"} {
		if e := os.MkdirAll(filepath.Join(p, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for fd, inode := range map[string]string{"3": "101", "4": "102", "5": "103"} {
		if e := os.Symlink("socket:["+inode+"]", filepath.Join(p, "fd", fd)); e != nil {
			t.Fatal(e)
		}
	}
	// The port alone must not count: inode 999 belongs to someone else, while
	// owned inode 102 is an established connection rather than a listener.
	tcp := "sl local_address rem_address st tx rx tr tm retr uid inode\n" +
		"0: 0100007F:2711 00000000:0000 0A 0:0 00:0 0 0 0 101\n" +
		"1: 0100007F:2712 00000000:0000 0A 0:0 00:0 0 0 0 999\n" +
		"2: 0100007F:2713 0100007F:1234 01 0:0 00:0 0 0 0 102\n"
	udp6 := "sl local_address rem_address st tx rx tr tm retr uid inode\n" +
		"0: 00000000000000000000000000000000:2714 00000000000000000000000000000000:0000 07 0:0 00:0 0 0 0 103\n"
	for name, data := range map[string]string{"tcp": tcp, "udp6": udp6} {
		if e := os.WriteFile(filepath.Join(p, "net", name), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	ready, e := coreOwnedListeners(root, 42)
	if e != nil || len(ready) != 2 || !ready[coreListener{"tcp", 10001}] || !ready[coreListener{"udp", 10004}] || ready[coreListener{"tcp", 10002}] || ready[coreListener{"tcp", 10003}] {
		t.Fatal("ownership, namespace table, or socket state was not enforced", ready, e)
	}
}

func TestWaitCoreListenersActualOwnTCPAndUDP(t *testing.T) {
	tcp, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	config := []byte(fmt.Sprintf(`{"inbounds":[{"type":"mixed","listen_port":%d},{"type":"hysteria2","listen_port":%d}]}`, tcp.Addr().(*net.TCPAddr).Port, udp.LocalAddr().(*net.UDPAddr).Port))
	if e = waitCoreListeners(os.Getpid(), config, make(chan struct{}), 5*time.Second); e != nil {
		t.Fatal("actual own listeners not observed", e)
	}
	exited := make(chan struct{})
	close(exited)
	if e = waitCoreListeners(os.Getpid(), config, exited, 5*time.Second); e == nil {
		t.Fatal("early-exit process accepted despite its stale matching sockets")
	}
}
