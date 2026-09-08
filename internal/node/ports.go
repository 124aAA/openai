package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Socket struct {
	Network string
	Address string
	Port    int
	Owned   bool
}

// MainPID alone is insufficient: the socket inode must belong to that process.
func ReadSockets(proc string, pid int) []Socket {
	inodes := map[string]bool{}
	if pid > 0 {
		fds, _ := os.ReadDir(filepath.Join(proc, strconv.Itoa(pid), "fd"))
		for _, f := range fds {
			p, _ := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "fd", f.Name()))
			if strings.HasPrefix(p, "socket:[") && strings.HasSuffix(p, "]") {
				inodes[p[8:len(p)-1]] = true
			}
		}
	}
	var sockets []Socket
	for _, network := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, _ := os.ReadFile(filepath.Join(proc, "net", network))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || (strings.HasPrefix(network, "tcp") && f[3] != "0A") {
				continue
			}
			a := strings.Split(f[1], ":")
			if len(a) != 2 {
				continue
			}
			port, e := strconv.ParseUint(a[1], 16, 16)
			if e != nil || port == 0 {
				continue
			}
			ip, e := hex.DecodeString(a[0])
			if e != nil || (len(ip) != 4 && len(ip) != 16) {
				continue
			}
			for i := 0; i < len(ip); i += 4 {
				ip[i], ip[i+3] = ip[i+3], ip[i]
				ip[i+1], ip[i+2] = ip[i+2], ip[i+1]
			}
			sockets = append(sockets, Socket{Network: strings.TrimSuffix(network, "6"), Address: net.IP(ip).String(), Port: int(port), Owned: inodes[f[9]]})
		}
	}
	return sockets
}
func Networks(n Node) []string {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	return append([]string{}, p.Networks...)
}
func SocketsReady(s State, sockets []Socket) bool {
	for _, n := range s.Nodes {
		if !n.Enabled {
			continue
		}
		for _, network := range Networks(n) {
			found := false
			for _, socket := range sockets {
				if socket.Owned && socket.Network == network && socket.Port == n.Port && socket.Address == n.Listen {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}
func AvailablePort(n Node) error {
	for _, network := range Networks(n) {
		if e := available(network, net.JoinHostPort(n.Listen, strconv.Itoa(n.Port))); e != nil {
			return e
		}
	}
	return nil
}
func RandomPort(s State, n Node, sshPorts []int) (int, error) {
	reserved := map[int]bool{22: true, 80: true, 443: true, 3306: true, 5432: true, 6379: true, 8080: true, 8443: true}
	for _, p := range sshPorts {
		reserved[p] = true
	}
	for _, old := range s.Nodes {
		reserved[old.Port] = true
	}
	for _, socket := range ReadSockets("/proc", 0) {
		reserved[socket.Port] = true
	}
	for i := 0; i < 512; i++ {
		r, e := rand.Int(rand.Reader, big.NewInt(40000))
		if e != nil {
			return 0, e
		}
		p := 10000 + int(r.Int64())
		if reserved[p] {
			continue
		}
		n.Port = p
		if AvailablePort(n) == nil {
			return p, nil
		}
	}
	return 0, errors.New("没有找到可用随机端口，请查看 qingnode ports 并手动选择")
}
func PortLabel(n Node) string { return fmt.Sprintf("%d/%s", n.Port, strings.Join(Networks(n), "+")) }

func SSHPorts() []int {
	ports := []int{22}
	if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) == 4 {
		if p, e := strconv.Atoi(fields[3]); e == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	if b, e := Run(5*time.Second, "/usr/sbin/sshd", "-T"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "port" {
				if p, e := strconv.Atoi(f[1]); e == nil {
					ports = append(ports, p)
				}
			}
		}
	}
	return ports
}
