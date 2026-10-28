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
	Inode   string
	State   string
}

type SocketSnapshot struct {
	Sockets           []Socket
	Complete          bool
	NamespaceVerified bool
}

// MainPID alone is insufficient: the socket inode must belong to that process.
func ReadSockets(proc string, pid int) []Socket {
	snapshot, _ := ReadSocketSnapshot(proc, pid)
	return snapshot.Sockets
}

// ReadSocketSnapshot preserves partial observations but never treats a failed
// table, fd or namespace read as proof that no foreign listener exists.
func ReadSocketSnapshot(proc string, pid int) (snapshot SocketSnapshot, err error) {
	snapshot.Complete = true
	snapshot.NamespaceVerified = pid == 0
	var failures []error
	record := func(e error) { failures = append(failures, e); snapshot.Complete = false }
	inodes := map[string]bool{}
	tableRoot := filepath.Join(proc, "net")
	if pid > 0 {
		processRoot := filepath.Join(proc, strconv.Itoa(pid))
		fds, e := os.ReadDir(filepath.Join(processRoot, "fd"))
		if e != nil {
			record(errors.New("无法读取服务进程socket归属"))
		}
		for _, f := range fds {
			p, e := os.Readlink(filepath.Join(processRoot, "fd", f.Name()))
			if e != nil {
				// ReadDir's own directory fd may already have closed. A vanished
				// fd never grants ownership to any socket in the tables below.
				if os.IsNotExist(e) {
					continue
				}
				record(errors.New("服务进程fd在检查时不可读取"))
				continue
			}
			if strings.HasPrefix(p, "socket:[") && strings.HasSuffix(p, "]") {
				inodes[p[8:len(p)-1]] = true
			}
		}
		if info, e := os.Stat(filepath.Join(processRoot, "net")); e == nil && info.IsDir() {
			tableRoot = filepath.Join(processRoot, "net")
		} else {
			record(errors.New("服务进程网络命名空间表不可读取"))
		}
		selfNS, selfErr := os.Readlink(filepath.Join(proc, "self", "ns", "net"))
		processNS, processErr := os.Readlink(filepath.Join(processRoot, "ns", "net"))
		if selfErr == nil && processErr == nil && selfNS == processNS {
			snapshot.NamespaceVerified = true
		} else {
			record(errors.New("无法证明预检与服务处于同一网络命名空间"))
		}
	}
	for _, network := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, e := os.ReadFile(filepath.Join(tableRoot, network))
		if e != nil {
			if !os.IsNotExist(e) || !strings.HasSuffix(network, "6") {
				record(fmt.Errorf("无法完整读取%s socket表", network))
			}
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || f[0] == "sl" {
				continue
			}
			if len(f) < 10 {
				record(errors.New("socket表记录格式不完整"))
				continue
			}
			if strings.HasPrefix(network, "tcp") && f[3] != "0A" {
				continue
			}
			a := strings.Split(f[1], ":")
			if len(a) != 2 {
				record(errors.New("socket地址记录无法解析"))
				continue
			}
			port, e := strconv.ParseUint(a[1], 16, 16)
			if e != nil {
				record(errors.New("socket端口记录无法解析"))
				continue
			}
			if port == 0 {
				continue
			}
			ip, e := hex.DecodeString(a[0])
			if e != nil || (len(ip) != 4 && len(ip) != 16) {
				record(errors.New("socket IP记录无法解析"))
				continue
			}
			for i := 0; i < len(ip); i += 4 {
				ip[i], ip[i+3] = ip[i+3], ip[i]
				ip[i+1], ip[i+2] = ip[i+2], ip[i+1]
			}
			snapshot.Sockets = append(snapshot.Sockets, Socket{Network: strings.TrimSuffix(network, "6"), Address: net.IP(ip).String(), Port: int(port), Owned: inodes[f[9]], Inode: f[9], State: f[3]})
		}
	}
	return snapshot, errors.Join(failures...)
}
func Networks(n Node) []string {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	return append([]string{}, p.Networks...)
}
func SocketsReady(s State, sockets []Socket) bool {
	return socketsReadyWithUnavailableFamilies(s, sockets, nil)
}

// A missing owned socket is never evidence that its address family is absent.
// Only an explicit EAFNOSUPPORT observation from activation may omit a family.
func socketsReadyWithUnavailableFamilies(s State, sockets []Socket, unavailable map[string]bool) bool {
	wgReady := map[string]bool{}
	for _, b := range StateBindings(s) {
		if wireGuardBinding(b) {
			if _, ok := wgReady[b.NodeID]; !ok {
				wgReady[b.NodeID] = false
			}
			if unavailable[b.Network] {
				continue
			}
		}
		listen := net.ParseIP(b.Address)
		network := bindingTransport(b.Network)
		found := false
		for _, socket := range sockets {
			if network == "udp" && socket.State != "" && socket.State != "07" {
				continue
			}
			if socket.Owned && socket.Network == network && socket.Port == b.Port && listen != nil && listen.Equal(net.ParseIP(socket.Address)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if wireGuardBinding(b) {
			wgReady[b.NodeID] = true
		}
	}
	for _, ready := range wgReady {
		if !ready {
			return false
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
	for _, binding := range StateBindings(s) {
		reserved[binding.Port] = true
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
