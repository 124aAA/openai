package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
)

// LocalBinding describes a local listener, never a client connection endpoint.
type LocalBinding struct {
	NodeID  string `json:"node_id,omitempty"`
	Network string `json:"network"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type BindingProbeOptions struct {
	ListenConfig     *net.ListenConfig
	Previous         []LocalBinding
	Sockets          []Socket
	SnapshotComplete bool
}

type BindingProbeResult struct {
	LocalBinding
	Status   string `json:"status"`
	Category string `json:"error_category,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type BindingProbeReport struct {
	Version int                  `json:"version"`
	Results []BindingProbeResult `json:"results"`
}

func NodeBindings(nodes []Node) []LocalBinding {
	var bindings []LocalBinding
	for _, n := range nodes {
		if n.Enabled {
			for _, network := range Networks(n) {
				bindings = append(bindings, LocalBinding{n.ID, network, n.Listen, n.Port})
			}
		}
	}
	return bindings
}

// StateBindings includes listeners owned by forwards and fixed-port WireGuard
// landing endpoints. wireguard-go StdNetBind uses distinct udp4/udp6 sockets;
// it does not use Go's unsuffixed dual-stack wildcard behavior.
func StateBindings(st State) []LocalBinding {
	bindings := NodeBindings(st.Nodes)
	if api := st.Observability; api != nil && api.Enabled {
		bindings = append(bindings, LocalBinding{"qingnode-api", "tcp", api.Listen, api.Port})
	}
	for _, f := range st.Forwards {
		if f.Enabled {
			for _, network := range ForwardNetworks(f) {
				bindings = append(bindings, LocalBinding{f.ID, network, f.Listen, f.Port})
			}
		}
	}
	for _, e := range st.Egresses {
		if w := e.WireGuard; w != nil && w.ListenPort > 0 {
			bindings = append(bindings, LocalBinding{EgressTag(e.ID), "udp4", "0.0.0.0", w.ListenPort}, LocalBinding{EgressTag(e.ID), "udp6", "::", w.ListenPort})
		}
	}
	return bindings
}

func wireGuardBinding(b LocalBinding) bool {
	return strings.HasPrefix(b.NodeID, "egress-") && (b.Network == "udp4" || b.Network == "udp6")
}

// wireGuardUnavailableFamilies checks the same distinct wildcard UDP binds as
// wireguard-go on temporary ports. No peer traffic is sent and no socket is
// retained. Only the core's supported EAFNOSUPPORT fallback is accepted.
func wireGuardUnavailableFamilies(ctx context.Context, st State, lc net.ListenConfig) (map[string]bool, error) {
	unavailable := map[string]bool{}
	seen := map[string]bool{}
	for _, binding := range StateBindings(st) {
		if !wireGuardBinding(binding) || seen[binding.Network] {
			continue
		}
		seen[binding.Network] = true
		binding.Port = 0
		listener, _, err := openLocalBinding(ctx, binding, lc)
		if err == nil {
			listener.Close()
		} else if errors.Is(err, syscall.EAFNOSUPPORT) {
			unavailable[binding.Network] = true
		} else {
			return nil, fmt.Errorf("无法核验WireGuard的%s监听能力：%w", binding.Network, err)
		}
	}
	if len(seen) != 0 && len(unavailable) == len(seen) {
		return nil, errors.New("WireGuard的IPv4和IPv6监听均不可用")
	}
	return unavailable, nil
}

func bindingTransport(network string) string {
	return strings.TrimSuffix(strings.TrimSuffix(network, "4"), "6")
}

func splitLocalAddress(address string) (string, int, error) {
	host, text, e := net.SplitHostPort(address)
	if e != nil {
		return "", 0, e
	}
	port, e := strconv.Atoi(text)
	return host, port, e
}

func validateLocalBinding(b LocalBinding) error {
	a, e := netip.ParseAddr(b.Address)
	if e != nil || a.Zone() != "" || b.Port < 1 || b.Port > 65535 {
		return errors.New("本地监听需要有效字面IP和1–65535端口")
	}
	switch b.Network {
	case "tcp", "udp":
	case "tcp4", "udp4":
		if !a.Unmap().Is4() {
			return errors.New("IPv4监听不能使用IPv6地址")
		}
	case "tcp6", "udp6":
		if !a.Is6() || a.Is4In6() {
			return errors.New("IPv6监听需要原生IPv6地址")
		}
	default:
		return errors.New("本地监听仅支持TCP或UDP及显式地址族")
	}
	return nil
}

// BindingOverlap returns (overlap, certain). A possible IPv6 dual-stack
// overlap is unknown; /proc addresses do not expose IPV6_V6ONLY.
func BindingOverlap(a, b LocalBinding) (bool, bool) {
	if bindingTransport(a.Network) != bindingTransport(b.Network) || a.Port != b.Port {
		return false, true
	}
	x, ex := netip.ParseAddr(a.Address)
	y, ey := netip.ParseAddr(b.Address)
	if ex != nil || ey != nil {
		return false, false
	}
	x, y = x.Unmap(), y.Unmap()
	if x.Is4() == y.Is4() {
		return x == y || x.IsUnspecified() || y.IsUnspecified(), true
	}
	if bindingMayDualStack(a) || bindingMayDualStack(b) {
		return false, false
	}
	return false, true
}

func bindingMayDualStack(b LocalBinding) bool {
	a, e := netip.ParseAddr(b.Address)
	return e == nil && a.Is6() && a.Unmap().IsUnspecified() && !strings.HasSuffix(b.Network, "6") && !strings.HasSuffix(b.Network, "4")
}

func ValidateNodeListeners(nodes []Node) error {
	return validateBindingSet(NodeBindings(nodes))
}

func validateBindingSet(bindings []LocalBinding) error {
	if len(bindings) > 2048 {
		return errors.New("一次本地监听预检最多2048项")
	}
	for i, b := range bindings {
		if e := validateLocalBinding(b); e != nil {
			return e
		}
		for _, previous := range bindings[:i] {
			if overlap, certain := BindingOverlap(b, previous); overlap && certain {
				return fmt.Errorf("本地监听冲突：%s 与 %s，%s/%d", previous.Address, b.Address, bindingTransport(b.Network), b.Port)
			}
		}
	}
	return nil
}

// The fixed sing-box 1.14 listener explicitly adds "4" only for the native
// IPv4 wildcard. Other literals use the unsuffixed network. In particular,
// IPv4-mapped unspecified addresses must not silently become tcp4/udp4.
func localBindingNetwork(b LocalBinding) string {
	if b.Network == "tcp" || b.Network == "udp" {
		if a, e := netip.ParseAddr(b.Address); e == nil && a == netip.IPv4Unspecified() {
			return b.Network + "4"
		}
	}
	return b.Network
}

func openLocalBinding(ctx context.Context, b LocalBinding, lc net.ListenConfig) (io.Closer, int, error) {
	if e := ctx.Err(); e != nil {
		return nil, 0, e
	}
	address := net.JoinHostPort(b.Address, strconv.Itoa(b.Port))
	network := localBindingNetwork(b)
	var closer io.Closer
	var addr net.Addr
	if bindingTransport(b.Network) == "udp" {
		listener, e := lc.ListenPacket(ctx, network, address)
		if e != nil {
			return nil, 0, e
		}
		closer, addr = listener, listener.LocalAddr()
	} else {
		listener, e := lc.Listen(ctx, network, address)
		if e != nil {
			return nil, 0, e
		}
		closer, addr = listener, listener.Addr()
	}
	_, text, e := net.SplitHostPort(addr.String())
	if e != nil {
		closer.Close()
		return nil, 0, e
	}
	port, e := strconv.Atoi(text)
	if e != nil {
		closer.Close()
		return nil, 0, e
	}
	return closer, port, nil
}

func localBindingCategory(e error) string {
	switch {
	case errors.Is(e, context.Canceled):
		return "canceled"
	case errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(e, syscall.EADDRINUSE):
		return "port_in_use"
	case errors.Is(e, syscall.EAFNOSUPPORT), errors.Is(e, syscall.EPROTONOSUPPORT):
		return "address_family_unavailable"
	case errors.Is(e, syscall.EADDRNOTAVAIL):
		return "address_unavailable"
	case errors.Is(e, syscall.EACCES), errors.Is(e, syscall.EPERM):
		return "permission_denied"
	default:
		return "bind_failed"
	}
}

// ProbeLocalBindings temporarily binds all candidate listeners together. It
// closes every owned socket before returning; success reserves no future port
// and proves neither service-user permissions nor external reachability.
func ProbeLocalBindings(ctx context.Context, bindings []LocalBinding, options BindingProbeOptions) (report BindingProbeReport, err error) {
	report = BindingProbeReport{Version: 1, Results: []BindingProbeResult{}}
	if e := validateBindingSet(bindings); e != nil {
		return report, e
	}
	var lc net.ListenConfig
	if options.ListenConfig != nil {
		lc = *options.ListenConfig
	}
	// Even if existing owned sockets prevent binding the requested ports,
	// validate every uncertain candidate group on one shared temporary port.
	// Probing these addresses individually would miss dual-stack conflicts.
	groups := map[string][]LocalBinding{}
	for _, b := range bindings {
		key := bindingTransport(b.Network) + "/" + strconv.Itoa(b.Port)
		groups[key] = append(groups[key], b)
	}
	for _, group := range groups {
		unknown := false
		for i, b := range group {
			for _, other := range group[:i] {
				_, certain := BindingOverlap(b, other)
				unknown = unknown || !certain
			}
		}
		if !unknown {
			continue
		}
		if e := probeTemporaryBindingGroup(ctx, group, lc); e != nil {
			return report, fmt.Errorf("候选监听的双栈范围不能同时绑定；没有改变现有服务：%w", e)
		}
	}
	var held []io.Closer
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i].Close()
		}
	}()
	for _, b := range bindings {
		result := BindingProbeResult{LocalBinding: b, Status: "bound"}
		listener, _, e := openLocalBinding(ctx, b, lc)
		if e == nil {
			held = append(held, listener)
		} else if errors.Is(e, syscall.EADDRINUSE) && bindingOwnedByPrevious(b, options) {
			result.Status = "owned_deferred"
			result.Reason = "占用已核验为本服务旧监听；切换后仍须由核心实际绑定并核对就绪"
		} else if wireGuardBinding(b) && errors.Is(e, syscall.EAFNOSUPPORT) {
			// Match wireguard-go's explicit fallback only for unsupported
			// families. Permission, address and conflict failures remain fatal.
			result.Status, result.Category, result.Reason = "family_unavailable", "address_family_unavailable", "WireGuard核心允许缺少一种地址族；另一族必须实际绑定成功"
		} else {
			result.Status, result.Category, result.Reason = "failed", localBindingCategory(e), "本地绑定未通过；没有关闭或接管已有监听"
			report.Results = append(report.Results, result)
			return report, fmt.Errorf("本地监听 %s/%s 无法绑定（%s）：%w", net.JoinHostPort(b.Address, strconv.Itoa(b.Port)), b.Network, result.Category, e)
		}
		report.Results = append(report.Results, result)
	}
	for _, b := range bindings {
		if wireGuardBinding(b) {
			available := false
			for _, result := range report.Results {
				if result.NodeID == b.NodeID && (result.Status == "bound" || result.Status == "owned_deferred") {
					available = true
				}
			}
			if !available {
				return report, errors.New("WireGuard的IPv4和IPv6监听均不可用")
			}
		}
	}
	return report, ctx.Err()
}

func probeTemporaryBindingGroup(ctx context.Context, group []LocalBinding, lc net.ListenConfig) error {
	var held []io.Closer
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i].Close()
		}
	}()
	port := 0
	for _, b := range group {
		b.Port = port
		listener, actualPort, e := openLocalBinding(ctx, b, lc)
		if e != nil {
			return e
		}
		held = append(held, listener)
		port = actualPort
	}
	return ctx.Err()
}

func bindingOwnedByPrevious(candidate LocalBinding, options BindingProbeOptions) bool {
	if !options.SnapshotComplete {
		return false
	}
	found := false
	for _, socket := range options.Sockets {
		observed := LocalBinding{Network: socket.Network, Address: socket.Address, Port: socket.Port}
		if overlaps, certain := BindingOverlap(candidate, observed); certain && !overlaps {
			continue
		}
		if !socket.Owned || socket.Inode == "" || (socket.Network == "udp" && socket.State != "07") {
			return false
		}
		matched := false
		for _, previous := range options.Previous {
			a, ea := netip.ParseAddr(previous.Address)
			b, eb := netip.ParseAddr(socket.Address)
			if ea == nil && eb == nil && a.Unmap() == b.Unmap() && bindingTransport(previous.Network) == socket.Network && previous.Port == socket.Port {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
		found = true
	}
	return found
}
