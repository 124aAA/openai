package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ValidateTopologyNetwork is an explicit apply-time preflight, not State
// loading. DNS results and host addresses are transient evidence: they never
// rewrite saved endpoints, resolver settings or routes. Rebinding after this
// check remains an external network change and cannot be ruled out here.
func ValidateTopologyNetwork(ctx context.Context, st State) error {
	if len(st.Egresses) == 0 && len(st.Forwards) == 0 {
		return nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return errors.New("无法读取本机地址以检查入口/隧道循环")
	}
	local := map[netip.Addr]bool{}
	for _, a := range addresses {
		if p, e := netip.ParsePrefix(a.String()); e == nil {
			local[p.Addr().Unmap()] = true
		}
	}
	resolver := net.DefaultResolver
	if d := st.DNS; d != nil && d.Type == "udp" {
		port := 53
		if d.Port != nil {
			port = *d.Port
		}
		address := net.JoinHostPort(d.Server, strconv.Itoa(port))
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}}
	}
	lookup := func(host string) ([]netip.Addr, error) {
		if a, e := netip.ParseAddr(host); e == nil {
			return []netip.Addr{a.Unmap()}, nil
		}
		query, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		ips, e := resolver.LookupNetIP(query, "ip", host)
		if e != nil {
			return nil, errors.New("拓扑目标DNS解析未完成，未应用候选配置")
		}
		return ips, nil
	}
	return validateTopologyResolved(st, local, lookup)
}

func validateTopologyResolved(st State, local map[netip.Addr]bool, lookup func(string) ([]netip.Addr, error)) error {
	bindings := StateBindings(st)
	resolved := map[string][]netip.Addr{}
	lookupHost := func(host string) ([]netip.Addr, error) {
		if ips, ok := resolved[host]; ok {
			return ips, nil
		}
		ips, err := lookup(host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("拓扑目标没有可用解析地址，未应用候选配置")
		}
		resolved[host] = ips
		return ips, nil
	}
	hits := func(a netip.Addr, port int, network string, b LocalBinding) bool {
		if b.Port != port || bindingTransport(b.Network) != network {
			return false
		}
		l, e := netip.ParseAddr(b.Address)
		if e != nil {
			return false
		}
		l, a = l.Unmap(), a.Unmap()
		if a == l {
			return true
		}
		return l.IsUnspecified() && (local[a] || a.IsLoopback() || a.IsUnspecified()) && (l.Is4() == a.Is4() || (l.Is6() && !strings.HasSuffix(b.Network, "6")))
	}
	check := func(host string, port int, network string, forward, localDial, localDNS bool) error {
		if host == "" || (!localDial && !localDNS) {
			return nil
		}
		ips, err := lookupHost(host)
		if err != nil {
			return err
		}
		if !localDial {
			return nil // Local DNS does not make a userland tunnel a host-local dial.
		}
		for _, a := range ips {
			for _, b := range bindings {
				if forward && !strings.HasPrefix(b.NodeID, "egress-") {
					isNode := false
					for _, n := range st.Nodes {
						isNode = isNode || n.ID == b.NodeID
					}
					if !isNode {
						continue
					}
				}
				if hits(a, port, network, b) {
					return errors.New("拓扑目标解析到本机受管入口/隧道，拒绝循环代理")
				}
			}
		}
		return nil
	}
	// The generated graph, rather than every saved unused definition, determines
	// which remote addresses the running core will actually need to resolve.
	used := map[string]bool{}
	add := func(id string) error {
		outs, eps, _, err := buildEgressGraph(st, id)
		if err != nil {
			return err
		}
		for _, m := range append(outs, eps...) {
			if tag, _ := m["tag"].(string); strings.HasPrefix(tag, "egress-") {
				used[strings.TrimPrefix(tag, "egress-")] = true
			}
		}
		return nil
	}
	for _, n := range st.Nodes {
		if n.Enabled {
			if err := add(n.EgressID); err != nil {
				return err
			}
		}
	}
	for _, f := range st.Forwards {
		if f.Enabled {
			if err := add(f.EgressID); err != nil {
				return err
			}
			localDial, localDNS, err := topologyRouteScope(st, f.EgressID)
			if err != nil {
				return err
			}
			for _, network := range ForwardNetworks(f) {
				if err := check(f.TargetHost, f.TargetPort, network, true, localDial, localDNS); err != nil {
					return fmt.Errorf("中转目标：%w", err)
				}
			}
		}
	}
	for _, e := range st.Egresses {
		if e.WireGuard != nil && e.WireGuard.ListenPort > 0 {
			used[e.ID] = true
			if err := add(e.WireGuard.ReceiveEgressID); err != nil {
				return err
			}
		}
	}
	for _, e := range st.Egresses {
		if used[e.ID] {
			localDial, localDNS := e.Detour == "", e.Detour == ""
			if e.Detour != "" {
				var err error
				_, localDNS, err = topologyRouteScope(st, e.Detour)
				if err != nil {
					return err
				}
			}
			for _, network := range egressServerNetworks(e) {
				if err := check(e.Server, e.Port, network, false, localDial, localDNS); err != nil {
					return fmt.Errorf("远程出口：%w", err)
				}
			}
			if e.WireGuard != nil {
				for _, p := range e.WireGuard.Peers {
					// Both fixed versions set ResolverOnDetour:true and use
					// dnsRouter.Lookup for peer domains, including with detour.
					if err := check(p.Address, p.Port, "udp", false, localDial, true); err != nil {
						return fmt.Errorf("WireGuard peer：%w", err)
					}
				}
			}
		}
	}
	// Literal validation cannot see DNS aliases. Evaluate the same directed
	// forward graph against this bounded apply-time resolution snapshot while
	// allowing distinct acyclic forwards to be connected explicitly.
	edges := map[string][]string{}
	for _, f := range st.Forwards {
		if !f.Enabled {
			continue
		}
		localDial, _, err := topologyRouteScope(st, f.EgressID)
		if err != nil {
			return err
		}
		if !localDial {
			continue
		}
		ips, err := lookupHost(f.TargetHost)
		if err != nil {
			return fmt.Errorf("中转目标：%w", err)
		}
		for _, target := range st.Forwards {
			if !target.Enabled {
				continue
			}
			for _, network := range ForwardNetworks(f) {
				for _, targetNetwork := range ForwardNetworks(target) {
					if network != targetNetwork {
						continue
					}
					for _, ip := range ips {
						if hits(ip, f.TargetPort, network, LocalBinding{Network: targetNetwork, Address: target.Listen, Port: target.Port}) {
							edges[f.ID] = append(edges[f.ID], target.ID)
						}
					}
				}
			}
		}
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return errors.New("中转目标DNS解析后形成循环")
		}
		if done[id] {
			return nil
		}
		visiting[id] = true
		for _, next := range edges[id] {
			if err := visit(next); err != nil {
				return err
			}
		}
		visiting[id], done[id] = false, true
		return nil
	}
	for id := range edges {
		if err := visit(id); err != nil {
			return err
		}
	}
	if d := st.DNS; d != nil && d.Type == "udp" {
		port := 53
		if d.Port != nil {
			port = *d.Port
		}
		if err := check(d.Server, port, "udp", false, true, true); err != nil {
			return fmt.Errorf("DNS引导：%w", err)
		}
	}
	return nil
}
