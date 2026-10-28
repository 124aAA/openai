package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

// NodeRouteDigest binds a client-side test record to the selected server-side
// path without disclosing remote credentials. The closure is the same actual
// rendered closure used by server configuration and impact classification.
// Historical direct nodes return an empty digest to retain profile v1 behavior.
// Unused definitions, display names and a dormant backup do not change it.
func NodeRouteDigest(st State, nodeID string) (string, error) {
	if err := st.Validate(); err != nil {
		return "", err
	}
	var selected *Node
	for i := range st.Nodes {
		if st.Nodes[i].ID == nodeID {
			selected = &st.Nodes[i]
			break
		}
	}
	if selected == nil {
		return "", errors.New("路径摘要需要现有节点ID")
	}
	id, err := ResolveEgressID(st, selected.EgressID)
	if err != nil {
		return "", err
	}
	if id == "direct" {
		return "", nil
	}
	outbounds, endpoints, final, err := buildEgressGraph(st, selected.EgressID)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		Core                 string
		DNS                  M
		Outbounds, Endpoints []M
		Final                string
	}{st.CoreVersion, ProjectDNS(st.DNS), outbounds, endpoints, final})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// BuildEgressGraph produces just the requested outbound and its immutable
// detour dependency closure. It has no implicit direct alternative. Callers
// testing a path must use finalTag as the route final, and must not add a
// direct rule to turn authentication/transport failure into apparent success.
// A passive WireGuard landing endpoint is not a client egress test target.
func BuildEgressGraph(st State, id string) (outbounds []M, endpoints []M, finalTag string, err error) {
	if err = st.Validate(); err != nil {
		return
	}
	return buildEgressGraph(st, id)
}
func buildEgressGraph(st State, id string) ([]M, []M, string, error) {
	id, err := ResolveEgressID(st, id)
	if err != nil {
		return nil, nil, "", err
	}
	if id == "direct" {
		return []M{{"type": "direct", "tag": "direct"}}, nil, "direct", nil
	}
	byID := map[string]Egress{}
	for _, e := range st.Egresses {
		byID[e.ID] = e
	}
	selected := map[string]bool{}
	for next := id; next != ""; next = byID[next].Detour {
		if selected[next] {
			return nil, nil, "", errors.New("出口链存在环")
		}
		if _, ok := byID[next]; !ok {
			return nil, nil, "", errors.New("出口链引用不存在")
		}
		selected[next] = true
	}
	ids := make([]string, 0, len(selected))
	for next := range selected {
		ids = append(ids, next)
	}
	sort.Strings(ids)
	var outbounds, endpoints []M
	for _, next := range ids {
		e := byID[next]
		m := renderEgress(e)
		if e.Protocol == "wireguard" {
			endpoints = append(endpoints, m)
		} else {
			outbounds = append(outbounds, m)
		}
	}
	return outbounds, endpoints, EgressTag(id), nil
}
func renderEgress(e Egress) M {
	m := M{"tag": EgressTag(e.ID)}
	if e.Protocol != "wireguard" {
		m["server"], m["server_port"] = e.Server, e.Port
	}
	if e.Detour != "" {
		m["detour"] = EgressTag(e.Detour)
	}
	switch e.Protocol {
	case "socks5":
		m["type"], m["version"] = "socks", "5"
		if !e.UDP {
			m["network"] = "tcp"
		}
		if p := e.Socks; p.Username != "" {
			m["username"], m["password"] = p.Username, p.Password
		}
	case "reality":
		p := e.Reality
		fp := p.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		m["type"], m["uuid"], m["flow"] = "vless", p.UUID, "xtls-rprx-vision"
		m["tls"] = M{"enabled": true, "server_name": p.ServerName, "utls": M{"enabled": true, "fingerprint": fp}, "reality": M{"enabled": true, "public_key": p.PublicKey, "short_id": p.ShortID}}
	case "ss2022":
		p := e.Shadowsocks
		m["type"], m["method"], m["password"] = "shadowsocks", p.Method, p.Password
		if !e.UDP {
			m["network"] = "tcp"
		}
	case "hysteria2":
		p := e.HY2
		m["type"], m["password"] = "hysteria2", p.Password
		tls := M{"enabled": true, "server_name": p.ServerName}
		if p.CertificatePEM != "" {
			tls["certificate"] = []string{p.CertificatePEM}
		}
		m["tls"] = tls
		if perf := p.Performance; perf != nil {
			if perf.ClientUpMbps != nil {
				m["up_mbps"] = *perf.ClientUpMbps
			}
			if perf.ClientDownMbps != nil {
				m["down_mbps"] = *perf.ClientDownMbps
			}
			hy2Transport(m, perf.Client)
		}
	case "wireguard":
		w := e.WireGuard
		m["type"], m["system"], m["address"], m["private_key"] = "wireguard", false, w.Address, w.PrivateKey
		if w.ListenPort != 0 {
			m["listen_port"] = w.ListenPort
		}
		if w.MTU != 0 {
			m["mtu"] = w.MTU
		}
		peers := []M{}
		for _, p := range w.Peers {
			peer := M{"public_key": p.PublicKey, "allowed_ips": p.AllowedIPs}
			if p.Address != "" {
				peer["address"], peer["port"] = p.Address, p.Port
			}
			if p.PreSharedKey != "" {
				peer["pre_shared_key"] = p.PreSharedKey
			}
			if p.Keepalive != 0 {
				peer["persistent_keepalive_interval"] = p.Keepalive
			}
			peers = append(peers, peer)
		}
		m["peers"] = peers
	}
	return m
}

func forwardInbound(f PortForward) M {
	m := M{"type": "direct", "tag": ForwardTag(f.ID), "listen": f.Listen, "listen_port": f.Port, "override_address": f.TargetHost, "override_port": f.TargetPort}
	if f.Network != "tcp+udp" {
		m["network"] = f.Network
	}
	return m
}

// topologyServerConfig augments the historical direct server only where an
// enabled listener actually refers to topology. Unused egress edits therefore
// do not restart the server, and client exports remain entry credentials only.
func topologyServerConfig(st State, inbounds []any, route M) (outbounds []any, endpoints []any, err error) {
	outbounds = []any{M{"type": "direct", "tag": "direct"}}
	used := map[string]M{}
	usedEndpoints := map[string]M{}
	receiveAllowed := map[string]bool{}
	rules := []M{}
	add := func(inbound, id string, explicit bool) error {
		outs, eps, tag, e := buildEgressGraph(st, id)
		if e != nil {
			return e
		}
		for _, out := range outs {
			if out["tag"] != "direct" {
				used[out["tag"].(string)] = out
			}
		}
		for _, ep := range eps {
			usedEndpoints[ep["tag"].(string)] = ep
		}
		if explicit || tag != "direct" {
			rules = append(rules, M{"inbound": []string{inbound}, "action": "route", "outbound": tag})
		}
		return nil
	}
	for _, n := range st.Nodes {
		if n.Enabled {
			if err = add(n.ID, n.EgressID, false); err != nil {
				return
			}
		}
	}
	for _, f := range st.Forwards {
		if f.Enabled {
			if err = add(ForwardTag(f.ID), f.EgressID, true); err != nil {
				return
			}
		}
	}
	for _, e := range st.Egresses {
		if w := e.WireGuard; w != nil && w.ListenPort > 0 {
			usedEndpoints[EgressTag(e.ID)] = renderEgress(e)
			receiveAllowed[EgressTag(e.ID)] = true
			if err = add(EgressTag(e.ID), w.ReceiveEgressID, true); err != nil {
				return
			}
		}
	}
	tags := make([]string, 0, len(used))
	for tag := range used {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		outbounds = append(outbounds, used[tag])
	}
	tags = tags[:0]
	for tag := range usedEndpoints {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		endpoints = append(endpoints, usedEndpoints[tag])
		if !receiveAllowed[tag] {
			// An active endpoint may receive peer-initiated flows after its
			// handshake. Only explicit landing listeners authorize routing
			// those flows; established outbound replies stay in their stack.
			rules = append(rules, M{"inbound": []string{tag}, "action": "reject"})
		}
	}
	if len(rules) != 0 {
		route["rules"] = rules
	}
	return
}

// HasEnabled includes explicit pure forwarding and userland landing listeners.
// Remote-only egress definitions without a listener do not start a service.
func HasEnabled(st State) bool {
	for _, n := range st.Nodes {
		if n.Enabled {
			return true
		}
	}
	for _, f := range st.Forwards {
		if f.Enabled {
			return true
		}
	}
	for _, e := range st.Egresses {
		if e.WireGuard != nil && e.WireGuard.ListenPort > 0 {
			return true
		}
	}
	return false
}
