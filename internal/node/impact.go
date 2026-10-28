package node

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// ChangeImpact describes derived behavior, rather than guessing from edited fields.
// NeedsRestart means Apply must activate/stop the service under its existing rules;
// it does not promise a reload or uninterrupted transport for runtime changes.
type ChangeImpact struct {
	Changed       bool            `json:"changed"`
	Display       bool            `json:"display"`
	ClientExport  bool            `json:"client_export"`
	ServerRuntime bool            `json:"server_runtime"`
	HostEffects   bool            `json:"host_effects"`
	RepairDerived bool            `json:"repair_derived"`
	NeedsRestart  bool            `json:"needs_restart"`
	Nodes         []NodeImpact    `json:"nodes"`
	Forwards      []ForwardImpact `json:"forwards,omitempty"`
	Devices       []DeviceImpact  `json:"devices,omitempty"`
}

type ForwardImpact struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Changed       bool   `json:"changed"`
	Display       bool   `json:"display"`
	ServerRuntime bool   `json:"server_runtime"`
	HostEffects   bool   `json:"host_effects"`
}

type NodeImpact struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Changed       bool   `json:"changed"`
	Display       bool   `json:"display"`
	ClientExport  bool   `json:"client_export"`
	ServerRuntime bool   `json:"server_runtime"`
	HostEffects   bool   `json:"host_effects"`
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func normalizeCandidate(next, old State) State {
	next = next.Clone()
	byID := map[string]Node{}
	for _, n := range old.Nodes {
		byID[n.ID] = n
	}
	for i := range next.Nodes {
		if before, ok := byID[next.Nodes[i].ID]; ok {
			// Timestamps belong to the store. Restoring/editing the same
			// content is a no-op even when the caller's copy predates them.
			next.Nodes[i].CreatedAt = before.CreatedAt
			next.Nodes[i].UpdatedAt = before.UpdatedAt
		}
	}
	return next
}

// runtimeInput includes both the generated core configuration and the selected
// executable. A new pinned archive digest alone does not replace that executable.
func runtimeInput(st State, root string) ([]byte, error) {
	config, err := Server(st, root)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Core   string
		Config json.RawMessage
	}{CorePath(root, st.CoreVersion), config})
}

// hostInput is the complete State-dependent effects of the current backend:
// service invocation/identity (the embedded unit) and owned firewall policy.
// UFW synchronization does not require a sing-box restart on its own.
func hostInput(st State) any {
	rules := RequiredRules(st)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Network != rules[j].Network {
			return rules[i].Network < rules[j].Network
		}
		if rules[i].Port != rules[j].Port {
			return rules[i].Port < rules[j].Port
		}
		return rules[i].Tag < rules[j].Tag
	})
	return struct {
		Service, Firewall string
		Rules             []FirewallRule
	}{ServiceUnit, st.Firewall, rules}
}

func displayInput(n Node) any {
	users := make([]string, 0, len(n.Users))
	for _, u := range n.Users {
		users = append(users, u.Name)
	}
	return struct {
		Name, Created, Updated string
		Users                  []string
		Tags                   []string
	}{n.Name, n.CreatedAt, n.UpdatedAt, users, n.Tags}
}

// These are the actual deterministic export sources. QR and base64 encode the
// same URI, and provider wraps the same Mihomo proxy, so comparing them again
// would add work without discovering an additional export change.
func clientInput(n *Node) any {
	if n == nil {
		return nil
	}
	items := make([]any, 0, (1+len(n.AdditionalEndpoints))*len(n.Users))
	for _, endpoint := range EffectiveEndpoints(*n) {
		selected, _ := WithEndpoint(*n, endpoint.ID) // The complete candidate is validated before impact comparison.
		for _, u := range n.Users {
			warnings := append([]string{}, HY2ExportWarnings(*n, "uri")...)
			warnings = append(warnings, HY2ExportWarnings(*n, "mihomo")...)
			warnings = append(warnings, HY2ExportWarnings(*n, "sing-box")...)
			warnings = append(warnings, ProtocolExportWarnings(*n, "uri")...)
			items = append(items, struct {
				Endpoint, ID, URI string
				SingBox, Mihomo   M
				Warnings          []string
			}{endpoint.ID, u.ID, URI(selected, u), Client(selected, u, 2080), MihomoProxy(selected, u), warnings})
		}
	}
	// Export rejects disabled nodes, but info --show-secrets still presents
	// their URI. Compare both the saved client definition and availability.
	return struct {
		Enabled bool
		Items   []any
	}{n.Enabled, items}
}

func nodeRuntimeInput(n *Node, st State, root string) any {
	if n == nil || !n.Enabled {
		return nil
	}
	p, _ := Protocol(n.Protocol)
	config := p.Inbound(*n, root)
	if n.Certificate != nil && n.Certificate.Mode == "acme" && n.Certificate.ACME != nil {
		if resource, e := st.FindCertificate(n.CertificateID); e == nil {
			config["tls"].(M)["certificate_provider"].(M)["data_directory"] = CertificateACMEDirectory(root, *resource)
		}
	}
	config["tag"], config["listen"], config["listen_port"] = n.ID, n.Listen, n.Port
	outbounds, endpoints, final, _ := buildEgressGraph(st, n.EgressID)
	return struct {
		Core                 string
		Config               M
		Outbounds, Endpoints []M
		Final                string
	}{CorePath(root, st.CoreVersion), config, outbounds, endpoints, final}
}

func nodeHostInput(n *Node, st State) any {
	if n == nil {
		return nil
	}
	x := NewState()
	x.Firewall = st.Firewall
	x.Nodes = []Node{*n}
	return RequiredRules(x)
}

func compareImpact(old, next State, root string) (ChangeImpact, error) {
	result := ChangeImpact{Changed: !equalJSON(old, next), Nodes: []NodeImpact{}}
	a, err := runtimeInput(old, root)
	if err != nil {
		return result, err
	}
	b, err := runtimeInput(next, root)
	if err != nil {
		return result, err
	}
	result.ServerRuntime = !bytes.Equal(a, b)
	result.NeedsRestart = result.ServerRuntime
	result.HostEffects = !equalJSON(hostInput(old), hostInput(next))
	// Global bookkeeping is display-only until it changes a derived input above.
	result.Display = old.CoreArchiveSHA256 != next.CoreArchiveSHA256 || !equalJSON(topologyDisplayInput(old), topologyDisplayInput(next))
	result.Display = result.Display || !equalJSON(old.Certificates, next.Certificates)
	// Include actual selected credentials/endpoints, so changing a node's tags
	// can affect a device even when its saved Profile did not change.
	result.Devices = compareDeviceImpact(old, next)
	for _, device := range result.Devices {
		result.Display = result.Display || device.Display
		result.ClientExport = result.ClientExport || device.ClientExport
	}
	before := map[string]*Node{}
	after := map[string]*Node{}
	ids := make([]string, 0, len(old.Nodes)+len(next.Nodes))
	for i := range old.Nodes {
		n := &old.Nodes[i]
		before[n.ID] = n
		ids = append(ids, n.ID)
	}
	for i := range next.Nodes {
		n := &next.Nodes[i]
		after[n.ID] = n
		if before[n.ID] == nil {
			ids = append(ids, n.ID)
		}
	}
	for _, id := range ids {
		o, n := before[id], after[id]
		impact := NodeImpact{ID: id, Changed: !equalJSON(o, n)}
		if n != nil {
			impact.Name = n.Name
		} else {
			impact.Name = o.Name
		}
		var od, nd any
		if o != nil {
			od = displayInput(*o)
		}
		if n != nil {
			nd = displayInput(*n)
		}
		impact.Display = !equalJSON(od, nd)
		impact.ClientExport = !equalJSON(clientInput(o), clientInput(n))
		impact.ServerRuntime = !equalJSON(nodeRuntimeInput(o, old, root), nodeRuntimeInput(n, next, root))
		impact.HostEffects = !equalJSON(nodeHostInput(o, old), nodeHostInput(n, next))
		if impact.Changed || impact.ServerRuntime || impact.HostEffects {
			result.Nodes = append(result.Nodes, impact)
		}
		result.Display = result.Display || impact.Display
		result.ClientExport = result.ClientExport || impact.ClientExport
	}
	beforeForward, afterForward := map[string]*PortForward{}, map[string]*PortForward{}
	ids = nil
	for i := range old.Forwards {
		f := &old.Forwards[i]
		beforeForward[f.ID] = f
		ids = append(ids, f.ID)
	}
	for i := range next.Forwards {
		f := &next.Forwards[i]
		afterForward[f.ID] = f
		if beforeForward[f.ID] == nil {
			ids = append(ids, f.ID)
		}
	}
	for _, id := range ids {
		o, n := beforeForward[id], afterForward[id]
		item := ForwardImpact{ID: id, Changed: !equalJSON(o, n)}
		if n != nil {
			item.Name = n.Name
		} else {
			item.Name = o.Name
		}
		name := func(f *PortForward) string {
			if f == nil {
				return ""
			}
			return f.Name
		}
		item.Display = name(o) != name(n)
		item.ServerRuntime = !equalJSON(forwardRuntimeInput(o, old, root), forwardRuntimeInput(n, next, root))
		item.HostEffects = !equalJSON(forwardHostInput(o, old), forwardHostInput(n, next))
		if item.Changed || item.ServerRuntime || item.HostEffects {
			result.Forwards = append(result.Forwards, item)
		}
		result.Display = result.Display || item.Display
	}
	return result, nil
}

func topologyDisplayInput(st State) any {
	items := make([][2]string, 0, len(st.Egresses)+len(st.EgressPolicies))
	for _, e := range st.Egresses {
		items = append(items, [2]string{e.ID, e.Name})
	}
	for _, p := range st.EgressPolicies {
		items = append(items, [2]string{p.ID, p.Name})
	}
	return items
}

func forwardRuntimeInput(f *PortForward, st State, root string) any {
	if f == nil || !f.Enabled {
		return nil
	}
	out, eps, final, _ := buildEgressGraph(st, f.EgressID)
	return struct {
		Core                 string
		Config               M
		Outbounds, Endpoints []M
		Final                string
	}{CorePath(root, st.CoreVersion), forwardInbound(*f), out, eps, final}
}
func forwardHostInput(f *PortForward, st State) any {
	if f == nil {
		return nil
	}
	x := NewState()
	x.Firewall = st.Firewall
	x.Forwards = []PortForward{*f}
	return RequiredRules(x)
}

// Preview requires the caller's inspection/management lock. It only reads saved
// state and derived files: no transaction repair, core probe, service query, or
// network/firewall mutation. Apply separately checks the staged candidate.
func (s *Store) Preview(next State) (ChangeImpact, error) {
	var resolveErr error
	next, resolveErr = CanonicalCertificates(next)
	if resolveErr != nil {
		return ChangeImpact{}, resolveErr
	}
	if err := next.Validate(); err != nil {
		return ChangeImpact{}, err
	}
	previous, err := s.current()
	if err != nil {
		return ChangeImpact{}, err
	}
	old, err := s.Load()
	if err != nil {
		return ChangeImpact{}, err
	}
	next = normalizeCandidate(next, old)
	result, err := compareImpact(old, next, s.Root)
	if err != nil {
		return result, err
	}
	if previous == "" {
		result.Changed, result.NeedsRestart = true, true
		return result, nil
	}
	expected, err := Server(old, s.Root)
	if err != nil {
		return result, err
	}
	actual, configErr := os.ReadFile(filepath.Join(s.Root, previous, "server.json"))
	core, coreErr := os.ReadFile(filepath.Join(s.Root, previous, "core-version"))
	result.RepairDerived = configErr != nil || coreErr != nil || !bytes.Equal(expected, actual) || string(core) != old.CoreVersion
	if provider, ok := s.Backend.(RuntimeIdentityBackend); ok {
		identity, err := provider.RuntimeIdentity(next)
		if err != nil {
			return result, err
		}
		saved, err := os.ReadFile(filepath.Join(s.Root, previous, "runtime-identity"))
		if os.IsNotExist(err) {
			// Legacy generations have no external-input receipt. Establish it
			// after candidate validation, without restarting the first rename.
			result.RepairDerived = true
		} else if err != nil {
			return result, err
		} else if !bytes.Equal(saved, identity) {
			result.ServerRuntime, result.HostEffects, result.NeedsRestart = true, true, true
			for _, n := range next.Nodes {
				if !n.Enabled {
					continue
				}
				found := false
				for i := range result.Nodes {
					if result.Nodes[i].ID == n.ID {
						result.Nodes[i].ServerRuntime = true
						found = true
					}
				}
				if !found {
					result.Nodes = append(result.Nodes, NodeImpact{ID: n.ID, Name: n.Name, ServerRuntime: true})
				}
			}
		}
	}
	result.Changed = result.Changed || result.RepairDerived
	result.Changed = result.Changed || result.NeedsRestart
	return result, nil
}
