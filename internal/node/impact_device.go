package node

import "sort"

type DeviceImpact struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Changed      bool     `json:"changed"`
	Display      bool     `json:"display"`
	ClientExport bool     `json:"client_export"`
	NodeIDs      []string `json:"node_ids"`
}

// This projection uses the same explicit binding, endpoint, naming and protocol
// adapters as export. Tags and binding order matter only through the selected
// members; remote server egress credentials never enter this comparison.
func deviceClientInput(st State, p *DeviceProfile) any {
	if p == nil {
		return nil
	}
	if p.Disabled {
		return "disabled"
	}
	settings := *p
	settings.ID, settings.Name = "", ""
	settings.Bindings, settings.NodeTags = nil, nil
	settings.Strategy, settings.Routing = deviceStrategy(*p), deviceRouting(*p)
	if settings.Strategy != "manual" {
		// An explicit timeout is rejected by sing-box URLTest, while zero
		// means use its native limit. Keep that compatibility difference.
		settings.IntervalSeconds, settings.ToleranceMS, _ = deviceTestSettings(*p)
		if settings.Strategy == "fallback" {
			settings.ToleranceMS = 0
		}
	}
	members := []any{}
	for _, b := range selectedDeviceBindings(st, *p) {
		n, u, err := deviceBinding(st, b)
		if err != nil {
			members = append(members, err.Error())
			continue
		}
		outbound, proxy := Outbound(n, u), MihomoProxy(n, u)
		outbound["tag"], proxy["name"] = deviceExportTag(b), deviceExportName(n, u, b)
		members = append(members, struct {
			Enabled         bool
			Name, URI       string
			SingBox, Mihomo M
			Warnings        []string
		}{n.Enabled, deviceExportName(n, u, b), URI(n, u), outbound, proxy,
			append(append(HY2ExportWarnings(n, "uri"), HY2ExportWarnings(n, "mihomo")...), HY2ExportWarnings(n, "sing-box")...)})
	}
	return struct {
		Settings DeviceProfile
		Members  []any
	}{settings, members}
}

func compareDeviceImpact(old, next State) []DeviceImpact {
	before, after := map[string]*DeviceProfile{}, map[string]*DeviceProfile{}
	ids := []string{}
	for i := range old.Devices {
		p := &old.Devices[i]
		before[p.ID] = p
		ids = append(ids, p.ID)
	}
	for i := range next.Devices {
		p := &next.Devices[i]
		after[p.ID] = p
		if before[p.ID] == nil {
			ids = append(ids, p.ID)
		}
	}
	sort.Strings(ids)
	items := []DeviceImpact{}
	for _, id := range ids {
		a, b := before[id], after[id]
		item := DeviceImpact{ID: id, Changed: !equalJSON(a, b), ClientExport: !equalJSON(deviceClientInput(old, a), deviceClientInput(next, b)), NodeIDs: []string{}}
		item.Display = item.Changed
		if b != nil {
			item.Name = b.Name
		} else {
			item.Name = a.Name
		}
		item.Name = Redact(item.Name, old, next)
		if !item.Changed && !item.ClientExport {
			continue
		}
		nodes := map[string]bool{}
		for i, p := range []*DeviceProfile{a, b} {
			if p == nil {
				continue
			}
			st := old
			if i == 1 {
				st = next
			}
			for _, binding := range selectedDeviceBindings(st, *p) {
				nodes[binding.NodeID] = true
			}
		}
		for node := range nodes {
			item.NodeIDs = append(item.NodeIDs, node)
		}
		sort.Strings(item.NodeIDs)
		items = append(items, item)
	}
	return items
}
