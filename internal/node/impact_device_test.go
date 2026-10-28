package node

import "testing"

func TestDeviceImpactPreservesExplicitTimeoutVersionGate(t *testing.T) {
	s, _, st := impactStore(t)
	st.Devices = []DeviceProfile{{ID: "eeeeeeeeeeeeeeee", Name: "phone", Strategy: "auto", TestURL: "https://controlled.example.test/health", SubscriptionFormats: []string{"sing-box"}, Bindings: []DeviceBinding{{NodeID: st.Nodes[0].ID, UserID: st.Nodes[0].Users[0].ID}}}}
	if err := s.WithLock(func() error { return s.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportDeviceProfile(st, st.Devices[0], "sing-box", "1.14.0", false); err != nil {
		t.Fatal(err)
	}
	c := st.Clone()
	c.Devices[0].TimeoutMS = 5000
	if _, err := ExportDeviceProfile(c, c.Devices[0], "sing-box", "1.14.0", false); err == nil {
		t.Fatal("unsupported explicit sing-box timeout accepted")
	}
	impact, err := s.Preview(c)
	if err != nil {
		t.Fatal(err)
	}
	if !impact.ClientExport || len(impact.Devices) != 1 || !impact.Devices[0].ClientExport || impact.NeedsRestart {
		t.Fatalf("version rejection missing from preview: %+v", impact)
	}
}

func TestDeviceImpactFollowsSelectedTagsCredentialsAndEndpoints(t *testing.T) {
	s, _, st := impactStore(t)
	st.Nodes[0].Tags = []string{"home"}
	st.Devices = []DeviceProfile{{ID: "eeeeeeeeeeeeeeee", Name: "phone", NodeTags: []string{"home"}, Bindings: []DeviceBinding{{NodeID: st.Nodes[0].ID, UserID: st.Nodes[0].Users[0].ID}}}}
	if err := s.WithLock(func() error { return s.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*State){
		"rename profile":                   func(c *State) { c.Devices[0].Name = "tablet" },
		"unused tag":                       func(c *State) { c.Nodes[0].Tags = []string{"home", "other"} },
		"filter removes selected entrance": func(c *State) { c.Nodes[0].Tags = []string{"other"} },
		"selected endpoint":                func(c *State) { port := 31000; c.Nodes[0].ConnectPort = &port },
	} {
		t.Run(name, func(t *testing.T) {
			c := st.Clone()
			change(&c)
			impact, err := s.Preview(c)
			if err != nil {
				t.Fatal(err)
			}
			wantExport := name == "filter removes selected entrance" || name == "selected endpoint"
			if !impact.Changed || !impact.Display && name != "selected endpoint" || impact.ClientExport != wantExport || impact.NeedsRestart || impact.ServerRuntime || impact.HostEffects {
				t.Fatalf("unexpected derived device impact: %+v", impact)
			}
			if wantExport {
				if len(impact.Devices) != 1 || impact.Devices[0].ID != st.Devices[0].ID || !impact.Devices[0].ClientExport || len(impact.Devices[0].NodeIDs) != 1 || impact.Devices[0].NodeIDs[0] != st.Nodes[0].ID {
					t.Fatalf("missing affected device/entrance IDs: %+v", impact.Devices)
				}
			}
			if name == "rename profile" && (len(impact.Devices) != 1 || impact.Devices[0].ClientExport || !impact.Devices[0].Display) {
				t.Fatal("display-only Profile name treated as generated configuration")
			}
		})
	}
}
