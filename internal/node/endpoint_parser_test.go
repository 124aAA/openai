package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOfficialCoreAndMihomoSelectedEndpointParsers(t *testing.T) {
	core, mihomo := os.Getenv("SING_BOX_BIN"), os.Getenv("MIHOMO_BIN")
	if core == "" || mihomo == "" {
		t.Skip("requires verified official core and Mihomo; selected endpoint parser evidence absent")
	}
	states := []State{fixture(t), hyFixture(t)}
	ss := NewState()
	ss.Nodes = []Node{ssFixture()}
	states = append(states, ss)
	for _, s := range states {
		n := s.Nodes[0]
		port := 30000
		n.ConnectPort = &port
		n.AdditionalEndpoints = []ConnectionEndpoint{{ID: "v6", Host: "2001:0db8::1", Port: 31000}, {ID: "domain", Host: "entry.example.test", Port: 32000}}
		for _, endpoint := range EffectiveEndpoints(n) {
			t.Run(n.Protocol+"/"+endpoint.ID, func(t *testing.T) {
				selected, err := WithEndpoint(n, endpoint.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, format := range []string{"sing-box", "mihomo"} {
					data, err := Export(selected, selected.Users[0], format)
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					path := filepath.Join(dir, "selected.config")
					if err = os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					command := exec.Command(core, "check", "-c", path)
					if format == "mihomo" {
						command = exec.Command(mihomo, "-t", "-d", dir, "-f", path)
					}
					if output, err := command.CombinedOutput(); err != nil {
						t.Fatalf("%s selected %s rejected: %v\n%s", format, endpoint.ID, err, output)
					}
				}
			})
		}
	}
}
