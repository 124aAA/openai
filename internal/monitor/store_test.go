package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusReadHasNoInitializationSideEffect(t *testing.T) {
	s := testStore(t)
	if _, err := s.LoadStatus(); err == nil {
		t.Fatal("missing status accepted")
	}
	if _, err := os.Lstat(s.Root); !os.IsNotExist(err) {
		t.Fatalf("read initialized root: %v", err)
	}
	if err := os.Mkdir(s.Root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root, "foreign"), []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(); err == nil {
		t.Fatal("claimed foreign directory")
	}
	if _, err := os.Lstat(filepath.Join(s.Root, markerName)); !os.IsNotExist(err) {
		t.Fatal("foreign marker created")
	}
}

func TestConfigPrivateCodecAndStrictFields(t *testing.T) {
	s := testStore(t)
	c := testConfig()
	c.Notifications.Enabled = true
	c.Notifications.Endpoint = "https://notify.example/private-path"
	c.Notifications.Token = "top-secret-value"
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Notifications.Token != c.Notifications.Token || !got.privateNotifications {
		t.Fatal("private codec lost credential")
	}
	public, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), c.Notifications.Token) || strings.Contains(string(public), c.Notifications.Endpoint) {
		t.Fatal("public config exposed credential")
	}
	for _, input := range []string{`{"version":1,"version":1}`, `{"version":1,"unknown":true}`, `{"version":2}`, `{"version":1,"notifications":{"token":"one","token":"two"}}`} {
		if _, err := decodeConfig([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestConfigBoundsAndReferences(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.IntervalSeconds = 1 }, func(c *Config) { c.MaxBytes = 65537 }, func(c *Config) { c.Concurrency = 5 }, func(c *Config) { c.TimeoutMS = 120001 },
		func(c *Config) { c.History.Records = 513 }, func(c *Config) { c.History.Bytes = MaxHistoryBytes + 1 }, func(c *Config) { c.History.Events = 1025 },
		func(c *Config) { c.Jobs[0].EgressID = "egress" }, func(c *Config) { c.Jobs[0].NodeID = "" }, func(c *Config) { c.Jobs[0].TargetURL = "https://target.example/?token=secret" },
		func(c *Config) { c.Jobs[0].TargetURL = "http://target.example/" }, func(c *Config) { c.Jobs[0].TargetURL = "https://u:p@target.example/" }, func(c *Config) { c.Jobs[0].UDPAddress = "target.example:0" },
		func(c *Config) { c.Jobs[0].Signals = []SignalKind{"invented"} }, func(c *Config) { c.Jobs[0].Labels = map[string]string{"x": strings.Repeat("x", 129)} },
		func(c *Config) { c.Jobs = append(c.Jobs, c.Jobs[0]) }, func(c *Config) { c.Recovery.ConsecutiveFailures = 1 },
	} {
		c := testConfig()
		change(&c)
		if _, err := NormalizeConfig(c); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	c := testConfig()
	c.Jobs[0].EndpointID = "default"
	if _, err := NormalizeConfig(c); err != nil {
		t.Fatalf("default endpoint rejected: %v", err)
	}
}

func TestSymlinkAndHardlinkBoundaries(t *testing.T) {
	t.Run("owned_file_hardlink", func(t *testing.T) {
		s := testStore(t)
		if err := s.Initialize(); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(filepath.Dir(s.Root), "outside")
		if err := os.WriteFile(outside, []byte("external-data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, filepath.Join(s.Root, "config.json")); err != nil {
			t.Skipf("hardlinks unsupported: %v", err)
		}
		if _, err := s.LoadConfig(); err == nil {
			t.Fatal("read linked config")
		}
		if err := s.SaveConfig(testConfig()); err == nil {
			t.Fatal("replaced linked config")
		}
		b, err := os.ReadFile(outside)
		if err != nil || string(b) != "external-data" {
			t.Fatal("outside changed")
		}
	})
	t.Run("owned_file_symlink", func(t *testing.T) {
		s := testStore(t)
		if err := s.Initialize(); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(filepath.Dir(s.Root), "outside")
		if err := os.WriteFile(outside, []byte("external-data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(s.Root, "status.json")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := s.LoadStatus(); err == nil {
			t.Fatal("read symlink")
		}
		if err := s.writeOwned("status.json", []byte("{}"), MaxStatusBytes); err == nil {
			t.Fatal("replaced symlink")
		}
		b, err := os.ReadFile(outside)
		if err != nil || string(b) != "external-data" {
			t.Fatal("outside changed")
		}
	})
	t.Run("root_symlink", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0700); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(parent, "link")
		if err := os.Symlink(real, linked); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		s := &Store{Root: linked}
		if err := s.Initialize(); err == nil {
			t.Fatal("claimed symlink root")
		}
		if _, err := os.Lstat(filepath.Join(real, markerName)); !os.IsNotExist(err) {
			t.Fatal("modified outside root")
		}
	})
}
