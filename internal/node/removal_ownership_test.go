package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/platform"
)

func TestRemovalRejectsChangedServiceBeforeMutation(t *testing.T) {
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		changes := []string{"command", "override", "symlink", "hardlink", "writable"}
		if kind == platform.InitSystemd {
			changes = append(changes, "fragment")
		}
		for _, change := range changes {
			t.Run(string(kind)+"/"+change, func(t *testing.T) {
				root, definitions, configs := t.TempDir(), t.TempDir(), t.TempDir()
				name := "qingnode"
				if kind == platform.InitSystemd {
					name += ".service"
				}
				unit := filepath.Join(definitions, name)
				definition, e := ServiceDefinition(kind)
				if e != nil {
					t.Fatal(e)
				}
				if change == "command" {
					definition = strings.ReplaceAll(definition, "/usr/local/bin/qingnode", "/usr/local/bin/external")
				}
				if e = os.WriteFile(unit, []byte(definition), 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.Mkdir(filepath.Join(root, "cores"), 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(root, "cores", "sentinel"), []byte("core identity"), 0600); e != nil {
					t.Fatal(e)
				}
				if change == "symlink" {
					saved := filepath.Join(root, "external-definition")
					if e = os.Rename(unit, saved); e == nil {
						e = os.Symlink(saved, unit)
					}
				} else if change == "hardlink" {
					e = os.Link(unit, filepath.Join(root, "external-hardlink"))
				} else if change == "writable" {
					e = os.Chmod(unit, 0666)
				}
				if e != nil {
					t.Fatal(e)
				}
				// OpenRC conf.d cannot be redirected by a production environment
				// variable. An explicit fixture Manager supplies its isolated path.
				if kind == platform.InitOpenRC && change == "override" {
					if e = os.WriteFile(filepath.Join(configs, "qingnode"), []byte("command=/external\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				var mutations []string
				r := Removal{Root: root, Unit: unit, Binary: filepath.Join(root, "manager"), Library: filepath.Join(root, "lib"), ManagerKind: kind, DefinitionRoot: definitions, ConfigRoot: configs,
					Execute: func(_ time.Duration, command string, args ...string) ([]byte, error) {
						if command == "systemctl" && args[0] == "show" {
							fragment := unit
							if change == "fragment" {
								fragment = "/usr/lib/systemd/system/external.service"
							}
							dropins := ""
							if change == "override" {
								dropins = "/etc/systemd/system/qingnode.service.d/override.conf"
							}
							return []byte("FragmentPath=" + fragment + "\nDropInPaths=" + dropins + "\n"), nil
						}
						mutations = append(mutations, command+" "+strings.Join(args, " "))
						return nil, errors.New("service mutation must not be attempted")
					}}
				if e = r.Remove(false); e == nil {
					t.Fatal("changed service accepted for removal")
				}
				if len(mutations) != 0 {
					t.Fatal("ownership rejection mutated a service", mutations)
				}
				if actual, e := os.ReadFile(unit); e != nil || !bytes.Equal(actual, []byte(definition)) {
					t.Fatal("service definition changed", e)
				}
				if actual, e := os.ReadFile(filepath.Join(root, "cores", "sentinel")); e != nil || string(actual) != "core identity" {
					t.Fatal("core recovery material changed", e)
				}
				if _, e := os.Lstat(filepath.Join(root, "uninstall.json")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("rejected removal wrote a journal", e)
				}
			})
		}
	}
}

func TestRemovalLogrotateRequiresExactOwnedRendering(t *testing.T) {
	for _, change := range []string{"original", "external-edit", "hardlink", "symlink", "writable"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "logrotate")
			content := managedLogrotate
			if change == "external-edit" {
				content = strings.ReplaceAll(content, "rotate 3", "rotate 30")
			}
			if e := os.WriteFile(path, []byte(content), 0600); e != nil {
				t.Fatal(e)
			}
			var e error
			if change == "hardlink" {
				e = os.Link(path, filepath.Join(dir, "foreign-link"))
			} else if change == "symlink" {
				saved := filepath.Join(dir, "foreign-file")
				if e = os.Rename(path, saved); e == nil {
					e = os.Symlink(saved, path)
				}
			} else if change == "writable" {
				e = os.Chmod(path, 0666)
			}
			if e != nil {
				t.Fatal(e)
			}
			r := Removal{Root: dir, Unit: filepath.Join(dir, "unit"), Binary: filepath.Join(dir, "bin"), Library: filepath.Join(dir, "lib"), Logrotate: path}
			included := false
			for _, pair := range r.pairs(true) {
				included = included || pair[0] == path
			}
			if included != (change == "original") {
				t.Fatal("unexpected ownership classification", included)
			}
			if actual, e := os.ReadFile(path); e != nil || string(actual) != content {
				t.Fatal("ownership classification changed external rule", e)
			}
		})
	}
}

func TestRemovalLogrotateRenderingMatchesInstaller(t *testing.T) {
	script, e := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.ReplaceAll(string(script), "\r\n", "\n"), "<<'QINGNODE_LOGROTATE'\n"+managedLogrotate+"QINGNODE_LOGROTATE\n") {
		t.Fatal("installer rotation no longer matches the only rendering removal may own")
	}
}
