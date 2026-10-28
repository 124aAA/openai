package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qingnode/internal/platform"
)

type removalGuardFixture struct {
	t         *testing.T
	r         Removal
	fragment  string
	mutations []string
	after     func(string, []string)
}

func newRemovalGuardFixture(t *testing.T, kind platform.InitKind) *removalGuardFixture {
	t.Helper()
	root, units := t.TempDir(), t.TempDir()
	member := "qingnode"
	if kind == platform.InitSystemd {
		member += ".service"
	}
	f := &removalGuardFixture{t: t}
	f.r = Removal{Root: root, Unit: filepath.Join(units, member), Binary: filepath.Join(root, "manager"), Library: filepath.Join(root, "lib"), DefinitionRoot: units, ConfigRoot: t.TempDir(), RunlevelRoot: t.TempDir(), ManagerKind: kind, Execute: f.run}
	f.fragment = f.r.Unit
	definition, err := ServiceDefinition(kind)
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{f.r.Unit: definition, f.r.Binary: "original manager"} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(f.r.Library, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.r.Library, ".qingnode-owner"), []byte(OwnerMarker), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "cores"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cores", "identity"), []byte("original core"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *removalGuardFixture) run(_ time.Duration, command string, args ...string) ([]byte, error) {
	if command == "systemctl" && len(args) > 0 && args[0] == "show" {
		if strings.Contains(strings.Join(args, " "), "LoadState,ActiveState,UnitFileState,FragmentPath") {
			return []byte("LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nFragmentPath=" + f.fragment + "\n"), nil
		}
		return []byte("FragmentPath=" + f.fragment + "\nDropInPaths=\n"), nil
	}
	if command == "rc-service" && len(args) == 2 && args[1] == "status" {
		return []byte(" * status: stopped\n"), errors.New("stopped")
	}
	f.mutations = append(f.mutations, command+" "+strings.Join(args, " "))
	if command == "systemctl" && len(args) == 1 && args[0] == "daemon-reload" {
		f.fragment = ""
		if _, err := os.Stat(f.r.Unit); err == nil {
			f.fragment = f.r.Unit
		}
	}
	if command == "rc-update" && len(args) == 3 {
		path := filepath.Join(f.r.RunlevelRoot, args[2], "qingnode")
		if args[0] == "add" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return nil, err
			}
			if err := os.Symlink(f.r.Unit, path); err != nil {
				return nil, err
			}
		} else if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	if f.after != nil {
		f.after(command, args)
	}
	return nil, nil
}

func (f *removalGuardFixture) external(change string) (string, []byte) {
	f.t.Helper()
	path := f.r.Unit
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		path += ".qingnode-uninstall"
	}
	content := []byte("# Managed by QingNode\n# administrator changed this service\n")
	if change == "override" {
		if f.r.ManagerKind == platform.InitOpenRC {
			path = filepath.Join(f.r.ConfigRoot, "qingnode")
		} else {
			path = filepath.Join(f.r.Unit+".d", "administrator.conf")
			if err := os.Mkdir(filepath.Dir(path), 0755); err != nil {
				f.t.Fatal(err)
			}
		}
		content = []byte("# external override\n")
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		f.t.Fatal(err)
	}
	return path, content
}

func TestRemovalNativeWaitPreservesForeignServiceAndRecoveryMaterials(t *testing.T) {
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		verbs := []string{"stop"}
		if kind == platform.InitSystemd {
			verbs = []string{"disable", "daemon-reload"}
		}
		for _, full := range []bool{false, true} {
			for _, verb := range verbs {
				for _, change := range []string{"unit", "override"} {
					t.Run(string(kind)+"/"+map[bool]string{false: "cores", true: "full"}[full]+"/"+verb+"/"+change, func(t *testing.T) {
						f := newRemovalGuardFixture(t, kind)
						fired, after := false, 0
						var path string
						var foreign []byte
						f.after = func(command string, args []string) {
							actual := ""
							if command == "systemctl" && len(args) > 0 {
								actual = args[0]
							}
							if command == "rc-service" && len(args) == 2 {
								actual = args[1]
							}
							if fired || actual != verb {
								return
							}
							fired = true
							path, foreign = f.external(change)
							after = len(f.mutations)
						}
						if err := f.r.Remove(full); err == nil {
							t.Fatal("foreign service change during native wait was accepted")
						}
						actual, err := os.ReadFile(path)
						if !fired || err != nil || !bytes.Equal(actual, foreign) {
							t.Fatal("foreign service material was moved, deleted or overwritten", err)
						}
						if len(f.mutations) != after {
							t.Fatal("automatic recovery controlled a service after external ownership change", f.mutations[after:])
						}
						if _, err := os.Stat(filepath.Join(f.r.Root, "uninstall.json")); err != nil {
							t.Fatal("pending recovery journal lost", err)
						}
						core := filepath.Join(f.r.Root, "cores", "identity")
						if _, err := os.Stat(core); errors.Is(err, os.ErrNotExist) {
							core = filepath.Join(f.r.Root, ".uninstall-cores", "identity")
						}
						if b, err := os.ReadFile(core); err != nil || string(b) != "original core" {
							t.Fatal("original core recovery material lost", err)
						}
					})
				}
			}
		}
	}
}

func TestRemovalRecoveryWaitNeverControlsChangedService(t *testing.T) {
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		verbs := []string{"add", "restart"}
		if kind == platform.InitSystemd {
			verbs = []string{"daemon-reload", "enable", "restart"}
		}
		for _, verb := range verbs {
			for _, change := range []string{"unit", "override"} {
				t.Run(string(kind)+"/"+verb+"/"+change, func(t *testing.T) {
					f := newRemovalGuardFixture(t, kind)
					for _, pair := range f.r.pairs(true) {
						if err := os.Rename(pair[0], pair[1]); err != nil {
							t.Fatal(err)
						}
					}
					f.fragment = ""
					j := removalJournal{Full: true, Active: true, Enabled: true}
					if kind == platform.InitOpenRC {
						j.Runlevels = []string{"custom"}
					}
					journal, _ := json.Marshal(j)
					if err := os.WriteFile(filepath.Join(f.r.Root, "uninstall.json"), journal, 0600); err != nil {
						t.Fatal(err)
					}
					fired, after := false, 0
					var path string
					var foreign []byte
					f.after = func(command string, args []string) {
						actual := ""
						if command == "systemctl" && len(args) > 0 {
							actual = args[0]
						}
						if command == "rc-service" && len(args) == 2 {
							actual = args[1]
						}
						if command == "rc-update" && len(args) > 0 {
							actual = args[0]
						}
						if fired || actual != verb {
							return
						}
						fired = true
						path, foreign = f.external(change)
						after = len(f.mutations)
					}
					if err := f.r.Recover(); err == nil {
						t.Fatal("recovery accepted changed service")
					}
					actual, err := os.ReadFile(path)
					if !fired || err != nil || !bytes.Equal(actual, foreign) {
						t.Fatal("recovery replaced foreign material", err)
					}
					if len(f.mutations) != after {
						t.Fatal("recovery continued native control after external change", f.mutations[after:])
					}
					if b, err := os.ReadFile(filepath.Join(f.r.Root, "uninstall.json")); err != nil || !bytes.Equal(b, journal) {
						t.Fatal("recovery discarded original journal", err)
					}
				})
			}
		}
	}
}

func TestRemovalRecoveryRejectsChangedStagedDefinitionBeforeRestoringAnything(t *testing.T) {
	f := newRemovalGuardFixture(t, platform.InitSystemd)
	for _, pair := range f.r.pairs(true) {
		if err := os.Rename(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	f.fragment = ""
	journal := []byte(`{"full":true,"active":true,"enabled":true}`)
	if err := os.WriteFile(filepath.Join(f.r.Root, "uninstall.json"), journal, 0600); err != nil {
		t.Fatal(err)
	}
	path, foreign := f.external("unit")
	if err := f.r.Recover(); err == nil {
		t.Fatal("changed staged definition was restored")
	}
	if len(f.mutations) != 0 {
		t.Fatal("changed staged definition triggered native control")
	}
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, foreign) {
		t.Fatal("changed staged definition was overwritten", err)
	}
	if _, err := os.Stat(filepath.Join(f.r.Root, ".uninstall-cores", "identity")); err != nil {
		t.Fatal("preflight restored other assets before checking service", err)
	}
}

func TestRemovalLibraryUnknownMembersArePreserved(t *testing.T) {
	for _, when := range []string{"preflight", "native-wait", "recovery"} {
		t.Run(when, func(t *testing.T) {
			f := newRemovalGuardFixture(t, platform.InitSystemd)
			path := filepath.Join(f.r.Library, "administrator-notes")
			foreign := []byte("external material must survive\n")
			created, after := false, 0
			create := func() {
				if err := os.WriteFile(path, foreign, 0600); err != nil {
					t.Fatal(err)
				}
				created = true
				after = len(f.mutations)
			}
			if when == "native-wait" {
				f.after = func(command string, args []string) {
					if !created && command == "systemctl" && len(args) > 0 && args[0] == "disable" {
						create()
					}
				}
			} else if when == "recovery" {
				for _, pair := range f.r.pairs(true) {
					if err := os.Rename(pair[0], pair[1]); err != nil {
						t.Fatal(err)
					}
				}
				f.fragment = ""
				path = filepath.Join(f.r.Library+".qingnode-uninstall", "administrator-notes")
				if err := os.WriteFile(filepath.Join(f.r.Root, "uninstall.json"), []byte(`{"full":true,"active":true,"enabled":true}`), 0600); err != nil {
					t.Fatal(err)
				}
				create()
			} else {
				create()
			}
			var err error
			if when == "recovery" {
				err = f.r.Recover()
			} else {
				err = f.r.Remove(true)
			}
			if err == nil {
				t.Fatal("unknown library member was silently adopted")
			}
			b, readErr := os.ReadFile(path)
			if !created || readErr != nil || !bytes.Equal(b, foreign) {
				t.Fatal("unknown library file was moved or deleted", readErr)
			}
			if len(f.mutations) != after {
				t.Fatal("foreign library member was followed by native control", f.mutations[after:])
			}
		})
	}
}

func TestRemovalServiceGuardAcceptsStructuredMissingOnlyDuringOwnedStaging(t *testing.T) {
	f := newRemovalGuardFixture(t, platform.InitSystemd)
	f.r.Execute = func(time.Duration, string, ...string) ([]byte, error) {
		return []byte("FragmentPath=\nDropInPaths=\n"), errors.New("unit not found")
	}
	if err := f.r.serviceMaterialSafe(false, false); err == nil {
		t.Fatal("live definition with an unloaded source was accepted")
	}
	if err := os.Rename(f.r.Unit, f.r.Unit+".qingnode-uninstall"); err != nil {
		t.Fatal(err)
	}
	if err := f.r.serviceMaterialSafe(true, false); err != nil {
		t.Fatal("structured missing source of our own staged unit was refused", err)
	}
	f.r.Execute = func(time.Duration, string, ...string) ([]byte, error) { return nil, errors.New("bus unavailable") }
	if err := f.r.serviceMaterialSafe(true, false); err == nil {
		t.Fatal("bus failure was treated as a structured missing unit")
	}
}

func TestRemovalSourceReadCallbackCannotAuthorizeLaterMoves(t *testing.T) {
	for _, target := range []string{"unit", "binary", "helper"} {
		t.Run(target, func(t *testing.T) {
			f := newRemovalGuardFixture(t, platform.InitSystemd)
			helper := filepath.Join(f.r.Library, "install.sh")
			if err := os.WriteFile(helper, []byte("original helper"), 0600); err != nil {
				t.Fatal(err)
			}
			path := f.r.Unit
			if target == "binary" {
				path = f.r.Binary
			}
			if target == "helper" {
				path = helper
			}
			original := f.r.Execute
			fired := false
			foreign := []byte("# administrator changed the service during source observation\n")
			f.r.Execute = func(timeout time.Duration, command string, args ...string) ([]byte, error) {
				out, err := original(timeout, command, args...)
				if !fired && command == "systemctl" && len(args) > 0 && args[0] == "show" {
					fired = true
					if err := os.WriteFile(path, foreign, 0600); err != nil {
						t.Fatal(err)
					}
				}
				return out, err
			}
			if err := f.r.Remove(true); err == nil {
				t.Fatal("source read callback modification was accepted")
			}
			if !fired || len(f.mutations) != 0 {
				t.Fatal("source callback was missed or followed by native mutations", f.mutations)
			}
			if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, foreign) {
				t.Fatal("foreign file changed", err)
			}
			if _, err := os.Stat(filepath.Join(f.r.Root, "cores", "identity")); err != nil {
				t.Fatal("core moved after source callback", err)
			}
			if _, err := os.Stat(filepath.Join(f.r.Root, "uninstall.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("ownership changed before a new transaction, but recovery journal was created", err)
			}
		})
	}
}

func TestRemovalFingerprintPreservesModeBinaryAndHelperChanges(t *testing.T) {
	for _, kind := range []platform.InitKind{platform.InitSystemd, platform.InitOpenRC} {
		for _, direction := range []string{"remove", "recover"} {
			for _, target := range []string{"mode", "binary", "helper", "rotation"} {
				t.Run(string(kind)+"/"+direction+"/"+target, func(t *testing.T) {
					f := newRemovalGuardFixture(t, kind)
					helper := filepath.Join(f.r.Library, "install.sh")
					if err := os.WriteFile(helper, []byte("original helper"), 0600); err != nil {
						t.Fatal(err)
					}
					f.r.Logrotate = filepath.Join(f.r.Root, "logrotate")
					if err := os.WriteFile(f.r.Logrotate, []byte(managedLogrotate), 0600); err != nil {
						t.Fatal(err)
					}
					if direction == "recover" {
						for _, pair := range f.r.pairs(true) {
							if err := os.Rename(pair[0], pair[1]); err != nil {
								t.Fatal(err)
							}
						}
						f.fragment = ""
						j := removalJournal{Full: true, Active: true, Enabled: true}
						if kind == platform.InitOpenRC {
							j.Runlevels = []string{"custom"}
						}
						b, _ := json.Marshal(j)
						if err := os.WriteFile(filepath.Join(f.r.Root, "uninstall.json"), b, 0600); err != nil {
							t.Fatal(err)
						}
					}
					fired, after := false, 0
					path := ""
					foreign := []byte("administrator changed file bytes\n")
					f.after = func(command string, args []string) {
						if fired {
							return
						}
						wanted := false
						if direction == "remove" {
							wanted = command == "systemctl" && len(args) > 0 && args[0] == "disable" || command == "rc-service" && len(args) == 2 && args[1] == "stop"
						} else {
							wanted = command == "systemctl" && len(args) > 0 && args[0] == "daemon-reload" || command == "rc-update" && len(args) > 0 && args[0] == "add"
						}
						if !wanted {
							return
						}
						fired = true
						switch target {
						case "mode":
							path = f.r.Unit
						case "binary":
							path = f.r.Binary
						case "helper":
							path = helper
						case "rotation":
							path = f.r.Logrotate
						}
						if target == "mode" {
							if err := os.Chmod(path, 0644); err != nil {
								t.Fatal(err)
							}
						} else if err := os.WriteFile(path, foreign, 0600); err != nil {
							t.Fatal(err)
						}
						after = len(f.mutations)
					}
					var err error
					if direction == "remove" {
						err = f.r.Remove(true)
					} else {
						err = f.r.Recover()
					}
					if err == nil || !fired {
						t.Fatal("native callback file identity change was accepted or not exercised", err)
					}
					if len(f.mutations) != after {
						t.Fatal("native control continued after original file identity changed", f.mutations[after:])
					}
					if target == "mode" {
						if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0644 {
							t.Fatal("external mode change was overwritten", err)
						}
					} else if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, foreign) {
						t.Fatal("external file content was moved, removed or overwritten", err)
					}
					if _, err := os.Stat(filepath.Join(f.r.Root, "uninstall.json")); err != nil {
						t.Fatal("identity change lost pending recovery journal", err)
					}
				})
			}
		}
	}
}
