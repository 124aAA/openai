package platform

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func hostFixture(t *testing.T, distro, version, pid string) string {
	t.Helper()
	root := t.TempDir()
	for path, value := range map[string]string{"etc/os-release": "ID=" + distro + "\nVERSION_ID=\"" + version + "\"\n", "proc/1/comm": pid + "\n"} {
		p := filepath.Join(root, path)
		if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(value), 0644); e != nil {
			t.Fatal(e)
		}
	}
	return root
}
func TestHostCapabilitiesSeparatesInstalledToolsAndRuntimeController(t *testing.T) {
	root := hostFixture(t, "rocky", "9.7", "bash")
	called := []string{}
	r := ProbeHost(HostProbeOptions{RootDir: root, LookPath: func(n string) (string, error) { return "/tools/" + n, nil }, Execute: func(_ time.Duration, n string, a ...string) ([]byte, error) {
		called = append(called, n+" "+strings.Join(a, " "))
		return nil, errors.New("ordinary container")
	}})
	if !r.Init.ToolPresent || r.Init.ControllerAvailable || r.Init.Kind != InitUnavailable {
		t.Fatal(r.Init)
	}
	if r.Distro != "rocky" || r.DistroVersion != "9.7" || r.PackageManager != "dnf" {
		t.Fatal(r)
	}
	if !r.Firewall["firewalld"].ToolPresent || r.Firewall["firewalld"].Available == nil || *r.Firewall["firewalld"].Available {
		t.Fatal(r.Firewall)
	}
	for _, c := range called {
		if strings.HasPrefix(c, "systemctl") || strings.Contains(c, "start") || strings.Contains(c, "reload") {
			t.Fatal("probe changed host", called)
		}
	}
}
func TestHostCapabilitiesControllerRequiresRuntimeEvidenceAndSuccessfulQuery(t *testing.T) {
	for _, kind := range []InitKind{InitSystemd, InitOpenRC} {
		t.Run(string(kind), func(t *testing.T) {
			pid := "init"
			if kind == InitSystemd {
				pid = "systemd"
			}
			root := hostFixture(t, "alpine", "3.24.0", pid)
			if kind == InitSystemd {
				os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0755)
			} else {
				os.MkdirAll(filepath.Join(root, "run/openrc"), 0755)
				os.WriteFile(filepath.Join(root, "run/openrc/softlevel"), []byte("default\n"), 0644)
			}
			for _, fail := range []bool{true, false} {
				r := ProbeHost(HostProbeOptions{RootDir: root, LookPath: func(n string) (string, error) {
					if n == "systemctl" || strings.HasPrefix(n, "rc-") {
						return "/tool/" + n, nil
					}
					return "", errors.New("missing")
				}, Execute: func(_ time.Duration, n string, a ...string) ([]byte, error) {
					if fail {
						return nil, errors.New("dbus or openrc inaccessible")
					}
					return []byte("ready"), nil
				}})
				if r.Init.Kind != kind || r.Init.ControllerAvailable == fail {
					t.Fatal(kind, fail, r.Init)
				}
			}
		})
	}
}
func TestHostCapabilitiesDoesNotEvaluateOSRelease(t *testing.T) {
	root := hostFixture(t, "$(touch bad)", "9.7", "init")
	r := ProbeHost(HostProbeOptions{RootDir: root, LookPath: func(string) (string, error) { return "", errors.New("missing") }, Execute: func(time.Duration, string, ...string) ([]byte, error) { t.Fatal("must not invoke"); return nil, nil }})
	if !strings.HasPrefix(r.InstallTarget, "unsupported:") || r.PackageManager != "" {
		t.Fatal(r)
	}
	if _, e := os.Stat(filepath.Join(root, "bad")); !os.IsNotExist(e) {
		t.Fatal("executed source")
	}
}

func TestHostCapabilitiesStandardOSReleaseLinksAndFallback(t *testing.T) {
	for _, target := range []string{"../usr/lib/os-release", "/usr/lib/os-release", "missing", "../outside", "../usr/lib/elsewhere"} {
		t.Run(target, func(t *testing.T) {
			root := hostFixture(t, "unused", "0", "bash")
			if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("ID=rocky\nVERSION_ID=9.8\n"), 0644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "etc/os-release")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if target != "missing" {
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			r := ProbeHost(HostProbeOptions{RootDir: root, LookPath: func(string) (string, error) { return "", errors.New("missing") }, Execute: func(time.Duration, string, ...string) ([]byte, error) { t.Fatal("must not invoke"); return nil, nil }})
			want := target == "missing" || target == "../usr/lib/os-release" || target == "/usr/lib/os-release"
			if want && (r.Distro != "rocky" || r.DistroVersion != "9.8" || r.PackageManager != "dnf") || !want && r.Distro != "" {
				t.Fatal(target, r)
			}
		})
	}
}
func TestPackagePlansBoundExactTargetsAndArchitecture(t *testing.T) {
	for _, c := range []struct{ d, v, m string }{{"debian", "12", "apt-get"}, {"debian", "13", "apt-get"}, {"ubuntu", "24.04", "apt-get"}, {"rocky", "9.7", "dnf"}, {"alpine", "3.24.0", "apk"}} {
		for _, arch := range []string{"amd64", "arm64"} {
			p, e := DependenciesFor(c.d, c.v, arch)
			if e != nil || p.Manager != c.m || len(p.Packages) < 10 {
				t.Fatal(p, e)
			}
			if strings.Contains(strings.Join(p.Install, " "), "upgrade") {
				t.Fatal(p)
			}
		}
	}
	for _, c := range []struct{ d, v, a string }{{"rocky", "10", "amd64"}, {"alpine", "3.23", "amd64"}, {"alpine", "3.24.evil", "amd64"}, {"rocky", "9.$(bad)", "amd64"}, {"debian", "12", "386"}, {"centos", "7", "amd64"}} {
		if _, e := DependenciesFor(c.d, c.v, c.a); e == nil {
			t.Fatal(c)
		}
	}
}
func TestPackageRefreshFailureNeverContinuesOrUpgrades(t *testing.T) {
	p, e := DependenciesFor("debian", "12", "amd64")
	if e != nil {
		t.Fatal(e)
	}
	var calls []string
	err := InstallDependencies(p, func(_ time.Duration, n string, a ...string) ([]byte, error) {
		calls = append(calls, n+" "+strings.Join(a, " "))
		return nil, errors.New("repository unavailable or lock busy")
	})
	if err == nil || len(calls) != 1 || !strings.Contains(calls[0], "update") || strings.Contains(calls[0], "upgrade") {
		t.Fatal(err, calls)
	}
}

func TestPackagePlansExcludeUnusedToolsAndKeepRequiredRuntime(t *testing.T) {
	for _, target := range []struct{ distro, version string }{{"debian", "12"}, {"ubuntu", "24.04"}, {"rocky", "9.8"}, {"alpine", "3.24.2"}} {
		t.Run(target.distro, func(t *testing.T) {
			plan, err := DependenciesFor(target.distro, target.version, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			packages := make(map[string]bool)
			for _, name := range plan.Packages {
				packages[name] = true
			}
			for _, unnecessary := range []string{"wget", "jq", "unzip"} {
				if packages[unnecessary] {
					t.Fatalf("unused utility %q must not be an install dependency", unnecessary)
				}
			}
			for _, required := range []string{"ca-certificates", "curl", "openssl", "tar", "gzip", "coreutils", "util-linux"} {
				if !packages[required] {
					t.Fatalf("required runtime package %q missing", required)
				}
			}
			if target.distro == "rocky" && !strings.Contains(strings.Join(plan.Install, " "), "--setopt=install_weak_deps=False") {
				t.Fatal("DNF must not install unrelated weak dependencies")
			}
			for _, arg := range append(append([]string{}, plan.Refresh...), plan.Install...) {
				for _, forbidden := range []string{"upgrade", "dist-upgrade", "full-upgrade", "autoremove", "erase"} {
					if arg == forbidden {
						t.Fatalf("global package operation %q is not permitted", arg)
					}
				}
			}
		})
	}
}
func TestPackageNoRefreshForDNFAndAPK(t *testing.T) {
	for _, d := range []struct{ d, v string }{{"rocky", "9.7"}, {"alpine", "3.24.0"}} {
		p, e := DependenciesFor(d.d, d.v, "arm64")
		if e != nil {
			t.Fatal(e)
		}
		var args []string
		if e = InstallDependencies(p, func(_ time.Duration, n string, a ...string) ([]byte, error) {
			args = append([]string{n}, a...)
			return nil, nil
		}); e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(args, append([]string{p.Manager}, p.Install...)) {
			t.Fatal(args)
		}
	}
}
