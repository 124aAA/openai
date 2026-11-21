package platform

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type PackagePlan struct {
	Target      string   `json:"target"`
	SupportTier string   `json:"support_tier,omitempty"`
	Manager     string   `json:"manager"`
	Packages    []string `json:"packages"`
	Refresh     []string `json:"refresh,omitempty"`
	Install     []string `json:"install"`
}

func isAlpineCompatibleVersion(version string) (ok bool, baseline bool) {
	for _, minor := range []string{"3.20", "3.21", "3.22", "3.23", "3.24"} {
		if version == minor || strings.HasPrefix(version, minor+".") {
			return true, minor == "3.24"
		}
	}
	return false, false
}

// DependenciesFor is an explicit install target list, not a support claim.
// SupportTier honestly distinguishes CI/VM baseline images ("baseline") from
// same-ecosystem compatible distributions ("compatible-family").
func DependenciesFor(distro, version, arch string) (PackagePlan, error) {
	if version == "" || strings.HasPrefix(version, ".") || strings.HasSuffix(version, ".") || strings.Contains(version, "..") {
		return PackagePlan{}, errors.New("发行版版本格式无效")
	}
	for _, c := range version {
		if !(c >= '0' && c <= '9' || c == '.') {
			return PackagePlan{}, errors.New("发行版版本格式无效")
		}
	}
	if arch != "amd64" && arch != "arm64" {
		return PackagePlan{}, errors.New("架构只适配amd64/arm64")
	}
	p := PackagePlan{}
	major := MajorVersion(version)
	alpineOK, alpineBaseline := isAlpineCompatibleVersion(version)
	switch {
	case distro == "debian" && (major == 11 || major == 12 || major == 13),
		distro == "ubuntu" && (version == "22.04" || version == "24.04" || version == "26.04"):
		p.Manager = "apt-get"
		p.Packages = []string{"ca-certificates", "curl", "openssl", "tar", "gzip", "coreutils", "util-linux", "libc-bin", "iproute2", "passwd"}
		p.Refresh = []string{"-o", "DPkg::Lock::Timeout=30", "update"}
		p.Install = []string{"-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends"}
		if distro == "debian" && major == 11 {
			p.SupportTier = "compatible-family"
		} else {
			p.SupportTier = "baseline"
		}
	case (distro == "rocky" || distro == "almalinux") && (major == 9 || major == 10),
		(distro == "ol" || distro == "centos") && major == 9:
		p.Manager = "dnf"
		p.Packages = []string{"ca-certificates", "curl", "openssl", "tar", "gzip", "coreutils", "util-linux", "glibc-common", "iproute", "shadow-utils", "policycoreutils", "libselinux-utils"}
		p.Install = []string{"--setopt=exit_on_lock=True", "--setopt=timeout=30", "--setopt=retries=1", "--setopt=install_weak_deps=False", "install", "-y"}
		if distro == "rocky" && major == 9 {
			p.SupportTier = "baseline"
		} else {
			p.SupportTier = "compatible-family"
		}
	case distro == "alpine" && alpineOK:
		p.Manager = "apk"
		p.Packages = []string{"ca-certificates", "curl", "openssl", "tar", "gzip", "coreutils", "util-linux", "musl-utils", "iproute2", "busybox", "libcap-utils", "logrotate", "gcompat", "libgcc", "libstdc++"}
		p.Install = []string{"add", "--no-cache", "--wait", "30"}
		if alpineBaseline {
			p.SupportTier = "baseline"
		} else {
			p.SupportTier = "compatible-family"
		}
	default:
		return p, fmt.Errorf("未适配发行版或版本：%s %s", distro, version)
	}
	p.Target = distro + " " + version + "/" + arch
	if p.SupportTier == "compatible-family" {
		p.Target += " (compatible-family)"
	}
	p.Install = append(p.Install, p.Packages...)
	return p, nil
}

// InstallDependencies stops on refresh/lock/repository failure, preserving the
// existing core and service. The enclosing installer owns rollback boundaries.
func InstallDependencies(plan PackagePlan, run CommandRunner) error {
	if run == nil {
		run = RunCommand
	}
	if plan.Manager != "apt-get" && plan.Manager != "dnf" && plan.Manager != "apk" {
		return errors.New("不支持的软件包管理器")
	}
	if len(plan.Packages) == 0 || len(plan.Install) == 0 {
		return errors.New("缺少经过适配的包计划")
	}
	if len(plan.Refresh) > 0 {
		if _, err := run(2*time.Minute, plan.Manager, plan.Refresh...); err != nil {
			return fmt.Errorf("软件仓库检查失败，未继续安装：%w", err)
		}
	}
	if _, err := run(3*time.Minute, plan.Manager, plan.Install...); err != nil {
		return fmt.Errorf("软件包安装失败；检查仓库、锁和网络：%w", err)
	}
	return nil
}
