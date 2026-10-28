package platform

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// ServiceSpec is local installation data. It is never decoded from backup data
// or subscription requests. Arguments are restricted before shell rendering.
type ServiceSpec struct {
	Name          string
	Description   string
	Command       string
	Args          []string
	User          string
	Group         string
	WritablePaths []string
	BindLowPorts  bool
}

var serviceWordRE = regexp.MustCompile(`^[A-Za-z0-9_./:@=,+-]+$`)

func CoreServiceSpec() ServiceSpec {
	return ServiceSpec{Name: "qingnode", Description: "QingNode sing-box proxy service", Command: "/usr/local/bin/qingnode", Args: []string{"serve"}, User: "qingnode", Group: "qingnode", WritablePaths: []string{"/var/lib/qingnode/acme"}, BindLowPorts: true}
}

func (s ServiceSpec) validate() error {
	if _, e := serviceName(s.Name); e != nil {
		return e
	}
	if s.Description == "" || strings.ContainsAny(s.Description, "\r\n\x00\"'`$\\%") || len(s.Description) > 200 {
		return errors.New("服务说明无效")
	}
	if !path.IsAbs(s.Command) || !serviceWordRE.MatchString(s.Command) || path.Clean(s.Command) != s.Command {
		return errors.New("服务程序必须是本机绝对路径")
	}
	monitorRoot := s.Name == "qingnode-monitor" && s.User == "root" && s.Group == "root" && !s.BindLowPorts
	if s.User == "" || s.Group == "" || !monitorRoot && (s.User == "root" || s.Group == "root") || !regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(s.User) || !regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(s.Group) {
		return errors.New("代理与订阅常驻服务必须使用专用非root账户；只有读取私有状态并执行授权管理动作的monitor可用root")
	}
	if len(s.Args) > 32 {
		return errors.New("服务参数过多")
	}
	for _, arg := range s.Args {
		if !serviceWordRE.MatchString(arg) || len(arg) > 1024 {
			return errors.New("服务参数含不支持的字符")
		}
	}
	for _, p := range s.WritablePaths {
		if !path.IsAbs(p) || !serviceWordRE.MatchString(p) || path.Clean(p) != p {
			return errors.New("服务可写路径无效")
		}
	}
	return nil
}

// RenderOpenRC follows OpenRC 0.63.2's default supervise_start/stop contract.
// pidfile belongs to the root supervisor, while qingnode_pid returns the core
// child. No reload action or custom restart implementation is invented.
func RenderOpenRC(s ServiceSpec) (string, error) {
	if e := s.validate(); e != nil {
		return "", e
	}
	n, _ := serviceName(s.Name)
	args := strings.Join(s.Args, " ")
	capabilitySettings, capabilityCheck := "", ""
	if s.BindLowPorts {
		// libcap IAB '^' means inheritable plus ambient, not a bounding-set
		// grant. Keep the inherited bounding set; no_new_privs prevents gaining
		// privileges from file capabilities or setuid programs. The actual child
		// must have only CAP_NET_BIND_SERVICE in its permitted/effective sets.
		// A file capability on sing-box would clear ambient during exec, and
		// glibc compatibility loaders can exec again, so no core file cap is used.
		capabilitySettings = "capabilities=\"^cap_net_bind_service\"\nno_new_privs=\"yes\"\n"
		capabilityCheck = `	# Check the actual supervisor build, not only its version string.
	qingnode_supervise_help=$(supervise-daemon "${RC_SVCNAME}" --help 2>&1) || return 1
	case "${qingnode_supervise_help}" in
		*--capabilities*) ;;
		*) eerror "supervise-daemon lacks --capabilities; refusing a root fallback"; return 1 ;;
	esac
	case "${qingnode_supervise_help}" in
		*--no-new-privs*) ;;
		*) eerror "supervise-daemon lacks --no-new-privs; refusing a root fallback"; return 1 ;;
	esac
	unset qingnode_supervise_help
`
	}
	return fmt.Sprintf(`#!/sbin/openrc-run
# Managed by QingNode
description="%s"
supervisor="supervise-daemon"
command="%s"
command_args="%s"
command_user="%s:%s"
%spidfile="%s"
output_log="%s"
error_log="%s"
umask="0077"
respawn_delay=3
respawn_max=5
respawn_period=60
retry="TERM/15/KILL/5"
extra_commands="qingnode_pid"

depend() {
	use net dns logger
	after firewall
}

start_pre() {
%s	# These paths remain root-owned; the service cannot replace supervisor PIDs.
	[ ! -L /run/qingnode ] && [ ! -L /var/log/qingnode ] || return 1
	checkpath --directory --mode 0755 --owner root:root /run/qingnode || return 1
	checkpath --directory --mode 0751 --owner root:root /var/log/qingnode || return 1
	[ ! -L "${pidfile}" ] && [ ! -L "${output_log}" ] || return 1
	# supervise-daemon opens logs after dropping UID; only this service owns its file.
	checkpath --file --mode 0600 --owner "${command_user}" "${output_log}" || return 1
	ulimit -n 65536 || return 1
}

qingnode_pid() {
	service_get_value child_pid
}
`, s.Description, s.Command, args, s.User, s.Group, capabilitySettings, ServicePIDPath(n), ServiceLogPath(n), ServiceLogPath(n), capabilityCheck), nil
}

// RenderSystemd is for auxiliary services. The existing core unit stays embedded
// unchanged in node so old installations and its hardening checks remain exact.
func RenderSystemd(s ServiceSpec) (string, error) {
	if e := s.validate(); e != nil {
		return "", e
	}
	command := s.Command
	if len(s.Args) > 0 {
		command += " " + strings.Join(s.Args, " ")
	}
	capabilities := "CapabilityBoundingSet=\n"
	if s.BindLowPorts {
		capabilities = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
	}
	writable := ""
	if len(s.WritablePaths) > 0 {
		writable = "ReadWritePaths=" + strings.Join(s.WritablePaths, " ") + "\n"
	}
	return fmt.Sprintf("# Managed by QingNode\n[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=exec\nUser=%s\nGroup=%s\nExecStart=%s\nRestart=on-failure\nRestartSec=3\nUMask=0077\nLimitNOFILE=65536\nNoNewPrivileges=true\n%sProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nPrivateDevices=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\n%s\n[Install]\nWantedBy=multi-user.target\n", s.Description, s.User, s.Group, command, capabilities, writable), nil
}
