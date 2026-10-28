package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"qingnode/internal/coreapi"
	"qingnode/internal/monitor"
	"qingnode/internal/node"
	"qingnode/internal/platform"
	"qingnode/internal/probe"
)

type monitorAdapter struct {
	app   *app
	state node.State
}
type monitorService struct {
	active, sub string
	pid         int
}

func monitorCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	// Never retain command output: it may contain configuration secrets.
	output := &monitorLimitedOutput{}
	c.Stdout = output
	c.Stderr = io.Discard
	err := c.Run()
	return output.Bytes(), err
}

type monitorLimitedOutput struct{ bytes.Buffer }

func (b *monitorLimitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64<<10 {
		return 0, errors.New("local_command_output_limit")
	}
	return b.Buffer.Write(p)
}
func readMonitorService(ctx context.Context) monitorService {
	c, cancel := context.WithTimeout(ctx, 650*time.Millisecond)
	defer cancel()
	if monitorInitKind() != platform.InitSystemd {
		state, e := monitorManager(c).State("qingnode")
		if e != nil || state.Active == nil {
			return monitorService{}
		}
		return monitorService{active: state.State, sub: state.SubState, pid: state.PID}
	}
	b, e := monitorCommand(c, "systemctl", "show", "qingnode.service", "--no-pager", "--property=ActiveState,SubState,MainPID")
	if e != nil {
		return monitorService{}
	}
	var s monitorService
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || seen[k] {
			return monitorService{}
		}
		seen[k] = true
		switch k {
		case "ActiveState":
			s.active = v
		case "SubState":
			s.sub = v
		case "MainPID":
			var e error
			s.pid, e = strconv.Atoi(v)
			if e != nil || s.pid < 0 {
				return monitorService{}
			}
		default:
			return monitorService{}
		}
	}
	if len(seen) != 3 || s.active == "" || s.sub == "" {
		return monitorService{}
	}
	switch s.active {
	case "active", "inactive", "failed", "activating", "deactivating", "reloading":
	default:
		return monitorService{}
	}
	return s
}

func monitorDiskStatus(r node.ResourceOverview) (monitor.Status, string) {
	if r.DiskAvailable == nil || r.DiskTotal == nil || *r.DiskTotal == 0 {
		return monitor.Unknown, "disk_reading_unavailable"
	}
	if *r.DiskAvailable < 64<<20 || float64(*r.DiskAvailable)/float64(*r.DiskTotal) < 0.05 {
		return monitor.Degraded, "disk_below_64mib_or_5percent"
	}
	return monitor.Healthy, "local_free_disk_above_threshold"
}

func (m *monitorAdapter) Collect(ctx context.Context, j monitor.Job, b monitor.Budget) (monitor.Observation, error) {
	o := monitor.Observation{PublicReachability: monitor.Unknown, CoreVersion: m.state.CoreVersion, AddressFamily: j.Family, MeasurementLocation: "local", Traffic: probe.Traffic{Accounting: "应用有效载荷；协议封装与API本机流量另受帧预算限制"}, Metrics: probe.Metrics{Availability: "unavailable", Scope: "managed-core PID unavailable"}}
	signals := map[monitor.SignalKind]monitor.Signal{}
	set := func(k monitor.SignalKind, status monitor.Status, location, cause string) {
		signals[k] = monitor.Signal{Kind: k, Status: status, Location: location, MeasuredAt: time.Now().UTC(), Cause: cause}
	}
	for _, k := range j.Signals {
		set(k, monitor.Unknown, "local", "not_measured")
	}
	wants := func(k monitor.SignalKind) bool { _, ok := signals[k]; return ok }
	if e := rejectMonitorPending(m.app.store.Root); e != nil {
		o.Maintenance = true
		for k := range signals {
			set(k, monitor.Unknown, "local", "pending_management_transaction")
		}
		for _, k := range j.Signals {
			o.Signals = append(o.Signals, signals[k])
		}
		return o, nil
	}
	service := readMonitorService(ctx)
	if service.active == "inactive" || service.active == "deactivating" || service.active == "failed" {
		o.ManualStopped = true
	}
	switch {
	case service.active == "active" && service.sub == "running" && service.pid > 0:
		set(monitor.Process, monitor.Healthy, "local", "service_running")
	case service.active != "":
		set(monitor.Process, monitor.Failed, "local", "service_not_running_no_automatic_start")
	default:
		set(monitor.Process, monitor.Unknown, "local", "service_manager_unavailable")
	}
	if service.pid > 0 {
		o.Metrics = probe.ReadMetrics(service.pid)
	}
	resource := node.OverviewResources(m.app.store.Root)
	ds, dc := monitorDiskStatus(resource)
	set(monitor.Disk, ds, "local", dc)
	if _, wanted := signals[monitor.SignalKind("core_api")]; wanted {
		status, cause := monitor.Unknown, "core_api_not_enabled"
		if api := m.state.Observability; api != nil && api.Enabled {
			client, e := coreapi.New(coreapi.Config{Endpoint: api.Endpoint(), Secret: api.Secret, Timeout: 650 * time.Millisecond, MaxFrameBytes: 64 << 10, MaxStreamBytes: 128 << 10, MaxFrames: 4})
			if e == nil {
				_, e = client.Status(ctx)
				client.Close()
				status, cause = monitor.Healthy, "authenticated_local_api_response"
			}
			if e != nil {
				status, cause = monitor.Unknown, "local_api_auth_or_capability_unavailable"
				if errors.Is(e, coreapi.ErrTransport) || errors.Is(e, context.DeadlineExceeded) {
					status, cause = monitor.Failed, "local_control_plane_unreachable"
				}
				if ctx.Err() != nil {
					status, cause = monitor.Unknown, "local_api_check_canceled"
				}
			}
		}
		set(monitor.SignalKind("core_api"), status, "local", cause)
	}
	var n *node.Node
	if j.NodeID != "" {
		selected, e := m.state.Find(j.NodeID)
		if e != nil {
			return o, errors.New("node_reference_missing")
		}
		n = selected
		o.ServerPathSHA256, _ = node.NodeRouteDigest(m.state, n.ID)
		if !n.Enabled {
			o.Inactive = true
		}
		if service.pid > 0 && n.Enabled {
			snapshot, e := node.ReadSocketSnapshot("/proc", service.pid)
			if e == nil && snapshot.Complete && snapshot.NamespaceVerified {
				status := monitor.Failed
				if node.SocketsReady(node.State{Nodes: []node.Node{*n}}, snapshot.Sockets) {
					status = monitor.Healthy
				}
				set(monitor.Listener, status, "local", "owned_listener_observation")
			} else {
				set(monitor.Listener, monitor.Unknown, "local", "socket_ownership_incomplete")
			}
		}
		if n.CertificateID != "" && wants(monitor.Certificate) {
			r, e := m.state.FindCertificate(n.CertificateID)
			if e == nil {
				s, e := node.InspectCertificateResource(*r, m.app.store.Root, time.Now().UTC())
				status := monitor.Unknown
				switch s.Status {
				case "available":
					status = monitor.Healthy
				case "expiring":
					status = monitor.Degraded
				case "failed", "expired":
					status = monitor.Failed
				}
				if e != nil {
					status = monitor.Unknown
				}
				set(monitor.Certificate, status, "local", "certificate_"+s.Status)
			}
		} else {
			set(monitor.Certificate, monitor.Unknown, "local", "protocol_has_no_managed_certificate")
		}
	} else {
		set(monitor.Listener, monitor.Unknown, "local", "remote_egress_has_no_local_inbound")
		set(monitor.Certificate, monitor.Unknown, "local", "remote_certificate_not_locally_owned")
	}
	if !o.Inactive && !o.ManualStopped && j.TargetURL != "" && b.MaxBytes >= 4 && (wants(monitor.Authentication) || wants(monitor.TCP) || wants(monitor.UDP) || wants(monitor.Target)) {
		m.measure(ctx, j, b, &o, set)
	} else {
		reason := "no_explicit_https_target"
		if b.MaxBytes == 0 {
			reason = "local_verification_only"
		} else if b.MaxBytes < 4 {
			reason = "payload_budget_too_small"
		} else if o.Inactive || o.ManualStopped {
			reason = "intentionally_inactive"
		}
		for _, k := range []monitor.SignalKind{monitor.Authentication, monitor.TCP, monitor.UDP, monitor.Target} {
			set(k, monitor.Unknown, "client-proxy", reason)
		}
	}
	for _, k := range j.Signals {
		o.Signals = append(o.Signals, signals[k])
	}
	return o, ctx.Err()
}

func (m *monitorAdapter) measure(ctx context.Context, j monitor.Job, b monitor.Budget, o *monitor.Observation, set func(monitor.SignalKind, monitor.Status, string, string)) {
	// Light probes use HEAD (no response body). Probe's UDP envelope has its own
	// 129-byte send/receive cap and must fit inside the proxy allocation.
	proxyBytes := b.MaxBytes - b.MaxBytes/4
	targetBytes := b.MaxBytes / 4
	defer func() {
		if ctx.Err() != nil {
			return
		}
		m.targetWitness(ctx, j, b.Timeout, targetBytes, o, set)
	}()
	udp := j.UDPAddress
	udpPreflight := ""
	if udp != "" {
		if proxyBytes < 129 {
			udp = ""
			udpPreflight = "udp_payload_budget_too_small"
			set(monitor.UDP, monitor.Unknown, "client-proxy", "udp_payload_budget_too_small")
		}
	}
	timeout := b.Timeout
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	if timeout < time.Millisecond {
		return
	}
	opts := probe.Options{Path: "client-proxy", Mode: "light", TargetURL: j.TargetURL, Family: j.Family, Timeout: timeout, MaxBytes: proxyBytes, Samples: 1, Concurrency: 1, Initiator: "qingnode-server-monitor", NodeID: j.NodeID, CoreVersion: m.state.CoreVersion, UDPAddress: udp, UDPTimeout: time.Second}
	var sandbox *probe.Sandbox
	var e error
	if j.NodeID != "" {
		p, err := buildProbeEndpointProfile(m.state, j.NodeID, j.UserID, monitorEndpoint(j.EndpointID))
		if err != nil {
			set(monitor.Authentication, monitor.Unknown, "client-proxy", "profile_validation_failed")
			return
		}
		opts.ConfigSHA256, opts.ServerPathSHA256 = p.ConfigSHA256, p.ServerPathSHA256
		o.ConfigSHA256, o.ServerPathSHA256 = p.ConfigSHA256, p.ServerPathSHA256
		core, err := m.app.probeDefaultCore(p)
		if err != nil {
			set(monitor.Authentication, monitor.Unknown, "client-proxy", "trusted_core_unavailable")
			return
		}
		sandbox, e = probe.StartSandbox(ctx, p, core)
	} else {
		p, err := makeEgressGraph(m.state, j.EgressID)
		if err != nil {
			set(monitor.Authentication, monitor.Unknown, "client-proxy", "egress_profile_invalid")
			return
		}
		if udp != "" && !p.SupportsNetwork("udp") {
			opts.UDPAddress = ""
			udpPreflight = "egress_does_not_support_udp"
			set(monitor.UDP, monitor.Failed, "client-proxy", "egress_does_not_support_udp")
		}
		core, err := m.app.probeDefaultCore(probe.Profile{CoreVersion: m.state.CoreVersion})
		if err != nil {
			set(monitor.Authentication, monitor.Unknown, "client-proxy", "trusted_core_unavailable")
			return
		}
		opts.NodeID, opts.ConfigSHA256 = j.EgressID, p.ConfigSHA256
		sandbox, e = probe.StartGraphSandbox(ctx, p, core)
		o.ConfigSHA256 = p.ConfigSHA256
	}
	if e != nil {
		set(monitor.Authentication, monitor.Unknown, "client-proxy", "isolated_client_start_failed")
		return
	}
	defer sandbox.Close()
	tr := sandbox.Transport()
	defer tr.CloseIdleConnections()
	opts.ClientVersion = sandbox.Version
	opts.UDPProxyAddress = sandbox.Address
	opts.UDPProxyUsername = sandbox.Username
	opts.UDPProxyPassword = sandbox.Password
	r, e := probe.Run(ctx, opts, probe.Dependencies{Transport: tr, MetricsPID: sandbox.PID})
	o.Statistics = r.Statistics
	o.UDP = r.UDP
	o.Traffic = r.Traffic
	o.CoreVersion = r.Conditions.CoreVersion
	o.ClientVersion = r.Conditions.ClientVersion
	o.TargetSHA256 = r.Conditions.TargetSHA256
	o.MeasurementLocation = "client-proxy"
	applyMonitorProbeResult(r, e, ctx.Err(), udpPreflight, set)
}

// A nil UDP result means no packet measurement. It cannot erase a known graph
// restriction or the budget reason which deliberately suppressed that packet.
func applyMonitorProbeResult(r probe.Report, err, cancel error, udpPreflight string, set func(monitor.SignalKind, monitor.Status, string, string)) {
	applyMonitorProbe(r, err, cancel, set)
	switch udpPreflight {
	case "egress_does_not_support_udp":
		set(monitor.UDP, monitor.Failed, "client-proxy", udpPreflight)
	case "udp_payload_budget_too_small":
		set(monitor.UDP, monitor.Unknown, "client-proxy", udpPreflight)
	}
}

func (m *monitorAdapter) targetWitness(ctx context.Context, j monitor.Job, timeout time.Duration, cap int64, o *monitor.Observation, set func(monitor.SignalKind, monitor.Status, string, string)) {
	// A separate path through this server's normal outbound network. Its failure
	// identifies a target-side uncertainty, never a restart instruction.
	direct := probe.Options{Path: "server-outbound", Mode: "light", TargetURL: j.TargetURL, Family: j.Family, Timeout: timeout, MaxBytes: cap, Samples: 1, Concurrency: 1, Initiator: "qingnode-server-monitor-target"}
	witness, we := probe.Run(ctx, direct, probe.Dependencies{})
	o.Traffic.PayloadBytesReceived += witness.Traffic.PayloadBytesReceived
	if o.TargetSHA256 == "" {
		o.TargetSHA256 = witness.Conditions.TargetSHA256
	}
	status, cause := monitor.Unknown, "target_check_incomplete"
	if we == nil && ctx.Err() == nil {
		status = monitor.Failed
		cause = "target_unavailable_from_server"
		for _, s := range witness.Samples {
			if s.HTTPStatus != nil {
				status = monitor.Degraded
				cause = "target_http_" + strconv.Itoa(*s.HTTPStatus)
			}
			if s.Status == "success" {
				status = monitor.Healthy
				cause = "target_available_from_server"
			}
		}
	}
	set(monitor.Target, status, "server-outbound", cause)
}

func monitorEndpoint(s string) string {
	if s == "" {
		return "default"
	}
	return s
}
func applyMonitorProbe(r probe.Report, err, cancel error, set func(monitor.SignalKind, monitor.Status, string, string)) {
	if err != nil || cancel != nil || r.Status == "canceled" || r.Status == "" || (len(r.Samples) == 0 && r.UDP == nil) {
		set(monitor.TCP, monitor.Unknown, "client-proxy", "probe_canceled_or_incomplete")
		set(monitor.UDP, monitor.Unknown, "client-proxy", "probe_canceled_or_incomplete")
		return
	}
	authenticated := false
	tcp := monitor.Failed
	cause := "proxy_path_or_target_failed"
	if len(r.Samples) == 0 {
		tcp, cause = monitor.Unknown, "no_https_measurement"
	}
	for _, s := range r.Samples {
		if s.HTTPStatus != nil {
			authenticated = true
			tcp, cause = monitor.Healthy, "authenticated_https_response"
		}
		if s.Status == "success" {
			tcp = monitor.Healthy
			cause = "authenticated_https_response"
		}
	}
	set(monitor.TCP, tcp, "client-proxy", cause)
	if r.UDP != nil {
		us := monitor.Failed
		uc := "controlled_udp_loss_or_timeout"
		if r.UDP.Unfinished > 0 || r.UDP.Sent == 0 {
			us = monitor.Unknown
			uc = "udp_incomplete"
		} else if r.UDP.Received > 0 && r.UDP.Lost == 0 {
			us = monitor.Healthy
			uc = "controlled_udp_response"
			authenticated = true
		}
		set(monitor.UDP, us, "client-proxy", uc)
	} else {
		set(monitor.UDP, monitor.Unknown, "client-proxy", "no_controlled_udp_measurement")
	}
	if authenticated {
		set(monitor.Authentication, monitor.Healthy, "client-proxy", "authenticated_path_response")
	} else {
		set(monitor.Authentication, monitor.Unknown, "client-proxy", "auth_route_target_cannot_be_separated")
	}
}

// Recovery never starts an inactive service. A config change during collection
// invalidates the action. try-restart also respects a concurrent manual stop.
func (m *monitorAdapter) Act(ctx context.Context, j monitor.Job, action string) error {
	if j.EgressID != "" || action != "restart" {
		return monitor.RedactedError("unsupported_recovery_action")
	}
	cfg, e := m.app.monitorStore().LoadConfig()
	if e != nil || !cfg.Enabled || cfg.Recovery.Mode != "restart" {
		return monitor.RedactedError("recovery_policy_revoked")
	}
	return m.app.store.InspectExisting(func() error {
		if e := rejectMonitorPending(m.app.store.Root); e != nil {
			return monitor.RedactedError("management_transaction_pending")
		}
		current, e := m.app.store.Load()
		if e != nil {
			return monitor.RedactedError("state_unavailable")
		}
		before, _ := json.Marshal(m.state)
		after, _ := json.Marshal(current)
		if !bytes.Equal(before, after) {
			return monitor.RedactedError("state_changed_since_observation")
		}
		service := readMonitorService(ctx)
		if service.active != "active" || service.sub != "running" || service.pid <= 0 {
			return monitor.RedactedError("inactive_service_not_restarted")
		}
		if !monitorOwnsUnit(ctx) {
			return monitor.RedactedError("service_ownership_or_dropins_unconfirmed")
		}
		expected, e := node.Server(current, m.app.store.Root)
		if e != nil {
			return monitor.RedactedError("configuration_invalid_use_explicit_rollback")
		}
		configPath := filepath.Join(m.app.store.Root, "current", "server.json")
		actual, e := readMonitorBounded(configPath, 16<<20)
		if e != nil || !bytes.Equal(expected, actual) {
			return monitor.RedactedError("derived_config_damaged_use_explicit_recover")
		}
		core := node.CorePath(m.app.store.Root, current.CoreVersion)
		sum, e := monitorCoreDigest(ctx, core)
		if e != nil {
			return monitor.RedactedError("trusted_core_unavailable")
		}
		trusted, e := readMonitorBounded(core+".sha256", 128)
		if e != nil || len(trusted) > 128 || strings.TrimSpace(string(trusted)) != sum {
			return monitor.RedactedError("trusted_core_digest_mismatch")
		}
		if e = node.CheckCertificateFilePermissions(current); e != nil {
			return monitor.RedactedError("certificate_permissions_invalid")
		}
		if _, e = monitorCommand(ctx, core, "check", "-c", configPath); e != nil {
			return monitor.RedactedError("configuration_check_failed_use_explicit_rollback")
		}
		latest, e := m.app.monitorStore().LoadConfig()
		oldPolicy, _ := json.Marshal(cfg)
		newPolicy, _ := json.Marshal(latest)
		if e != nil || ctx.Err() != nil || !latest.Enabled || latest.Recovery.Mode != "restart" || !bytes.Equal(oldPolicy, newPolicy) {
			return monitor.RedactedError("recovery_policy_revoked")
		}
		if e = monitorManager(ctx).TryRestart("qingnode"); e != nil {
			return monitor.RedactedError("service_try_restart_failed")
		}
		return nil
	})
}

func readMonitorBounded(path string, max int64) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var s syscall.Stat_t
	if syscall.Fstat(fd, &s) != nil || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Nlink != 1 || s.Size > max {
		return nil, errors.New("invalid_bounded_file")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("bounded_file_limit")
	}
	return b, nil
}

func monitorCoreDigest(ctx context.Context, path string) (string, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Size() > 256<<20 {
		return "", errors.New("invalid_core_file")
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if e = ctx.Err(); e != nil {
			return "", e
		}
		n, readErr := f.Read(buffer)
		total += int64(n)
		if total > 256<<20 {
			return "", errors.New("core_size_limit")
		}
		if n > 0 {
			_, _ = h.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func monitorOwnsUnit(ctx context.Context) bool {
	if monitorInitKind() != platform.InitSystemd {
		definition, e := node.ServiceDefinition(monitorInitKind())
		return e == nil && monitorManager(ctx).VerifyOwnership("qingnode", []byte(definition)) == nil
	}
	b, e := monitorCommand(ctx, "systemctl", "show", "qingnode.service", "--property=FragmentPath,DropInPaths")
	if e != nil {
		return false
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, dup := fields[k]; dup {
			return false
		}
		fields[k] = v
	}
	if fields["FragmentPath"] != "/etc/systemd/system/qingnode.service" || fields["DropInPaths"] != "" {
		return false
	}
	if _, present := fields["DropInPaths"]; !present {
		return false
	}
	actual, e := readMonitorBounded(fields["FragmentPath"], 128<<10)
	return e == nil && bytes.Equal(actual, []byte(node.ServiceUnit))
}
func (m *monitorAdapter) Verify(ctx context.Context, j monitor.Job, b monitor.Budget) (monitor.Observation, error) {
	b.MaxBytes = 0
	return m.Collect(ctx, j, b)
}

var _ monitor.Collector = (*monitorAdapter)(nil)
var _ monitor.ActionVerifier = (*monitorAdapter)(nil)
