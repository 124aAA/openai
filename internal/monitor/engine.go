package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"qingnode/internal/probe"
)

func validStatus(s Status) bool {
	switch s {
	case Healthy, Degraded, Failed, Unknown, Disabled:
		return true
	}
	return false
}

// Evaluate never equates missing measurements with success. Mixed successful
// and failed signals are degraded; unknown required signals prevent healthy.
func Evaluate(signals []Signal) Status {
	if len(signals) == 0 {
		return Unknown
	}
	healthy, failed, unknown, disabled, degraded := 0, 0, 0, 0, 0
	for _, s := range signals {
		switch s.Status {
		case Healthy:
			healthy++
		case Failed:
			failed++
		case Degraded:
			degraded++
		case Disabled:
			disabled++
		default:
			unknown++
		}
	}
	if disabled == len(signals) {
		return Disabled
	}
	if degraded > 0 {
		return Degraded
	}
	if failed > 0 {
		if healthy == 0 && unknown == 0 && disabled == 0 {
			return Failed
		}
		return Degraded
	}
	if unknown > 0 || disabled > 0 {
		return Unknown
	}
	return Healthy
}

func safeCode(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 64 {
		return "details_redacted"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "details_redacted"
		}
	}
	return s
}

func normalizeObservation(o Observation, j Job, start, end time.Time, collectionErr error, budgetBytes int64) Observation {
	// A measurement initiated here cannot prove public inbound reachability.
	o.PublicReachability = Unknown
	o.UDP = sanitizeUDP(o.UDP, budgetBytes)
	for _, p := range []*string{&o.ConfigSHA256, &o.ServerPathSHA256, &o.TargetSHA256} {
		if !validDigest(*p) {
			*p = ""
		}
	}
	for _, p := range []*string{&o.CoreVersion, &o.ClientVersion} {
		if len(*p) > 128 || strings.ContainsAny(*p, "\r\n\x00") {
			*p = ""
		}
	}
	if o.AddressFamily != "auto" && o.AddressFamily != "ipv4" && o.AddressFamily != "ipv6" {
		o.AddressFamily = ""
	}
	switch o.MeasurementLocation {
	case "local", "server-outbound", "client-proxy", "controlled-link", "public":
	default:
		o.MeasurementLocation = ""
	}
	o.Traffic.WireBytes = nil
	o.Traffic.Accounting = "应用有效载荷；真实线速字节数未知"
	counts := []int64{o.Traffic.PayloadBytesReceived, o.Traffic.UDPPayloadBytesSent, o.Traffic.UDPPayloadBytesReceived}
	totalBytes := int64(0)
	for _, n := range counts {
		if n < 0 || n > 64<<10 {
			collectionErr = errors.New("collector_budget_exceeded")
			o.Traffic = probe.Traffic{Accounting: "unavailable_budget_exceeded"}
			totalBytes = 0
			break
		}
		totalBytes += n
	}
	if totalBytes > budgetBytes {
		collectionErr = errors.New("collector_budget_exceeded")
	}
	if totalBytes > 64<<10 {
		o.Traffic = probe.Traffic{Accounting: "unavailable_budget_exceeded"}
	}
	byKind := map[SignalKind]Signal{}
	duplicates := map[SignalKind]bool{}
	for _, s := range o.Signals {
		if !validKind(s.Kind) {
			continue
		}
		if _, ok := byKind[s.Kind]; ok {
			duplicates[s.Kind] = true
		}
		byKind[s.Kind] = s
	}
	signals := make([]Signal, 0, len(j.Signals))
	for _, k := range j.Signals {
		s, ok := byKind[k]
		if !ok {
			s = Signal{Kind: k, Status: Unknown, Location: "unavailable", MeasuredAt: end, Cause: "not_measured"}
		}
		if collectionErr != nil {
			s.Status = Unknown
			s.Cause = "collection_failed"
			if errors.Is(collectionErr, context.Canceled) {
				s.Cause = "cancelled"
			}
			if errors.Is(collectionErr, context.DeadlineExceeded) {
				s.Cause = "timeout"
			}
		}
		if duplicates[k] || !validStatus(s.Status) || s.MeasuredAt.IsZero() || s.MeasuredAt.Before(start.Add(-5*time.Second)) || s.MeasuredAt.After(end.Add(5*time.Second)) {
			s.Status = Unknown
			s.Cause = "invalid_or_stale_measurement"
			s.MeasuredAt = end
		}
		switch s.Location {
		case "local", "server-outbound", "client-proxy", "controlled-link", "public", "unavailable":
		default:
			s.Status = Unknown
			s.Location = "unavailable"
			s.Cause = "unknown_measurement_location"
		}
		s.Cause = safeCode(s.Cause)
		s.EvidenceGroup = safeCode(s.EvidenceGroup)
		if s.Status == Disabled {
			s.Status = Unknown
			s.Cause = "signal_not_measured"
		}
		signals = append(signals, s)
	}
	o.Signals = signals
	o.Statistics = boundedStatistics(o.Statistics)
	o.Metrics.Scope = "CPU/RSS为所观测进程；UDP计数为测量端网络空间总量，不能归因到节点"
	if o.Metrics.Availability != "partial" && o.Metrics.Availability != "available" {
		o.Metrics.Availability = "unavailable"
	}
	if o.Metrics.CPUPercent != nil && (math.IsNaN(*o.Metrics.CPUPercent) || math.IsInf(*o.Metrics.CPUPercent, 0) || *o.Metrics.CPUPercent < 0) {
		o.Metrics.CPUPercent = nil
	}
	if o.Metrics.RSSBytes != nil && *o.Metrics.RSSBytes < 0 {
		o.Metrics.RSSBytes = nil
	}
	return o
}

func boundedStatistics(in map[string]probe.Statistics) map[string]probe.Statistics {
	out := map[string]probe.Statistics{}
	for _, k := range []string{"idle_request", "load_request", "https_ttfb", "download_throughput"} {
		s, ok := in[k]
		if !ok {
			continue
		}
		if s.Attempts < 0 || s.Attempts > 64 || s.Successes < 0 || s.Successes > s.Attempts || s.Values < 0 || s.Values > s.Successes {
			continue
		}
		if s.Unit != "ms" && s.Unit != "Mbps" {
			continue
		}
		for _, p := range []*float64{s.SuccessRate, s.Median, s.P95} {
			if p != nil && (math.IsNaN(*p) || math.IsInf(*p, 0) || *p < 0) {
				ok = false
			}
		}
		if !ok {
			continue
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RunOnce holds the same nonblocking process lock used by Watch. Collector
// adapters must honor context cancellation; no goroutine is abandoned and a
// subsequent cycle cannot overlap an adapter that is still returning.
func (e Engine) RunOnce(ctx context.Context, c Config, collector Collector, verifier ActionVerifier) (Snapshot, error) {
	c, err := NormalizeConfig(c)
	if err != nil {
		return Snapshot{}, err
	}
	if err = ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if e.Store == nil {
		return Snapshot{}, errors.New("监控需要私有Store")
	}
	if err = e.Store.Initialize(); err != nil {
		return Snapshot{}, err
	}
	l, err := e.Store.acquire()
	if err != nil {
		return Snapshot{}, err
	}
	defer l.Close()
	return e.runOnce(ctx, c, collector, verifier)
}

func (e Engine) runOnce(ctx context.Context, c Config, collector Collector, verifier ActionVerifier) (Snapshot, error) {
	previous, err := e.Store.LoadStatus()
	if err != nil && !os.IsNotExist(err) {
		return Snapshot{}, err
	}
	prior := map[string]JobStatus{}
	for _, j := range previous.Jobs {
		prior[j.JobID] = j
	}
	result := Snapshot{Version: 1, StartedAt: time.Now().UTC(), Jobs: make([]JobStatus, len(c.Jobs)), Actions: retainedActions(previous.Actions, time.Now().UTC(), c.Recovery)}
	round, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	enabled := 0
	for _, j := range c.Jobs {
		if c.Enabled && j.Enabled {
			enabled++
		}
	}
	if enabled > 0 && c.MaxBytes < int64(enabled) {
		return Snapshot{}, errors.New("整轮字节预算不足以分配给所有启用任务")
	}
	jobs := make(chan int)
	budgets := make([]Budget, len(c.Jobs))
	ordinal := int64(0)
	actedThisRound := false
	for i, j := range c.Jobs {
		result.Jobs[i] = JobStatus{JobID: j.ID, NodeID: j.NodeID, EgressID: j.EgressID, Status: Disabled, StartedAt: result.StartedAt, FinishedAt: result.StartedAt, Observation: Observation{PublicReachability: Unknown}}
		if c.Enabled && j.Enabled {
			maxBytes := c.MaxBytes / int64(enabled)
			if ordinal < c.MaxBytes%int64(enabled) {
				maxBytes++
			}
			ordinal++
			budgets[i] = Budget{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond, MaxBytes: maxBytes, Concurrency: 1}
		}
	}
	var wg sync.WaitGroup
	for n := 0; n < c.Concurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				j := c.Jobs[i]
				start := time.Now().UTC()
				o := Observation{}
				var collectErr error
				if round.Err() != nil {
					collectErr = round.Err()
				} else if collector == nil {
					collectErr = errors.New("collector unavailable")
				} else {
					o, collectErr = collector.Collect(round, j, budgets[i])
				}
				if round.Err() != nil {
					collectErr = round.Err()
				}
				end := time.Now().UTC()
				o = normalizeObservation(o, j, start, end, collectErr, budgets[i].MaxBytes)
				status := Evaluate(o.Signals)
				if o.ManualStopped || o.Maintenance || o.Inactive {
					status = Disabled
				}
				result.Jobs[i] = JobStatus{JobID: j.ID, NodeID: j.NodeID, EgressID: j.EgressID, Status: status, StartedAt: start, FinishedAt: end, Observation: o}
			}
		}()
	}
	for i, j := range c.Jobs {
		if c.Enabled && j.Enabled {
			jobs <- i
		}
	}
	close(jobs)
	wg.Wait()
	for i, j := range c.Jobs {
		current := &result.Jobs[i]
		current.ConfigurationSHA256 = jobConfigFingerprint(c, j)
		old, exists := prior[j.ID]
		// Reusing a job ID for another stable reference starts a fresh state.
		if exists && (old.NodeID != j.NodeID || old.EgressID != j.EgressID) {
			old = JobStatus{}
			exists = false
		}
		from := Unknown
		if old.ConfigurationSHA256 != current.ConfigurationSHA256 || old.Observation.ConfigSHA256 != current.Observation.ConfigSHA256 || old.Observation.ServerPathSHA256 != current.Observation.ServerPathSHA256 {
			old.ConsecutiveFailures = 0
		}
		if exists {
			from = old.Status
		}
		if current.Status != from {
			result.Events = append(result.Events, Event{At: current.FinishedAt, JobID: j.ID, From: from, To: current.Status, Kind: "status-change", Notification: "disabled"})
		}
		current.Actions = retainedActions(old.Actions, time.Now().UTC(), c.Recovery)
		evidence, _ := recoveryEvidence(current.Observation)
		if (current.Status == Failed || current.Status == Degraded) && evidence >= 2 {
			current.ConsecutiveFailures = old.ConsecutiveFailures + 1
			if current.ConsecutiveFailures > 100000 {
				current.ConsecutiveFailures = 100000
			}
		}
		initial := current.Status
		before := len(result.Actions)
		if actedThisRound {
			current.RecoveryReason = "shared_service_action_deferred"
		} else {
			e.recover(round, c, j, current, verifier, &result.Actions)
		}
		if len(result.Actions) > before {
			actedThisRound = true
		}
		if current.Status == Healthy && initial != Healthy {
			result.Events = append(result.Events, Event{At: current.FinishedAt, JobID: j.ID, From: initial, To: Healthy, Kind: "recovery", Notification: "disabled"})
		} else if current.Status == Healthy && (from == Failed || from == Degraded) && len(result.Events) > 0 {
			result.Events[len(result.Events)-1].Kind = "recovery"
		}
	}
	result.FinishedAt = time.Now().UTC()
	// Local transitions are durable before any external delivery is attempted.
	if err = e.Store.save(result, c.History); err != nil {
		return result, err
	}
	if c.Notifications.Enabled {
		n := e.Notifier
		if n == nil {
			n = &Notifier{}
		}
		for i := range result.Events {
			latest, loadErr := e.Store.LoadConfig()
			state := "private_config_required"
			if loadErr == nil {
				if !latest.Enabled || !latest.Notifications.Enabled {
					state = "disabled"
				} else {
					state = n.Send(round, latest, result.Events[i])
				}
			}
			result.Events[i].Notification = state
		}
		if err = e.Store.save(result, c.History); err != nil {
			return result, err
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

// Watch is deliberately finite. It waits after each completed attempt and uses
// bounded error backoff instead of accumulating ticker events or work items.
func (e Engine) Watch(ctx context.Context, c Config, collector Collector, verifier ActionVerifier, cycles int) (Snapshot, error) {
	if cycles < 1 || cycles > 10000 {
		return Snapshot{}, errors.New("前台watch需要1到10000个明确轮次")
	}
	c, err := NormalizeConfig(c)
	if err != nil {
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		return Snapshot{}, ctx.Err()
	}
	if e.Store == nil {
		return Snapshot{}, errors.New("监控需要私有Store")
	}
	if err = e.Store.Initialize(); err != nil {
		return Snapshot{}, err
	}
	l, err := e.Store.acquire()
	if err != nil {
		return Snapshot{}, err
	}
	defer l.Close()
	var result Snapshot
	failures := 0
	for i := 0; i < cycles; i++ {
		latest, loadErr := e.Store.LoadConfig()
		if loadErr == nil {
			c = latest
		} else if !os.IsNotExist(loadErr) {
			return result, loadErr
		}
		result, err = e.runOnce(ctx, c, collector, verifier)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			failures++
		} else {
			failures = 0
		}
		if i == cycles-1 {
			return result, err
		}
		delay := time.Duration(c.IntervalSeconds) * time.Second
		for n := 0; n < failures && n < 3; n++ {
			delay *= 2
		}
		if delay > 24*time.Hour {
			delay = 24 * time.Hour
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !t.Stop() {
				<-t.C
			}
			return result, ctx.Err()
		case <-t.C:
		}
	}
	return result, err
}

func retainedActions(actions []ActionAttempt, now time.Time, p RecoveryPolicy) []ActionAttempt {
	out := []ActionAttempt{}
	cut := now.Add(-time.Duration(max(p.WindowSeconds, p.CooldownSeconds)) * time.Second)
	for _, a := range actions {
		if a.At.After(cut) {
			if a.At.After(now.Add(5 * time.Second)) {
				a.At = now
			}
			a.Cause = safeCode(a.Cause)
			a.VerificationCause = safeCode(a.VerificationCause)
			if a.Action != "restart" {
				continue
			}
			if a.AttemptStatus != "succeeded" && a.AttemptStatus != "failed" && a.AttemptStatus != "attempted" {
				a.AttemptStatus = "failed"
			}
			if !validStatus(a.Verification) {
				a.Verification = Unknown
			}
			out = append(out, a)
		}
	}
	if len(out) > 20 {
		out = out[len(out)-20:]
	}
	return out
}

func recoveryEvidence(o Observation) (int, string) {
	if o.ManualStopped {
		return 0, "manual_stopped"
	}
	if o.Maintenance {
		return 0, "maintenance"
	}
	if o.Inactive {
		return 0, "inactive"
	}
	processKnown := false
	groups := map[string]bool{}
	for _, s := range o.Signals {
		if s.Kind == Process {
			if s.Status == Failed {
				return 0, "service_manager_owns_crash"
			}
			processKnown = s.Status == Healthy
		}
		if s.Status != Failed || s.Location != "local" {
			continue
		}
		group := s.EvidenceGroup
		switch s.Kind {
		case Listener, TCP, UDP:
			if group == "" {
				group = "local_transport"
			}
		case Authentication:
			if group == "" {
				group = "local_authentication"
			}
		case CoreAPI:
			if group == "" {
				group = "local_control_plane"
			}
		default:
			continue
		}
		if group != "details_redacted" {
			groups[group] = true
		}
	}
	if !processKnown {
		return 0, "process_not_confirmed_running"
	}
	return len(groups), "insufficient_independent_local_evidence"
}

func (e Engine) recover(ctx context.Context, c Config, j Job, current *JobStatus, v ActionVerifier, global *[]ActionAttempt) {
	current.RecoveryReason = "observe_only"
	if c.Recovery.Mode != "restart" {
		return
	}
	if j.EgressID != "" {
		current.RecoveryReason = "egress_observe_only"
		return
	}
	latest, loadErr := e.Store.LoadConfig()
	if loadErr != nil {
		current.RecoveryReason = "private_policy_required"
		return
	}
	allowed := latest.Enabled && latest.Recovery.Mode == "restart"
	found := false
	for _, active := range latest.Jobs {
		if active.ID == j.ID && active.Enabled && active.NodeID == j.NodeID && active.EgressID == j.EgressID && active.UserID == j.UserID && active.EndpointID == j.EndpointID {
			found = jobConfigFingerprint(latest, active) == current.ConfigurationSHA256
			break
		}
	}
	if !allowed || !found {
		current.RecoveryReason = "policy_revoked"
		return
	}
	c.Recovery = latest.Recovery
	n, reason := recoveryEvidence(current.Observation)
	if current.Status != Degraded && current.Status != Failed {
		current.RecoveryReason = "no_recoverable_failure"
		return
	}
	if n < 2 {
		current.RecoveryReason = reason
		return
	}
	if current.ConsecutiveFailures < c.Recovery.ConsecutiveFailures {
		current.RecoveryReason = "failure_threshold_not_met"
		return
	}
	now := time.Now().UTC()
	window := now.Add(-time.Duration(c.Recovery.WindowSeconds) * time.Second)
	recent := 0
	for _, a := range *global {
		if a.At.After(window) {
			recent++
		}
		if now.Sub(a.At) < time.Duration(c.Recovery.CooldownSeconds)*time.Second {
			current.RecoveryReason = "cooldown"
			return
		}
	}
	if recent >= c.Recovery.MaxActions {
		current.RecoveryReason = "rolling_window_limit"
		return
	}
	if v == nil {
		current.RecoveryReason = "action_adapter_unavailable"
		return
	}
	if ctx.Err() != nil {
		current.RecoveryReason = "cancelled"
		return
	}
	attempt := ActionAttempt{At: now, Action: "restart", Cause: "corroborated_local_failures", AttemptStatus: "attempted", Verification: Unknown}
	current.Actions = append(current.Actions, attempt)
	index := len(current.Actions) - 1
	*global = append(*global, attempt)
	globalIndex := len(*global) - 1
	defer func() { (*global)[globalIndex] = current.Actions[index] }()
	current.RecoveryReason = "action_attempted"
	// Persist the attempt before the side effect. An interrupted process still
	// consumes cooldown/window budget and cannot immediately repeat the action.
	// runOnce writes the full snapshot; this focused safety ledger is updated
	// through the preceding persisted status by recordAttempt.
	if err := e.recordAttempt(j.ID, *current, *global, c.History); err != nil {
		current.Actions[index].AttemptStatus = "failed"
		current.Actions[index].VerificationCause = "attempt_not_durable"
		current.RecoveryReason = "attempt_not_durable"
		return
	}
	// Revocation can be written during collection and during the durable write.
	// Recheck immediately before delegating the service side effect.
	latest, loadErr = e.Store.LoadConfig()
	allowed = loadErr == nil && latest.Enabled && latest.Recovery.Mode == "restart"
	found = false
	for _, active := range latest.Jobs {
		if active.ID == j.ID && active.Enabled && active.NodeID == j.NodeID && active.EgressID == j.EgressID && active.UserID == j.UserID && active.EndpointID == j.EndpointID {
			found = jobConfigFingerprint(latest, active) == current.ConfigurationSHA256
			break
		}
	}
	if !allowed || !found || ctx.Err() != nil {
		current.Actions[index].AttemptStatus = "failed"
		current.Actions[index].VerificationCause = "policy_revoked_or_cancelled"
		current.RecoveryReason = "policy_revoked_or_cancelled"
		return
	}
	if err := v.Act(ctx, j, "restart"); err != nil {
		current.Actions[index].AttemptStatus = "failed"
		current.Actions[index].VerificationCause = controlledCause("action_", err, "action_failed")
		return
	}
	current.Actions[index].AttemptStatus = "succeeded"
	if ctx.Err() != nil {
		current.Actions[index].VerificationCause = "verification_cancelled"
		return
	}
	start := time.Now().UTC()
	o, err := v.Verify(ctx, j, Budget{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond, MaxBytes: 0, Concurrency: 1})
	end := time.Now().UTC()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	o = normalizeObservation(o, j, start, end, err, 0)
	status := Evaluate(o.Signals)
	if o.ManualStopped || o.Maintenance || o.Inactive {
		status = Disabled
	}
	current.Actions[index].Verification = status
	current.Actions[index].VerificationCause = "verification_incomplete"
	if err != nil {
		current.Actions[index].VerificationCause = controlledCause("verification_", err, "verification_failed")
	}
	if status == Healthy {
		current.Actions[index].VerificationCause = "verified_healthy"
		current.Status = Healthy
		current.Observation = o
		current.ConsecutiveFailures = 0
		current.RecoveryReason = "verified_recovered"
	}
	current.FinishedAt = end
}

func (e Engine) recordAttempt(id string, current JobStatus, global []ActionAttempt, limits HistoryLimits) error {
	v, err := e.Store.LoadStatus()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) {
		v = Snapshot{Version: 1, StartedAt: current.StartedAt, FinishedAt: current.FinishedAt}
	}
	found := false
	for i := range v.Jobs {
		if v.Jobs[i].JobID == id {
			v.Jobs[i] = current
			found = true
			break
		}
	}
	if !found {
		v.Jobs = append(v.Jobs, current)
	}
	v.Actions = global
	return e.Store.save(v, limits)
}

// RedactedError is useful to adapters that need to expose a stable category
// without passing an endpoint, credential or raw transport error to history.
type categoryError struct{ code string }

func (e categoryError) Error() string { return e.code }
func RedactedError(category string) error {
	return categoryError{code: strings.TrimSpace(safeCode(category))}
}
func controlledCause(prefix string, err error, fallback string) string {
	var trusted categoryError
	if errors.As(err, &trusted) && trusted.code != "" && trusted.code != "details_redacted" && len(prefix)+len(trusted.code) <= 64 {
		return prefix + trusted.code
	}
	return fallback
}

func validDigest(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}

func jobConfigFingerprint(c Config, j Job) string {
	b, _ := json.Marshal(struct {
		Job                                     Job
		Recovery                                RecoveryPolicy
		TimeoutMS, Concurrency, IntervalSeconds int
		MaxBytes                                int64
	}{j, c.Recovery, c.TimeoutMS, c.Concurrency, c.IntervalSeconds, c.MaxBytes})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func sanitizeUDP(in *probe.UDPResult, budget int64) *probe.UDPResult {
	if in == nil {
		return nil
	}
	u := *in
	u.Target = ""
	u.Error = safeCode(u.Error)
	u.LimitNote = safeCode(u.LimitNote)
	switch u.Status {
	case "passed", "failed", "cancelled", "unknown":
	default:
		u.Status = "unknown"
	}
	switch u.Path {
	case "proxy_socks5_udp":
		u.Path = "client-proxy"
	case "direct":
		u.Path = "server-outbound"
	case "client-proxy", "server-outbound":
	default:
		u.Path = "unknown"
	}
	if u.AddressFamily != "ipv4" && u.AddressFamily != "ipv6" && u.AddressFamily != "auto" {
		u.AddressFamily = "unknown"
	}
	if u.Sent < 0 || u.Sent > 1 || u.Received < 0 || u.Received > u.Sent || u.Lost < 0 || u.Lost > 1 || u.Unfinished < 0 || u.Unfinished > 1 || u.Received+u.Lost+u.Unfinished != u.Sent || len(u.Samples) > 1 {
		return &probe.UDPResult{Status: "unknown", Error: "invalid_udp_result", Path: u.Path, AddressFamily: u.AddressFamily}
	}
	if u.SentBytes < 0 || u.ReceivedBytes < 0 || u.DiscardedBytes < 0 || u.SentBytes > budget || u.ReceivedBytes > budget || u.DiscardedBytes > budget || u.SentBytes+u.ReceivedBytes+u.DiscardedBytes > budget {
		return &probe.UDPResult{Status: "unknown", Error: "udp_budget_exceeded", Path: u.Path, AddressFamily: u.AddressFamily}
	}
	u.Samples = append([]probe.UDPSample(nil), u.Samples...)
	for i := range u.Samples {
		s := &u.Samples[i]
		if s.Sequence != 0 || s.Discarded < 0 || s.Discarded > 64 {
			return &probe.UDPResult{Status: "unknown", Error: "invalid_udp_sample", Path: u.Path, AddressFamily: u.AddressFamily}
		}
		s.Error = safeCode(s.Error)
		if !finiteRange(s.RTTMS, 120000) {
			s.RTTMS = nil
		}
	}
	for _, p := range []**float64{&u.MedianRTTMS, &u.P95RTTMS, &u.JitterMS} {
		if !finiteRange(*p, 120000) {
			*p = nil
		}
	}
	if math.IsNaN(u.DurationMS) || math.IsInf(u.DurationMS, 0) || u.DurationMS < 0 || u.DurationMS > 120000 {
		u.DurationMS = 0
		u.Status = "unknown"
		u.Error = "invalid_udp_duration"
	}
	// A zero denominator, interrupted request, or missing measurement has no
	// loss percentage. Only completed sent requests produce known loss.
	u.LossPercent = nil
	if u.Sent > 0 && u.Unfinished == 0 && u.Error != "cancelled" && u.Error != "timeout" && u.Error != "byte_limit" {
		loss := float64(u.Lost) * 100 / float64(u.Sent)
		u.LossPercent = &loss
	}
	if u.Status == "passed" && (u.Sent != 1 || u.Received != 1 || u.Lost != 0 || u.Unfinished != 0 || len(u.Samples) != 1 || u.Samples[0].RTTMS == nil) {
		u.Status = "unknown"
		u.Error = "incomplete_udp_result"
	}
	return &u
}

func finiteRange(p *float64, max float64) bool {
	return p == nil || (!math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0 && *p <= max)
}
