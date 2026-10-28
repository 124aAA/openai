// Package monitor coordinates bounded observations. It never implements network
// probes or directly manages services; callers supply those adapters.
package monitor

import (
	"context"
	"time"

	"qingnode/internal/probe"
)

const ConfigVersion = 1

type Status string

const (
	Healthy  Status = "healthy"
	Degraded Status = "degraded"
	Failed   Status = "failed"
	Unknown  Status = "unknown"
	Disabled Status = "disabled"
)

type SignalKind string

const (
	Process        SignalKind = "process"
	Listener       SignalKind = "listener"
	Authentication SignalKind = "authentication"
	TCP            SignalKind = "tcp"
	UDP            SignalKind = "udp"
	Target         SignalKind = "target"
	Certificate    SignalKind = "certificate"
	Disk           SignalKind = "disk"
	CoreAPI        SignalKind = "core_api"
)

// A signal is a single observation, not an inference about other signals.
// Location is local, server-outbound, client-proxy, controlled-link or public.
// Unknown includes unsupported, missing, cancelled and unmeasured results.
type Signal struct {
	Kind       SignalKind `json:"kind"`
	Status     Status     `json:"status"`
	Location   string     `json:"location"`
	MeasuredAt time.Time  `json:"measured_at"`
	Cause      string     `json:"cause,omitempty"`
	// Related checks share a group and count only once toward recovery.
	EvidenceGroup string `json:"evidence_group,omitempty"`
}

type Job struct {
	ID         string            `json:"id"`
	NodeID     string            `json:"node_id,omitempty"`
	EgressID   string            `json:"egress_id,omitempty"`
	UserID     string            `json:"user_id,omitempty"`
	EndpointID string            `json:"endpoint_id,omitempty"`
	TargetURL  string            `json:"target_url,omitempty"`
	UDPAddress string            `json:"udp_address,omitempty"`
	Family     string            `json:"family,omitempty"`
	Enabled    bool              `json:"enabled"`
	Signals    []SignalKind      `json:"signals"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type Budget struct {
	Timeout     time.Duration
	MaxBytes    int64
	Concurrency int
}

type HistoryLimits struct {
	Records int   `json:"records"`
	Bytes   int64 `json:"bytes"`
	Events  int   `json:"events"`
}

type RecoveryPolicy struct {
	Mode                string `json:"mode"` // observe (default) or restart
	ConsecutiveFailures int    `json:"consecutive_failures"`
	CooldownSeconds     int    `json:"cooldown_seconds"`
	WindowSeconds       int    `json:"window_seconds"`
	MaxActions          int    `json:"max_actions"`
}

// Secrets are deliberately excluded from ordinary JSON. Only SaveConfig and
// LoadConfig serialize these fields, in the private monitor configuration.
type NotificationConfig struct {
	Enabled   bool   `json:"enabled"`
	Kind      string `json:"kind"` // webhook or telegram
	Endpoint  string `json:"-"`
	Token     string `json:"-"`
	ChatID    string `json:"-"`
	TimeoutMS int    `json:"timeout_ms"`
	Retries   int    `json:"retries"`
}

type Config struct {
	Version                 int                `json:"version"`
	Enabled                 bool               `json:"enabled"`
	IntervalSeconds         int                `json:"interval_seconds"`
	TimeoutMS               int                `json:"timeout_ms"`
	Concurrency             int                `json:"concurrency"`
	MaxBytes                int64              `json:"max_bytes"`
	History                 HistoryLimits      `json:"history"`
	Jobs                    []Job              `json:"jobs"`
	Recovery                RecoveryPolicy     `json:"recovery"`
	Notifications           NotificationConfig `json:"notifications"`
	privateNotifications    bool
	privateNotificationHash [32]byte
	privateConfigPath       string
}

type Observation struct {
	UDP                 *probe.UDPResult            `json:"udp,omitempty"`
	Traffic             probe.Traffic               `json:"traffic"`
	ConfigSHA256        string                      `json:"config_sha256,omitempty"`
	ServerPathSHA256    string                      `json:"server_path_sha256,omitempty"`
	CoreVersion         string                      `json:"core_version,omitempty"`
	ClientVersion       string                      `json:"client_version,omitempty"`
	AddressFamily       string                      `json:"address_family,omitempty"`
	MeasurementLocation string                      `json:"measurement_location,omitempty"`
	TargetSHA256        string                      `json:"target_sha256,omitempty"`
	PublicReachability  Status                      `json:"public_reachability"`
	Signals             []Signal                    `json:"signals"`
	Statistics          map[string]probe.Statistics `json:"statistics,omitempty"`
	Metrics             probe.Metrics               `json:"metrics"`
	ManualStopped       bool                        `json:"manual_stopped"`
	Maintenance         bool                        `json:"maintenance"`
	Inactive            bool                        `json:"inactive"`
}

type Collector interface {
	Collect(context.Context, Job, Budget) (Observation, error)
}

type CollectorFunc func(context.Context, Job, Budget) (Observation, error)

func (f CollectorFunc) Collect(ctx context.Context, j Job, b Budget) (Observation, error) {
	return f(ctx, j, b)
}

type ActionVerifier interface {
	Act(context.Context, Job, string) error
	Verify(context.Context, Job, Budget) (Observation, error)
}

type ActionAttempt struct {
	At                time.Time `json:"at"`
	Action            string    `json:"action"`
	Cause             string    `json:"cause"`
	AttemptStatus     string    `json:"attempt_status"`
	Verification      Status    `json:"verification"`
	VerificationCause string    `json:"verification_cause,omitempty"`
}

type JobStatus struct {
	ConfigurationSHA256 string          `json:"configuration_sha256"`
	JobID               string          `json:"job_id"`
	NodeID              string          `json:"node_id,omitempty"`
	EgressID            string          `json:"egress_id,omitempty"`
	Status              Status          `json:"status"`
	StartedAt           time.Time       `json:"started_at"`
	FinishedAt          time.Time       `json:"finished_at"`
	Observation         Observation     `json:"observation"`
	ConsecutiveFailures int             `json:"consecutive_failures"`
	Actions             []ActionAttempt `json:"actions,omitempty"`
	RecoveryReason      string          `json:"recovery_reason,omitempty"`
}

type Event struct {
	At           time.Time `json:"at"`
	JobID        string    `json:"job_id"`
	From         Status    `json:"from"`
	To           Status    `json:"to"`
	Kind         string    `json:"kind"`         // status-change or recovery
	Notification string    `json:"notification"` // disabled, delivered, failed, cancelled
}

type Snapshot struct {
	Version    int             `json:"version"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Jobs       []JobStatus     `json:"jobs"`
	Events     []Event         `json:"events,omitempty"`
	Actions    []ActionAttempt `json:"actions,omitempty"`
}

type Store struct{ Root string }

type Engine struct {
	Store    *Store
	Notifier *Notifier
}

// CounterDelta deliberately preserves missing and reset counters as unknown.
func CounterDelta(before, after *uint64) *uint64 {
	if before == nil || after == nil || *after < *before {
		return nil
	}
	v := *after - *before
	return &v
}
