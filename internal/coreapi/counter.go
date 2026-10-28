package coreapi

import (
	"errors"
	"math"
)

var ErrCounterRegression = errors.New("core traffic counters regressed within the same epoch")

// StatusCounter stores an observation baseline, not an accounting entitlement.
// Epoch must identify one core lifetime (for example PID plus process start
// identity and API StartedAt). Persist the whole value atomically when needed.
// Its owner must serialize access.
type StatusCounter struct {
	Epoch            string `json:"epoch"`
	LastUplink       int64  `json:"last_uplink"`
	LastDownlink     int64  `json:"last_downlink"`
	ObservedUplink   int64  `json:"observed_uplink"`
	ObservedDownlink int64  `json:"observed_downlink"`
	HaveBaseline     bool   `json:"have_baseline"`
	Interrupted      bool   `json:"interrupted"`
}

type CounterDelta struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
	Baseline bool  `json:"baseline"`
	Reset    bool  `json:"reset"`
	Gap      bool  `json:"gap"`
}

// MarkGap records an unavailable sample or transport break. A later sample in
// the same epoch can recover the global difference, but per-user events lost
// during that interval cannot be reconstructed from the global counter.
func (c *StatusCounter) MarkGap() { c.Interrupted = true }

func (c *StatusCounter) Apply(epoch string, status Status) (CounterDelta, error) {
	if epoch == "" {
		return CounterDelta{}, errors.New("core epoch identity is required")
	}
	if !status.TrafficAvailable {
		c.MarkGap()
		return CounterDelta{Gap: true}, ErrUnavailable
	}
	if status.UplinkTotal < 0 || status.DownlinkTotal < 0 || c.LastUplink < 0 || c.LastDownlink < 0 || c.ObservedUplink < 0 || c.ObservedDownlink < 0 {
		c.MarkGap()
		return CounterDelta{Gap: true}, ErrProtocol
	}
	delta := CounterDelta{Gap: c.Interrupted}
	if !c.HaveBaseline || c.Epoch != epoch {
		delta.Baseline = true
		delta.Reset = c.HaveBaseline && c.Epoch != epoch
		delta.Gap = delta.Gap || delta.Reset
		c.Epoch, c.LastUplink, c.LastDownlink = epoch, status.UplinkTotal, status.DownlinkTotal
		c.HaveBaseline, c.Interrupted = true, false
		return delta, nil
	}
	if status.UplinkTotal < c.LastUplink || status.DownlinkTotal < c.LastDownlink {
		// Keep the high-water baseline: accepting a stale sample as a fresh
		// baseline would count the following repeated sample twice. A true
		// counter restart requires the caller to supply a new epoch identity.
		c.MarkGap()
		return CounterDelta{Reset: true, Gap: true}, ErrCounterRegression
	}
	delta.Uplink, delta.Downlink = status.UplinkTotal-c.LastUplink, status.DownlinkTotal-c.LastDownlink
	if delta.Uplink > math.MaxInt64-c.ObservedUplink || delta.Downlink > math.MaxInt64-c.ObservedDownlink {
		c.MarkGap()
		return CounterDelta{Gap: true}, ErrLimit
	}
	c.ObservedUplink += delta.Uplink
	c.ObservedDownlink += delta.Downlink
	c.LastUplink, c.LastDownlink = status.UplinkTotal, status.DownlinkTotal
	c.Interrupted = false
	return delta, nil
}

const UnknownOwner = "unknown"

// Ownership uses only exact, locally managed labels. User labels are scoped to
// the inbound because usernames need not be globally unique. Missing or
// ambiguous labels must not be inserted into these maps by the caller.
type Ownership struct {
	NodesByInbound map[string]string
	UsersByInbound map[string]map[string]string
}

func (o Ownership) Resolve(connection Connection) (nodeID, userID string) {
	nodeID, userID = UnknownOwner, UnknownOwner
	if connection.Inbound == "" {
		return
	}
	if value := o.NodesByInbound[connection.Inbound]; value != "" {
		nodeID = value
	}
	if connection.User != "" {
		if value := o.UsersByInbound[connection.Inbound][connection.User]; value != "" {
			userID = value
		}
	}
	return
}

// ConnectionView maintains a bounded current observation. UPDATE deltas have
// no sequence number and can be lost or replayed; it deliberately never adds
// them to absolute byte totals. Use StatusCounter for global observations.
type ConnectionView struct {
	Epoch          string
	Connections    map[string]Connection
	Gap            bool
	Ready          bool
	MaxConnections int
}

func (v *ConnectionView) MarkGap() { v.Gap = true; v.Ready = false }

func (v *ConnectionView) Apply(epoch string, batch ConnectionBatch) error {
	if epoch == "" {
		return errors.New("core epoch identity is required")
	}
	if v.MaxConnections == 0 {
		v.MaxConnections = 16384
	}
	if v.MaxConnections < 1 || v.MaxConnections > 65536 {
		return ErrLimit
	}
	if v.Epoch != epoch {
		v.Connections = nil
		v.Ready = false
		v.Gap = v.Epoch != ""
		v.Epoch = epoch
	}
	if !v.Ready && !batch.Reset {
		v.MarkGap()
		return ErrProtocol
	}
	if batch.Reset {
		v.Connections = make(map[string]Connection)
		v.Ready = true
	}
	for _, event := range batch.Events {
		if event.ID == "" || event.Type < 0 || event.Type > 2 || event.Connection != nil && event.Connection.ID != event.ID {
			v.MarkGap()
			return ErrProtocol
		}
		switch event.Type {
		case 0, 2:
			if event.Connection == nil {
				if event.Type == 2 {
					delete(v.Connections, event.ID)
				}
				v.Gap = true
				continue
			}
			connection := *event.Connection
			if event.Type == 2 {
				connection.ClosedAt = event.ClosedAt
			}
			if _, exists := v.Connections[event.ID]; !exists && len(v.Connections) >= v.MaxConnections {
				v.MarkGap()
				return ErrLimit
			}
			v.Connections[event.ID] = connection
		case 1:
			if _, exists := v.Connections[event.ID]; !exists {
				v.Gap = true
			}
		}
	}
	return nil
}
