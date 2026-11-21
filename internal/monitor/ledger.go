package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"qingnode/internal/coreapi"
	"qingnode/internal/probe"
)

const (
	TrafficLedgerVersion = 1
	MaxLedgerBytes       = 1 << 20
	MaxAlertsBytes       = 256 << 10
	MaxLedgerConns       = 4096
	MaxLedgerUsers       = 4096
	MaxLedgerDays        = 66
	MaxAlertEntries      = 1024
)

type TrafficPair struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type ConnWatermark struct {
	NodeID   string    `json:"node_id"`
	UserID   string    `json:"user_id"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Closed   bool      `json:"closed"`
	SeenAt   time.Time `json:"seen_at"`
}

type UserTrafficLedger struct {
	NodeID        string                 `json:"node_id"`
	UserID        string                 `json:"user_id"`
	TotalUpload   int64                  `json:"total_upload"`
	TotalDownload int64                  `json:"total_download"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Daily         map[string]TrafficPair `json:"daily,omitempty"`
}

// TrafficLedger persists cumulative observation deltas across core restarts.
// GapDetected honestly records unclean restarts or counter regressions; it
// never claims billing-grade accuracy.
type TrafficLedger struct {
	Version              int                      `json:"version"`
	UpdatedAt            time.Time                `json:"updated_at"`
	ActiveEpoch          string                   `json:"active_epoch,omitempty"`
	CleanShutdownEpoch   string                   `json:"clean_shutdown_epoch,omitempty"`
	LastUplink           int64                    `json:"last_uplink"`
	LastDownlink         int64                    `json:"last_downlink"`
	GlobalUpload         int64                    `json:"global_upload"`
	GlobalDownload       int64                    `json:"global_download"`
	UnattributedUpload   int64                    `json:"unattributed_upload"`
	UnattributedDownload int64                    `json:"unattributed_download"`
	GapDetected          bool                     `json:"gap_detected"`
	GapCount             int                      `json:"gap_count"`
	LastGapReason        string                   `json:"last_gap_reason,omitempty"`
	LastGapAt            string                   `json:"last_gap_at,omitempty"`
	BillingSuitable      bool                     `json:"billing_suitable"`
	Entries              []UserTrafficLedger      `json:"entries"`
	ConnWatermarks       map[string]ConnWatermark `json:"conn_watermarks,omitempty"`
}

type LedgerConnection struct {
	ID       string
	NodeID   string
	UserID   string
	Upload   int64
	Download int64
	Closed   bool
}

type LedgerSample struct {
	ObservedAt           time.Time
	Epoch                string
	Status               coreapi.Status
	Connections          []LedgerConnection
	ConnectionsAvailable bool
	PreStop              bool
}

type AlertLedger struct {
	Version   int                  `json:"version"`
	UpdatedAt time.Time            `json:"updated_at"`
	Sent      map[string]time.Time `json:"sent,omitempty"`
}

func NewTrafficLedger(now time.Time) TrafficLedger {
	return TrafficLedger{
		Version:         TrafficLedgerVersion,
		UpdatedAt:       now.UTC(),
		BillingSuitable: false,
		Entries:         []UserTrafficLedger{},
	}
}

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// QuotaPeriodStart returns the UTC start of the current quota window for
// resetDay (1..31), clamping to month length (e.g. 31 -> Feb 28/29).
// For resetDay <= 0 (lifetime), it returns the zero Time.
func QuotaPeriodStart(now time.Time, resetDay int) time.Time {
	if resetDay <= 0 {
		return time.Time{}
	}
	if resetDay > 31 {
		resetDay = 31
	}
	u := now.UTC()
	year, month, _ := u.Date()
	day := min(resetDay, daysInMonth(year, month))
	start := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	if u.Before(start) {
		prevMonth := month - 1
		prevYear := year
		if prevMonth < time.January {
			prevMonth = time.December
			prevYear--
		}
		prevDay := min(resetDay, daysInMonth(prevYear, prevMonth))
		start = time.Date(prevYear, prevMonth, prevDay, 0, 0, 0, 0, time.UTC)
	}
	return start
}

func QuotaPeriodKey(now time.Time, resetDay int) string {
	if resetDay <= 0 {
		return "lifetime"
	}
	return QuotaPeriodStart(now, resetDay).Format("2006-01-02")
}

func safeAddInt64(a, b int64) int64 {
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func (l *TrafficLedger) RecordGap(at time.Time, reason string) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	l.GapDetected = true
	if l.GapCount < 1000000 {
		l.GapCount++
	}
	code := safeCode(reason)
	if code == "" {
		code = "observation_gap"
	}
	l.LastGapReason = code
	l.LastGapAt = at.UTC().Format(time.RFC3339Nano)
	l.UpdatedAt = at.UTC()
	l.BillingSuitable = false
}

func (l *TrafficLedger) ApplySample(s LedgerSample) error {
	now := s.ObservedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if l.Version == 0 {
		l.Version = TrafficLedgerVersion
	}
	if l.Entries == nil {
		l.Entries = []UserTrafficLedger{}
	}
	l.BillingSuitable = false
	if s.Epoch == "" || len(s.Epoch) > 128 || strings.ContainsAny(s.Epoch, "\r\n\x00 ") {
		l.RecordGap(now, "invalid_core_epoch")
		return errors.New("core epoch identity is invalid")
	}
	if !s.Status.TrafficAvailable || s.Status.UplinkTotal < 0 || s.Status.DownlinkTotal < 0 {
		l.RecordGap(now, "core_traffic_unavailable")
		return coreapi.ErrUnavailable
	}

	var globalDeltaUp, globalDeltaDown int64
	switch {
	case l.ActiveEpoch == "":
		l.ActiveEpoch = s.Epoch
		l.LastUplink = s.Status.UplinkTotal
		l.LastDownlink = s.Status.DownlinkTotal
		globalDeltaUp = s.Status.UplinkTotal
		globalDeltaDown = s.Status.DownlinkTotal
		l.ConnWatermarks = map[string]ConnWatermark{}
	case l.ActiveEpoch != s.Epoch:
		if l.CleanShutdownEpoch != l.ActiveEpoch {
			l.RecordGap(now, "unclean_epoch_change")
		}
		l.ActiveEpoch = s.Epoch
		l.CleanShutdownEpoch = ""
		l.LastUplink = s.Status.UplinkTotal
		l.LastDownlink = s.Status.DownlinkTotal
		globalDeltaUp = s.Status.UplinkTotal
		globalDeltaDown = s.Status.DownlinkTotal
		l.ConnWatermarks = map[string]ConnWatermark{}
	default:
		if s.Status.UplinkTotal < l.LastUplink || s.Status.DownlinkTotal < l.LastDownlink {
			l.RecordGap(now, "counter_regression")
			return coreapi.ErrCounterRegression
		}
		globalDeltaUp = s.Status.UplinkTotal - l.LastUplink
		globalDeltaDown = s.Status.DownlinkTotal - l.LastDownlink
		l.LastUplink = s.Status.UplinkTotal
		l.LastDownlink = s.Status.DownlinkTotal
		if !s.PreStop {
			l.CleanShutdownEpoch = ""
		}
	}

	l.GlobalUpload = safeAddInt64(l.GlobalUpload, globalDeltaUp)
	l.GlobalDownload = safeAddInt64(l.GlobalDownload, globalDeltaDown)
	if s.PreStop {
		l.CleanShutdownEpoch = s.Epoch
	}

	if !s.ConnectionsAvailable {
		l.UnattributedUpload = safeAddInt64(l.UnattributedUpload, globalDeltaUp)
		l.UnattributedDownload = safeAddInt64(l.UnattributedDownload, globalDeltaDown)
		l.RecordGap(now, "connections_snapshot_unavailable")
		l.pruneDaily(now)
		l.UpdatedAt = now
		return nil
	}

	if l.ConnWatermarks == nil {
		l.ConnWatermarks = map[string]ConnWatermark{}
	}
	entryIndex := make(map[string]int, len(l.Entries))
	for i, e := range l.Entries {
		entryIndex[e.NodeID+"/"+e.UserID] = i
	}
	dayKey := now.Format("2006-01-02")
	presentConns := make(map[string]bool, len(s.Connections))
	var attributedUp, attributedDown int64

	for _, c := range s.Connections {
		if c.ID == "" || c.ID == coreapi.UnknownOwner || len(c.ID) > 64 || c.Upload < 0 || c.Download < 0 {
			continue
		}
		presentConns[c.ID] = true
		prev, exists := l.ConnWatermarks[c.ID]
		if exists && (c.Upload < prev.Upload || c.Download < prev.Download) {
			l.RecordGap(now, "connection_counter_regression")
			continue
		}
		dUp := c.Upload - prev.Upload
		dDown := c.Download - prev.Download
		l.ConnWatermarks[c.ID] = ConnWatermark{
			NodeID:   c.NodeID,
			UserID:   c.UserID,
			Upload:   c.Upload,
			Download: c.Download,
			Closed:   c.Closed,
			SeenAt:   now,
		}
		if c.NodeID != "" && c.NodeID != coreapi.UnknownOwner && validID(c.NodeID) &&
			c.UserID != "" && c.UserID != coreapi.UnknownOwner && validID(c.UserID) {
			attributedUp = safeAddInt64(attributedUp, dUp)
			attributedDown = safeAddInt64(attributedDown, dDown)
			if dUp > 0 || dDown > 0 || !exists {
				key := c.NodeID + "/" + c.UserID
				idx, ok := entryIndex[key]
				if !ok {
					if len(l.Entries) >= MaxLedgerUsers {
						l.RecordGap(now, "ledger_user_cap_reached")
						continue
					}
					idx = len(l.Entries)
					l.Entries = append(l.Entries, UserTrafficLedger{
						NodeID:    c.NodeID,
						UserID:    c.UserID,
						UpdatedAt: now,
						Daily:     map[string]TrafficPair{},
					})
					entryIndex[key] = idx
				}
				entry := &l.Entries[idx]
				entry.TotalUpload = safeAddInt64(entry.TotalUpload, dUp)
				entry.TotalDownload = safeAddInt64(entry.TotalDownload, dDown)
				entry.UpdatedAt = now
				if dUp > 0 || dDown > 0 {
					if entry.Daily == nil {
						entry.Daily = map[string]TrafficPair{}
					}
					pair := entry.Daily[dayKey]
					pair.Upload = safeAddInt64(pair.Upload, dUp)
					pair.Download = safeAddInt64(pair.Download, dDown)
					entry.Daily[dayKey] = pair
				}
			}
		}
	}

	if globalDeltaUp > attributedUp {
		l.UnattributedUpload = safeAddInt64(l.UnattributedUpload, globalDeltaUp-attributedUp)
	}
	if globalDeltaDown > attributedDown {
		l.UnattributedDownload = safeAddInt64(l.UnattributedDownload, globalDeltaDown-attributedDown)
	}

	// Evict closed connections already dropped from core's snapshot first so
	// ConnWatermarks remains strictly bounded.
	for id, wm := range l.ConnWatermarks {
		if wm.Closed && !presentConns[id] {
			delete(l.ConnWatermarks, id)
		}
	}
	if len(l.ConnWatermarks) > MaxLedgerConns {
		type candidate struct {
			id     string
			closed bool
			seen   time.Time
		}
		evict := make([]candidate, 0, len(l.ConnWatermarks))
		for id, wm := range l.ConnWatermarks {
			if !presentConns[id] {
				evict = append(evict, candidate{id: id, closed: wm.Closed, seen: wm.SeenAt})
			}
		}
		sort.Slice(evict, func(i, j int) bool {
			if evict[i].closed != evict[j].closed {
				return evict[i].closed
			}
			return evict[i].seen.Before(evict[j].seen)
		})
		for _, c := range evict {
			if len(l.ConnWatermarks) <= MaxLedgerConns {
				break
			}
			if !c.closed {
				l.RecordGap(now, "active_watermark_evicted")
			}
			delete(l.ConnWatermarks, c.id)
		}
		if len(l.ConnWatermarks) > MaxLedgerConns {
			all := make([]candidate, 0, len(l.ConnWatermarks))
			for id, wm := range l.ConnWatermarks {
				all = append(all, candidate{id: id, closed: wm.Closed, seen: wm.SeenAt})
			}
			sort.Slice(all, func(i, j int) bool {
				if all[i].closed != all[j].closed {
					return all[i].closed
				}
				return all[i].seen.Before(all[j].seen)
			})
			for _, c := range all {
				if len(l.ConnWatermarks) <= MaxLedgerConns {
					break
				}
				if !c.closed {
					l.RecordGap(now, "watermark_cap_reached")
				}
				delete(l.ConnWatermarks, c.id)
			}
		}
	}

	sort.Slice(l.Entries, func(i, j int) bool {
		if l.Entries[i].NodeID != l.Entries[j].NodeID {
			return l.Entries[i].NodeID < l.Entries[j].NodeID
		}
		return l.Entries[i].UserID < l.Entries[j].UserID
	})
	l.pruneDaily(now)
	l.UpdatedAt = now
	return nil
}

func (l *TrafficLedger) pruneDaily(now time.Time) {
	cutoff := now.UTC().AddDate(0, 0, -MaxLedgerDays).Format("2006-01-02")
	for i := range l.Entries {
		for day := range l.Entries[i].Daily {
			if day < cutoff {
				delete(l.Entries[i].Daily, day)
			}
		}
		if len(l.Entries[i].Daily) == 0 {
			l.Entries[i].Daily = nil
		}
	}
}

func (l TrafficLedger) UsageFor(nodeID, userID string, resetDay int, now time.Time) (TrafficPair, bool) {
	for _, e := range l.Entries {
		if e.NodeID != nodeID || e.UserID != userID {
			continue
		}
		if resetDay <= 0 {
			return TrafficPair{Upload: e.TotalUpload, Download: e.TotalDownload}, true
		}
		startKey := QuotaPeriodStart(now, resetDay).Format("2006-01-02")
		endKey := now.UTC().Format("2006-01-02")
		var sum TrafficPair
		for day, p := range e.Daily {
			if day >= startKey && day <= endKey {
				sum.Upload = safeAddInt64(sum.Upload, p.Upload)
				sum.Download = safeAddInt64(sum.Download, p.Download)
			}
		}
		return sum, true
	}
	return TrafficPair{}, false
}

func (l TrafficLedger) UsageByUserMap(resetDay int, now time.Time) map[string]TrafficPair {
	out := make(map[string]TrafficPair, len(l.Entries))
	for _, e := range l.Entries {
		p, _ := l.UsageFor(e.NodeID, e.UserID, resetDay, now)
		out[e.NodeID+"/"+e.UserID] = p
	}
	return out
}

func strictNoNullJSON(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var check func(int) error
	check = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting limit exceeded")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			return errors.New("JSON null is not allowed")
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					kt, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := kt.(string)
					if !ok {
						return errors.New("invalid JSON key")
					}
					fold := strings.Map(func(r rune) rune {
						c := r
						for n := unicode.SimpleFold(r); n != r; n = unicode.SimpleFold(n) {
							if n < c {
								c = n
							}
						}
						return c
					}, key)
					if seen[fold] {
						return errors.New("duplicate JSON key")
					}
					seen[fold] = true
					if err = check(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err = check(depth + 1); err != nil {
						return err
					}
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := check(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return probe.StrictJSON(data, v)
}

func validateTrafficLedger(v TrafficLedger) error {
	if v.Version != TrafficLedgerVersion || v.BillingSuitable || len(v.Entries) > MaxLedgerUsers || len(v.ConnWatermarks) > MaxLedgerConns || v.GapCount < 0 {
		return errors.New("流量账本版本或上限无效")
	}
	if v.LastUplink < 0 || v.LastDownlink < 0 || v.GlobalUpload < 0 || v.GlobalDownload < 0 || v.UnattributedUpload < 0 || v.UnattributedDownload < 0 {
		return errors.New("流量账本计数不能为负")
	}
	seen := map[string]bool{}
	for _, e := range v.Entries {
		key := e.NodeID + "/" + e.UserID
		if !validID(e.NodeID) || !validID(e.UserID) || seen[key] || e.TotalUpload < 0 || e.TotalDownload < 0 || len(e.Daily) > MaxLedgerDays+8 {
			return errors.New("流量账本用户条目无效")
		}
		seen[key] = true
		for day, p := range e.Daily {
			if len(day) != 10 || p.Upload < 0 || p.Download < 0 {
				return errors.New("流量账本按日分桶无效")
			}
			if _, err := time.Parse("2006-01-02", day); err != nil {
				return errors.New("流量账本日期格式无效")
			}
		}
	}
	return nil
}

// LoadTrafficLedger is strictly read-only and never creates directories or repairs permissions.
func (s *Store) LoadTrafficLedger() (TrafficLedger, error) {
	var v TrafficLedger
	if err := s.checkRoot(false); err != nil {
		return v, err
	}
	b, err := readOwned(filepath.Join(s.Root, "traffic-ledger.json"), MaxLedgerBytes, true)
	if err != nil {
		return v, err
	}
	if err = strictNoNullJSON(b, &v); err != nil {
		return TrafficLedger{}, errors.New("监控流量账本JSON无效")
	}
	if err = validateTrafficLedger(v); err != nil {
		return TrafficLedger{}, err
	}
	return v, nil
}

func (s *Store) saveTrafficLedgerLocked(v TrafficLedger) error {
	v.BillingSuitable = false
	if v.Entries == nil {
		v.Entries = []UserTrafficLedger{}
	}
	if err := validateTrafficLedger(v); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil || len(b)+1 > MaxLedgerBytes {
		// Evict watermarks first if approaching the 1MiB cap.
		v.ConnWatermarks = nil
		b, err = json.MarshalIndent(v, "", "  ")
		if err != nil || len(b)+1 > MaxLedgerBytes {
			return errors.New("监控流量账本超过1MiB上限")
		}
	}
	return s.writeOwned("traffic-ledger.json", append(b, '\n'), MaxLedgerBytes)
}

func (s *Store) RecordTrafficSample(sample LedgerSample) (TrafficLedger, error) {
	if err := s.Initialize(); err != nil {
		return TrafficLedger{}, err
	}
	lock, err := s.acquire()
	if err != nil {
		return TrafficLedger{}, err
	}
	defer lock.Close()
	return s.RecordTrafficSampleUnlocked(sample)
}

// RecordTrafficSampleUnlocked updates traffic-ledger.json when the caller
// already holds .monitor.lock (such as inside Engine.RunOnce recovery).
func (s *Store) RecordTrafficSampleUnlocked(sample LedgerSample) (TrafficLedger, error) {
	ledger, err := s.LoadTrafficLedger()
	if os.IsNotExist(err) {
		ledger = NewTrafficLedger(sample.ObservedAt)
		err = nil
	}
	if err != nil {
		return TrafficLedger{}, err
	}
	applyErr := ledger.ApplySample(sample)
	if saveErr := s.saveTrafficLedgerLocked(ledger); saveErr != nil {
		return ledger, saveErr
	}
	return ledger, applyErr
}

func (s *Store) RecordTrafficGap(at time.Time, reason string) error {
	if _, err := os.Lstat(filepath.Join(s.Root, "traffic-ledger.json")); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	lock, err := s.acquire()
	if err != nil {
		return err
	}
	defer lock.Close()
	ledger, err := s.LoadTrafficLedger()
	if err != nil {
		return err
	}
	if ledger.ActiveEpoch == "" || ledger.CleanShutdownEpoch == ledger.ActiveEpoch {
		return nil
	}
	ledger.RecordGap(at, reason)
	return s.saveTrafficLedgerLocked(ledger)
}

func (s *Store) LoadAlerts() (AlertLedger, error) {
	var v AlertLedger
	if err := s.checkRoot(false); err != nil {
		return v, err
	}
	b, err := readOwned(filepath.Join(s.Root, "alerts.json"), MaxAlertsBytes, true)
	if err != nil {
		return v, err
	}
	if err = strictNoNullJSON(b, &v); err != nil || v.Version != 1 || len(v.Sent) > MaxAlertEntries {
		return AlertLedger{}, errors.New("监控告警去重记录无效")
	}
	return v, nil
}

func (s *Store) RecordAlertKey(key string, at time.Time) error {
	if key == "" || len(key) > 256 || strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("告警去重键无效")
	}
	if err := s.Initialize(); err != nil {
		return err
	}
	lock, err := s.acquire()
	if err != nil {
		return err
	}
	defer lock.Close()
	return s.recordAlertKeyLocked(key, at)
}

func (s *Store) recordAlertKeyLocked(key string, at time.Time) error {
	v, err := s.LoadAlerts()
	if os.IsNotExist(err) {
		v = AlertLedger{Version: 1, Sent: map[string]time.Time{}}
		err = nil
	}
	if err != nil {
		return err
	}
	if v.Sent == nil {
		v.Sent = map[string]time.Time{}
	}
	now := at.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	v.Sent[key] = now
	cutoff := now.AddDate(0, 0, -180)
	for k, ts := range v.Sent {
		if ts.Before(cutoff) {
			delete(v.Sent, k)
		}
	}
	if len(v.Sent) > MaxAlertEntries {
		type item struct {
			k string
			t time.Time
		}
		items := make([]item, 0, len(v.Sent))
		for k, ts := range v.Sent {
			items = append(items, item{k, ts})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].t.Before(items[j].t) })
		for i := 0; len(v.Sent) > MaxAlertEntries && i < len(items); i++ {
			delete(v.Sent, items[i].k)
		}
	}
	v.UpdatedAt = now
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil || len(b)+1 > MaxAlertsBytes {
		return errors.New("监控告警去重记录超过上限")
	}
	return s.writeOwned("alerts.json", append(b, '\n'), MaxAlertsBytes)
}

// AcquireAllLocks serializes runtime and configuration writes (and cleans any
// stale owned write temporaries) before capturing a migration package.
func (s *Store) AcquireAllLocks() (func(), error) {
	cfgLock, err := s.acquireNamed(".monitor-config.lock")
	if err != nil {
		return nil, err
	}
	runLock, err := s.acquireNamed(".monitor.lock")
	if err != nil {
		_ = cfgLock.Close()
		return nil, err
	}
	return func() {
		_ = runLock.Close()
		_ = cfgLock.Close()
	}, nil
}
