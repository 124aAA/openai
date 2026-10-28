package node

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

const MaxCredentialExpirations = 4096

// CredentialExpiration is a proxy authentication deadline, independent of any
// subscription download token. DeviceID limits the operation to a credential
// explicitly bound to that device; sharing that credential blocks the operation.
// One record names one credential, even when a device has several bindings.
type CredentialExpiration struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	UserID     string `json:"user_id"`
	DeviceID   string `json:"device_id,omitempty"`
	ExpiresAt  string `json:"expires_at"`
	DisabledAt string `json:"disabled_at,omitempty"`
}

type ExpirationDecision struct {
	CredentialExpiration
	Status            string   `json:"status"`
	Due               bool     `json:"due"`
	AffectedDeviceIDs []string `json:"affected_device_ids,omitempty"`
	StopsNode         bool     `json:"stops_node,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}

type ExpirationPlan struct {
	EvaluatedAt string               `json:"evaluated_at"`
	Items       []ExpirationDecision `json:"items"`
	Due         int                  `json:"due"`
	Ready       int                  `json:"ready"`
	Blocked     int                  `json:"blocked"`
}

var expirationTimeRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

// ParseExpirationTime accepts explicit UTC RFC3339 only. It does not silently
// reinterpret local time, offsets, or an epoch value as the requested deadline.
func ParseExpirationTime(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || !expirationTimeRE.MatchString(raw) || t.Year() < 2020 {
		return time.Time{}, errors.New("到期时间须为2020年或之后的RFC3339 UTC时间，例如2030-01-02T03:04:05Z；不能使用本地时间或时区偏移")
	}
	return t.UTC(), nil
}

func expirationNode(st *State, id string) *Node {
	for i := range st.Nodes {
		if st.Nodes[i].ID == id {
			return &st.Nodes[i]
		}
	}
	return nil
}

func expirationUser(n *Node, id string) *User {
	if n != nil {
		for i := range n.Users {
			if n.Users[i].ID == id {
				return &n.Users[i]
			}
		}
	}
	return nil
}

func expirationDevice(st *State, id string) *DeviceProfile {
	for i := range st.Devices {
		if st.Devices[i].ID == id {
			return &st.Devices[i]
		}
	}
	return nil
}

func expirationHasBinding(p DeviceProfile, e CredentialExpiration) bool {
	for _, b := range p.Bindings {
		if b.NodeID == e.NodeID && b.UserID == e.UserID {
			return true
		}
	}
	return false
}

// Pending records require exact live references. Completed records retain a
// historical user ID because stopping a non-final user removes that credential;
// their node and optional device must still exist until explicitly unscheduled.
func ValidateCredentialExpirations(st State) error {
	if len(st.CredentialExpirations) > MaxCredentialExpirations {
		return errors.New("代理凭据到期计划最多4096条")
	}
	ids, targets := map[string]bool{}, map[string]bool{}
	for _, e := range st.CredentialExpirations {
		key := e.NodeID + "/" + e.UserID
		if !idRE.MatchString(e.ID) || !idRE.MatchString(e.NodeID) || !idRE.MatchString(e.UserID) || (e.DeviceID != "" && !idRE.MatchString(e.DeviceID)) || ids[e.ID] || targets[key] {
			return errors.New("到期计划须使用16位小写十六进制稳定ID；计划ID及同一节点凭据的计划不能重复")
		}
		ids[e.ID], targets[key] = true, true
		deadline, err := ParseExpirationTime(e.ExpiresAt)
		if err != nil {
			return err
		}
		n := expirationNode(&st, e.NodeID)
		if n == nil {
			return fmt.Errorf("到期计划 %s 引用的节点ID不存在；请先显式移除计划", e.ID)
		}
		var p *DeviceProfile
		if e.DeviceID != "" {
			p = expirationDevice(&st, e.DeviceID)
			if p == nil {
				return fmt.Errorf("到期计划 %s 引用的设备ID不存在；请先显式移除计划", e.ID)
			}
		}
		u := expirationUser(n, e.UserID)
		if e.DisabledAt == "" {
			if u == nil || (p != nil && !expirationHasBinding(*p, e)) {
				return fmt.Errorf("到期计划 %s 引用的凭据或设备绑定不存在；请先显式移除计划", e.ID)
			}
			continue
		}
		disabledAt, err := ParseExpirationTime(e.DisabledAt)
		if err != nil || disabledAt.Before(deadline) {
			return fmt.Errorf("到期计划 %s 的停用记录无效或早于到期时间", e.ID)
		}
		if u != nil && n.Enabled {
			return fmt.Errorf("凭据 %s 已按到期计划 %s 停用；重新启用前须显式移除该计划并确认恢复，或删除保留的历史凭据", e.UserID, e.ID)
		}
		for _, d := range st.Devices {
			if !d.Disabled && expirationHasBinding(d, e) {
				return fmt.Errorf("到期计划 %s 已执行，活跃设备不能重新绑定该历史凭据；请先显式移除计划", e.ID)
			}
		}
	}
	return nil
}

// SetCredentialExpiration is an explicit scheduling operation. Display changes,
// exports and token renewal never call it. A completed record cannot be quietly
// renewed or retargeted: remove it explicitly before creating another schedule.
func SetCredentialExpiration(st *State, e CredentialExpiration) error {
	if e.DisabledAt != "" {
		return errors.New("设置到期计划不能伪造disabled_at停用记录")
	}
	c := st.Clone()
	found := false
	for i, old := range c.CredentialExpirations {
		if old.ID != e.ID {
			continue
		}
		if old.DisabledAt != "" || old.NodeID != e.NodeID || old.UserID != e.UserID || old.DeviceID != e.DeviceID {
			return errors.New("既有计划不能改绑身份或直接续期已停用凭据；请显式移除计划后重新设置")
		}
		c.CredentialExpirations[i], found = e, true
		break
	}
	if !found {
		c.CredentialExpirations = append(c.CredentialExpirations, e)
	}
	if err := c.Validate(); err != nil {
		return err
	}
	*st = c
	return nil
}

func RemoveCredentialExpiration(st *State, id string) error {
	c := st.Clone()
	for i, e := range c.CredentialExpirations {
		if e.ID == id {
			c.CredentialExpirations = append(c.CredentialExpirations[:i], c.CredentialExpirations[i+1:]...)
			if err := c.Validate(); err != nil {
				return err
			}
			*st = c
			return nil
		}
	}
	return errors.New("到期计划ID不存在；移除计划不会恢复已删除凭据、设备绑定或节点监听")
}

func expirationClock(st State, now, lastRun time.Time) error {
	if now.IsZero() || now.Year() < 2020 || now.Year() > 9999 {
		return errors.New("当前时钟无效或早于2020年；拒绝执行凭据到期停用，请先核对系统时间")
	}
	if !lastRun.IsZero() && now.Before(lastRun) {
		return errors.New("当前时钟早于上次已观察时间；拒绝执行到期停用，请先核对系统时间")
	}
	for _, e := range st.CredentialExpirations {
		if e.DisabledAt != "" {
			t, err := ParseExpirationTime(e.DisabledAt)
			if err != nil || now.Before(t) {
				return errors.New("当前时钟早于已有停用记录；拒绝执行到期停用，请先核对系统时间")
			}
		}
	}
	return nil
}

func PlanExpirations(st State, now time.Time) (ExpirationPlan, error) {
	return PlanExpirationsSince(st, now, time.Time{})
}

// lastRun is supplied by an observing caller such as the bounded monitor. It is
// not inferred from node stop state and never changes a deadline in State.
func PlanExpirationsSince(st State, now, lastRun time.Time) (ExpirationPlan, error) {
	p := ExpirationPlan{EvaluatedAt: now.UTC().Format(time.RFC3339Nano), Items: []ExpirationDecision{}}
	if err := st.Validate(); err != nil {
		return p, err
	}
	if err := expirationClock(st, now, lastRun); err != nil {
		return p, err
	}
	entries := append([]CredentialExpiration{}, st.CredentialExpirations...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		d := ExpirationDecision{CredentialExpiration: e, Status: "scheduled"}
		if e.DisabledAt != "" {
			d.Status = "disabled"
			p.Items = append(p.Items, d)
			continue
		}
		deadline, _ := ParseExpirationTime(e.ExpiresAt)
		d.Due = !now.Before(deadline)
		if d.Due {
			d.Status, p.Due = "due", p.Due+1
		}
		n := expirationNode(&st, e.NodeID)
		d.StopsNode = n != nil && len(n.Users) == 1
		for _, device := range st.Devices {
			if !expirationHasBinding(device, e) {
				continue
			}
			d.AffectedDeviceIDs = append(d.AffectedDeviceIDs, device.ID)
			if e.DeviceID != "" && device.ID != e.DeviceID {
				d.Status = "blocked"
				d.Reason = "该代理凭据仍由其他设备共享；需先分配独立凭据或显式改为凭据级到期计划；撤销下载令牌不会使代理认证失效"
			}
		}
		sort.Strings(d.AffectedDeviceIDs)
		if d.Due && d.Status == "blocked" {
			p.Blocked++
		} else if d.Due {
			p.Ready++
		}
		p.Items = append(p.Items, d)
	}
	// Several deadlines can together remove every user of a listener. Preview
	// that batch effect before the final surviving credential is preserved.
	dueByNode := map[string]int{}
	for _, d := range p.Items {
		if d.Due && d.Status != "blocked" {
			dueByNode[d.NodeID]++
		}
	}
	for i := range p.Items {
		d := &p.Items[i]
		if n := expirationNode(&st, d.NodeID); d.Due && n != nil && dueByNode[d.NodeID] == len(n.Users) {
			d.StopsNode = true
		}
	}
	return p, nil
}

func ApplyDueExpirations(st State, now time.Time) (State, ExpirationPlan, error) {
	return ApplyDueExpirationsSince(st, now, time.Time{})
}

// ApplyDueExpirationsSince only builds a candidate. Its caller holds the Store
// lock and commits once; this function never edits files, tokens or a service.
// A single blocked due record rejects the entire candidate before mutation.
func ApplyDueExpirationsSince(st State, now, lastRun time.Time) (State, ExpirationPlan, error) {
	plan, err := PlanExpirationsSince(st, now, lastRun)
	if err != nil {
		return st, plan, err
	}
	if plan.Blocked > 0 {
		return st, plan, fmt.Errorf("%d条到期计划被共享凭据阻止；整批未应用，请查看expiration list", plan.Blocked)
	}
	if plan.Ready == 0 {
		return st, plan, nil
	}
	c := st.Clone()
	for _, d := range plan.Items {
		if !d.Due {
			continue
		}
		e := d.CredentialExpiration
		for i := range c.CredentialExpirations {
			if c.CredentialExpirations[i].ID == e.ID {
				c.CredentialExpirations[i].DisabledAt = now.UTC().Format(time.RFC3339Nano)
			}
		}
		for i := range c.Devices {
			device := &c.Devices[i]
			if !expirationHasBinding(*device, e) {
				continue
			}
			kept := make([]DeviceBinding, 0, len(device.Bindings))
			for _, b := range device.Bindings {
				if b.NodeID != e.NodeID || b.UserID != e.UserID {
					kept = append(kept, b)
				}
			}
			if len(kept) == 0 {
				device.Disabled = true // Retain its last bindings as explicit history.
			} else {
				device.Bindings = kept // Preserve other users, bindings and download access.
			}
		}
		n := expirationNode(&c, e.NodeID)
		for i, u := range n.Users {
			if u.ID != e.UserID {
				continue
			}
			if len(n.Users) == 1 {
				n.Enabled = false // The model requires one credential even when stopped.
			} else {
				n.Users = append(n.Users[:i], n.Users[i+1:]...)
			}
			break
		}
	}
	if err := c.Validate(); err != nil {
		return st, plan, err
	}
	return c, plan, nil
}
