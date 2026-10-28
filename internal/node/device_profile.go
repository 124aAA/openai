package node

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const MaxDeviceProfiles = 128
const MaxDeviceBindings = 256

// A device binding always names one credential explicitly. A node display name
// or its first user must never decide which secret a device receives.
type DeviceBinding struct {
	NodeID     string `json:"node_id"`
	UserID     string `json:"user_id"`
	EndpointID string `json:"endpoint_id,omitempty"`
}

type DeviceProfile struct {
	SubscriptionFormats []string        `json:"subscription_formats,omitempty"`
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Disabled            bool            `json:"disabled,omitempty"`
	Bindings            []DeviceBinding `json:"bindings"`
	NodeTags            []string        `json:"node_tags,omitempty"`
	Strategy            string          `json:"strategy,omitempty"`
	AllowDegradedAuto   bool            `json:"allow_degraded_auto,omitempty"`
	Routing             string          `json:"routing,omitempty"`
	TestURL             string          `json:"test_url,omitempty"`
	IntervalSeconds     int             `json:"interval_seconds,omitempty"`
	ToleranceMS         int             `json:"tolerance_ms,omitempty"`
	TimeoutMS           int             `json:"timeout_ms,omitempty"`
}

func deviceStrategy(p DeviceProfile) string {
	if p.Strategy == "" {
		return "manual"
	}
	return p.Strategy
}

func deviceRouting(p DeviceProfile) string {
	if p.Routing == "" {
		return "global"
	}
	return p.Routing
}

func deviceEndpoint(id string) string {
	if id == "" {
		return DefaultEndpointID
	}
	return id
}

func deviceBindingKey(b DeviceBinding) string {
	return b.NodeID + "/" + b.UserID + "/" + deviceEndpoint(b.EndpointID)
}

func ValidateDeviceProfiles(st State) error {
	if len(st.Devices) > MaxDeviceProfiles {
		return errors.New("设备 Profile 最多 128 个")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, p := range st.Devices {
		if ids[p.ID] || names[p.Name] {
			return errors.New("设备 Profile ID 或名称重复")
		}
		ids[p.ID], names[p.Name] = true, true
		if err := ValidateDeviceProfile(st, p); err != nil {
			return fmt.Errorf("设备 %s：%w", p.ID, err)
		}
	}
	return nil
}

func ValidateDeviceProfile(st State, p DeviceProfile) error {
	if p.AllowDegradedAuto && deviceStrategy(p) != "auto" {
		return errors.New("allow_degraded_auto 只允许用于 auto 策略；它表示明确接受已核验客户端的自动选择缺陷")
	}
	formats := map[string]bool{}
	for _, format := range p.SubscriptionFormats {
		switch format {
		case "uri", "base64", "sing-box", "mihomo", "provider":
		default:
			return errors.New("设备订阅格式不支持")
		}
		if formats[format] {
			return errors.New("设备订阅格式不能重复")
		}
		formats[format] = true
	}
	if !idRE.MatchString(p.ID) || !cleanName(p.Name) {
		return errors.New("设备 ID 须为 16 位小写十六进制，名称须为 1–160 字节且不含控制字符")
	}
	if len(p.Bindings) < 1 || len(p.Bindings) > MaxDeviceBindings {
		return errors.New("设备必须明确绑定 1–256 条节点凭据")
	}
	if err := ValidateNodeTags(p.NodeTags); err != nil {
		return err
	}
	switch deviceRouting(p) {
	case "global", "basic":
	default:
		return errors.New("设备分流只支持 global 或 basic")
	}
	switch deviceStrategy(p) {
	case "manual":
		if p.TestURL != "" || p.IntervalSeconds != 0 || p.ToleranceMS != 0 || p.TimeoutMS != 0 {
			return errors.New("手动选择不执行自动测试，请清除自动测试 URL、间隔、容差与超时")
		}
	case "auto", "fallback":
		u, err := url.Parse(p.TestURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || !ValidHost(u.Hostname()) || len(p.TestURL) > 2048 || strings.ContainsAny(p.TestURL, "\x00\r\n") {
			return errors.New("自动测试须明确填写 HTTPS URL，不含登录信息、片段或控制字符；不会替你选择公共测速站")
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("自动测试 URL 端口无效")
			}
		}
		if p.IntervalSeconds != 0 && (p.IntervalSeconds < 60 || p.IntervalSeconds > 3600) {
			return errors.New("自动测试间隔为 60–3600 秒，省略采用 300 秒")
		}
		if p.ToleranceMS < 0 || p.ToleranceMS > 1000 {
			return errors.New("自动测试容差为 0–1000 毫秒，0 表示采用 50 毫秒")
		}
		if p.TimeoutMS != 0 && (p.TimeoutMS < 500 || p.TimeoutMS > 15000) {
			return errors.New("自动测试超时为 500–15000 毫秒；省略时采用客户端已核验默认值")
		}
		if deviceStrategy(p) == "fallback" && p.ToleranceMS != 0 {
			return errors.New("顺序主备不支持延迟容差；容差只适用于自动选择")
		}
	default:
		return errors.New("设备策略只支持 manual、auto 或 fallback")
	}
	seen := map[string]bool{}
	for _, b := range p.Bindings {
		if !idRE.MatchString(b.NodeID) || !idRE.MatchString(b.UserID) || !endpointIDRE.MatchString(deviceEndpoint(b.EndpointID)) {
			return errors.New("设备绑定必须填写稳定节点 ID、凭据 ID 及有效端点 ID")
		}
		key := deviceBindingKey(b)
		if seen[key] {
			return errors.New("设备绑定重复（省略端点与 default 是同一个入口）")
		}
		seen[key] = true
		if p.Disabled {
			continue // Keep historical identity without blocking explicit removal.
		}
		if _, _, err := deviceBinding(st, b); err != nil {
			return err
		}
	}
	return nil
}

// deviceBinding only accepts exact IDs. SelectUser's human-name fallback is
// useful interactively but is intentionally unsuitable for a saved device.
func deviceBinding(st State, b DeviceBinding) (Node, User, error) {
	for _, n := range st.Nodes {
		if n.ID != b.NodeID {
			continue
		}
		selected, err := WithEndpoint(n, deviceEndpoint(b.EndpointID))
		if err != nil {
			return Node{}, User{}, fmt.Errorf("节点 %s 的连接端点不存在或无效", b.NodeID)
		}
		for _, u := range n.Users {
			if u.ID == b.UserID {
				return selected, u, nil
			}
		}
		return Node{}, User{}, fmt.Errorf("节点 %s 中指定的凭据 ID 不存在", b.NodeID)
	}
	return Node{}, User{}, fmt.Errorf("设备引用的节点 %s 不存在", b.NodeID)
}

func selectedDeviceBindings(st State, p DeviceProfile) []DeviceBinding {
	bindings := make([]DeviceBinding, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		if len(p.NodeTags) == 0 {
			bindings = append(bindings, b)
			continue
		}
		for _, n := range st.Nodes {
			if n.ID != b.NodeID {
				continue
			}
			matches := false
			for _, wanted := range p.NodeTags {
				for _, tag := range n.Tags {
					matches = matches || wanted == tag
				}
			}
			if matches {
				bindings = append(bindings, b)
			}
			break
		}
	}
	// Order is the meaning of a fallback policy. Every other mode is stable
	// across source slice order, user order, display edits and map iteration.
	if deviceStrategy(p) != "fallback" {
		sort.Slice(bindings, func(i, j int) bool { return deviceBindingKey(bindings[i]) < deviceBindingKey(bindings[j]) })
	}
	return bindings
}
