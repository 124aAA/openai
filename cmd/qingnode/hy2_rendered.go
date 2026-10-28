package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"qingnode/internal/node"
)

type hy2Rendered struct {
	Server node.M `json:"server"`
	Client node.M `json:"client"`
}

var hy2PerformanceKeys = map[string]bool{
	"up_mbps": true, "down_mbps": true, "ignore_client_bandwidth": true,
	"bbr_profile": true, "brutal_debug": true, "disable_chrome_parrot": true,
	"stream_receive_window": true, "connection_receive_window": true,
	"idle_timeout": true, "keep_alive_period": true, "max_concurrent_streams": true,
	"initial_packet_size": true, "disable_path_mtu_discovery": true,
}

func hy2FilterPerformance(raw node.M) node.M {
	out := node.M{}
	for k, v := range raw {
		if hy2PerformanceKeys[k] {
			out[k] = v
		}
	}
	return out
}

// Read from the actual flattened server/outbound renderers. Never copy users,
// passwords, addresses, TLS objects, certificates or private keys into a plan.
func hy2RenderedFields(s node.State, id, user, root string) (hy2Rendered, error) {
	r := hy2Rendered{Server: node.M{}, Client: node.M{}}
	n, e := s.Find(id)
	if e != nil {
		return r, e
	}
	u, e := node.SelectUser(*n, user)
	if e != nil {
		return r, e
	}
	b, e := node.Server(s, root)
	if e != nil {
		return r, e
	}
	var server struct {
		Inbounds []node.M `json:"inbounds"`
	}
	if e = json.Unmarshal(b, &server); e != nil {
		return r, e
	}
	for _, in := range server.Inbounds {
		if in["tag"] == n.ID {
			r.Server = hy2FilterPerformance(in)
			break
		}
	}
	r.Client = hy2FilterPerformance(node.Outbound(*n, u))
	return r, nil
}

func validateHY2Rendered(r hy2Rendered) error {
	if r.Server == nil || r.Client == nil {
		return errors.New("性能计划缺少实际派生字段；核心默认须保存为空对象而不是省略")
	}
	for endpoint, m := range map[string]node.M{"server": r.Server, "client": r.Client} {
		for k, v := range m {
			if !hy2PerformanceKeys[k] || (endpoint == "server" && k == "disable_chrome_parrot") || (endpoint == "client" && k == "ignore_client_bandwidth") {
				return errors.New("性能计划实际字段含未支持的设置或私密字段")
			}
			switch k {
			case "ignore_client_bandwidth", "brutal_debug", "disable_chrome_parrot", "disable_path_mtu_discovery":
				if _, ok := v.(bool); !ok {
					return errors.New("性能计划布尔派生字段无效")
				}
			case "bbr_profile":
				if v != "standard" && v != "conservative" && v != "aggressive" {
					return errors.New("性能计划BBR派生字段无效")
				}
			case "idle_timeout", "keep_alive_period":
				s, ok := v.(string)
				if !ok {
					return errors.New("性能计划超时派生字段无效")
				}
				d, e := time.ParseDuration(s)
				upper := 10 * time.Minute
				if k == "keep_alive_period" {
					upper = 2 * time.Minute
				}
				if e != nil || d < time.Second || d > upper {
					return errors.New("性能计划超时派生字段超出范围")
				}
			default:
				var n float64
				switch x := v.(type) {
				case int:
					n = float64(x)
				case int64:
					n = float64(x)
				case float64:
					n = x
				default:
					return errors.New("性能计划数值派生字段类型无效")
				}
				lo, hi := float64(1), float64(1000000)
				switch k {
				case "stream_receive_window", "connection_receive_window":
					lo, hi = 64<<10, 256<<20
				case "max_concurrent_streams":
					hi = 4096
				case "initial_packet_size":
					lo, hi = 1200, 1452
				}
				if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < lo || n > hi {
					return fmt.Errorf("性能计划派生字段%s超出范围", k)
				}
			}
		}
	}
	return nil
}
