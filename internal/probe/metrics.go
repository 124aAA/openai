package probe

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Metrics struct {
	CollectedAt     time.Time `json:"collected_at"`
	PID             int       `json:"pid"`
	Availability    string    `json:"availability"`
	CPUTicks        *uint64   `json:"cpu_ticks"`
	CPUPercent      *float64  `json:"cpu_percent"`
	RSSBytes        *int64    `json:"rss_bytes"`
	UDPInErrors     *uint64   `json:"udp_in_errors"`
	UDPRcvbufErrors *uint64   `json:"udp_receive_buffer_errors"`
	Scope           string    `json:"scope"`
}

// ReadMetrics reads procfs only. UDP counters belong to the current network
// namespace and are not attributed to the selected node or process.
func ReadMetrics(pid int) Metrics {
	if pid <= 0 {
		pid = os.Getpid()
	}
	m := Metrics{CollectedAt: time.Now().UTC(), PID: pid, Availability: "unavailable", Scope: "CPU/RSS为所观测进程；UDP计数为本机网络空间总量"}
	if b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); e == nil {
		// comm can contain spaces and parentheses; fields after its final ')'
		// begin at field 3. utime and stime are fields 14 and 15.
		s := string(b)
		end := strings.LastIndex(s, ")")
		if end >= 0 {
			f := strings.Fields(s[end+1:])
			if len(f) > 12 {
				u, e1 := strconv.ParseUint(f[11], 10, 64)
				v, e2 := strconv.ParseUint(f[12], 10, 64)
				if e1 == nil && e2 == nil {
					n := u + v
					m.CPUTicks = &n
				}
			}
		}
	}
	if b, e := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid)); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 1 {
			n, e := strconv.ParseInt(f[1], 10, 64)
			if e == nil && n >= 0 {
				n *= int64(os.Getpagesize())
				m.RSSBytes = &n
			}
		}
	}
	if b, e := os.ReadFile("/proc/net/snmp"); e == nil {
		lines := strings.Split(string(b), "\n")
		for i := 0; i+1 < len(lines); i++ {
			names := strings.Fields(lines[i])
			values := strings.Fields(lines[i+1])
			if len(names) > 0 && names[0] == "Udp:" && len(names) == len(values) && values[0] == "Udp:" {
				for j, n := range names {
					v, e := strconv.ParseUint(values[j], 10, 64)
					if e != nil {
						continue
					}
					switch n {
					case "InErrors":
						m.UDPInErrors = &v
					case "RcvbufErrors":
						m.UDPRcvbufErrors = &v
					}
				}
				break
			}
		}
	}
	if m.CPUTicks != nil || m.RSSBytes != nil || m.UDPInErrors != nil {
		m.Availability = "partial"
	}
	return m
}
