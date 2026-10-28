package node

import (
	"errors"
	"net"
	"strconv"
)

// CoreObservation is opt-in and owns only the local read observation endpoint.
// Official API also includes management methods; loopback plus secret protects
// the endpoint, while QingNode's client exposes only read calls.
type CoreObservation struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
	Port    int    `json:"port"`
	Secret  string `json:"secret"`
}

func ValidateCoreObservation(c *CoreObservation) error {
	if c == nil {
		return nil
	}
	ip := net.ParseIP(c.Listen)
	if ip == nil || !ip.IsLoopback() || (c.Listen != "127.0.0.1" && c.Listen != "::1") || c.Port < 1024 || c.Port > 65535 {
		return errors.New("观测API仅允许127.0.0.1或::1的1024–65535端口")
	}
	if len(c.Secret) < 32 || len(c.Secret) > 256 {
		return errors.New("观测API必须使用32–256字节非空私有鉴权值，不能含空白")
	}
	for _, ch := range c.Secret {
		if ch < 33 || ch > 126 {
			return errors.New("观测API鉴权值仅允许可见ASCII字符，不能含空白或控制字符")
		}
	}
	return nil
}

func (c CoreObservation) Endpoint() string {
	return "http://" + net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}
