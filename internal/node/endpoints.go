package node

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ConnectionEndpoint is an explicitly declared client entry. It neither creates
// a listener nor changes provider NAT, TLS identity, or REALITY handshake targets.
type ConnectionEndpoint struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

const DefaultEndpointID = "default"
const MaxAdditionalEndpoints = 16

var endpointIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

// EffectiveConnectPort preserves omission for new in-memory nodes. Legacy State
// migration saves its original Port explicitly, so later listener edits cannot
// silently change an existing client's connection port.
func EffectiveConnectPort(n Node) int {
	if n.ConnectPort != nil {
		return *n.ConnectPort
	}
	return n.Port
}

func EffectiveEndpoints(n Node) []ConnectionEndpoint {
	endpoints := make([]ConnectionEndpoint, 0, 1+len(n.AdditionalEndpoints))
	endpoints = append(endpoints, ConnectionEndpoint{ID: DefaultEndpointID, Host: n.Host, Port: EffectiveConnectPort(n)})
	return append(endpoints, n.AdditionalEndpoints...)
}

// WithEndpoint projects one client entry onto a copy. Server parameters,
// credentials, SNI and saved endpoint declarations remain untouched.
func WithEndpoint(n Node, id string) (Node, error) {
	if err := ValidateEndpoints(n); err != nil {
		return Node{}, err
	}
	if id == "" || id == DefaultEndpointID {
		return n, nil
	}
	for _, endpoint := range n.AdditionalEndpoints {
		if endpoint.ID == id {
			port := endpoint.Port
			n.Host, n.ConnectPort = endpoint.Host, &port
			return n, nil
		}
	}
	return Node{}, fmt.Errorf("连接端点不存在：%s", id)
}

// NormalizeEndpointHost is for explicit user input, not State migration. Keep
// existing valid spelling (including IPv6 compression) so old URIs stay equal.
func NormalizeEndpointHost(host string) (string, error) {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		inside := host[1 : len(host)-1]
		if ip := net.ParseIP(inside); ip != nil && strings.Contains(inside, ":") {
			return inside, nil
		}
		return "", errors.New("方括号仅用于 IPv6 字面地址，端口请单独填写")
	}
	if !ValidHost(host) {
		return "", errors.New("连接地址须为 IP 或域名；不含协议、端口、IPv6 zone 或空白")
	}
	return host, nil
}

func endpointAddressKey(host string, port int) string {
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func ValidateEndpoints(n Node) error {
	if len(n.AdditionalEndpoints) > MaxAdditionalEndpoints {
		return errors.New("额外连接端点最多 16 条")
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	for _, endpoint := range EffectiveEndpoints(n) {
		if !endpointIDRE.MatchString(endpoint.ID) || ids[endpoint.ID] {
			return errors.New("连接端点 ID 须为 1–32 位字母、数字、下划线或连字符，首位为字母/数字且不可重复；default 为保留主入口")
		}
		ids[endpoint.ID] = true
		if !ValidHost(endpoint.Host) || endpoint.Port < 1 || endpoint.Port > 65535 {
			return fmt.Errorf("连接端点 %s 的地址或端口无效", endpoint.ID)
		}
		key := endpointAddressKey(endpoint.Host, endpoint.Port)
		if addresses[key] {
			return errors.New("连接端点地址与端口重复")
		}
		addresses[key] = true
	}
	return nil
}
