package node

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
)

// Pair generation creates private handoff material, never a host interface,
// route, service or remote transaction. The two hosts must apply separately.
type WireGuardPairOptions struct {
	ID, EntryTunnel, LandingTunnel, LandingHost string
	ConnectPort, ListenPort                     int
	AllowedIPs                                  []string
	MTU, Keepalive                              int
}

type WireGuardPair struct {
	Version int    `json:"version"`
	Entry   Egress `json:"entry"`
	Landing Egress `json:"landing"`
}

var wireGuardPairID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$`)

func NewWireGuardPair(o WireGuardPairOptions) (WireGuardPair, error) {
	if !wireGuardPairID.MatchString(o.ID) {
		return WireGuardPair{}, errors.New("配对ID须为1–24位字母、数字、下划线或连字符，首位字母或数字")
	}
	a, ea := netip.ParsePrefix(o.EntryTunnel)
	b, eb := netip.ParsePrefix(o.LandingTunnel)
	if ea != nil || eb != nil || a.Bits() != a.Addr().BitLen() || b.Bits() != b.Addr().BitLen() || a.Addr().Is4() != b.Addr().Is4() || a.Addr() == b.Addr() || a.Addr().IsUnspecified() || b.Addr().IsUnspecified() || a.Addr().IsMulticast() || b.Addr().IsMulticast() || a.Addr().IsLoopback() || b.Addr().IsLoopback() {
		return WireGuardPair{}, errors.New("两端须使用不同的同族隧道主机地址：IPv4 /32或IPv6 /128；不能是回环、组播或未指定地址")
	}
	host, err := NormalizeEndpointHost(o.LandingHost)
	if err != nil || o.ConnectPort < 1 || o.ConnectPort > 65535 || o.ListenPort < 1 || o.ListenPort > 65535 {
		return WireGuardPair{}, errors.New("需明确落地连接地址、外部UDP端口及落地本地UDP监听端口")
	}
	if len(o.AllowedIPs) == 0 || len(o.AllowedIPs) > 64 {
		return WireGuardPair{}, errors.New("须明确提供1–64个经隧道到达的目标CIDR；只影响本项目流量，不修改宿主默认路由")
	}
	allowed := make([]string, 0, len(o.AllowedIPs))
	seen := map[string]bool{}
	for _, text := range o.AllowedIPs {
		p, e := netip.ParsePrefix(text)
		if e != nil || p.Addr().Zone() != "" || p.Addr().IsMulticast() || p.Addr().Is4() != a.Addr().Is4() {
			return WireGuardPair{}, errors.New("AllowedIPs必须是有效目标CIDR并与本次隧道地址同族；双族请分别声明完整地址与Peer")
		}
		text = p.Masked().String()
		if seen[text] {
			return WireGuardPair{}, errors.New("AllowedIPs不能重复")
		}
		seen[text] = true
		allowed = append(allowed, text)
	}
	if o.MTU != 0 && (o.MTU < 1280 || o.MTU > 1500) || o.Keepalive < 0 || o.Keepalive > 120 {
		return WireGuardPair{}, errors.New("MTU保留默认填0或1280–1500；keepalive为0–120秒，0保持关闭")
	}
	ka, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WireGuardPair{}, err
	}
	kb, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WireGuardPair{}, err
	}
	psk := make([]byte, 32)
	if _, err = rand.Read(psk); err != nil {
		return WireGuardPair{}, err
	}
	enc := base64.StdEncoding.EncodeToString
	aprivate, bprivate := ka.Bytes(), kb.Bytes()
	for _, key := range [][]byte{aprivate, bprivate} {
		key[0] &= 248
		key[31] = (key[31] & 127) | 64
	}
	entry := Egress{ID: Token(8), Name: o.ID + " 入口隧道", Protocol: "wireguard", UDP: true,
		WireGuard: &WireGuardEndpoint{Address: []string{a.String()}, PrivateKey: enc(aprivate), MTU: o.MTU,
			Peers: []WireGuardPeer{{Address: host, Port: o.ConnectPort, PublicKey: enc(kb.PublicKey().Bytes()), PreSharedKey: enc(psk), AllowedIPs: allowed, Keepalive: o.Keepalive}}}}
	landing := Egress{ID: Token(8), Name: o.ID + " 落地隧道", Protocol: "wireguard", UDP: true,
		WireGuard: &WireGuardEndpoint{Address: []string{b.String()}, PrivateKey: enc(bprivate), ListenPort: o.ListenPort, MTU: o.MTU, ReceiveEgressID: "direct",
			Peers: []WireGuardPeer{{PublicKey: enc(ka.PublicKey().Bytes()), PreSharedKey: enc(psk), AllowedIPs: []string{a.String()}}}}}
	return WireGuardPair{Version: 1, Entry: entry, Landing: landing}, nil
}
