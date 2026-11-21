package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"qingnode/internal/node"
)

// Topology requests are a separate, bounded management format. These typed
// objects are never merged into arbitrary sing-box JSON.
type topologyBatch struct {
	Version    int                 `json:"version"`
	Operations []topologyOperation `json:"operations"`
}

type topologyOperation struct {
	Action   string             `json:"action"`
	ID       string             `json:"id,omitempty"`
	NodeID   string             `json:"node_id,omitempty"`
	EgressID *string            `json:"egress_id,omitempty"`
	Egress   *node.Egress       `json:"egress,omitempty"`
	Policy   *node.EgressPolicy `json:"policy,omitempty"`
	Forward  *node.PortForward  `json:"forward,omitempty"`
}

func rejectTopologyFlags(f *flag.FlagSet, allowed ...string) error {
	ok := map[string]bool{}
	for _, name := range allowed {
		ok[name] = true
	}
	var err error
	f.Visit(func(v *flag.Flag) {
		if !ok[v.Name] && err == nil {
			err = fmt.Errorf("此操作不接受 --%s", v.Name)
		}
	})
	return err
}

func directEgress(id string) string {
	if id == "direct" {
		return ""
	}
	return id
}

func displayEgress(id string) string {
	if id == "" {
		return "direct"
	}
	return id
}

func egressIndex(s node.State, id string) (int, error) {
	for i, v := range s.Egresses {
		if v.ID == id {
			return i, nil
		}
	}
	for i, v := range s.Egresses {
		if v.Name == id {
			return i, nil
		}
	}
	return -1, errors.New("出口不存在；请用 egress list 查看稳定ID")
}

func policyIndex(s node.State, id string) (int, error) {
	for i, v := range s.EgressPolicies {
		if v.ID == id {
			return i, nil
		}
	}
	for i, v := range s.EgressPolicies {
		if v.Name == id {
			return i, nil
		}
	}
	return -1, errors.New("出口策略不存在")
}

func forwardIndex(s node.State, id string) (int, error) {
	for i, v := range s.Forwards {
		if v.ID == id {
			return i, nil
		}
	}
	for i, v := range s.Forwards {
		if v.Name == id {
			return i, nil
		}
	}
	return -1, errors.New("端口中转不存在")
}

func (a *app) changeTopology(preview bool, change func(*node.State) error) error {
	if !preview {
		return a.mutate(func(s *node.State) error {
			before := s.Clone()
			if err := change(s); err != nil {
				return err
			}
			if err := s.Validate(); err != nil {
				return err
			}
			impact, err := a.store.Preview(*s)
			if err != nil {
				return err
			}
			printChangeImpact(topologySafeImpact(impact, before, *s))
			if a.menuPreview {
				a.menuPreviewDone = true
			}
			return nil
		})
	}
	return a.store.InspectExisting(func() error {
		if err := rejectPending(a.store.Root); err != nil {
			return err
		}
		s, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = s.Validate(); err != nil {
			return err
		}
		before := s.Clone()
		if err = change(&s); err != nil {
			return err
		}
		if err = s.Validate(); err != nil {
			return err
		}
		impact, err := a.store.Preview(s)
		if err != nil {
			return err
		}
		printChangeImpact(topologySafeImpact(impact, before, s))
		fmt.Println("只读拓扑预览：未保存、未恢复事务、未启动服务；共享核心发生运行配置变更时会影响已有连接。")
		return nil
	})
}

func topologySafeImpact(impact node.ChangeImpact, states ...node.State) node.ChangeImpact {
	impact.Nodes = append([]node.NodeImpact{}, impact.Nodes...)
	impact.Forwards = append([]node.ForwardImpact{}, impact.Forwards...)
	impact.Devices = append([]node.DeviceImpact{}, impact.Devices...)
	for i := range impact.Nodes {
		impact.Nodes[i].Name = node.Redact(impact.Nodes[i].Name, states...)
	}
	for i := range impact.Forwards {
		impact.Forwards[i].Name = node.Redact(impact.Forwards[i].Name, states...)
	}
	for i := range impact.Devices {
		impact.Devices[i].Name = node.Redact(impact.Devices[i].Name, states...)
	}
	return impact
}

func (a *app) egress(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：egress list|show|add|edit|remove|probe|health；出口凭据独立于入口用户")
	}
	action := args[0]
	if action == "probe" || action == "health" {
		return a.egressHealth(args[1:])
	}
	if action == "policy" {
		return a.egressPolicy(args[1:])
	}
	f := fs("egress " + action)
	machine := f.Bool("json", false, "仅list/show：版本1出口声明，不含远程凭据或连通性承诺")
	id := f.String("id", "", "出口稳定ID或已有名称；add省略则生成ID")
	name := f.String("name", "", "出口名称")
	protocol := f.String("protocol", "", "socks5 / http / reality / ss2022 / ss-aead / hysteria2 / trojan / vless-tls / vmess-tls / anytls / tuic；WireGuard用配对或严格批量导入")
	server := f.String("server", "", "远程出口连接IP或域名")
	port := namedPortFlag(f, "port", 0, "远程出口端口（十进制1–65535）")
	via := f.String("via", "", "通过另一真实出口连接；direct明确清除上游")
	udp := f.Bool("udp", false, "明确声明远程出口支持UDP；socks5与http默认false，其他协议默认true")
	username := f.String("username", "", "远程SOCKS5/HTTP代理用户名")
	password := f.String("password", "", "远程出口密码或SS2022组合密钥；会保存于私有State")
	clearAuth := f.Bool("clear-auth", false, "显式清除SOCKS5/HTTP代理认证；不适用于其他协议")
	tlsEnabled := f.Bool("tls", false, "远程HTTP代理开启HTTPS(TLS)连接")
	uuid := f.String("uuid", "", "远程REALITY/VLESS/VMess/TUIC用户UUID")
	security := f.String("security", "", "远程VMess+TLS加密方式：auto（默认）/ aes-128-gcm / chacha20-poly1305")
	packetEncoding := f.String("packet-encoding", "", "远程VLESS/VMess UDP包编码：xudp / packetaddr（clear清除）")
	sni := f.String("sni", "", "远程TLS名称，独立于连接地址")
	publicKey := f.String("public-key", "", "远程REALITY公钥")
	shortID := f.String("short-id", "", "远程REALITY short ID")
	fingerprint := f.String("fingerprint", "", "远程REALITY指纹；新出口默认chrome")
	method := f.String("method", "", "远程SS2022或传统ss-aead加密方法")
	ca := f.String("ca", "", "远程TLS/HY2的PEM信任证书文件；clear清除已固定证书")
	obfsPassword := f.String("obfs-password", "", "远程HY2 salamander混淆密码（clear清除）")
	hopPorts := f.String("hop-ports", "", "远程HY2端口跳跃区间（如20000-30000，clear清除）")
	hopInterval := f.String("hop-interval", "", "远程HY2端口跳跃间隔（如30s，clear清除）")
	congestion := f.String("congestion-control", "", "远程TUIC拥塞控制：bbr / cubic / new_reno（clear恢复默认）")
	udpRelayMode := f.String("udp-relay-mode", "", "远程TUIC UDP模式：native / quic（clear恢复默认）")
	heartbeat := f.String("heartbeat", "", "远程TUIC心跳间隔（如10s，clear恢复默认）")
	idleCheck := f.String("idle-session-check-interval", "", "远程AnyTLS空闲检查间隔（如30s，clear恢复默认）")
	idleTimeout := f.String("idle-session-timeout", "", "远程AnyTLS空闲超时（如30s，clear恢复默认）")
	minIdle := f.Int("min-idle-session", 0, "远程AnyTLS最小保活空闲会话数（0–64）")
	transport := f.String("transport", "", "远程出口传输层：tcp / ws / grpc / httpupgrade / http(h2)")
	transportPath := f.String("path", "", "远程WebSocket/HTTPUpgrade/HTTP2路径")
	transportHost := f.String("transport-host", "", "远程WebSocket/HTTPUpgrade/HTTP2 Host头")
	serviceName := f.String("service-name", "", "远程gRPC serviceName")
	wsMaxEarlyData := f.Int("ws-max-early-data", 0, "远程WebSocket Early Data最大字节数（0关闭）")
	wsEarlyDataHeader := f.String("ws-early-data-header", "", "远程WebSocket Early Data头名称（default恢复默认）")
	multiplex := f.String("multiplex", "", "远程TCP出口多路复用：h2mux / smux / yamux / off")
	muxMaxConnections := f.Int("mux-max-connections", 0, "远程多路复用最大连接数（0–64）")
	muxMinStreams := f.Int("mux-min-streams", 0, "远程多路复用单连接最小流数（0–256）")
	muxPadding := f.Bool("mux-padding", false, "远程多路复用填充（padding）")
	preview := f.Bool("preview", false, "只读预览；不验证远程应用层连接")
	yes := f.Bool("yes", false, "确认删除未被引用的出口")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if flagSet(f, "json") && action != "list" && action != "show" {
		return errors.New("--json仅用于出口list/show；修改请使用明确预览与事务入口")
	}
	if action == "list" || action == "show" {
		if err := rejectTopologyFlags(f, "id", "json"); err != nil {
			return err
		}
		if action == "show" && *id == "" {
			return errors.New("show需要 --id")
		}
		return a.inspectState(func(s *node.State) error {
			if err := s.Validate(); err != nil {
				return err
			}
			items := s.Egresses
			if *id != "" {
				i, err := egressIndex(*s, *id)
				if err != nil {
					return err
				}
				items = []node.Egress{items[i]}
			}
			if *machine {
				rows := []publicEgress{}
				for _, e := range items {
					rows = append(rows, publicEgress{e.ID, publicQueryText(e.Name, *s), e.Protocol, net.JoinHostPort(e.Server, strconv.Itoa(e.Port)), e.UDP, displayEgress(e.Detour), "not-tested"})
				}
				return queryJSON("qingnode-egress-declarations", rows)
			}
			for _, e := range items {
				fmt.Print(node.Redact(fmt.Sprintf("%s (%s)  %s  %s  UDP声明:%t  上游:%s；远程凭据已隐藏，链路未由查询验证。\n", e.Name, e.ID, e.Protocol, net.JoinHostPort(e.Server, strconv.Itoa(e.Port)), e.UDP, displayEgress(e.Detour)), *s))
			}
			if len(items) == 0 {
				fmt.Println("未配置远程出口；旧节点默认direct。")
			}
			return nil
		})
	}
	if action != "add" && action != "edit" && action != "remove" {
		return errors.New("未知出口操作")
	}
	if action != "add" && *id == "" {
		return errors.New("需要 --id")
	}
	if flagSet(f, "via") && *via == "" {
		return errors.New("--via不能为空；清除上游请显式填写direct")
	}
	if action == "remove" {
		if err := rejectTopologyFlags(f, "id", "preview", "yes"); err != nil {
			return err
		}
		if !*preview && !*yes {
			return errors.New("删除出口需要 --yes；有引用时须先显式迁移，或使用topology批量事务")
		}
	} else if *yes {
		return errors.New("--yes只用于remove")
	}
	if flagSet(f, "server") {
		h, err := node.NormalizeEndpointHost(*server)
		if err != nil {
			return err
		}
		*server = h
	}
	var certPEM string
	if flagSet(f, "ca") && strings.ToLower(strings.TrimSpace(*ca)) != "clear" {
		b, err := readLimited(*ca, 1<<20)
		if err != nil {
			return errors.New("无法读取远程HY2 CA文件")
		}
		certPEM = string(b)
	}
	return a.changeTopology(*preview, func(s *node.State) error {
		candidate := s.Clone()
		i := -1
		if action != "add" {
			var err error
			i, err = egressIndex(candidate, *id)
			if err != nil {
				return err
			}
		}
		if action == "remove" {
			candidate.Egresses = append(candidate.Egresses[:i], candidate.Egresses[i+1:]...)
		} else {
			var e node.Egress
			impliedTransport := ""
			if action == "add" {
				if *protocol == "" || *server == "" || !flagSet(f, "port") {
					return errors.New("add需要 --protocol、--server、--port及该协议的远程凭据")
				}
				resolvedProto, impTr := resolveEgressProtocolAlias(*protocol)
				impliedTransport = impTr
				e = node.Egress{ID: *id, Name: *name, Protocol: resolvedProto, Server: *server, Port: *port, UDP: resolvedProto != "socks5" && resolvedProto != "http"}
				if e.ID == "" {
					e.ID = node.Token(8)
				}
				if e.Name == "" {
					e.Name = e.ID
				}
				for _, saved := range candidate.Egresses {
					if saved.ID == e.ID {
						return errors.New("出口ID已存在；修改请使用edit")
					}
				}
			} else {
				e = candidate.Egresses[i]
				if flagSet(f, "protocol") {
					return errors.New("edit不更换协议；请新增出口后显式迁移引用")
				}
				if f.NFlag() <= 1 || (f.NFlag() == 2 && *preview) {
					return errors.New("edit需要至少一个修改字段")
				}
			}
			allowed := []string{"id", "name", "protocol", "server", "port", "via", "udp", "preview"}
			transportFlags := []string{"transport", "path", "transport-host", "service-name", "ws-max-early-data", "ws-early-data-header"}
			muxFlags := []string{"multiplex", "mux-max-connections", "mux-min-streams", "mux-padding"}
			switch e.Protocol {
			case "socks5":
				allowed = append(allowed, "username", "password", "clear-auth")
				if e.Socks == nil {
					e.Socks = &node.RemoteSOCKS{}
				}
				if *clearAuth {
					if flagSet(f, "username") || flagSet(f, "password") {
						return errors.New("--clear-auth不能与新认证参数同用")
					}
					e.Socks.Username, e.Socks.Password = "", ""
				}
				if flagSet(f, "username") {
					e.Socks.Username = *username
				}
				if flagSet(f, "password") {
					e.Socks.Password = *password
				}
			case "http":
				allowed = append(allowed, "username", "password", "clear-auth", "tls", "sni", "ca")
				if e.HTTP == nil {
					e.HTTP = &node.RemoteHTTP{}
				}
				if *clearAuth {
					if flagSet(f, "username") || flagSet(f, "password") {
						return errors.New("--clear-auth不能与新认证参数同用")
					}
					e.HTTP.Username, e.HTTP.Password = "", ""
				}
				if flagSet(f, "username") {
					e.HTTP.Username = *username
				}
				if flagSet(f, "password") {
					e.HTTP.Password = *password
				}
				if flagSet(f, "tls") {
					e.HTTP.TLS = *tlsEnabled
					if !*tlsEnabled && !flagSet(f, "sni") && !flagSet(f, "ca") {
						e.HTTP.ServerName = ""
						e.HTTP.CertificatePEM = ""
					}
				}
				if flagSet(f, "sni") {
					e.HTTP.ServerName = *sni
				}
				if flagSet(f, "ca") {
					e.HTTP.CertificatePEM = certPEM
				}
			case "reality":
				allowed = append(allowed, "uuid", "sni", "public-key", "short-id", "fingerprint", "transport", "service-name")
				if e.Reality == nil {
					e.Reality = &node.RemoteReality{Fingerprint: "chrome"}
				}
				for k, p := range map[string]*string{"uuid": &e.Reality.UUID, "sni": &e.Reality.ServerName, "public-key": &e.Reality.PublicKey, "short-id": &e.Reality.ShortID, "fingerprint": &e.Reality.Fingerprint} {
					if flagSet(f, k) {
						*p = map[string]string{"uuid": *uuid, "sni": *sni, "public-key": *publicKey, "short-id": *shortID, "fingerprint": *fingerprint}[k]
					}
				}
			case "ss2022":
				allowed = append(allowed, "method", "password")
				allowed = append(allowed, muxFlags...)
				if e.Shadowsocks == nil {
					e.Shadowsocks = &node.RemoteSS{Method: node.SS2022Method}
				}
				if flagSet(f, "method") {
					e.Shadowsocks.Method = *method
				}
				if flagSet(f, "password") {
					e.Shadowsocks.Password = *password
				}
			case "ss-aead":
				allowed = append(allowed, "method", "password")
				allowed = append(allowed, muxFlags...)
				if e.Shadowsocks == nil {
					e.Shadowsocks = &node.RemoteSS{Method: node.DefaultSSAEADMethod}
				}
				if flagSet(f, "method") {
					e.Shadowsocks.Method = *method
				}
				if flagSet(f, "password") {
					e.Shadowsocks.Password = *password
				}
			case "hysteria2":
				allowed = append(allowed, "sni", "password", "ca", "obfs-password", "hop-ports", "hop-interval")
				if e.HY2 == nil {
					e.HY2 = &node.RemoteHY2{}
				}
				if flagSet(f, "sni") {
					e.HY2.ServerName = *sni
				}
				if flagSet(f, "password") {
					e.HY2.Password = *password
				}
				if flagSet(f, "ca") {
					e.HY2.CertificatePEM = certPEM
				}
				if flagSet(f, "obfs-password") || flagSet(f, "hop-ports") || flagSet(f, "hop-interval") {
					var perf node.HY2Performance
					if e.HY2.Performance != nil {
						perf = *e.HY2.Performance
					}
					if flagSet(f, "obfs-password") {
						if strings.EqualFold(strings.TrimSpace(*obfsPassword), "clear") {
							perf.Obfs = nil
						} else {
							perf.Obfs = &node.HY2Obfs{Type: "salamander", Password: *obfsPassword}
						}
					}
					if flagSet(f, "hop-ports") {
						hp := strings.TrimSpace(*hopPorts)
						if strings.EqualFold(hp, "clear") {
							perf.HopPorts = ""
						} else {
							perf.HopPorts = hp
						}
					}
					if flagSet(f, "hop-interval") {
						hi := strings.TrimSpace(*hopInterval)
						if strings.EqualFold(hi, "clear") {
							perf.HopInterval = ""
						} else {
							perf.HopInterval = hi
						}
					}
					if b, _ := json.Marshal(perf); string(b) == "{}" {
						e.HY2.Performance = nil
					} else {
						e.HY2.Performance = &perf
					}
				}
			case "trojan":
				allowed = append(allowed, "sni", "password", "ca")
				allowed = append(allowed, transportFlags...)
				allowed = append(allowed, muxFlags...)
				if e.Trojan == nil {
					e.Trojan = &node.RemoteTrojan{}
				}
				if flagSet(f, "sni") {
					e.Trojan.ServerName = *sni
				}
				if flagSet(f, "password") {
					e.Trojan.Password = *password
				}
				if flagSet(f, "ca") {
					e.Trojan.CertificatePEM = certPEM
				}
			case "vless-tls":
				allowed = append(allowed, "uuid", "sni", "ca", "packet-encoding")
				allowed = append(allowed, transportFlags...)
				allowed = append(allowed, muxFlags...)
				if e.VLESS == nil {
					e.VLESS = &node.RemoteVLESS{}
				}
				if flagSet(f, "uuid") {
					e.VLESS.UUID = *uuid
				}
				if flagSet(f, "sni") {
					e.VLESS.ServerName = *sni
				}
				if flagSet(f, "ca") {
					e.VLESS.CertificatePEM = certPEM
				}
				if flagSet(f, "packet-encoding") {
					pe := strings.TrimSpace(*packetEncoding)
					if strings.EqualFold(pe, "clear") {
						e.VLESS.PacketEncoding = ""
					} else {
						e.VLESS.PacketEncoding = pe
					}
				}
			case "vmess-tls":
				allowed = append(allowed, "uuid", "security", "sni", "ca", "packet-encoding")
				allowed = append(allowed, transportFlags...)
				allowed = append(allowed, muxFlags...)
				if e.VMess == nil {
					e.VMess = &node.RemoteVMess{Security: "auto"}
				}
				if flagSet(f, "uuid") {
					e.VMess.UUID = *uuid
				}
				if flagSet(f, "security") {
					e.VMess.Security = strings.TrimSpace(*security)
				}
				if flagSet(f, "sni") {
					e.VMess.ServerName = *sni
				}
				if flagSet(f, "ca") {
					e.VMess.CertificatePEM = certPEM
				}
				if flagSet(f, "packet-encoding") {
					pe := strings.TrimSpace(*packetEncoding)
					if strings.EqualFold(pe, "clear") {
						e.VMess.PacketEncoding = ""
					} else {
						e.VMess.PacketEncoding = pe
					}
				}
			case "anytls":
				allowed = append(allowed, "sni", "password", "ca", "idle-session-check-interval", "idle-session-timeout", "min-idle-session")
				if e.AnyTLS == nil {
					e.AnyTLS = &node.RemoteAnyTLS{}
				}
				if flagSet(f, "sni") {
					e.AnyTLS.ServerName = *sni
				}
				if flagSet(f, "password") {
					e.AnyTLS.Password = *password
				}
				if flagSet(f, "ca") {
					e.AnyTLS.CertificatePEM = certPEM
				}
				if flagSet(f, "idle-session-check-interval") {
					v := strings.TrimSpace(*idleCheck)
					if strings.EqualFold(v, "clear") {
						e.AnyTLS.IdleSessionCheckInterval = ""
					} else {
						e.AnyTLS.IdleSessionCheckInterval = v
					}
				}
				if flagSet(f, "idle-session-timeout") {
					v := strings.TrimSpace(*idleTimeout)
					if strings.EqualFold(v, "clear") {
						e.AnyTLS.IdleSessionTimeout = ""
					} else {
						e.AnyTLS.IdleSessionTimeout = v
					}
				}
				if flagSet(f, "min-idle-session") {
					v := *minIdle
					e.AnyTLS.MinIdleSession = &v
				}
			case "tuic":
				allowed = append(allowed, "uuid", "password", "sni", "ca", "congestion-control", "udp-relay-mode", "heartbeat")
				if e.TUIC == nil {
					e.TUIC = &node.RemoteTUIC{}
				}
				if flagSet(f, "uuid") {
					e.TUIC.UUID = *uuid
				}
				if flagSet(f, "password") {
					e.TUIC.Password = *password
				}
				if flagSet(f, "sni") {
					e.TUIC.ServerName = *sni
				}
				if flagSet(f, "ca") {
					e.TUIC.CertificatePEM = certPEM
				}
				if flagSet(f, "congestion-control") {
					v := strings.TrimSpace(*congestion)
					if strings.EqualFold(v, "clear") {
						e.TUIC.CongestionControl = ""
					} else {
						e.TUIC.CongestionControl = v
					}
				}
				if flagSet(f, "udp-relay-mode") {
					v := strings.TrimSpace(*udpRelayMode)
					if strings.EqualFold(v, "clear") {
						e.TUIC.UDPRelayMode = ""
					} else {
						e.TUIC.UDPRelayMode = v
					}
				}
				if flagSet(f, "heartbeat") {
					v := strings.TrimSpace(*heartbeat)
					if strings.EqualFold(v, "clear") {
						e.TUIC.Heartbeat = ""
					} else {
						e.TUIC.Heartbeat = v
					}
				}
			default:
				return errors.New("此协议请使用wireguard配对或topology严格批量导入")
			}
			if err := rejectTopologyFlags(f, allowed...); err != nil {
				return err
			}
			if err := applyEgressTransportCLI(&e, impliedTransport, flagSet(f, "transport"), *transport, flagSet(f, "path"), *transportPath, flagSet(f, "transport-host"), *transportHost, flagSet(f, "service-name"), *serviceName, flagSet(f, "ws-max-early-data"), *wsMaxEarlyData, flagSet(f, "ws-early-data-header"), *wsEarlyDataHeader); err != nil {
				return err
			}
			if err := applyEgressMultiplexCLI(&e, flagSet(f, "multiplex"), *multiplex, flagSet(f, "mux-max-connections"), *muxMaxConnections, flagSet(f, "mux-min-streams"), *muxMinStreams, flagSet(f, "mux-padding"), *muxPadding); err != nil {
				return err
			}
			if flagSet(f, "name") {
				e.Name = *name
			}
			if flagSet(f, "server") {
				e.Server = *server
			}
			if flagSet(f, "port") {
				e.Port = *port
			}
			if flagSet(f, "via") {
				e.Detour = directEgress(*via)
			}
			if flagSet(f, "udp") {
				e.UDP = *udp
			}
			if action == "add" {
				candidate.Egresses = append(candidate.Egresses, e)
			} else {
				candidate.Egresses[i] = e
			}
		}
		if err := candidate.Validate(); err != nil {
			return errors.New(node.Redact(err.Error(), candidate))
		}
		*s = candidate
		return nil
	})
}

func resolveEgressProtocolAlias(raw string) (string, string) {
	p := strings.ToLower(strings.TrimSpace(raw))
	switch p {
	case "socks5", "http", "ss2022", "ss-aead", "hysteria2", "anytls", "tuic", "wireguard":
		return p, ""
	case "https":
		return "http", ""
	case "reality-grpc":
		return "reality", "grpc"
	}
	normProto, normTr, err := node.NormalizeProtocolAndTransport(p, "", "", "", "")
	if err == nil && (normProto == "reality" || node.ProtocolSupportsTransport(normProto)) {
		if normTr != nil {
			return normProto, normTr.Type
		}
		return normProto, ""
	}
	return p, ""
}

func applyEgressTransportCLI(e *node.Egress, impliedTr string, trSet bool, trVal string, pathSet bool, pathVal string, hostSet bool, hostVal string, svcSet bool, svcVal string, wsMaxSet bool, wsMaxVal int, wsHdrSet bool, wsHdrVal string) error {
	if impliedTr == "" && !trSet && !pathSet && !hostSet && !svcSet && !wsMaxSet && !wsHdrSet {
		return nil
	}
	var tr node.TransportOptions
	if e.Transport != nil {
		tr = *e.Transport
	} else {
		tr.Type = "tcp"
	}
	nextType := tr.Type
	if impliedTr != "" {
		nextType = impliedTr
	}
	if trSet {
		rawTr := strings.ToLower(strings.TrimSpace(trVal))
		switch rawTr {
		case "none", "clear":
			rawTr = "tcp"
		case "websocket":
			rawTr = "ws"
		case "h2":
			rawTr = "http"
		}
		if impliedTr != "" && rawTr != impliedTr {
			return fmt.Errorf("协议缩写与 --transport %s 冲突", trVal)
		}
		nextType = rawTr
	}
	if nextType != tr.Type {
		tr.Type = nextType
		switch nextType {
		case "tcp":
			tr = node.TransportOptions{Type: "tcp"}
		case "ws":
			tr.ServiceName = ""
		case "httpupgrade", "http":
			tr.ServiceName = ""
			tr.MaxEarlyData = 0
			tr.EarlyDataHeaderName = ""
		case "grpc":
			tr.Path = ""
			tr.Host = ""
			tr.MaxEarlyData = 0
			tr.EarlyDataHeaderName = ""
		}
	}
	if pathSet {
		tr.Path = pathVal
	}
	if hostSet {
		tr.Host = hostVal
	}
	if svcSet {
		tr.ServiceName = svcVal
	}
	_, normTr, err := node.NormalizeProtocolAndTransport(e.Protocol, tr.Type, tr.Path, tr.Host, tr.ServiceName)
	if err != nil {
		return err
	}
	if normTr != nil && normTr.Type == "ws" {
		normTr.MaxEarlyData = tr.MaxEarlyData
		normTr.EarlyDataHeaderName = tr.EarlyDataHeaderName
	}
	normTr, err = applyWSEarlyDataFlags(normTr, wsMaxSet, wsMaxVal, wsHdrSet, wsHdrVal)
	if err != nil {
		return err
	}
	e.Transport = normTr
	return nil
}

func applyEgressMultiplexCLI(e *node.Egress, muxSet bool, muxProto string, maxConnSet bool, maxConn int, minStrSet bool, minStr int, padSet bool, pad bool) error {
	if !muxSet && !maxConnSet && !minStrSet && !padSet {
		return nil
	}
	var mux node.MultiplexOptions
	if e.Multiplex != nil {
		mux = *e.Multiplex
	}
	turningOff := false
	if muxSet {
		mp := strings.ToLower(strings.TrimSpace(muxProto))
		switch mp {
		case "off", "none", "false", "clear":
			turningOff = true
		case "on", "true":
			mux.Enabled = true
			if mux.Protocol == "" {
				mux.Protocol = "h2mux"
			}
		default:
			mux.Enabled = true
			mux.Protocol = mp
		}
	}
	if turningOff {
		if maxConnSet || minStrSet || (padSet && pad) {
			return errors.New("关闭多路复用时不能同时指定连接数、流数或 padding")
		}
		e.Multiplex = nil
		return nil
	}
	if !mux.Enabled {
		mux.Enabled = true
		if mux.Protocol == "" {
			mux.Protocol = "h2mux"
		}
	}
	if maxConnSet {
		mux.MaxConnections = maxConn
	}
	if minStrSet {
		mux.MinStreams = minStr
	}
	if padSet {
		mux.Padding = pad
	}
	if err := node.ValidateMultiplexOptions(&mux); err != nil {
		return err
	}
	e.Multiplex = &mux
	return nil
}

func (a *app) route(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("用法：route set --id 入口节点 --egress direct或出口/策略ID [--preview]")
	}
	f := fs("route set")
	id := f.String("id", "", "已有入口节点ID或名称")
	egress := f.String("egress", "", "direct或出口/策略稳定ID；失败不会回落direct")
	preview := f.Bool("preview", false, "只读预览")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *id == "" || *egress == "" {
		return errors.New("需要 --id 和 --egress；直连须显式填写direct")
	}
	return a.changeTopology(*preview, func(s *node.State) error {
		n, err := s.Find(*id)
		if err != nil {
			return err
		}
		n.EgressID = directEgress(*egress)
		return nil
	})
}

func (a *app) forward(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：forward list|add|edit|remove；纯TCP/UDP端口中转不生成代理用户")
	}
	action := args[0]
	f := fs("forward " + action)
	machine := f.Bool("json", false, "仅list：版本1固定转发声明，不发起链路测试")
	id := f.String("id", "", "中转稳定ID或已有名称；add省略生成ID")
	name := f.String("name", "", "中转名称")
	listen := f.String("listen", "", "本地监听IP；新增默认127.0.0.1")
	port := portFlag(f, 0)
	network := f.String("network", "", "tcp / udp / tcp+udp，须明确选择")
	targetHost := f.String("target-host", "", "固定转发目标IP或域名，不是分享入口")
	targetPort := namedPortFlag(f, "target-port", 0, "固定转发目标端口（十进制1–65535）")
	egress := f.String("egress", "", "direct或出口/策略ID；新增默认direct")
	enabled := f.Bool("enabled", true, "是否启用此中转")
	preview := f.Bool("preview", false, "只读预览，不建立监听")
	yes := f.Bool("yes", false, "确认删除")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if flagSet(f, "json") && action != "list" {
		return errors.New("--json仅用于中转list")
	}
	if action == "list" {
		if err := rejectTopologyFlags(f, "id", "json"); err != nil {
			return err
		}
		return a.inspectState(func(s *node.State) error {
			if err := s.Validate(); err != nil {
				return err
			}
			items := s.Forwards
			if *id != "" {
				i, err := forwardIndex(*s, *id)
				if err != nil {
					return err
				}
				items = []node.PortForward{items[i]}
			}
			if *machine {
				rows := []publicForward{}
				for _, v := range items {
					rows = append(rows, publicForward{v.ID, publicQueryText(v.Name, *s), v.Network, net.JoinHostPort(v.Listen, strconv.Itoa(v.Port)), net.JoinHostPort(v.TargetHost, strconv.Itoa(v.TargetPort)), displayEgress(v.EgressID), v.Enabled, "not-tested"})
				}
				return queryJSON("qingnode-forward-declarations", rows)
			}
			for _, v := range items {
				fmt.Print(node.Redact(fmt.Sprintf("%s (%s)  %s  %s -> %s  出口:%s  启用:%t；实际链路未由查询验证。\n", v.Name, v.ID, v.Network, net.JoinHostPort(v.Listen, strconv.Itoa(v.Port)), net.JoinHostPort(v.TargetHost, strconv.Itoa(v.TargetPort)), displayEgress(v.EgressID), v.Enabled), *s))
			}
			return nil
		})
	}
	if action != "add" && action != "edit" && action != "remove" {
		return errors.New("未知中转操作")
	}
	if action != "add" && *id == "" {
		return errors.New("需要 --id")
	}
	if flagSet(f, "egress") && *egress == "" {
		return errors.New("--egress不能为空；直连请显式填写direct")
	}
	if action == "remove" {
		if err := rejectTopologyFlags(f, "id", "preview", "yes"); err != nil {
			return err
		}
		if !*preview && !*yes {
			return errors.New("删除中转需要 --yes")
		}
	} else if *yes {
		return errors.New("--yes只用于remove")
	}
	if flagSet(f, "target-host") {
		h, err := node.NormalizeEndpointHost(*targetHost)
		if err != nil {
			return err
		}
		*targetHost = h
	}
	return a.changeTopology(*preview, func(s *node.State) error {
		candidate := s.Clone()
		i := -1
		if action != "add" {
			var err error
			i, err = forwardIndex(candidate, *id)
			if err != nil {
				return err
			}
		}
		if action == "remove" {
			candidate.Forwards = append(candidate.Forwards[:i], candidate.Forwards[i+1:]...)
		} else {
			var v node.PortForward
			if action == "add" {
				if !flagSet(f, "port") || *network == "" || *targetHost == "" || !flagSet(f, "target-port") {
					return errors.New("add需要 --port、--network、--target-host和--target-port")
				}
				v = node.PortForward{ID: *id, Name: *name, Listen: "127.0.0.1", Port: *port, Network: *network, TargetHost: *targetHost, TargetPort: *targetPort, Enabled: *enabled}
				if v.ID == "" {
					v.ID = node.Token(8)
				}
				if v.Name == "" {
					v.Name = v.ID
				}
				for _, saved := range candidate.Forwards {
					if saved.ID == v.ID {
						return errors.New("中转ID已存在；修改请使用edit")
					}
				}
			} else {
				v = candidate.Forwards[i]
				if f.NFlag() <= 1 || (f.NFlag() == 2 && *preview) {
					return errors.New("edit需要至少一个修改字段")
				}
			}
			if flagSet(f, "name") {
				v.Name = *name
			}
			if flagSet(f, "listen") {
				v.Listen = *listen
			}
			if flagSet(f, "port") {
				v.Port = *port
			}
			if flagSet(f, "network") {
				v.Network = *network
			}
			if flagSet(f, "target-host") {
				v.TargetHost = *targetHost
			}
			if flagSet(f, "target-port") {
				v.TargetPort = *targetPort
			}
			if flagSet(f, "egress") {
				v.EgressID = directEgress(*egress)
			}
			if flagSet(f, "enabled") {
				v.Enabled = *enabled
			}
			if action == "add" {
				candidate.Forwards = append(candidate.Forwards, v)
			} else {
				candidate.Forwards[i] = v
			}
		}
		if err := candidate.Validate(); err != nil {
			return errors.New(node.Redact(err.Error(), candidate))
		}
		*s = candidate
		return nil
	})
}

func (a *app) egressPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：egress policy list|add|edit|remove；主备健康观测用egress health")
	}
	action := args[0]
	f := fs("egress policy " + action)
	machine := f.Bool("json", false, "仅list：版本1出口选择声明，不发起探测或切换")
	id := f.String("id", "", "策略稳定ID或已有名称")
	name := f.String("name", "", "策略名称")
	mode := f.String("mode", "", "fixed / failover")
	primary := f.String("primary", "", "主出口ID")
	backup := f.String("backup", "", "备出口ID；fixed不接受")
	target := f.String("target", "", "经该出口实际请求的HTTPS健康目标")
	udpTarget := f.String("udp-target", "", "可选受控UDP响应端点 host:port")
	failure := f.Int("failure-threshold", 0, "连续失败切换阈值")
	recovery := f.Int("recovery-threshold", 0, "主出口连续恢复阈值")
	cooldown := f.Int("cooldown-seconds", 0, "切换冷却秒数")
	timeout := f.Int("timeout-seconds", 0, "每次健康请求独立超时秒数")
	preview := f.Bool("preview", false, "只读预览；不主动测速或切换")
	yes := f.Bool("yes", false, "确认删除未被引用的策略")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if flagSet(f, "json") && action != "list" {
		return errors.New("--json仅用于策略list")
	}
	if action == "list" {
		if err := rejectTopologyFlags(f, "id", "json"); err != nil {
			return err
		}
		return a.inspectState(func(s *node.State) error {
			if err := s.Validate(); err != nil {
				return err
			}
			items := s.EgressPolicies
			if *id != "" {
				i, err := policyIndex(*s, *id)
				if err != nil {
					return err
				}
				items = []node.EgressPolicy{items[i]}
			}
			if *machine {
				rows := []publicEgressPolicy{}
				for _, p := range items {
					selected := p.Selected
					if selected == "" {
						selected = "primary"
					}
					rows = append(rows, publicEgressPolicy{p.ID, publicQueryText(p.Name, *s), p.Mode, p.Primary, p.Backup, selected, "not-tested"})
				}
				return queryJSON("qingnode-egress-policy-declarations", rows)
			}
			for _, p := range items {
				selected := p.Selected
				if selected == "" {
					selected = "primary"
				}
				fmt.Print(node.Redact(fmt.Sprintf("%s (%s)  %s  主:%s  备:%s  当前:%s；查询不发起探测、不改变选择。\n", p.Name, p.ID, p.Mode, p.Primary, p.Backup, selected), *s))
			}
			return nil
		})
	}
	if action != "add" && action != "edit" && action != "remove" {
		return errors.New("未知策略操作")
	}
	if action != "add" && *id == "" {
		return errors.New("需要 --id")
	}
	if action == "remove" {
		if err := rejectTopologyFlags(f, "id", "preview", "yes"); err != nil {
			return err
		}
		if !*preview && !*yes {
			return errors.New("删除策略需要 --yes；被引用策略不能单独删除")
		}
	} else if *yes {
		return errors.New("--yes只用于remove")
	}
	return a.changeTopology(*preview, func(s *node.State) error {
		candidate := s.Clone()
		i := -1
		if action != "add" {
			var err error
			i, err = policyIndex(candidate, *id)
			if err != nil {
				return err
			}
		}
		if action == "remove" {
			candidate.EgressPolicies = append(candidate.EgressPolicies[:i], candidate.EgressPolicies[i+1:]...)
		} else {
			var p node.EgressPolicy
			if action == "add" {
				if *mode == "" || *primary == "" {
					return errors.New("add需要 --mode和--primary；failover还需要显式备出口和健康条件")
				}
				p = node.EgressPolicy{ID: *id, Name: *name, Mode: *mode, Primary: *primary}
				if p.ID == "" {
					p.ID = node.Token(8)
				}
				if p.Name == "" {
					p.Name = p.ID
				}
				for _, saved := range candidate.EgressPolicies {
					if saved.ID == p.ID {
						return errors.New("策略ID已存在；修改请使用edit")
					}
				}
			} else {
				p = candidate.EgressPolicies[i]
				if flagSet(f, "mode") {
					return errors.New("edit不切换策略模式；请新建并显式迁移引用")
				}
				if f.NFlag() <= 1 || (f.NFlag() == 2 && *preview) {
					return errors.New("edit需要至少一个修改字段")
				}
			}
			if flagSet(f, "name") {
				p.Name = *name
			}
			if flagSet(f, "primary") {
				p.Primary = *primary
			}
			if flagSet(f, "backup") {
				p.Backup = *backup
			}
			healthSet := false
			for _, name := range []string{"target", "udp-target", "failure-threshold", "recovery-threshold", "cooldown-seconds", "timeout-seconds"} {
				healthSet = healthSet || flagSet(f, name)
			}
			if healthSet {
				if p.Health == nil {
					p.Health = &node.EgressHealth{}
				}
				if flagSet(f, "target") {
					p.Health.URL = *target
				}
				if flagSet(f, "udp-target") {
					p.Health.UDPAddress = *udpTarget
				}
				for _, v := range []struct {
					name string
					to   *int
					from int
				}{{"failure-threshold", &p.Health.FailureThreshold, *failure}, {"recovery-threshold", &p.Health.RecoveryThreshold, *recovery}, {"cooldown-seconds", &p.Health.CooldownSeconds, *cooldown}, {"timeout-seconds", &p.Health.TimeoutSeconds, *timeout}} {
					if flagSet(f, v.name) {
						*v.to = v.from
					}
				}
			}
			if action == "add" {
				candidate.EgressPolicies = append(candidate.EgressPolicies, p)
			} else {
				candidate.EgressPolicies[i] = p
			}
		}
		if err := candidate.Validate(); err != nil {
			return errors.New(node.Redact(err.Error(), candidate))
		}
		*s = candidate
		return nil
	})
}

// All JSON names in this format and its nested typed objects are lowercase.
// Reject null, duplicate and case-disguised keys before encoding/json can accept
// their last value or case-insensitively match a field.
func checkTopologyJSON(d *json.Decoder) error {
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if t == nil {
			return errors.New("拓扑批量不接受null；保留字段请省略，清除使用明确操作")
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || name != strings.ToLower(name) || seen[name] {
					return errors.New("拓扑批量含重复、非小写或无效JSON字段")
				}
				// All format keys are ASCII snake_case. encoding/json also folds
				// Unicode aliases (for example long s), which must not overwrite
				// a previous credential or format version under another spelling.
				for _, char := range name {
					if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_') {
						return errors.New("拓扑批量字段只接受明确的ASCII小写名称")
					}
				}
				seen[name] = true
				if err = walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err = walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("拓扑批量含多余JSON数据")
	}
	return nil
}

func decodeTopologyBatch(raw []byte) (topologyBatch, error) {
	var b topologyBatch
	if len(raw) > maxBatchBytes {
		return b, errors.New("拓扑批量超过1MiB")
	}
	if err := checkTopologyJSON(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return b, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		// Inputs contain remote credentials: never echo the raw JSON or values.
		return b, errors.New("拓扑批量字段或类型无效；仅接受帮助中列出的结构")
	}
	if b.Version != 1 || len(b.Operations) < 1 || len(b.Operations) > maxBatchEdits {
		return b, errors.New("拓扑批量需要version:1和1–256个operations")
	}
	seen := map[string]bool{}
	for i, op := range b.Operations {
		kind, id := "", ""
		valid := false
		switch op.Action {
		case "egress-put":
			valid = op.Egress != nil && op.Policy == nil && op.Forward == nil && op.ID == "" && op.NodeID == "" && op.EgressID == nil
			if op.Egress != nil {
				kind, id = "egress", op.Egress.ID
			}
		case "policy-put":
			valid = op.Policy != nil && op.Egress == nil && op.Forward == nil && op.ID == "" && op.NodeID == "" && op.EgressID == nil
			if op.Policy != nil {
				kind, id = "policy", op.Policy.ID
			}
		case "forward-put":
			valid = op.Forward != nil && op.Egress == nil && op.Policy == nil && op.ID == "" && op.NodeID == "" && op.EgressID == nil
			if op.Forward != nil {
				kind, id = "forward", op.Forward.ID
			}
		case "egress-remove", "policy-remove", "forward-remove":
			valid = op.ID != "" && op.Egress == nil && op.Policy == nil && op.Forward == nil && op.NodeID == "" && op.EgressID == nil
			kind, id = strings.TrimSuffix(op.Action, "-remove"), op.ID
		case "route-set":
			valid = op.NodeID != "" && op.EgressID != nil && *op.EgressID != "" && op.ID == "" && op.Egress == nil && op.Policy == nil && op.Forward == nil
			kind, id = "route", op.NodeID
		}
		if !valid || id == "" || seen[kind+":"+id] {
			return b, fmt.Errorf("第%d项操作结构无效、缺少稳定ID或重复修改同一对象", i+1)
		}
		seen[kind+":"+id] = true
	}
	return b, nil
}

func applyTopologyBatch(s *node.State, b topologyBatch) error {
	before := s.Clone()
	candidate := s.Clone()
	seenNodes := map[string]bool{}
	for i, op := range b.Operations {
		var err error
		switch op.Action {
		case "egress-put":
			found := false
			for j := range candidate.Egresses {
				if candidate.Egresses[j].ID == op.Egress.ID {
					candidate.Egresses[j], found = *op.Egress, true
					break
				}
			}
			if !found {
				candidate.Egresses = append(candidate.Egresses, *op.Egress)
			}
		case "policy-put":
			found := false
			for j := range candidate.EgressPolicies {
				if candidate.EgressPolicies[j].ID == op.Policy.ID {
					candidate.EgressPolicies[j], found = *op.Policy, true
					break
				}
			}
			if !found {
				candidate.EgressPolicies = append(candidate.EgressPolicies, *op.Policy)
			}
		case "forward-put":
			found := false
			for j := range candidate.Forwards {
				if candidate.Forwards[j].ID == op.Forward.ID {
					candidate.Forwards[j], found = *op.Forward, true
					break
				}
			}
			if !found {
				candidate.Forwards = append(candidate.Forwards, *op.Forward)
			}
		case "egress-remove":
			found := false
			for j := range candidate.Egresses {
				if candidate.Egresses[j].ID == op.ID {
					candidate.Egresses, found = append(candidate.Egresses[:j], candidate.Egresses[j+1:]...), true
					break
				}
			}
			if !found {
				err = errors.New("待删除出口ID不存在")
			}
		case "policy-remove":
			found := false
			for j := range candidate.EgressPolicies {
				if candidate.EgressPolicies[j].ID == op.ID {
					candidate.EgressPolicies, found = append(candidate.EgressPolicies[:j], candidate.EgressPolicies[j+1:]...), true
					break
				}
			}
			if !found {
				err = errors.New("待删除策略ID不存在")
			}
		case "forward-remove":
			found := false
			for j := range candidate.Forwards {
				if candidate.Forwards[j].ID == op.ID {
					candidate.Forwards, found = append(candidate.Forwards[:j], candidate.Forwards[j+1:]...), true
					break
				}
			}
			if !found {
				err = errors.New("待删除中转ID不存在")
			}
		case "route-set":
			var n *node.Node
			n, err = before.Find(op.NodeID)
			if err == nil && seenNodes[n.ID] {
				err = errors.New("同一节点不能用ID和旧名称重复修改")
			}
			if err == nil {
				seenNodes[n.ID] = true
				current, _ := candidate.Find(n.ID)
				current.EgressID = directEgress(*op.EgressID)
			}
		default:
			err = errors.New("未知拓扑操作")
		}
		if err != nil {
			return fmt.Errorf("第%d项：%w", i+1, err)
		}
	}
	if err := candidate.Validate(); err != nil {
		return errors.New(node.Redact(err.Error(), candidate))
	}
	*s = candidate
	return nil
}

func (a *app) topology(args []string) error {
	if len(args) == 0 || (args[0] != "batch" && args[0] != "apply") {
		return errors.New("用法：topology batch --file 私有拓扑.json [--preview]；统一校验后仅应用一次")
	}
	f := fs("topology " + args[0])
	file := f.String("file", "", "version:1，最多1MiB/256个严格operations；含远程凭据须私下保存")
	preview := f.Bool("preview", false, "只读预览，不写State或启动服务")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "用法：qingnode topology batch --file topology.json [--preview]（apply为同义入口）")
		f.PrintDefaults()
		fmt.Fprintln(f.Output(), `格式：{"version":1,"operations":[{"action":"route-set","node_id":"入口ID","egress_id":"direct或出口/策略ID"}]}`)
		fmt.Fprintln(f.Output(), "操作：egress-put/egress-remove、policy-put/policy-remove、forward-put/forward-remove、route-set。put携带同名egress/policy/forward完整类型对象并保留其稳定ID，remove使用id。")
		fmt.Fprintln(f.Output(), "put替换完整对象（含远程凭据），省略的对象不改；无任意sing-box字段注入。全部引用/环/UDP/监听校验通过后统一应用，错误整批不生效。")
		fmt.Fprintln(f.Output(), "跨主机配置不能本地原子部署；此命令只管理本机，WireGuard配对逐端执行。")
	}
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("需要 --file")
	}
	raw, err := readTopologyFile(*file)
	if err != nil {
		return err
	}
	b, err := decodeTopologyBatch(raw)
	if err != nil {
		return err
	}
	return a.changeTopology(*preview, func(s *node.State) error { return applyTopologyBatch(s, b) })
}

func readTopologyFile(path string) ([]byte, error) {
	i, err := os.Lstat(path)
	if err != nil || !i.Mode().IsRegular() || i.Size() > maxBatchBytes {
		return nil, errors.New("拓扑输入须为最多1MiB的普通文件，不接受符号链接、管道或设备")
	}
	if i.Mode().Perm()&0077 != 0 {
		return nil, errors.New("拓扑输入可能含远程凭据，须为私有文件；请先chmod 600")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("无法安全打开拓扑输入")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(i, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > maxBatchBytes {
		return nil, errors.New("读取期间拓扑输入文件发生变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBatchBytes+1))
	if err != nil || len(raw) > maxBatchBytes {
		return nil, errors.New("无法读取拓扑输入或超过1MiB")
	}
	return raw, nil
}
