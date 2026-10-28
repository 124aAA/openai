package node

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ValidateHY2ClientCertificate applies the client's actual QUIC handshake
// restriction. Ed25519 remains a valid server certificate and recovery asset;
// only sing-box's Chrome-parroting client path cannot authenticate that leaf.
// Unknown ACME leaf algorithms are not inferred from account or CA keys.
func ValidateHY2ClientCertificate(n Node, format string) error {
	if n.Protocol != "hysteria2" || (format != "sing-box" && format != "sing-box-outbounds") || n.Certificate == nil {
		return nil
	}
	c := n.Certificate
	if c.Mode != "pem" && c.Mode != "file" {
		return nil
	}
	cert, key, err := certificateMaterial(*c)
	if err != nil {
		return errors.New("Hysteria2客户端证书材料无法验证")
	}
	leaf, _, err := parseCertificateChain(cert, key)
	if err != nil {
		return errors.New("Hysteria2客户端证书材料无法验证")
	}
	disabled := n.HY2 != nil && n.HY2.Client != nil && n.HY2.Client.DisableChromeParrot != nil && *n.HY2.Client.DisableChromeParrot
	if leaf.PublicKeyAlgorithm == x509.Ed25519 && !disabled {
		return errors.New("sing-box默认Chrome QUIC指纹不支持服务端Ed25519证书；请使用ECDSA/RSA证书，或明确选择disable_chrome_parrot=true后导出完整配置。不会自动关闭指纹，也不能用allow_lossy绕过")
	}
	return nil
}

// The direction is local to each endpoint: server up is VPS -> client;
// client up is client -> VPS. Nil retains the existing core default.
type HY2Performance struct {
	ServerUpMbps          *int          `json:"server_up_mbps,omitempty"`
	ServerDownMbps        *int          `json:"server_down_mbps,omitempty"`
	ClientUpMbps          *int          `json:"client_up_mbps,omitempty"`
	ClientDownMbps        *int          `json:"client_down_mbps,omitempty"`
	IgnoreClientBandwidth *bool         `json:"ignore_client_bandwidth,omitempty"`
	ClientMode            string        `json:"client_mode,omitempty"`
	Server                *HY2Transport `json:"server,omitempty"`
	Client                *HY2Transport `json:"client,omitempty"`
}

type HY2Transport struct {
	BBRProfile          string   `json:"bbr_profile,omitempty"`
	QUIC                *HY2QUIC `json:"quic,omitempty"`
	BrutalDebug         *bool    `json:"brutal_debug,omitempty"`
	DisableChromeParrot *bool    `json:"disable_chrome_parrot,omitempty"`
}

// These are fields consumed by the HY2 QUIC transport in sing-box 1.14.0/3.
// They are not HTTP/2 tuning and never alter a global host or network setting.
type HY2QUIC struct {
	StreamReceiveWindow     *int64 `json:"stream_receive_window,omitempty"`
	ConnectionReceiveWindow *int64 `json:"connection_receive_window,omitempty"`
	IdleTimeout             string `json:"idle_timeout,omitempty"`
	KeepAlivePeriod         string `json:"keep_alive_period,omitempty"`
	MaxConcurrentStreams    *int   `json:"max_concurrent_streams,omitempty"`
	InitialPacketSize       *int   `json:"initial_packet_size,omitempty"`
	DisablePathMTUDiscovery *bool  `json:"disable_path_mtu_discovery,omitempty"`
}

func validateHY2Performance(p *HY2Performance) error {
	if p == nil {
		return nil
	}
	for _, v := range []*int{p.ServerUpMbps, p.ServerDownMbps, p.ClientUpMbps, p.ClientDownMbps} {
		if v != nil && (*v < 1 || *v > 1000000) {
			return errors.New("Hysteria2 Mbps必须为1到1000000；恢复默认应清除字段而不是填0")
		}
	}
	if p.IgnoreClientBandwidth != nil && *p.IgnoreClientBandwidth && (p.ServerUpMbps != nil || p.ServerDownMbps != nil) {
		return errors.New("明确非Brutal服务策略不能同时设置服务端带宽上限")
	}
	if p.IgnoreClientBandwidth != nil && *p.IgnoreClientBandwidth && (p.ClientUpMbps != nil || p.ClientDownMbps != nil || p.ClientMode == "brutal") {
		return errors.New("服务端忽略带宽申报时不能同时选择客户端固定Brutal速率；实际协商会改用BBR")
	}
	if p.IgnoreClientBandwidth != nil && *p.IgnoreClientBandwidth && (p.ClientUpMbps != nil || p.ClientDownMbps != nil) {
		return errors.New("服务端明确要求非Brutal时，客户端不能同时声明固定Brutal预期速率")
	}
	if (p.ClientUpMbps == nil) != (p.ClientDownMbps == nil) {
		return errors.New("客户端Brutal预期上传与下载须同时提供")
	}
	switch p.ClientMode {
	case "":
	case "bbr":
		if p.ClientUpMbps != nil || p.ClientDownMbps != nil {
			return errors.New("客户端bbr模式不能同时设置Brutal预期速率")
		}
	case "brutal":
		if p.ClientUpMbps == nil || p.ClientDownMbps == nil {
			return errors.New("客户端brutal模式必须明确上传与下载预期速率")
		}
	default:
		return errors.New("客户端拥塞模式只支持bbr、brutal或清除为核心默认")
	}
	for i, t := range []*HY2Transport{p.Server, p.Client} {
		if t == nil {
			continue
		}
		if t.BBRProfile != "" && t.BBRProfile != "standard" && t.BBRProfile != "conservative" && t.BBRProfile != "aggressive" {
			return errors.New("BBR配置仅支持standard、conservative、aggressive")
		}
		if i == 0 && t.DisableChromeParrot != nil {
			return errors.New("Chrome QUIC伪装开关只适用于客户端")
		}
		if err := validateHY2QUIC(t.QUIC); err != nil {
			return err
		}
	}
	return nil
}

func validateHY2QUIC(q *HY2QUIC) error {
	if q == nil {
		return nil
	}
	for _, w := range []*int64{q.StreamReceiveWindow, q.ConnectionReceiveWindow} {
		if w != nil && (*w < 64<<10 || *w > 256<<20) {
			return errors.New("QUIC接收窗口须为64KiB到256MiB")
		}
	}
	if q.StreamReceiveWindow != nil && q.ConnectionReceiveWindow != nil && *q.ConnectionReceiveWindow < *q.StreamReceiveWindow {
		return errors.New("QUIC连接接收窗口不能小于单流接收窗口")
	}
	var idle, keep time.Duration
	if q.IdleTimeout != "" {
		d, e := time.ParseDuration(q.IdleTimeout)
		if e != nil || d < time.Second || d > 10*time.Minute {
			return errors.New("QUIC空闲超时须为1秒到10分钟")
		}
		idle = d
	}
	if q.KeepAlivePeriod != "" {
		d, e := time.ParseDuration(q.KeepAlivePeriod)
		if e != nil || d < time.Second || d > 2*time.Minute {
			return errors.New("QUIC保活间隔须为1秒到2分钟")
		}
		keep = d
	}
	if idle > 0 && keep > idle {
		return errors.New("QUIC保活间隔不能大于空闲超时")
	}
	if q.MaxConcurrentStreams != nil && (*q.MaxConcurrentStreams < 1 || *q.MaxConcurrentStreams > 4096) {
		return errors.New("QUIC并发流上限须为1到4096")
	}
	if q.InitialPacketSize != nil && (*q.InitialPacketSize < 1200 || *q.InitialPacketSize > 1452) {
		return errors.New("QUIC初始包须为1200到1452字节")
	}
	return nil
}

// A nil tag list means no actual binary was inspected; ordinary State loading
// cannot turn this into proof that the selected binary contains QUIC support.
func ValidateHY2Capabilities(n Node, coreVersion string, tags []string) error {
	if err := validateHY2Performance(n.HY2); err != nil {
		return err
	}
	if n.HY2 == nil {
		return nil
	}
	if n.Protocol != "hysteria2" {
		return errors.New("Hysteria2性能设置只能用于Hysteria2节点")
	}
	if !SupportedVersion(coreVersion) {
		return errors.New("Hysteria2性能设置只适配sing-box 1.14.x正式版")
	}
	if tags != nil {
		found := false
		for _, tag := range tags {
			if tag == "with_quic" {
				found = true
			}
		}
		if !found {
			return errors.New("所选核心缺少with_quic构建能力")
		}
	}
	return nil
}

func hy2Transport(out M, t *HY2Transport) {
	if t == nil {
		return
	}
	if t.BBRProfile != "" {
		out["bbr_profile"] = t.BBRProfile
	}
	if t.BrutalDebug != nil {
		out["brutal_debug"] = *t.BrutalDebug
	}
	if t.DisableChromeParrot != nil {
		out["disable_chrome_parrot"] = *t.DisableChromeParrot
	}
	q := t.QUIC
	if q == nil {
		return
	}
	if q.StreamReceiveWindow != nil {
		out["stream_receive_window"] = *q.StreamReceiveWindow
	}
	if q.ConnectionReceiveWindow != nil {
		out["connection_receive_window"] = *q.ConnectionReceiveWindow
	}
	if q.IdleTimeout != "" {
		out["idle_timeout"] = q.IdleTimeout
	}
	if q.KeepAlivePeriod != "" {
		out["keep_alive_period"] = q.KeepAlivePeriod
	}
	if q.MaxConcurrentStreams != nil {
		out["max_concurrent_streams"] = *q.MaxConcurrentStreams
	}
	if q.InitialPacketSize != nil {
		out["initial_packet_size"] = *q.InitialPacketSize
	}
	if q.DisablePathMTUDiscovery != nil {
		out["disable_path_mtu_discovery"] = *q.DisablePathMTUDiscovery
	}
}

// HY2ExportWarnings describes concrete lost or overridden semantics. It is also
// used by info/URI callers, which do not have an error return in the old API.
func HY2ExportWarnings(n Node, format string) []string {
	var warnings []string
	if err := ValidateHY2ClientCertificate(n, format); err != nil {
		warnings = append(warnings, err.Error())
	}
	p := n.HY2
	if p == nil {
		return warnings
	}
	if format == "uri" || format == "qr" || format == "base64" {
		if p.ClientUpMbps != nil || p.ClientMode != "" || hy2TransportConfigured(p.Client) {
			warnings = append(warnings, "分享链接不能完整表示客户端Hysteria2性能选择；请导出sing-box配置")
		}
		return warnings
	}
	t := p.Client
	if t == nil {
		return warnings
	}
	if format == "mihomo" || format == "provider" {
		if t.BrutalDebug != nil && *t.BrutalDebug {
			warnings = append(warnings, "Mihomo 1.19.30没有等价的独立Brutal调试开关")
		}
		if t.DisableChromeParrot != nil && !*t.DisableChromeParrot {
			warnings = append(warnings, "Mihomo 1.19.30没有Chrome QUIC伪装路径，不能保留明确启用伪装的选择")
		}
		q := t.QUIC
		if q != nil && (q.StreamReceiveWindow != nil || q.ConnectionReceiveWindow != nil) && (t.DisableChromeParrot == nil || !*t.DisableChromeParrot) {
			warnings = append(warnings, "Mihomo窗口同时写入初始值与上限；sing-box默认Chrome伪装会覆盖初始窗口，两个客户端不能保证初始阶段相同")
		}
		if q != nil && (q.IdleTimeout != "" || q.KeepAlivePeriod != "" || q.MaxConcurrentStreams != nil || q.InitialPacketSize != nil || q.DisablePathMTUDiscovery != nil) {
			warnings = append(warnings, "Mihomo 1.19.30不能完整表示所选QUIC超时、并发流、初始包或路径MTU选项")
		}
	}
	if format == "sing-box" {
		disabled := t.DisableChromeParrot != nil && *t.DisableChromeParrot
		q := t.QUIC
		if !disabled && q != nil && (q.IdleTimeout != "" || q.MaxConcurrentStreams != nil || q.InitialPacketSize != nil || q.StreamReceiveWindow != nil || q.ConnectionReceiveWindow != nil) {
			warnings = append(warnings, "Chrome QUIC伪装保持开启：空闲超时固定30秒，并发流与初始包被Chrome值覆盖；接收窗口从Chrome起始值增长至配置上限")
		}
	}
	return warnings
}

func hy2TransportConfigured(t *HY2Transport) bool {
	if t == nil {
		return false
	}
	if t.BBRProfile != "" || t.BrutalDebug != nil || t.DisableChromeParrot != nil {
		return true
	}
	q := t.QUIC
	return q != nil && (q.StreamReceiveWindow != nil || q.ConnectionReceiveWindow != nil || q.IdleTimeout != "" || q.KeepAlivePeriod != "" || q.MaxConcurrentStreams != nil || q.InitialPacketSize != nil || q.DisablePathMTUDiscovery != nil)
}

type ExportResult struct {
	Data     []byte
	Warnings []string
}

func ExportWithCapabilities(n Node, u User, format, clientVersion string, tags []string, allowLossy bool) (ExportResult, error) {
	r := ExportResult{Warnings: HY2ExportWarnings(n, format)}
	if err := ValidateProtocolClient(n, format, clientVersion, tags); err != nil {
		return r, err
	}
	if notes := ProtocolExportWarnings(n, format); len(notes) > 0 {
		return r, errors.New(strings.Join(notes, "；"))
	}
	if n.HY2 != nil {
		if n.Protocol != "hysteria2" {
			return r, errors.New("Hysteria2性能设置不能用于其他协议")
		}
		if err := validateHY2Performance(n.HY2); err != nil {
			return r, err
		}
		if format == "sing-box" {
			if err := ValidateHY2Capabilities(n, clientVersion, tags); err != nil {
				return r, err
			}
		}
		if (format == "mihomo" || format == "provider") && clientVersion != "1.19.30" {
			return r, errors.New("Hysteria2性能导出仅核验Mihomo 1.19.30；不会按其他版本猜测兼容")
		}
		if format != "sing-box" && len(r.Warnings) > 0 && !allowLossy {
			return r, fmt.Errorf("导出将丢失性能选择：%s", strings.Join(r.Warnings, "；"))
		}
	}
	// Export performs the same loss gate. Only this explicit, warning-bearing
	// entry may select the unchecked serializer for a user-approved downgrade.
	var err error
	r.Data, err = exportUnchecked(n, u, format)
	return r, err
}
