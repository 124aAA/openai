package main

import (
	"fmt"
	"os"

	"qingnode/internal/ui"
)

type protocolSelection struct {
	Protocol string
	NAT      bool
}
type protocolConditions struct {
	Client, Certificate, TCP, UDP, NAT, Resources string
}

// This is an explanation of prerequisites, never a speed ranking or a probe of
// the user's operator. Unknown UDP availability must not become an assumption.
func recommendProtocol(c protocolConditions) (string, string) {
	if c.TCP == "no" {
		if c.UDP != "yes" || c.Certificate == "none" {
			return "", "已知入口缺少TCP，UDP或证书条件也不足；当前条件不能推荐完整TCP业务节点，请先补齐入口或证书。不会用出站探测假定入站可用。"
		}
		return "hysteria2", "TCP入口不可用，但已明确UDP和证书条件；HY2可经UDP承载TCP/UDP业务。资源和体验仍需在目标客户端实测。"
	}
	if c.Client == "other" {
		return "ss-aead", "客户端能力尚未核实，先考虑现代SS AEAD；仍须确认目标客户端支持所选方法，不默认它支持SS2022或新协议。"
	}
	if c.Certificate == "none" {
		return "reality", "没有自己的TLS证书时可用REALITY；仍需要TCP公网入口和已核实的握手目标，不需要为此申请自己的域名。"
	}
	if c.UDP != "yes" || c.Resources == "limited" {
		return "trojan", "已有或可申请证书，先使用标准TCP/TLS；不依赖尚未证明的UDP入站，不默认启用QUIC或常驻空闲连接池。"
	}
	return "hysteria2", "已明确具备证书条件和UDP映射，可选择HY2；采用核心默认性能参数。是否更快必须由客户端同条件测试决定。"
}

func (a *app) guidedChoice(label string, options map[string]string) (string, error) {
	for {
		value, err := a.wizardPrompt(label+"；0返回", "")
		if err != nil {
			return "", err
		}
		if value == "0" {
			return "", errMenuCanceled
		}
		if result, ok := options[value]; ok {
			return result, nil
		}
		a.message("WARN", "请选择列出的编号；未知条件请选“不确定”，不要按通过填写。")
	}
}
func (a *app) guidedProtocol() (protocolSelection, error) {
	var c protocolConditions
	var err error
	fmt.Fprintln(ui.HumanWriter(os.Stderr), "只按你已知的客户端和入站条件给建议，不测试或推断用户端最快协议；任何一步可输入:cancel取消。客户端版本是配置内核版本，不等于手机GUI导入已验收。")
	c.Client, err = a.guidedChoice("目标客户端：1 sing-box 1.14 / 2 Mihomo 1.19.30 / 3 其他或不确定", map[string]string{"1": "sing-box", "2": "mihomo", "3": "other"})
	if err != nil {
		return protocolSelection{}, err
	}
	c.Certificate, err = a.guidedChoice("证书条件：1 已有匹配域名PEM或受管资源 / 2 已确认公网80可申请HTTP01 / 3 没有或不确定", map[string]string{"1": "pem", "2": "acme", "3": "none"})
	if err != nil {
		return protocolSelection{}, err
	}
	c.TCP, err = a.guidedChoice("公网TCP入站：1 已确认TCP/映射可用 / 2 不可用 / 3 不确定", map[string]string{"1": "yes", "2": "no", "3": "unknown"})
	if err != nil {
		return protocolSelection{}, err
	}
	c.UDP, err = a.guidedChoice("公网UDP入站：1 已确认UDP/映射可用 / 2 只有TCP / 3 不确定", map[string]string{"1": "yes", "2": "no", "3": "unknown"})
	if err != nil {
		return protocolSelection{}, err
	}
	c.NAT, err = a.guidedChoice("连接入口：1 本机公网地址 / 2 NAT或外端口不同 / 3 不确定（先填写明确映射）", map[string]string{"1": "direct", "2": "nat", "3": "nat"})
	if err != nil {
		return protocolSelection{}, err
	}
	c.Resources, err = a.guidedChoice("资源条件：1 常规资源 / 2 小内存或不确定", map[string]string{"1": "normal", "2": "limited"})
	if err != nil {
		return protocolSelection{}, err
	}
	protocol, reason := recommendProtocol(c)
	fmt.Fprintln(ui.HumanWriter(os.Stderr), "建议依据："+reason)
	if c.TCP == "unknown" || c.UDP == "unknown" {
		fmt.Fprintln(ui.HumanWriter(os.Stderr), "有入站条件尚未验证，建议不是连通性证明；创建后仍须从外部客户端分别测试所需TCP/UDP。")
	}
	if protocol == "" {
		return protocolSelection{}, errMenuCanceled
	}
	fmt.Fprintln(ui.HumanWriter(os.Stderr), "只能DNS01签发时，先通过证书菜单导入私有ACME资源，再在创建表单选择resource；把HTTP01本地端口改高不会改变CA从公网80验证的要求。")
	if c.NAT == "nat" {
		fmt.Fprintln(ui.HumanWriter(os.Stderr), "将分别填写本地监听和外部连接端口；工具不会修改云厂商NAT，TCP/UDP映射仍须分别验证。")
	}
	status, err := a.inspectProtocolMenuCore()
	if err != nil {
		return protocolSelection{}, err
	}
	for {
		choice, err := a.wizardPrompt("协议（留空采用建议；可输入1–7或协议名称；0返回）", protocol)
		if err != nil {
			return protocolSelection{}, err
		}
		if choice == "0" {
			return protocolSelection{}, errMenuCanceled
		}
		for _, candidate := range protocolMenuChoices {
			if choice != candidate.protocol && choice != candidate.number {
				continue
			}
			if reason := status.unavailableReason(candidate.protocol); reason != "" {
				a.message("WARN", reason)
				break
			}
			if c.TCP == "no" && candidate.protocol != "hysteria2" && candidate.protocol != "tuic" {
				a.message("WARN", "所填条件没有TCP入口，此协议不能在这里提供完整TCP业务；请改选或先补齐TCP映射。")
				break
			}
			if c.UDP == "no" && (candidate.protocol == "hysteria2" || candidate.protocol == "tuic") {
				a.message("WARN", "所填条件只有TCP，此UDP监听协议当前不能部署；请改选或先核实UDP条件。")
				break
			}
			if c.Certificate == "none" && candidate.protocol != "reality" && candidate.protocol != "ss2022" && candidate.protocol != "ss-aead" {
				a.message("WARN", "所填条件没有TLS证书；请先准备证书资源，或选择不需要自有证书的协议。")
				break
			}
			return protocolSelection{candidate.protocol, c.NAT == "nat"}, nil
		}
		a.message("WARN", "协议未选定；可修改选择，尚未安装核心或创建节点。")
	}
}
