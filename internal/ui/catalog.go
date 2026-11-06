package ui

// Only zh-CN is shipped. Adding a locale can reuse these stable menu keys.
const Locale = "zh-CN"

var zh = map[string]string{
	"main":            "选择要做的事\n1 创建节点\n2 节点管理：查看、修改、停用\n3 导出链接、二维码或配置\n4 状态与诊断：端口、连通性、测速\n5 备份与更新：恢复、回退、卸载\n6 高级设置：网络、证书、设备订阅\n7 服务管理：启动、停止、日志\n8 刷新总览（只读本机）\n9 检查更新（联网）\n0 退出",
	"exports":         "设备与订阅\n1 查看设备配置\n2 为节点凭据创建设备配置\n3 导出设备完整配置\n4 查看订阅下载权限\n5 签发设备订阅链接到私有文件\n6 撤销设备下载权限（已下载的代理仍有效）\n0 返回",
	"tests":           "状态与诊断\n1 服务器自检（联网）\n2 本机诊断（只读）\n3 服务器出站测速\n4 经节点连接测速\n5 查看监听端口\n6 公网客户端验证说明/登记\n7 查看监控结果\n8 查看服务运行状态\n0 返回",
	"certificates":    "证书管理\n1 证书列表与有效期\n2 查看证书详细状态\n3 从私有文件导入证书\n4 绑定证书到节点\n0 返回",
	"advanced":        "高级设置\n1 连接地址与端口映射\n2 出口、中转与策略\n3 从文件预览并应用网络配置\n4 DNS配置与诊断\n5 HY2性能设置\n6 系统网络与防火墙\n7 证书管理\n8 设备与订阅\n9 本机能力与限制\n10 协议与客户端要求\n0 返回",
	"nodes":           "节点管理\n1 查看节点   2 添加节点   3 修改名称/地址\n4 修改端口   5 启用节点   6 停用节点\n7 删除节点   8 设备凭据   9 REALITY/证书\n0 返回",
	"service":         "服务管理\n1 状态与运行时间  2 启动  3 停止  4 重启\n5 开机自启        6 取消自启       7 最近日志\n0 返回",
	"maintenance":     "备份与更新\n1 加密备份   2 恢复备份   3 更新 sing-box\n4 更新管理器 5 配置回退   6 恢复中断操作\n7 卸载\n0 返回",
	"system":          "系统网络与防火墙\n1 防火墙规则\n2 系统网络优化\n0 返回",
	"firewall":        "防火墙\n1 查看检测结果与所需端口\n2 启用项目 UFW 规则管理（要求 UFW 已启用）\n3 停止项目规则管理并移除自身规则\n4 同步当前节点端口\n0 返回",
	"network":         "网络优化\n1 查看拥塞控制与队列\n2 启用系统内核 BBR + fq\n0 返回",
	"reality":         "REALITY / 证书\n1 查看连接参数   2 查看私钥   3 修改 SNI/握手目标\n4 修改 fingerprint   5 重新生成 REALITY 密钥\n6 仅重新生成 short ID   7 导入续期 PEM 证书\n0 返回",
	"users":           "设备凭据\n1 添加凭据   2 删除凭据   3 轮换单个凭据\n4 轮换 SS2022 服务密钥（全部客户端失效）\n0 返回",
	"users-basic":     "设备凭据\n1 添加凭据   2 删除凭据   3 轮换单个凭据\n0 返回",
	"uninstall":       "卸载 QingNode\n1 只卸载 sing-box，保留管理器与配置\n2 完全卸载本项目（先保存权限 600 的最终快照）\n0 返回",
	"rotate_warning":  "此操作会使受影响的旧客户端链接失效；确认后需要重新导入。输入 yes 继续",
	"delete_warning":  "将删除选中的节点或凭据；其他节点会保留。输入 yes 继续",
	"restore_warning": "将用备份替换当前节点；恢复前会自动加密备份当前状态。输入 yes 继续",
	"exit_choice":     "选择",
}

func Text(key string) string {
	if s, ok := zh[key]; ok {
		return s
	}
	return key
}
