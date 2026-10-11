# 第三方组件与来源

QingNode 的管理器与安装器为本项目独立实现，未复制同类一键脚本的业务源码。
本项目 MIT 许可只适用于本项目自己的代码，不替代任何第三方组件的许可。

| 组件 | 用途 | 上游 |
| --- | --- | --- |
| Go 标准库 | CLI、HTTP、密码学、文件事务与运行时 | https://go.dev/ |
| go-qrcode | 本地二维码 | https://github.com/skip2/go-qrcode |
| golang.org/x/term、x/sys | 无回显口令输入、系统兼容 | https://go.googlesource.com/term/ ，https://go.googlesource.com/sys/ |
| yaml.v3 | YAML 生成与测试 | https://github.com/go-yaml/yaml/tree/v3.0.1 |

精确版本在 go.mod、go.sum 与 vendor/modules.txt 中，第三方许可副本在源码包的 vendor 目录中。
发行二进制包含上述依赖；构建脚本同时把相应许可附在本文件后。

sing-box 是运行时独立下载的官方可执行程序，不包含于本项目发行包，也不改写或重新标注其许可。
基线为 1.14.0，下载来源：https://github.com/SagerNet/sing-box/releases/tag/v1.14.0 。
本项目仅管理其进程与配置，不冒充 SagerNet 官方项目。

Mihomo 1.19.30 只在测试环境用于验证 YAML，本项目不分发其二进制。

配置依据：

- https://sing-box.sagernet.org/configuration/inbound/vless/
- https://sing-box.sagernet.org/configuration/inbound/hysteria2/
- https://sing-box.sagernet.org/configuration/inbound/shadowsocks/
- https://sing-box.sagernet.org/manual/proxy-protocol/shadowsocks/
- https://shadowsocks.org/doc/sip002.html
- https://sing-box.sagernet.org/configuration/shared/tls/
- https://sing-box.sagernet.org/configuration/shared/certificate-provider/acme/
- https://wiki.metacubex.one/config/proxies/vless/
- https://wiki.metacubex.one/config/proxies/hysteria2/
- https://wiki.metacubex.one/config/proxies/ss/
- https://v2.hysteria.network/docs/developers/URI-Scheme/
- https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html
- https://docs.kernel.org/networking/ip-sysctl.html

交互地址探测和诊断使用 ipify 的公开 IPv4/IPv6 HTTPS 接口；仅查询公网地址，不发送节点密钥或配置：https://www.ipify.org/ 。

架构调研参考：233boy/sing-box、mack-a/v2ray-agent、yonggekkk/sing-box-yg、XTLS/Xray-install、HyNetworks/hysteria、MHSanaei/3x-ui。参考不表示这些项目为本项目背书。

2026-10-11 本轮系统调研覆盖上述列表中的 233boy、mack-a、Xray-install、Hysteria、3x-ui，以及 [fscarmen/sing-box](https://github.com/fscarmen/sing-box)、[alireza0/s-ui](https://github.com/alireza0/s-ui)、[SagerNet/sing-box](https://github.com/SagerNet/sing-box)、[charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea)、[charmbracelet/huh](https://github.com/charmbracelet/huh)，共十个项目。固定提交源码、Issue/Release、许可证及采用/延后原因见本轮独立交付的《开源借鉴报告》。本轮学习交互、恢复材料与副作用边界的设计并独立实现，没有复制外部GPL/AGPL业务源码，也未引入这些项目的框架、面板或数据库依赖。
