# 第三方组件与来源

## 第 07 批固定来源：2026-10-22

证书资源、状态事件白名单、typed迁移包、暂存恢复与保留策略由本项目独立实现。复用现有AES-GCM/PBKDF2备份设计，没有复制ACME/代理实现或GPL面板业务代码；不把外部程序纳入本项目MIT许可。

| 项目 / 固定版本与提交 | 核验机制 | 许可 / 分发边界 |
| --- | --- | --- |
| SagerNet/sing-box v1.14.0 `0b8995879f29a9b98ee027bc17b75e101445b238`、v1.14.3 `7054cac5124465ffdb145870d7c01885566711b1` | `option/acme.go`、`service/acme/service.go`、DNS01字段、TLS文件监视、QUIC证书限制、`with_acme`；新旧ACME入口不同，不混拼字段 | [GPL-3.0及上游条款](https://github.com/SagerNet/sing-box/blob/v1.14.3/LICENSE)，独立官方核心，不随管理器包分发 |
| caddyserver/certmagic `60d9d8b415d6e3f2fa7aec9b440c7dc2473126d4` | 固定核心依赖中的文件存储/每证书签发锁、十分钟续期检查；按CA/邮箱/域名构造的Safe账户与证书存储键用于检查资产覆盖，独立实现路径兼容；无整个目录快照锁，因此受管完整快照需显式短停 | [Apache-2.0](https://github.com/caddyserver/certmagic/blob/60d9d8b415d6e3f2fa7aec9b440c7dc2473126d4/LICENSE.txt)，仅核验依赖行为，未新增链接依赖 |
| mholt/acmez v3.1.6 `7dcf056529711646f5b419cac305fa170b108bb7` | 固定 `acme/account.go` 的status/contact/location账户登记结构；离线校验不冒充CA在线有效性，不丢弃未知原始元数据 | [Apache-2.0](https://github.com/mholt/acmez/blob/v3.1.6/LICENSE)，仅接口核验，不链接或复制ACME客户端实现 |
| letsencrypt/pebble v2.10.1 `b1e1ca4f3c30abb64111adaca4544bc5374cc306` | 本机测试CA，真实HTTP01/短有效期/CA拒绝/错误端口和续期验证；官方发布归档摘要核对 | [MPL-2.0](https://github.com/letsencrypt/pebble/blob/v2.10.1/LICENSE)，仅测试工具，不安装生产服务，不随QingNode发行包分发 |
| caddyserver/certmagic `60d9d8b415d6e3f2fa7aec9b440c7dc2473126d4`，及上述 Pebble/acmez 固定源码 | 第10批核对 `async.go` / `acmeissuer.go` 的原生60s、120s重试及第三次省略Replaces；Pebble的 `ca/ca.go`、`core/types.go`、`db/memorystore.go` 对DER正数前导00的键不一致已在受控CA实测500。仅为该确定错误留有界测试等待，仍断言真实续期、账号身份与传输，不修改CA/核心二进制或加生产续期循环 | [Apache-2.0](https://github.com/caddyserver/certmagic/blob/60d9d8b415d6e3f2fa7aec9b440c7dc2473126d4/LICENSE.txt)；只核对接口与失败机制，未复制实现 |
| MetaCubeX/mihomo v1.19.30 `ac017cdd246ce8bd547653d927e7bf77d7ee73d5` | [adapter URLTest](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/adapter.go) 将耗时截成整数毫秒，[delay API](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/hub/route/proxies.go) 对0返回503；自有健康目标增加可取消5ms等待和真实命中计数，保留原主备/TCP/UDP断言，不重试 | [GPL-3.0](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/LICENSE)；只核验上游接口边界，未复制实现或将其纳入MIT代码，既有官方测试工具不随包分发 |
| Linux/systemd | unit状态、MainPID/ControlPID、InvocationID、受管cgroup无成员与限量journal证据；不执行备份内服务指令 | 系统现有接口；真实宿主验收与mock/源码核验分开 |

固定文档：[ACME provider](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/certificate-provider/acme.md)、[DNS01](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/dns01_challenge.md)、[HY2客户端](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/outbound/hysteria2.md)。公开滚动文档与其它ACME工具插件不视为本项目支持范围。两版选项文件相同也不替代两版实际解析与传输。

本批测试工具归档SHA-256：Pebble linux-amd64 `4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed`，windows-amd64 `3201b904957c8ad81a27ee879cd246d97e7a9c79b01d840b09ec478f065794b3`。实际使用范围及原始失败见 [BATCH07.md](docs/BATCH07.md)。

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

Mihomo 1.19.30 只在测试环境用于验证 YAML 和受控 HY2 互通，本项目不分发其二进制。

## 第 01 批固定来源：2026-10-13

本批使用上游字段与独立核心能力，未复制上游代理实现、GPL/AGPL 面板或其他项目管理器源码。管理器的新变更分类、批量编辑与观察脚本均独立实现。原有 vendor 依赖和所需许可声明保持。

| 项目 / 固定版本 | 本批采用或核验的机制 | 许可证与分发边界 |
| --- | --- | --- |
| SagerNet/sing-box `v1.14.0` / `0b8995879f29a9b98ee027bc17b75e101445b238` | 保留官方核心默认基线、现有三协议配置与官方集成测试 | [GPL-3.0-or-later 及上游附加条款](https://github.com/SagerNet/sing-box/blob/v1.14.0/LICENSE)；作为独立运行程序下载，本项目 MIT 不覆盖它 |
| SagerNet/sing-box `v1.14.3` / `7054cac5124465ffdb145870d7c01885566711b1` | 核验 VLESS、SS2022、HY2/TLS/ACME 字段、QUIC/uTLS/ACME 构建标签和两架构官方归档；作为候选验证，不自动跨兼容线 | [上游 LICENSE](https://github.com/SagerNet/sing-box/blob/v1.14.3/LICENSE)；同上，未复制协议源码 |
| SagerNet/sing-box `a364ff4794f0f8715ff26b11dc52402771415525` | [移除未实现的 manager hot reload](https://github.com/SagerNet/sing-box/commit/a364ff4794f0f8715ff26b11dc52402771415525)；据此保持“免调用重启”和“运行配置变化可能中断”的边界，不推断控制 API 保证无损 | 同上；只参考行为与支持范围 |
| MetaCubeX/mihomo `v1.19.30` | 保留官方 amd64-compatible 测试工具，`-t` 解析生成 YAML；不宣称 GUI/流量验收 | [GPL-3.0](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/LICENSE)；仅测试使用，不随项目发行二进制分发 |
| systemd / Linux `/proc` 接口 | 沿现有 `systemctl show MainPID`、服务启动/停止与 socket 检查；观察脚本额外核对 `/proc/PID/stat` 启动身份和持续 TCP 帧 | 使用系统提供的命令/内核接口，未复制实现；行为以真实宿主验收为准 |

v1.14.3 的官方归档摘要取自固定 [Release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3) 的 GitHub asset digest，下载后计算 SHA-256 一致：

| 官方归档 | SHA-256 |
| --- | --- |
| `sing-box-1.14.3-linux-amd64.tar.gz` | `e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee` |
| `sing-box-1.14.3-linux-arm64.tar.gz` | `29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e` |

固定源码：[VLESS](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/vless.go)、[Shadowsocks](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/shadowsocks.go)、[Hysteria2](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/hysteria2.go)、[TLS](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/tls.go)、[ACME 注册](https://github.com/SagerNet/sing-box/blob/v1.14.3/include/acme.go)、[默认构建标签](https://github.com/SagerNet/sing-box/blob/v1.14.3/release/DEFAULT_BUILD_TAGS)、[构建说明](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/installation/build-from-source.md)。补丁差异参考 [v1.14.0...v1.14.3](https://github.com/SagerNet/sing-box/compare/v1.14.0...v1.14.3)，其中包含连接取消、half-close、DNS 初始化与 UDP 目的地/校验和等修复；这些修复不能推导出本项目吞吐提升或公网测试结果。

## 第 02 批固定来源：2026-10-13

本批网络测试、SOCKS5 测试连接、带序号的 UDP 回应及报告逻辑由本项目独立实现。只调用官方 sing-box 的既有协议能力，没有复制代理协议实现；以下工具不作为必装依赖，不随 QingNode 分发，也没有引入面板、数据库或后台监控服务。

| 项目 / 固定版本与提交 | 参考或核验的机制 | 许可 / 使用边界 |
| --- | --- | --- |
| SagerNet/sing-box `v1.14.0` / `0b8995879f29a9b98ee027bc17b75e101445b238`；`v1.14.3` / `7054cac5124465ffdb145870d7c01885566711b1` | 隔离客户端只含所选代理出站、`route.final` 指向该出站；`mixed` 本机入站支持 SOCKS5 TCP 和 UDP；区分节点地址的 bootstrap DNS 与代理目标域名解析 | GPL-3.0-or-later 及上游附加条款，见上方声明；独立运行程序，只参考接口，未复制源码 |
| ESnet/iperf `3.22` / `926bd905501b792bd082d2200d1d1a84aa543e3a` | [固定手册](https://github.com/esnet/iperf/blob/3.22/src/iperf3.1)：`-R` 反向、`-J` JSON、UDP 仍需 TCP 控制连接、`-t`/`-n`/`-k` 互斥；外部受控链路流程保留独立总超时与版本检查 | [BSD-style 及附属声明](https://github.com/esnet/iperf/blob/3.22/LICENSE)；文档参考，可选独立工具，不复制或分发 |
| heistp/irtt `v0.9.1` / `c5ed230a672f5233f4a87b2a28dd6d5c86b6feba` | [固定 README](https://github.com/heistp/irtt/blob/v0.9.1/README.md) 与 [客户端参数](https://github.com/heistp/irtt/blob/v0.9.1/irtt_client.go)：请求/响应 RTT、丢包、IPDV；单向延迟需两端时钟同步；样本不足不产生抖动结论 | [GPL v2](https://github.com/heistp/irtt/blob/v0.9.1/LICENSE)；仅可选外部流程，不复制或分发，项目独立 UDP 测试不采用其协议实现 |
| prometheus/blackbox_exporter `v0.28.0` / `5a059bee8d8ffa4e75947c5055fb0abeefc582e6` | [HTTP 探测](https://github.com/prometheus/blackbox_exporter/blob/v0.28.0/prober/http.go) 与 [探测分派](https://github.com/prometheus/blackbox_exporter/blob/v0.28.0/prober/prober.go)：借鉴分层成功/失败和 HTTP 观察阶段的报告方式；普通 HTTP/TCP 成功不替代协议认证及 UDP 转发验收 | [Apache-2.0](https://github.com/prometheus/blackbox_exporter/blob/v0.28.0/LICENSE)；只参考机制，未复制代码或引入 Prometheus |
| IETF SOCKS5 `RFC 1928` | [SOCKS5 CONNECT / UDP ASSOCIATE 与 UDP 头格式](https://www.rfc-editor.org/rfc/rfc1928)；本地测试通过明确的 SOCKS 请求发送 TCP/UDP，不依赖 `HTTP_PROXY` 假定所有流量过代理 | 公开规范参考；只实现本机测试入口的标准封装，不重新实现 VLESS/SS2022/Hysteria2 |
| IETF SOCKS5 认证 `RFC 1929` | [用户名/密码协商与拒绝状态](https://www.rfc-editor.org/rfc/rfc1929)；本次临时 mixed 入站生成随机认证，UDP 请求明确完成认证，不降级为未认证方式 | 公开规范参考；本项目独立实现本机测试认证封装，未复制协议库或上游示例源码 |
| Linux procfs / Microsoft Win32 TCP 表 API | Linux [`/proc/net/tcp`](https://docs.kernel.org/networking/proc_net_tcp.html) 与 [`/proc/PID/fd`](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) 比较监听 socket inode；Windows [`GetExtendedTcpTable`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) / [`MIB_TCPROW_OWNER_PID`](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid) 核对实际监听端口归属 PID | 2026-10-13 查阅公开系统接口规范，本项目独立实现读取/解析和调用，未复制内核、Microsoft 示例或面板源码；`x/sys/windows` 原有 vendor 许可保留 |

本批原生 Windows 测试所用官方 `sing-box-1.14.3-windows-amd64.zip` 归档 SHA-256 为 `d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518`，本批实际下载时已核对固定 v1.14.3 官方 Release asset digest 与下载摘要。它是归档摘要，不是 `--core-sha256` 所需的解出后二进制摘要。

sing-box 固定接口来源：[mixed 入站](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/inbound/mixed.md)、[mixed 路由实现](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/mixed/inbound.go)、[route.final](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/route/index.md)、[domain_resolver](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/dial.md)。同一版本文档和源码分别核验；滚动官网的 1.15 字段不进入隔离配置。固定 tag 只证明接口依据，工具性能与公网结果须另行实测。

## 第 03 批固定来源：2026-10-14

本批只参考固定接口、单位、协商和系统参数机制，HY2/QUIC 传输仍交给独立官方核心。模型、迁移、影响预览、宿主事务、DNS 诊断和验收逻辑独立实现，没有复制 GPL/AGPL 代理或面板实现，也不将其标为本项目 MIT 代码。下列外部二进制不随本项目发行；已有 Go/vendor 声明保留。

| 项目 / 固定版本和提交 | 本批核验机制 / 具体来源 | 许可与边界 |
| --- | --- | --- |
| SagerNet/sing-box `v1.14.0` / `0b8995879f29a9b98ee027bc17b75e101445b238`；`v1.14.3` / `7054cac5124465ffdb145870d7c01885566711b1` | HY2 两端 `up_mbps/down_mbps`、`ignore_client_bandwidth`、`bbr_profile` 与 QUIC 选项；Chrome 覆盖与默认；局部 local/UDP resolver、`domain_resolver` 区分节点地址和目标地址。见 [HY2 选项](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/hysteria2.go)、[共享选项结构](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/http.go)、[客户端文档](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/outbound/hysteria2.md)、[DNS](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/dns/server/udp.md) | [GPL-3.0-or-later 及附加条款](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/LICENSE)，沿原独立核心使用边界，未复制实现 |
| SagerNet/sing-quic；1.14.0 固定依赖 `v0.7.0-beta.4`；1.14.3 固定依赖 `v0.7.2-0.20261002084117-75c3ac4fa12b` / `75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876` | [依赖锁定](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/go.mod)、[窗口 initial/max 同值映射与 UDP 缓冲请求](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/quic.go)、[服务端速率协商](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/hysteria2/service.go)、[客户端方向](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/hysteria2/client.go) | [GPL-3.0-or-later](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/LICENSE)，只读机制核验，不引入依赖或复制协议代码 |
| MetaCubeX/mihomo `v1.19.30` / `ac017cdd246ce8bd547653d927e7bf77d7ee73d5`；其 `sing-quic` pin `38b0e9295f51d1e96e7564b1d804c2e3a56c8610`、`quic-go` pin `2548683b76f4d57a720b95a2a52f2fd1ecec5f10` | [HY2 字段和窗口](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outbound/hysteria2.go)、[速率字符串与单位](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/common/utils/mbps.go)、[固定依赖](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/go.mod)、[原生 QUIC 客户端](https://github.com/MetaCubeX/sing-quic/blob/38b0e9295f51d1e96e7564b1d804c2e3a56c8610/hysteria2/client.go)。保留无字段/默认差异，不发明 Chrome 开关 | [GPL-3.0](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/LICENSE)，仅独立测试程序；其依赖许可证由各项目保留，不复制代码 |
| HyNetworks/hysteria-website / `aa652ff62c9e0c920c43b9da65a8dae51a9d44f1` | [HY2 URI 规范](https://github.com/HyNetworks/hysteria-website/blob/aa652ff62c9e0c920c43b9da65a8dae51a9d44f1/docs/docs/developers/URI-Scheme.md)：必要连接信息、扩展不保证跨客户端理解，带宽/客户端模式不应塞进分享 URI | [MIT，Copyright 2023 Toby](https://github.com/HyNetworks/hysteria-website/blob/aa652ff62c9e0c920c43b9da65a8dae51a9d44f1/LICENSE.md)，规范参考，无正文或源码复制 |
| Linux `v6.18` / `7d0a66e4bb9081d75c82ec4957c50034cb0ea449` | [TCP sysctl](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/Documentation/networking/ip-sysctl.rst)、[net.core 缓冲/默认队列](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/Documentation/admin-guide/sysctl/net.rst)、[TCP BBR](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/net/ipv4/tcp_bbr.c)：可用/默认/现有连接、系统 TCP 与用户态 QUIC、默认/实际队列分别看待 | [GPL-2.0 及内核逐文件声明](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/COPYING)，使用系统接口与独立测试命令，不复制内核实现 |

固定文档证明参数依据，不证明已实测性能。1.14.x 范围接受、二进制构建标签、官方解析、真实 sing-box/Mihomo TCP/UDP、netem/cgroup/服务宿主、手机 UI 与公网分别记录；当前批次实际证据见 [BATCH_03.md](docs/BATCH_03.md)。

Mihomo 测试初始化屏障另核同一 `ac017cdd246ce8bd547653d927e7bf77d7ee73d5`：[ApplyConfig](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/hub/executor/executor.go) 先建立监听，完成 provider/GC 后才进入 Running；[tunnel](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/tunnel/tunnel.go) 在未 Running 时关闭外部请求，[HTTP 代理](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/listener/http/proxy.go) 将请求错误转为 502；[main.go 的 post-up](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/main.go) 在完整 hub.Parse/ApplyConfig 之后调用。本项目只在自有 fixture 调用该官方命令接口写私有就绪标记，没有复制实现、预热/重试请求或启用生产脚本钩子。GPL 许可边界同上。

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

## 第 04 批固定来源：2026-10-14

连接端点、schema 迁移、本机绑定预检与能力报告均由本项目独立实现。只核对官方固定版本字段与地址族机制，不复制GPL/AGPL面板、协议库或其他管理器源码；沿已有依赖的vendor许可和分发声明保持。

| 项目 / 固定版本与提交 | 本批核验机制 | 许可证与边界 |
| --- | --- | --- |
| SagerNet/sing-box v1.14.0 / `0b8995879f29a9b98ee027bc17b75e101445b238`；v1.14.3 / `7054cac5124465ffdb145870d7c01885566711b1` | [ListenOptions](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/inbound.go)、[固定Listen文档](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/shared/listen.md)、[TCP](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/common/listener/listener_tcp.go)/[UDP](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/common/listener/listener_udp.go)选族；0.0.0.0选IPv4、::走通用套接字；两版没有入站v6only JSON。Dial域名策略不作为监听开关 | [GPL-3.0-or-later及命名附加条款](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/LICENSE)；独立官方程序，未复制实现，不随QingNode包分发 |
| SagerNet/sing v0.9.0-beta.4 / `3f8f790b7a2968307bbf900544fc8030791c715e`（1.14.0依赖）；`0ad23b637bd49e7c2982640137df7598dde93ff9`（1.14.3依赖） | 固定[NetworkFromNetAddr](https://github.com/SagerNet/sing/blob/0ad23b637bd49e7c2982640137df7598dde93ff9/common/metadata/network.go)如何保留IPv6通配并区别IPv4通配；只核机制，不把函数源码复制进项目 | [GPL-3.0-or-later](https://github.com/SagerNet/sing/blob/0ad23b637bd49e7c2982640137df7598dde93ff9/LICENSE)；未增加此Go依赖或分发其源码/二进制 |
| golang/go go1.26.8 / `c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e` | 官方1.14.3文件构建元数据对应工具链；[自动地址族](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/src/net/ipsock_posix.go)和[Linux IPV6_V6ONLY设置](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/src/net/sockopt_linux.go)，说明全局默认不等于已有socket值；实际管理器编译版本另记回执 | [BSD 3-Clause](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/LICENSE)；使用标准库接口，没有复制其实现 |

固定1.14.0/1.14.3的 `option/inbound.go`、`option/outbound.go`、`option/wireguard.go` 与共享Listen文档原始字节相同；Dial文档差异为netns警告说明，没有新增字段。本批只澄清连接地址/监听/Dial含义，不新增出站源绑定、DNS族偏好或WireGuard配置。上游[WireGuard endpoint](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/endpoint/wireguard.md)是另一种顶层对象，需要独立标签、设备权限和协议验收；不能与本批客户端连接入口混为一谈。

本批本机能力报告通过现有Go/x/sys读有限系统接口，不调用第三方探测服务，不写sysctl/TUN/路由。固定来源核对只证明接口依据；本批实际编译、解析、IPv4/IPv6、官方协议和服务证据见 [BATCH04.md](docs/BATCH04.md)，不能从上游能力推导项目已实测。

## 第 05 批固定来源：中转、链式出站与 WireGuard

以下记录公开接口和概念比较，不把 GPL 核心、转发器或面板实现复制成 QingNode 的 MIT 源码。新增拓扑校验、图派生、应用层主备观测、事务接线、配对材料及测试均由本项目独立实现；不新增 Realm/GOST/WireGuard 数据面依赖或分发包，已有 Go/vendor 许可保留。

| 项目 / 固定版本与提交 | 核对的具体机制 | 许可证与采用边界 |
| --- | --- | --- |
| SagerNet/sing-box v1.14.0 / `0b8995879f29a9b98ee027bc17b75e101445b238`；v1.14.3 / `7054cac5124465ffdb145870d7c01885566711b1` | [direct 入站](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/inbound/direct.md) 固定目标 TCP/UDP；[Dial](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/shared/dial.md) 的 detour 与其余同层字段互斥语义；[WireGuard endpoint](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/endpoint/wireguard.md) 顶层对象、system=false、AllowedIPs、MTU/keepalive、监听/detour冲突与入站路由标签 | [GPL-3.0-or-later 及命名附加条款](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/LICENSE)；独立官方核心，不复制协议实现、不随管理器包分发 |
| SagerNet/wireguard-go；两核心固定依赖 `v0.0.5-0.20260823125007-8bd032a91a30` / `v0.0.8-0.20260929150556-6731c7387c81` | [StdNetBind](https://github.com/SagerNet/wireguard-go/blob/6731c7387c81/conn/bind_std.go) 固定端口分别绑定 udp4/udp6，不等于通用 :: 单 socket；只在缺族错误时容忍缺失 | 该源文件 MIT / WireGuard LLC；只核对行为，不复制、不新增本项目依赖 |
| go-gost/gost v3.2.6 / `340ba32ef0bebc7293908007cc423dd5f33dd88c`；依赖 x v0.8.1 / `77eda4ce008ebebea57bb017fcd4b20ddc09a154`、core v0.3.3 / `867317c9656d92a1f1494ff308d8cab8d4a212fb` | 固定 [selector/filter](https://github.com/go-gost/x/blob/77eda4ce008ebebea57bb017fcd4b20ddc09a154/selector/filter.go) 与 [Marker](https://github.com/go-gost/core/blob/867317c9656d92a1f1494ff308d8cab8d4a212fb/selector/selector.go) 的失败计数、冷却、主项失效后考虑 backup；滚动文档3.3.0 race不当作此版本保证 | [MIT，ginuerzh](https://github.com/go-gost/gost/blob/340ba32ef0bebc7293908007cc423dd5f33dd88c/LICENSE)；仅比较概念，未安装、集成或复制调度实现。QingNode 的应用层探测、恢复阈值和持久检查点另行实现 |
| zhboner/realm v2.9.3 / `2ab8e400cea3edf3f1103a0f0cc80c2665081c11` | [固定小写 readme](https://github.com/zhboner/realm/blob/2ab8e400cea3edf3f1103a0f0cc80c2665081c11/readme.md) 的独立 TCP/UDP 转发组件；本批官方 direct 入站已满足目标，因此不引入第二数据面 | [MIT，zhboner](https://github.com/zhboner/realm/blob/2ab8e400cea3edf3f1103a0f0cc80c2665081c11/LICENSE)；未安装、集成或复制源码 |
| golang/go go1.26.8 / `c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e` | Go 标准库 X25519 生成配对密钥；既有网络、文件与进程接口；管理器自身构建版本和原生 Windows Go1.27.2 测试另列回执 | [BSD 3-Clause](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/LICENSE)；使用标准库，不重新实现 WireGuard 协议 |

用户态栈与标签依据固定 [device_stack.go](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/transport/wireguard/device_stack.go)、[endpoint 初始化](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/protocol/wireguard/endpoint.go) 和 [构建说明](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/installation/build-from-source.md)，服务端/客户端分别核对 with_wireguard 与 with_gvisor。固定源码说明上游支持范围，不代表当前提交通过真实链路、权限、系统服务或公网验收。实现与本批实际证据见 [TOPOLOGY.md](docs/TOPOLOGY.md) 和 [BATCH05.md](docs/BATCH05.md)。

本批另核固定 [1.14.3 默认接口同步](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/route/network.go)、[1.14.0 对应实现](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/route/network.go) 与 [WG 暂停回调](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/transport/wireguard/endpoint.go)，用于定位缺默认接口时的 NetworkPause 测试条件；以及 [1.14.0 新入流路由](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/protocol/wireguard/endpoint.go)、[1.14.3 对应实现](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/protocol/wireguard/endpoint.go)，确认主动 endpoint 也可携入新 TCP/UDP 流。项目独立生成显式入站拒绝规则并做真实前后对照，没有复制核心或协议实现。固定源码核查、隔离 A/B 和公网行为分别记录。

架构调研参考：233boy/sing-box、mack-a/v2ray-agent、yonggekkk/sing-box-yg、XTLS/Xray-install、HyNetworks/hysteria、MHSanaei/3x-ui。参考不表示这些项目为本项目背书。

2026-10-11 本轮系统调研覆盖上述列表中的 233boy、mack-a、Xray-install、Hysteria、3x-ui，以及 [fscarmen/sing-box](https://github.com/fscarmen/sing-box)、[alireza0/s-ui](https://github.com/alireza0/s-ui)、[SagerNet/sing-box](https://github.com/SagerNet/sing-box)、[charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea)、[charmbracelet/huh](https://github.com/charmbracelet/huh)，共十个项目。固定提交源码、Issue/Release、许可证及采用/延后原因见本轮独立交付的《开源借鉴报告》。本轮学习交互、恢复材料与副作用边界的设计并独立实现，没有复制外部GPL/AGPL业务源码，也未引入这些项目的框架、面板或数据库依赖。

## 第 06 批固定来源：2026-10-18

新增设备模型、序列化、下载令牌、私有快照和HTTP服务为本项目独立实现；不复制GPL面板/调度源码，不集成S-UI，不增加数据库或在线转换依赖。

测试启动就绪另核两版固定源码的 [Box.Start 生命周期](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/box.go)、[1.14.0 初始网络通知](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/route/network.go)、[HY2 接口更新](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/protocol/hysteria2/outbound.go) 和 [1.14.3 重置门控](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/route/network.go)。监听打开早于全部启动阶段结束，因此自有测试在原5秒总预算内观察所属监听和完整启动日志；单次正向载荷断言不重试，不承诺异步网络回调已全部结束。14份固定源码/许可证的URL和SHA见交付证据 `batch06-core-startup-source-receipt.json`。只采用公开生命周期/日志接口，不复制GPL实现，不改生产日志、协议、网络策略或600000次备份密钥派生。

| 项目 / 固定版本与commit | 核对机制 | 许可证 / 边界 |
| --- | --- | --- |
| sing-box v1.14.0 / `0b8995879f29a9b98ee027bc17b75e101445b238`；v1.14.3 / `7054cac5124465ffdb145870d7c01885566711b1` | [option/group.go](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/group.go)、[URLTest](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/protocol/group/urltest.go)、[timeout](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/constant/timeout.go)：手动/最低时延组、容差、内部15秒超时；无有序fallback字段 | [GPL-3.0-or-later及附加条款](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/LICENSE)；独立官方核心，不分发于管理器包 |
| Mihomo v1.19.30 / `ac017cdd246ce8bd547653d927e7bf77d7ee73d5` | [parser](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outboundgroup/parser.go)、[url-test](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outboundgroup/urltest.go)、[fallback](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outboundgroup/fallback.go)、[provider](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/provider/provider.go)：单位、时延容差、有序HTTP可用项和节点集合 | [GPL v3](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/LICENSE)；仅官方测试程序，不复制实现或随包分发 |
| S-UI v1.3.8 / `e84f7530e34a4769390007d37cb9f5e0f2ac01b2`；独立Wiki `798e4c542298fa74472a4eaba2901fff08dc8739` | [订阅说明](https://github.com/alireza0/s-ui/wiki/Subscription-Service)：独立服务、多种客户端格式和响应头概念；本批不采用按显示名授权、外部递归订阅或通用模板 | [GPL v3](https://github.com/alireza0/s-ui/blob/e84f7530e34a4769390007d37cb9f5e0f2ac01b2/LICENSE)；未安装、集成或复制面板代码，Wiki版本独立记录 |
| RFC1918 / RFC4193 | [RFC1918](https://www.rfc-editor.org/rfc/rfc1918)、[RFC4193](https://www.rfc-editor.org/rfc/rfc4193)：可选基础分流的固定私有网段常量 | 仅采用规范中网段值；没有导入庞大第三方规则库 |

固定raw源码16份和Wiki文件的原始哈希记录在本批外部证据 `batch06-upstream-fixed-receipt.json`，tag/commit通过只读ls-remote核验。常规HTTP/TLS使用Go标准库，原vendor及许可保持；不伪造流量配额，不把HTTP探测当作UDP真实测试。实际版本、构建标签与执行边界见[本批记录](docs/BATCH06.md)。

targeted1两次真实Mihomo1.19.30自动组测试均在容差内切换，故完整auto默认拒绝，只有显式接受缺陷才降级。另取固定[adapter/outboundgroup/urltest.go第118–140行](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outboundgroup/urltest.go#L118-L140)核对：首项没有进入“当前成员仍在列表”的容差保护分支；这里只解释观察到的行为，没有复制调度实现或通过重排节点掩盖缺陷。原始5439字节SHA256为`6d58af720ff6bcb368b2d43253a784865fd040d6871598cd2cc7eb8237083565`，单独收据`batch06-mihomo-urltest-source-receipt.json`保留于本批证据，不修改原16份来源回执。上游GPLv3许可边界不变；修订入口的后续测试结果必须另记，不能把缺陷复现当作容差达标。

## 第10批固定来源：发行版、架构与安装维护

本批的HostCapabilities、包计划、服务/调度接线、归属与回滚、防火墙日志和验收脚本由本项目独立实现。继续运行用户系统提供的init/包管理/防火墙及独立官方core；不复制Xray安装器、GPL面板、OpenRC监督器或代理协议实现，不新增面板、数据库或容器运行依赖。

| 项目 / 固定版本与提交 | 本批核对的具体机制 | 许可与采用边界 |
| --- | --- | --- |
| OpenRC/openrc `0.62.1` / `10b2f0732c571c21cb26cfabdc0b11094cfbc5ee`（annotated tag `3658e552a2fd18dd80a3c2db3ae3f0ceadb28989`）；实际Alpine包对应上游 `0.63.2` / `b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e`（annotated tag `f1c71c4d8388b59f04a0114aecab23e7cf28f7e7`） | [固定服务指南](https://github.com/OpenRC/openrc/blob/10b2f0732c571c21cb26cfabdc0b11094cfbc5ee/service-script-guide.md)、[0.63.2监督脚本](https://github.com/OpenRC/openrc/blob/b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e/sh/supervise-daemon.sh)、[监督程序](https://github.com/OpenRC/openrc/blob/b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e/src/supervise-daemon/supervise-daemon.c) 与 [手册](https://github.com/OpenRC/openrc/blob/b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e/man/supervise-daemon.8)：PID文件属于supervisor，child_pid单独读取；降UID后日志打开、重生限制、capabilities/no_new_privs、帮助选项需要实际服务名。另核[openrc-init](https://github.com/OpenRC/openrc/blob/b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e/src/openrc-init/openrc-init.c) 的真实PID1与启动顺序 | [BSD-2-Clause](https://github.com/OpenRC/openrc/blob/b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e/LICENSE)；参考公开接口后独立渲染服务定义，未复制实现。实际包为0.63.2-r0，原APK字节与包签名另留回执，不假定无发行版补丁 |
| Linux libcap `libcap-2.78` / `a1fef85d27d0ee12729a64d1c9b2183c6007e56a`（annotated tag `7a89aa42efc57e18f8c42de700f6367bd7531a1a`） | 官方kernel.org仓库镜像的固定 [cap_iab(3)](https://kernel.googlesource.com/pub/scm/libs/libcap/libcap/+/a1fef85d27d0ee12729a64d1c9b2183c6007e56a/doc/cap_iab.3)、[IAB文本解析](https://kernel.googlesource.com/pub/scm/libs/libcap/libcap/+/a1fef85d27d0ee12729a64d1c9b2183c6007e56a/libcap/cap_text.c)：`^`表示继承加ambient，`!`才涉及bounding阻挡；有filecap的再次exec会改变ambient语义。结合OpenRC核对setuid→IAB设置→no_new_privs顺序 | [BSD-3-Clause OR GPL-2.0-only](https://kernel.googlesource.com/pub/scm/libs/libcap/libcap/+/a1fef85d27d0ee12729a64d1c9b2183c6007e56a/License)；只读机制参考，不复制代码、不加入Go依赖。Alpine实际libcap包2.78-r0与上游源码证据分别登记 |
| firewalld `v1.3.4` / `83d46a9f8c4f01da463cf426c083c69e79bf008a` | 固定 [firewall-cmd手册源](https://github.com/firewalld/firewalld/blob/83d46a9f8c4f01da463cf426c083c69e79bf008a/doc/xml/firewall-cmd.xml.in)、[持久配置](https://github.com/firewalld/firewalld/blob/83d46a9f8c4f01da463cf426c083c69e79bf008a/src/firewall/server/config.py)、[service](https://github.com/firewalld/firewalld/blob/83d46a9f8c4f01da463cf426c083c69e79bf008a/src/firewall/core/fw_service.py)、[zone](https://github.com/firewalld/firewalld/blob/83d46a9f8c4f01da463cf426c083c69e79bf008a/src/firewall/core/fw_zone.py)：运行与永久状态分开、rich-rule增删及读回、新建永久service不经reload不自动存在于运行注册表 | [GPL-2.0-or-later](https://github.com/firewalld/firewalld/blob/83d46a9f8c4f01da463cf426c083c69e79bf008a/COPYING)；只使用系统命令契约，不复制实现，不随管理器包分发 |
| XTLS/Xray-install / `b0d349e9c6234e8fa1b0d50ca9a29ce54452918f` | 固定 [Alpine安装器](https://github.com/XTLS/Xray-install/blob/b0d349e9c6234e8fa1b0d50ca9a29ce54452918f/alpinelinux/install-release.sh)：比较systemd与OpenRC分别处理依赖、用户与生命周期的边界 | [GPL-3.0](https://github.com/XTLS/Xray-install/blob/b0d349e9c6234e8fa1b0d50ca9a29ce54452918f/LICENSE)；仅方案比较，没有复制、翻译或重新标为MIT |
| SagerNet/sing-box `v1.14.0` / `0b8995879f29a9b98ee027bc17b75e101445b238`；`v1.14.3` / `7054cac5124465ffdb145870d7c01885566711b1` | [固定构建说明](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/installation/build-from-source.md) 与原有构建标签；另直接检查官方发行ELF架构、PT_INTERP、摘要、version/check，再验证TCP/UDP，不能由静态manager推导musl兼容 | [GPL-3.0-or-later及上游附加条款](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/LICENSE)；沿既有独立官方core边界，不复制或随manager分发 |
| Alpine apk-tools `v3.0.2` 的 [apk-verify手册](https://github.com/alpinelinux/apk-tools/blob/v3.0.2/doc/apk-verify.8.scd)；实际捕获的3.24.2 minirootfs、v3.24仓库签名索引/APK | VM使用原根文件系统公钥，实际apk verify/add校验原包；离线仓库按原索引补齐拆分/条件包，不用allow-untrusted | [GPL-2.0-only](https://github.com/alpinelinux/apk-tools/blob/v3.0.2/LICENSE)；只在丢弃式测试VM使用官方工具，不复制进本项目 |
| Ubuntu24.04 `release-20261017` amd64 cloud image；Rocky9.8 `20260525.0` x86_64 GenericCloud | [Ubuntu固定镜像](https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img) 与 [Rocky固定镜像目录](https://download.rockylinux.org/pub/rocky/9.8/images/x86_64/) 的官方摘要/签名核验；只读基盘加自有overlay，实际init/生命周期与镜像准备分别记证据 | 发行版包按各自许可证，镜像仅本地测试、不随QingNode发行。签名有效、下载成功或启动PID1均不能替代产品验收 |

本批固定源码URL、字节SHA和获取记录分别保留在外层 `batch10-service-sources.md`、`batch10-host-firewall-source-hashes.json`、`batch10-installer-sources.md`、Alpine `supervisor-source-receipt.json`、`libcap-source-receipt.json`。libcap/OpenRC的早期filecap构想已被真实musl失败推翻；当前使用监督程序ambient+no_new_privs并重新验收，不能继续引用早期构想为已支持能力。没有假设gcompat本身授予权限，也没有给系统加载器设置全局filecap。

镜像下载回执另保留 `batch10-vm/image-source-receipt.json`：Ubuntu镜像SHA256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`，官方签名指纹 `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`；Rocky镜像SHA256 `92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8`，官方签名指纹 `21CB256AE16FC54C6E652949702D426D350D275D`。它们只绑定来源与测试输入；执行结果见[BATCH10.md](docs/BATCH10.md)，未验证范围继续明确列出。


## 第11批：文本终端与Unicode宽度数据

任务分组、选择依据、影响预览和普通文本渲染由本项目独立实现。没有新增Huh、Bubble Tea或其他TUI运行依赖，没有引入常驻前端组件；继续使用已存在的`golang.org/x/term v0.45.0`与`golang.org/x/sys v0.47.0`，许可证沿vendor保留。分组与校验是本项目任务入口，不把用户引用的Huh项目当作已链接依赖或已复制实现。

`internal/ui/terminal_width.go`的120个W/F区间从Unicode固定15.1.0数据机械合并，数据文件194188字节、SHA256为`b08191401dc125f4e84ef262a95754faae6b737c79538e17ea9664a63434e94e`；[固定数据](https://www.unicode.org/Public/15.1.0/ucd/EastAsianWidth.txt)和[UAX #11 revision 41](https://www.unicode.org/reports/tr11/tr11-41.html)用于区分宽/全宽。ANSI/OSC/Bidi清理、普通换行与常见组合emoji成簇是独立实现。模糊宽度按1列，组合标记不单独计列，ZWJ/修饰符/区域旗帜/keycap作菜单用途的有限处理；不宣称实现完整UAX #29编辑器，也不把UAX #11当作所有终端字体通用布局规则。

数据使用UNICODE LICENSE V3，当前取得的[许可原始字节](https://www.unicode.org/license.txt)为1995字节、SHA256 `e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96`。完整声明保留在生成的Go源文件，分发文档同时保留如下许可。表和许可的原始获取收据另存本批外层`batch11-unicode/receipt.json`，不以下载成功替代终端/字体实测。

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2026 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```
