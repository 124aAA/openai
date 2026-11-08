# 核心、协议、客户端与平台能力矩阵

## 第11批当前界面与证据分层

0.3.0源码整合前11批能力；本版正式资产、最终SHA和当前运行结果以Release、RELEASE.json及TEST_REPORT给出的来源为准。以下表区分代码能做什么、固定版本基线测过什么，以及本轮没有证据的部分；本轮准确提交、执行命令和结果只记[BATCH11.md](BATCH11.md)。后面历史表保持各自当时的范围，不把旧成功、计划或编译结果转成新验收。

本批最终本地证据绑定`9db2d6f`（运行代码与`801e9fd`相同）：22/22门槛、53/53安装器、Go/race各1686通过/10跳过，官方1.14.3定向114通过/4跳过；同字节Ubuntu24.04.5 amd64/systemd服务生命周期、32/40/80列PTY、实际CLI及两版核心受控传输另列。跳过不算通过；专门重跑与尚未启用项目逐项见[BATCH11.md](BATCH11.md)。这些本地证据不表示远程workflow、手机GUI、公网或原生ARM已经通过。

| 层次 | 当前边界 | 如何核对 | 不能推断 |
| --- | --- | --- | --- |
| 管理器 | 静态Go CLI、Bash引导、本机systemd/OpenRC；状态当前schema9 | `version --json`、`help --json`、候选提交/摘要 | 管理器静态不证明官方核心没有动态加载器 |
| 官方核心 | 默认1.14.0；1.14.3同兼容线候选；管理器协议最低适配版本1.14.0 | 归档摘要、实际ELF架构/加载器、version、构建标签和check分别检查 | 接受版本字符串不证明自定义核心有完整标签；不自动跨到1.15 |
| 协议声明 | 七协议入站、单用户/多用户管理和客户端导出；监听网络与承载业务分开 | `protocols list`的版本化能力JSON、下表 | TCP监听也可能封装UDP业务，不能用一个supportsUDP字段概括 |
| sing-box客户端 | 完整配置固定核对1.14.0/1.14.3，新协议要求明确客户端版本 | 官方解析与受控实际TCP/UDP；运行位置及源码见各批记录 | check通过不能替代代理认证、UDP或公网入口 |
| Mihomo客户端 | 固定1.19.30；provider与完整配置不同，auto容差缺陷保留 | Mihomo实际解析、受控流量、具体策略专门测试 | YAML语法可读不等于Mihomo能用，更不等于FlClash/手机UI通过 |
| GUI与用户网络 | 本轮没有从界面功能自动推造设备验收 | 真正设备导入、目标请求、节点停用负例和独立UDP测试 | 桌面/手机图形界面、用户运营商质量与本机回环不能互换 |
| 人类终端显示 | 普通文本路径，按真实TTY列宽折行；清理终端控制/Bidi；不改raw模式 | 32/40/80列、中文/IPv6/emoji、NO_COLOR/dumb/nonTTY与PTY检查分记 | Unicode宽度表不是所有字体/终端的通用像素布局；PTY不等于每款手机SSH应用 |
| 机器与私有文件 | 全局可选私有执行回执；领域数据按明确JSON或私有导出入口；URI/二维码/完整配置不进折行器 | [任务与机器接口](WORKFLOWS.md)，具体命令`--help` | 回执不是完整State或stdout副本；不能给全部命令追加`--json`，也不能从屏幕换行还原凭据；错误仍可能已提交 |

### 七协议接口矩阵

本表来自当前适配器和`ProtocolCapabilities`，协议业务均可声明TCP/UDP；是否真正到达目标仍须按组合实测。列出的核心版本是本项目固定基线，最低1.14.0，不是对全部上游版本的承诺。

| 协议 | 本机监听 | 独立认证 | 证书与构建条件 | 分享/完整配置边界 |
| --- | --- | --- | --- | --- |
| VLESS REALITY/Vision | TCP | UUID | 服务端REALITY密钥；客户端with_utls；不需要自有TLS证书 | URI与完整JSON/YAML；TLS目标与连接端点独立 |
| SS2022 | TCP+UDP | 服务密钥及独立用户密钥 | 固定2022方法；不使用TLS证书 | 保持原复合密钥字节语义，不能套传统SS密码 |
| Hysteria2 | UDP | 独立用户密码 | 匹配名称证书；两端with_quic；ACME另需with_acme | URI不包含所有性能设置，优先完整JSON/YAML；Chrome指纹/证书算法限制另列 |
| AnyTLS | TCP | 独立用户密码 | 共享受管TLS证书 | 完整JSON/YAML可表达三项空闲设置，URI不能静默丢失 |
| Trojan | TCP | 独立用户密码 | 可信匹配域名TLS；本批仅标准传输 | URI默认Chrome/Ed25519组合明确拒绝，完整原生TLS配置另核对 |
| 传统SS AEAD | TCP+UDP | 独立UTF-8密码 | aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305；无旧流密码 | 不使用SS2022服务密钥/用户密钥拼法，方法分别验证 |
| TUIC v5 | UDP | UUID+独立密码 | 共享TLS证书，两端with_quic；0-RTT默认关闭 | 完整JSON/YAML，无项目已核验的通用分享URI；不套HY2带宽字段 |

服务器远程出口不是客户端导出列表：当前七协议的`client_outbound`均可声明，`server_egress`固定支持原REALITY/SS2022/HY2，其他新协议不能因有导出能力就宣称可作远程出口。SOCKS5、WireGuard及路由策略沿[拓扑说明](TOPOLOGY.md)的独立能力与权限边界。

### 平台与架构证据

| 系统/架构 | 代码路径 | 已有准确基线证据 | 本轮证据边界 |
| --- | --- | --- | --- |
| Debian12/13、Ubuntu22.04/24.04/26.04 / amd64、arm64 | systemd+apt | 第10批source18实际Ubuntu24.04.5 amd64完整安装/传输/升级回退/卸载；另有准确source14核心双启动 | 不能扩大成所有列出版本与ARM原生；本轮重跑项目见BATCH11 |
| Rocky9系 / amd64、arm64 | systemd+dnf、保留SELinux、可选精确firewalld | 第10批source18 Rocky9.8 amd64 Enforcing与运行/持久规则、外部资产保留通过 | 外部真实包过滤路径仍未知，不能关闭Enforcing换取通过 |
| Alpine3.24系 / amd64、arm64 | OpenRC+apk、官方core动态ABI兼容库 | 第10批source18 Alpine3.24.2/OpenRC0.63.2-r0 amd64、musl非root443及完整生命周期通过 | 静态manager可运行不代表ARM版core在musl上已执行 |
| Linux amd64/arm64管理器与探针、Windows amd64探针 | 五个构建目标 | 第10批最终19构建与产物ELF/PE/摘要独立核对 | 交叉编译、配置解析、VM、原生ARM、桌面GUI均单列；无原生Android程序 |

更细的系统版本、包名、capability和恢复边界见[平台矩阵](PLATFORMS.md)；证书、订阅、拓扑和监控的已实现/未测项分别见对应指南。以下各批历史保持原始证据。


第10批当前State9和平台适配状态优先见[PLATFORMS.md](PLATFORMS.md)、[BATCH10.md](BATCH10.md)。前批核心/协议结果保留原提交，不能替代新的发行版、init或架构验收。

## 第09批阶段结果（未发行，按当时源码记录）

最终代码冻结为 `d0fd58a`：targeted8完整25/25项退出0，891项摘要独立审计通过；另补一个未被筛选式选中的能力JSON单测，实际Linux退出0。finalbuild6五步及39项离线发行保护通过，749个源码与7个产物经独立审计v2核对。完整race通过属于full2的 `481113f`，最终提交未重跑完整62项；full2的探针失败已定向复验，Alpine宿主识别失败与Ubuntu元数据夹具33/33分开保留。`client_outbound`与`server_egress`分别登记客户端导出与服务器远程出口，旧`outbound`仅为前者的兼容别名。准确命令与边界见[BATCH09.md](BATCH09.md)。

七协议已实现：原三协议与AnyTLS/Trojan、传统SS AEAD三方法、TUIC。AnyTLS高级设置不能进入URI；Trojan URI默认Chrome/Ed25519组合拒绝；TUIC仅完整配置、无通用URI。传统SS使用同方法独立多用户password，不拼SS2022服务密钥。TUIC分开保存两端参数，心跳向Mihomo精确换算毫秒，0-RTT关闭。第09批当时State为schema8，旧1–7内存兼容，当前写入格式为第10批schema9。基线502cfda的8/8项通过；第一阶段1a7d58的10/11保留CLI端口冲突，521b9a7复验11/11通过；第二阶段ca0df8a定向25/25项通过，保留targeted3中断和targeted4真实失败。完整回归另列。字段、场景和限制见[PROTOCOLS.md](PROTOCOLS.md)，准确证据见[BATCH09.md](BATCH09.md)；以下旧批表不替代当前源码验收。

## 第08批监控、流量观测和到期范围

实现说明见[MONITORING.md](MONITORING.md)，准确当前源码执行状态见[BATCH08.md](BATCH08.md)。以下为接口和限制，不能替代实测。

| 能力 | 实现条件 | 验证边界 |
| --- | --- | --- |
| 有限监控 | 私有计划、分信号状态、时间/有效载荷/并发/历史预算；主动probe互斥 | 服务PID资源、服务器出站、经代理和公网可达分开，缺失为unknown |
| 有限恢复 | 显式restart、连续失败/独立本机证据/冷却/滚动次数、动作前复核、try-restart | 默认只观察；不启动人工stop、不回滚调参；共享连接会断，下一轮完整复验 |
| 通知与timer | 明确私有配置的webhook/Telegram，状态变化去重与有限重试；timer仅生成 | 外部送达、真实systemd安装/自启/停用另验，不自动部署 |
| 官方核心API | 1.14.0/1.14.3固定公开gRPC-Web契约，显式本机地址与秘密 | 客户端只读但官方接口还含管理能力；不暴露公网，缺统计不计零 |
| 全局与连接流量 | 当前核心生命周期累计/差分、reset快照、稳定标签映射 | 事件无序号/有限历史/缺口，unknown归属；无持久用户计费/硬配额 |
| 代理凭据到期 | UTC稳定Node/User/可选Device绑定，预览、共享整批阻止、一次Apply | 下载到期独立；默认监控不执行，仅--apply-expiry；旧会话/新认证分别实测 |
| State与迁移 | schema7真实字段，旧1–6内存兼容，独立monitor资产列缺项 | 旧管理器拒绝，完整迁移不能冒称已带监控秘密/政策/历史 |

### 第08批已执行结果与源码边界

| 准确源码 / 轮次 | 实际结果 | 不能扩大为 |
| --- | --- | --- |
| 8e752238 / full1 | 44项43项0；唯一Alpine原生安装33项中32过、宿主OS断言失败保留；普通Go/race各7包、vet、权限、netem两版、三协议/Mihomo、五包构建/归档、39项离线发行保护通过 | 44项全过、支持系统真机安装、最新补丁的全量race |
| 8e752238 / 长续期门槛 | 候选1.14.3真实自然续期601.23秒，PID10074保持，证书序列/有效期更新，账户与HTTPS/UDP前后可用 | 公共CA、真实systemd MainPID或所有版本长期保证 |
| 9b6bb79 / targeted5 | 15/15项0；两版API真实kill/wait/restart、epoch基线/缺口/重复保护；两版真实UDP预检及错误凭据负例保留 | 持久用户计费、UDP被HTTPS成功代替、全量44重跑 |
| 9b6bb79 / finalbuild | Windows独立5构建步骤、5包架构/内外摘要/allowlist/6段许可逐包核对；Windows助手version/help/local退出0 | Linux/ARM原生执行、qingnode监控服务、Android/iOS/客户端UI |
| 91db289 / targeted6与build2 | 窄Linux9项7项0、static-cli与snapshot-monitor-race各1，direct合法空摘要被helper误拒绝的回归保留；build2五步成功也不等于功能正确 | 删除失败断言、将可打包写成功能通过或最终包 |
| 4bd1af9 / targeted7修复闭合 | 窄9项全部0，QEMU0且严格提取完成；8worker持真实管理锁配置一致、State/代不变、原wrapper busy/pending保护保持；原5项CLI回归、相关Linux race/vet通过 | 最终源码全44项或全量race重跑、真实systemd验收 |
| 4bd1af9 / finalbuild3最终五包 | 独立Windows构建五步骤/五包与39项离线发行保护完成，749项摘要独立审计通过；实际包SHA、审计SHA及复现driver见BATCH08 | ARM原生执行、安装/发布授权或公网/UI验收 |

本批真实systemd故障恢复/timer生命周期、公共Telegram/webhook送达、公网客户端与移动UI、原生ARM仍未验证。独立monitor目录未纳入QNBK3完整资产，发现时明确受限缺项；State的API设置/到期计划沿配置恢复，目标机另审监控授权。完整源码、复现命令、SHA与保留失败见[BATCH08.md](BATCH08.md)；接口和关闭/撤回流程见[MONITORING.md](MONITORING.md)。

## 第07批证书与迁移的既有范围

下表是源码接口范围。解析、传输、真实宿主与公网是不同证据，当前实际执行统一绑定 [BATCH07.md](BATCH07.md)，不把后文各前批的“本批成功”转记到第 07 批。

| 能力 | 服务端 / 版本 / 条件 | 客户端与验证边界 |
| --- | --- | --- |
| 共享证书资源 | schema6 稳定 ID、PEM/file/ACME；旧1–5只读迁移，普通节点编辑独立复制，共享更新显式确认；显式导入/更新额外校验完整证书路径 | 本机/附带根的验证不代表其它客户端信任；只导出入口地址、SNI 与原代理认证，不导出服务端私钥/DNS Token |
| ACME | 固定官方1.14.0/1.14.3，`with_acme`；新 `certificate_provider` 的 HTTP-01/DNS-01/TLS-ALPN；旧资源保留默认与存储 | 解析不等于签发，公网80/443或真实DNS权限另验；三DNS提供者仅alidns/cloudflare/acmedns |
| HY2 证书算法 | 优先P-256/P-384、RSA；旧Ed25519资源/备份保留，sing-box默认Chrome客户端不接受该组合，显式关闭的原选择保持 | 服务端结构、客户端导出、X.509合法、核心互通、Mihomo解析、GUI导入分别验证；不默认关闭指纹 |
| 状态 | 只读证书/匹配私钥/SAN/有效期；`status --id` 限量读取当前unit日志观测事件 | 默认warn可能没有成功事件；缺失时间与签发中状态保持未知，NotBefore不代替签发时间 |
| 受管 PEM 更新 | 候选验证、原子新代、旧材料保留、失败恢复；真实派生影响决定服务动作 | 没有通用热重载或无损承诺；外部文件监视与文件对一致性另验 |
| QNBK3 | 完整迁移typed v1，原AES-GCM/KDF保护；旧QNBK1/2继续可读 | 完整需资产覆盖与停止证明；外部文件只能列缺项受限，未知/恶意条目拒绝 |
| 一致性短停 | 持管理锁，明确 `--quiesce`，unit/PID/控制进程/cgroup确认，自有目录两次清单核对 | 不接管别的服务；无可证明停止能力时不可用，不将命令错误当已停 |
| 目标恢复 | 本机路径/服务UID/GID映射、私有暂存、资产journal、State候选事务、原恢复点保护 | 不执行归档服务命令，不覆盖核心程序，不自动改DNS/NAT/公网入口 |
| 保留策略 | 数量/时间/容量，私有自有备份索引及摘要；当前点与最近完整迁移点始终保留 | 两点不同时可能保留至少两份并暂超上限；不扫描删除任意qnbk或用户目录 |

命令与数据格式见 [CERTIFICATES.md](CERTIFICATES.md)、[MIGRATION.md](MIGRATION.md)。默认核心仍为1.14.0，没有因证书功能自动升级到候选或跨兼容线。

本表区分“管理器允许选择”“上游提供能力”“配置能解析”“实际传输了数据”和“真实宿主验收”。允许选择一个版本，不代表该版本已在本项目全套验收通过；历史结果也不能替代当前提交的实测。

当前管理器仍使用Bash引导、静态Go CLI、独立下载的官方sing-box与本机systemd/OpenRC。State（保存节点身份和用户选择的数据）当前为schema9；schema1–8只读内存兼容，保留旧客户端端口、默认direct、原证书与ACME路径，写入留原件。第08批的schema7和第09批的schema8是各自历史格式。默认配置备份保持QNBK1/2，完整迁移另用QNBK3 typed v1，旧二进制拒绝新State/包。第01批提交 `ab14c74102f161ec80ebc33f514c5aba6d714180` 的证据见[BATCH_01.md](BATCH_01.md)，此前发行证据见[TEST_REPORT.md](TEST_REPORT.md)；各后续批次结果分别记录，第07批见[BATCH07.md](BATCH07.md)，第09批见[BATCH09.md](BATCH09.md)，当前平台适配见[BATCH10.md](BATCH10.md)。

第 02 批分路径网络测试使用同一核心兼容线，默认核心仍为 1.14.0，不因测速自动升级。新能力的实现、当前提交实测和未验证项单列在本文件末尾及 [BATCH_02.md](BATCH_02.md)；下方核心/协议表中的已有“本批”证据属于第 01 批，不视为第 02 批已重跑。

## 核心版本与构建能力

核对时间：2026-10-13。官方 [v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3) 为该时点的 1.14 兼容线稳定补丁。配置依据固定到 `v1.14.3` / `7054cac5124465ffdb145870d7c01885566711b1`，不把滚动官网里的 1.15 字段带入现有配置。

| 核心 | 管理器规则 | 第 01 批证据 | 默认选择 |
| --- | --- | --- | --- |
| 官方 1.14.0 | 接受，内置 Linux amd64/arm64 官方归档摘要 | 本批 Linux 三协议 TCP/UDP、服务端/客户端/ACME 解析、归档安装幂等通过；实际 PID 3662 和同一连接 81 连续 TCP 帧保持，实际进程重启/注入故障恢复通过 | 继续锁定 |
| 官方 1.14.3 | 接受 1.14.x 正式版本；非默认版本必须显式提供官方归档 SHA-256 | 两架构归档摘要已核对；amd64 三协议 TCP/UDP、配置/ACME 解析、候选安装通过；实际 PID 4002 和同一连接 127 连续 TCP 帧保持，实际进程故障恢复通过；真实 systemd 更新恢复尚未验证 | 保持候选，不自动升级 |
| 其他 1.14.x 正式补丁 | 版本范围允许，仍需归档摘要、架构、版本、构建能力与候选配置检查 | 本批没有逐个补丁重跑三协议和恢复验收 | 不自动选择 |
| 1.15、其他兼容线、预发布和第三方核心 | 拒绝；必须先更新适配与测试 | 未适配 | 不使用 |

`with_quic` 等是核心编译时启用功能的“构建标签”，不是运行时配置开关。必须分别核对服务端与客户端需要的标签；版本号相同但标签缺失仍不能使用相关能力。本项目安装器与既有二进制 VerifyCore 均精确核对 `with_quic`、`with_utls`、`with_acme` 标签；仍校验本地摘要与锁定版本，不自行编译核心。

| 功能 | 服务端要求 | sing-box 客户端要求 | 固定来源 |
| --- | --- | --- | --- |
| VLESS + REALITY + Vision | VLESS/REALITY 实现及 `xtls-rprx-vision`；服务端无需用 uTLS 模拟客户端指纹 | 本项目导出启用 uTLS，要求 `with_utls`；客户端使用公钥与 short ID，服务端使用私钥与握手目标 | [option/vless.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/vless.go)、[option/tls.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/tls.go)、[utls_client.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/common/tls/utls_client.go) |
| Shadowsocks 2022 | 本项目仅生成 `2022-blake3-aes-256-gcm` 多用户配置 | 支持该方法，以及 `服务密钥:用户密钥` 的客户端密码 | [option/shadowsocks.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/shadowsocks.go)、[Shadowsocks 说明](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/inbound/shadowsocks.md) |
| Hysteria2 | `with_quic`；TLS 证书或 ACME；不生成 Hysteria 原生配置 | `with_quic`；正常验证证书；客户端没有服务端 ACME 申请配置 | [option/hysteria2.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/hysteria2.go)、[include/quic.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/include/quic.go) |
| HY2 ACME | `with_acme`；1.14 的 `tls.certificate_provider`，使用 `type: acme`、域名、邮箱与项目缓存目录 | 只使用域名与正常证书校验，不申请证书 | [option/tls.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/tls.go)、[include/acme.go](https://github.com/SagerNet/sing-box/blob/v1.14.3/include/acme.go)、[证书配置](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/tls.md) |

官方默认标签的完整列表在 [release/DEFAULT_BUILD_TAGS](https://github.com/SagerNet/sing-box/blob/v1.14.3/release/DEFAULT_BUILD_TAGS)；Windows 另有 [DEFAULT_BUILD_TAGS_WINDOWS](https://github.com/SagerNet/sing-box/blob/v1.14.3/release/DEFAULT_BUILD_TAGS_WINDOWS)。[固定版本构建说明](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/installation/build-from-source.md)解释标签和平台依赖；上游文档列出的功能不等于 QingNode 已实现这些功能。

## 协议与客户端

下面三协议表与客户端解析/流量结果保留第01批历史范围；当前七协议和第09批已完成/待执行结果见[PROTOCOLS.md](PROTOCOLS.md)、[BATCH09.md](BATCH09.md)。`protocols list`的outbound=true表示客户端配置导出，远程Egress仍限SOCKS5/REALITY/SS2022/HY2/WireGuard，不自动新增四协议远程出口。

| 本项目协议 | VPS 监听 | 本项目生成的认证/TLS配置 | 验收入口与边界 |
| --- | --- | --- | --- |
| `reality` | TCP | 稳定用户 ID 作为用户名；UUID、Vision；REALITY 私钥、公钥、short ID、SNI/握手目标分别按服务端/客户端生成 | 官方核心测试同时验证代理 TCP 与承载的 UDP；UDP 成功不表示服务端额外打开 VLESS UDP 监听 |
| `ss2022` | TCP + UDP | 32 字节 Base64 服务密钥和独立用户密钥；客户端组合密码；URI 按 SIP002 编码 | 官方核心 HTTP/UDP 回环；真实 systemd 维护脚本使用 SS2022 的一条持续 TCP 连接 |
| `hysteria2` | UDP / QUIC | 用户密码；PEM 或 ACME 证书；客户端正常验证 TLS | 官方核心 TCP/UDP 回环使用私有测试 CA，仅测试客户端额外添加该 CA；正式导出不关闭校验。真实 ACME 签发/续期另验 |

| 客户端/格式 | 版本与范围 | 配置解析证据 | 真实使用证据的限制 |
| --- | --- | --- | --- |
| sing-box JSON | 测试锁定官方 1.14.0；1.14.3 为补核候选 | 本批两版本 `TestOfficialCoreAllExportedConfigs` 和 ACME 语法均通过，包含三协议服务端与客户端 | 两版本 `TestOfficialCoreEndToEnd` 的 Linux 回环真实 TCP/UDP 均通过；不等于桌面/手机 UI 或公网成功 |
| Mihomo YAML | 测试锁定官方 `v1.19.30` amd64-compatible | 本批 `TestMihomoExportAcceptedByOfficialParser` 官方 `-t` 检查完整三协议 YAML 通过 | 不宣称 Mihomo 流量、GUI 导入或移动客户端已通过本批实测；其他版本须自行验证 |
| provider YAML | 使用相同 Mihomo 节点对象，外包 `proxies` | 生成一致性由业务测试覆盖，完整 YAML 的官方解析另测 | provider 文件接入客户端本体与更新机制未在本批实现 |
| 分享 URI / Base64 / 二维码 | 三协议 URI；Base64 和二维码包装相同 URI | 业务测试覆盖编码、地址、名称和凭据 | URI 格式合法不等于任意应用都支持该协议、方法和参数 |

服务端使用稳定节点 ID 作为 `tag`，稳定用户 ID 作为用户名。展示名、客户端服务器地址和 REALITY fingerprint 的变更能否免重启，由本批的真实派生配置比较决定。停用节点的 `info --show-secrets` URI 和导出可用性也参与客户端影响比较。SNI、监听端口、认证材料、证书或核心/服务输入变化仍会按需应用，不能把“地址”或“名称”作为固定免重启白名单。

## 第01批当时的平台与服务证据

本节保留第01批当时的安装范围与测试环境，不表示当前仍拒绝Alpine。第10批的Rocky/OpenRC实现、准确VM版本与独立未验收项以[PLATFORMS.md](PLATFORMS.md)、[BATCH10.md](BATCH10.md)为准。

| 平台 | 安装器识别 | 管理器构建/运行 | 真实宿主与网络证据 |
| --- | --- | --- | --- |
| Debian 12/13 amd64、arm64 | 识别并要求 PID 1 为 systemd | Linux 两架构构建是原发行门槛 | 本批没有逐一实机安装；识别测试不等于 apt/systemd 实机验收 |
| Ubuntu 22.04/24.04/26.04 amd64、arm64 | 同上 | 同上 | 现有 CI/release 的 Ubuntu 24.04 一次性 runner 会执行真实 systemd 脚本；本批未推送时不能引用它为本批成功 |
| Alpine amd64 隔离 QEMU | 不在受支持安装器系统范围 | 本批 QEMU TCG、4 CPU/4 GiB、Linux 6.18.52-0-virt、Go 1.26.8、gcompat：全项目 Go 与 1.14.0/1.14.3 官方核心测试实际通过 | 真进程 PID、同连接持续帧和注入启动故障恢复已验；没有 systemd，不计 MainPID/完整服务生命周期，也不代表 Debian/Ubuntu 安装成功 |
| Linux arm64 | 支持发行交叉构建及官方归档 | 原生 ARM 执行与 amd64 交叉构建分开记录 | 本批无原生 ARM 主机；amd64 通过不能替代 ARM 运行 |
| Windows/macOS | VPS 管理器不支持作为本机服务平台 | Windows 构建/本机工具检查不能计 Linux 管理器测试 | 官方客户端可能可用；本批没有客户端 UI/公网验收 |

第01批当时的轻量服务只有 `qingnode.service` 和专用账户，防火墙只处理可核验归属的项目UFW规则；后续可选订阅、监控与firewalld分别按对应批次扩展，仍不接管别人的服务。ACME、BBR、云安全组、NAT、公网双栈和客户端UI属于独立验收范围。

## 不停流量的验证边界

本批降低维护中断的方法是：服务器派生配置和宿主输入不变时保存新 State/导出来源/历史，不调用服务重启。运行配置改变仍使用已校验候选与原子应用，可能中断连接。本项目没有承诺任意配置热更新或零中断。

上游比较中包含 [a364ff4：移除未实现的 manager 热重载](https://github.com/SagerNet/sing-box/commit/a364ff4794f0f8715ff26b11dc52402771415525)。控制 API 的存在不能证明连接会保留。本项目也没有把 `systemctl restart` 改名为 `reload` 来宣称零中断。

真实证明必须同时看到 MainPID/进程启动身份保持，以及同一条持续 TCP 连接在修改前后传输校验帧；只看 mock 调用次数、配置解析或新建请求成功都不够。

第 01 批在官方 1.14.0/1.14.3 真实核心进程中分别观察 PID 3662/4002，以及同一连接后台持续校验 81/127 帧，元数据维护期间连接不重建；运行端口变更和注入启动失败后的真实进程恢复通过。进程由测试直接管理，因此这些 PID 不能写成 systemd MainPID。真实 systemd 入口仍未在本批执行，默认核心保持 1.14.0；帧数也不能用于声称吞吐提升。

真实 systemd 的可重建空白主机入口为：

```bash
sudo bash scripts/acceptance-vps.sh --disposable /绝对路径/完整发行包 --core-archive /绝对路径/官方归档
```

脚本会安装临时 SS2022/REALITY 节点、观察真实 systemd、执行维护与恢复，并在成功后卸载；失败保留安装现场。不要在已有 QingNode 或生产主机运行。当前批次是否真正执行成功，以 BATCH_01 的本批记录为准。

## 第 02 批网络测试能力

实现与证据是两列不同的事实。下面列出的配置边界来自源码和固定上游；是否真正执行通过仅以 [BATCH_02.md](BATCH_02.md) 所绑定的本批测试记录为准，不引用上方历史结果冒充复验。

| 能力 | 本批实现 / 条件 | 独立验收边界 |
| --- | --- | --- |
| 只读本机诊断 | `local` 不接网络目标；平台/权限允许时读取本机指标 | 本机资源可读不表示代理可用；procfs 不存在时指标未知 |
| 服务器出站 | `server-outbound` 明确目标、发起端和地址族；关闭环境代理 | 只代表命令所在服务器到目标，不能推断用户运营商质量 |
| 客户端经代理 | `client-proxy` 独立官方核心；本机临时 mixed 入站，HTTPS 经 HTTP CONNECT、UDP 经 SOCKS5，只有所选代理出站，失败不 direct 回落 | 核心服务端/客户端标签分别验证；三协议真实 TCP/UDP、认证失败、核心退出与清理另外实测 |
| HTTPS / 有限下载 | 正常证书验证、状态、首字节、原始请求样本、单连接/显式并发与有限有效载荷 | 应用端到端时间，外层代理握手和目标 DNS不能拆时未知；不声明纯网络 RTT或带宽容量 |
| 受控 UDP | SOCKS5 UDP ASSOCIATE 或明确直连；版本帧、本次随机标识、序号与超时，丢包/RTT/相邻 RTT 差 | UDP DNS 成功不能代替丢包/抖动验收；无回应的具体封锁位置未知 |
| 条件对比 | 版本化自动报告，条件一致且结果有效才比较；保留原始样本、成功率、中位数与 p95 | 缺失值不是零，取消不是通过，小样本不声明高置信或性能提升原因 |
| 独立 `qingprobe` | Linux/Windows 测试助手，不加载服务端 State 或调用服务管理 | 本批原生 Windows amd64、官方 1.14.3 的 SS2022/TCP→受控 HTTPS、代理停用负例与取消/崩溃清理已执行，范围见 BATCH_02；其他协议/UDP/GUI/公网分别计证据，没有原生 Android/iOS 程序 |
| 两台受控机器 | 直连 `controlled-link` 与可选 iperf3/IRTT 操作流程，独立总超时 | 工具不解析分享链接；TUN/固定转发路径须目标日志/路由/代理禁用负例证明，不靠 HTTP_PROXY |
| 手机客户端 | 现有客户端手动选节点、核验路由、受控 HTTPS/UDP 和记录网络 | 手机 GUI、系统 VPN、后台保活与公网双栈须实机另验 |

本批不增加 State 字段、性能参数或默认公网测速站；自动 JSON 报告与原 `public-check` 手动历史分开。完整使用和指标定义见 [NETWORK_TESTS.md](NETWORK_TESTS.md)。

## 第 03 批性能选择、宿主参数与 DNS

下表是实现接口和固定来源范围，实际本批执行单列在 [BATCH_03.md](BATCH_03.md)，不将前两批流量或宿主历史成功搬作本批重跑。字段方向、限制、命令与恢复见 [NETWORK_PERFORMANCE.md](NETWORK_PERFORMANCE.md)。

| 能力 | 已实现接口 / 固定适配范围 | 证据与限制 |
| --- | --- | --- |
| HY2 服务端/客户端独立选择 | 服务端方向上限、客户端方向预期、非 Brutal、BBR 档位和有限 QUIC；未保存保留旧默认 | 每条 QUIC 协商不是 VPS 全局硬整形；下载不能证明上传能力 |
| sing-box 1.14.x | 两端分别检查正式兼容线及实际 `with_quic`；固定源码核 1.14.0/1.14.3 | 本批两版本 HY2 TCP/UDP 和同连接维护专项实测通过；Chrome 默认保留且说明覆盖；其它补丁不冒充实测，默认不升级 |
| Mihomo 1.19.30 | 显式 `N Mbps`、BBR profile、initial/max 成对接收窗口；原生 QUIC 选择可表达 | 两核心的首请求/UDP/禁用负例及各 count=3 实际通过；初始化后才测，无请求重试；不代表 GUI。其它版本不猜兼容，非等价字段默认拒绝丢失 |
| URI / QR / Base64 | 必要连接信息保持 | 不能完整表达性能选择，默认拒绝静默丢失；完整配置单独导出 |
| 影响预览 / 一次应用 | 实际服务器、客户端和宿主派生比较；客户端选择免重启，运行变化按需原子应用 | 凭据身份不变；损坏派生文件和 rollback 仍完整校验 |
| 宿主网络状态/计划/恢复 | 只读可用/默认 TCP、实际接口队列、缓冲/错误/资源；有限 sysctl + v1 原始快照、v2 pending、v1/v2 active | 系统 TCP BBR 不等于用户态 QUIC BBR；不加载模块、不改现有接口 qdisc，外部手改条件保留；有效内存取宿主与可见 cgroup 余额最小值，不保证总 RSS |
| DNS 诊断/项目 resolver | 查询耗时、明确预期答案、IPv4/IPv6、system/UDP 局部解析器 | 没有 expected 时正确性未知；不写 resolv.conf、不强制 DoH，客户端 bootstrap 独立 |
| 方案关联前后对比 | 声明配置摘要变化，其余报告条件保持 | 不改原报告、不自动推断显著收益或变化原因、不自动调参 |
| 受控网络/资源验收 | opt-in netns/veth/netem + 真实 HY2 HTTPS/UDP、UDP-only drop、128 MiB 服务端测试组 | b4e6bb0 两核心全部子项实测通过，原始样本/资源/qdisc 保存于 BATCH_03 记录；不承诺公网/手机或性能增益，其它环境缺模块/权限仍标未验证 |
| 源码回归与最后补丁 | b4e6bb0 全项目普通 Go/全量 race/vet、候选核心实际退出 0；最后源码 b698d04 普通全项目、相关 race、vet 也已退出 0 | b698d04 只跑相关 race，不能声称最后源码已跑全量 race；旧实现的非法文件权限/悬空输出边界负例已实际失败 |
| 安装器、五包与发行保护 | b698d04 管理器两包/助手三包及归档契约、发行保护 38、维护观察器 3、ShellCheck/Bash 实际通过；安装器元数据 32/32 通过，546.813 秒，final2 完整结束 | b4e6bb0 Alpine 安装器 31/32，后续夹具被 40 分钟外层预算中断的历史保留；Ubuntu 24.04 只是元数据夹具，不等于 Ubuntu 实机/公开发行；两个修复前负例仍退出 1 |
| 最终预览包 | 最终构建修订、架构、原生执行与包冒烟以交付目录 build-receipt / QA / 交付说明为准 | 不把编译当执行；包命令冒烟不代替协议传输或服务生命周期 |
| 原生 Windows 助手复验 | b4e6bb0 的 probe/probecli/qingprobe 测试和 vet 实际退出 0，回执绑定提交；相关包在 b698d04 未变 | 与 Linux 服务、Windows 三协议全传输/UDP、GUI 和公网证据分开 |

第 03 批 schema 2 的只读兼容不使旧二进制理解该格式；当时恢复旧快照或 rollback 仍写 schema 2，不能作为自动降级管理器的方法。原始 schema 1 材料保留供独立验证的离线恢复，未完成事务须用理解其格式的管理器显式处理；不能改 schema 或删字段伪装兼容。宿主参数快照独立于节点 State/备份，节点 rollback 不擅自恢复全机网络。全项目 Go/race/安装/构建和真实 systemd/公网证据各自见该批记录，专项成功不代替这些门槛。final1 已闭合的检查文本来自原串口配对提取，标记 source_serial_extraction，不冒充 guest 原始文件；整轮未完成和实际失败均保留。

## 第 04 批 NAT、双栈与连接端点

本表列实现范围；实际本批执行、源码提交、失败与跳过单列 [BATCH04.md](BATCH04.md)，用法见 [ENDPOINTS.md](ENDPOINTS.md)。上方前批历史成功不算本批重跑，以下“可声明”也不表示公网已经可用。

| 能力 / 选择 | 管理器及固定上游范围 | 需分别核验的证据 |
| --- | --- | --- |
| 本地与连接端口 | Listen/Port 供入站与宿主；Host/ConnectPort 供客户端；旧schema1/2内存迁移显式等于旧Port | 旧身份/原URI、备份恢复、外TCP30000→内443、HY2独立UDP映射；不能以出口IP证明入站 |
| 多连接入口 | 默认default、最多16个额外稳定ID；所有URI/JSON/YAML和私密Profile可按--endpoint选择 | 配置解析、确实走指定入口、代理停用后失败、摘要/历史失效；SS2022单入口TCP/UDP同外部端口 |
| IPv4 | 0.0.0.0按固定核心IPv4绑定；具体本地IPv4和客户端IPv4可分别声明 | 本机绑定/回环、生产入站、外部认证；无IPv6不应使IPv4节点失败 |
| IPv6字面/域名 | 标准序列化IPv6括号；新输入去外括号，域名A/AAAA不覆盖用户声明 | URI/客户端解析、真实IPv6流量、坏AAAA/不可达IPv6；缺IPv6环境单列未验证 |
| ::自动双栈 | 1.14.0/1.14.3 ListenOptions没有v6only/ipv6_only/dual_stack字段；沿核心通用TCP/UDP策略 | 同一真实socket分别收发IPv4/IPv6；不能从proc tcp6行、全局bindv6only或解析通过推出保证双栈/严格v6only |
| 本地冲突 | 传输层+实际地址范围，具体不同IP可同端口；不确定通配交实际候选绑定 | 同协议真实冲突拒绝、TCP443/UDP443共存、持有候选socket/旧进程归属、竞争失败恢复；不是未来端口预留 |
| NAT向导/材料 | 明确填写映射，材料version1列所需TCP/UDP、摘要与unknown；cloud_nat_changed=false | 云厂商、DNS、公网与实际客户端分别验；不会自动创建或修复映射，ACME另需TCP80 |
| 本机能力 | 架构/init、当前进程权限与可见内存/容器、固定内核值、TUN/路径访问位，报告version1 | available与exercised分开；目录未实际写、TUN未打开/创建、远端unknown；不代表专用服务账户 |
| 局部回环 | TCP4/UDP4/TCP6/UDP6自有临时socket，32字节请求/响应；可skip | 绑定与收发分别报告，不证明代理认证、NAT、公网或另一族；取消关闭自有资源 |
| 免重启与恢复 | 遍历全部端点×用户的真实客户端派生；服务器/宿主未变时沿原服务状态 | 原PID和同一持续TCP流须真实观察，mock仅补充；派生损坏/rollback/失败恢复仍测试 |
| WireGuard / 接口拓扑（第 04 批当时边界） | 固定核心有with_wireguard等上游能力；第 04 批未实现模型/命令，第 05 批见下表 | 客户端连接“端点”与sing-box顶层wireguard endpoint仍是两种对象；不能混同前批证据 |
| 本批实际回归 | e153add 的全项目 Go、全量 race、vet，两核心三协议/受控 NAT/单监听双栈/持续流，Mihomo 解析互通，ShellCheck、发行保护 38/38、维护观察器 3/3 均退出 0 | full1 已完整结束；真实 Alpine 安装器 32/33 退出 1，Ubuntu 标识夹具 33/33 退出 0；不等于真实 Ubuntu/systemd、公网或手机验收，分轮失败原件保留 |

第 04 批交付的 schema3 已由当时旧二进制明确拒绝；该批恢复仍生成 schema3，不是程序自动降级。默认核心继续1.14.0，1.14.3作为候选独立核验，不因NAT或双栈选择自动升级。该批最终构建、原生执行、官方解析/流量、真实服务与公网边界以 BATCH04 和对应交付回执为准。

## 第 05 批中转、链式出站与用户态 WireGuard

下面是当前源码和固定版本接口的能力范围，实际执行、失败、跳过与提交仅以 [BATCH05.md](BATCH05.md) 为准。历史三协议或 WireGuard 握手不能代替本批整条链路验收。

| 能力 / 选择 | 管理器与固定核心范围 | 需分别核验的证据 |
| --- | --- | --- |
| TCP/UDP 端口中转 | sing-box direct 入站固定 override_address/override_port；默认 loopback，明确 network | TCP 与 UDP 实际目标数据、不同传输同端口、本机冲突、公开范围；此入站无代理用户认证 |
| 远程出口 | SOCKS5、VLESS REALITY、SS2022、HY2；旧 Node 空引用仍 direct，远端凭据独立 | 服务端/客户端版本、标签、错误凭据、TCP/UDP、所选出口停用负例；客户端导出不泄漏内部认证 |
| 单条 detour 链 | 固定 1.14.0/1.14.3 Dial 语义；只保存上游稳定 ID，不堆同层 bind/source 字段 | 每一段与端到端分别测、源 IP/目标日志；不能相减耗时猜握手，不能自动 direct 回落 |
| UDP 能力 | 同时核对实际载荷及每段协议自身的 TCP/UDP 需要；SOCKS5默认只声明 TCP | SOCKS UDP 的 TCP 控制与 UDP 数据、HY2/WG 的 UDP 上游、实际受控序号回应；声明不是实测 |
| 用户态 WireGuard | 顶层 endpoint，`system:false`，服务端/测试端分别要求 `with_wireguard`+`with_gvisor`；不创建宿主接口 | 双端 HTTPS/UDP 目标数据、AllowedIPs 源范围、出口 IP、错误密钥、停止落地、固定 UDP4/UDP6 socket；握手不等于落地可用 |
| WireGuard 接收权限 | 实际使用的主动出口新入流显式 reject；被动监听且明确 `ReceiveEgressID` 才可作落地，接收策略全部候选拒绝自回指 | 两版核心修前新 TCP/UDP 实际抵达保护目标，修后目标计数为零且正常 HTTPS/序号 UDP 继续；不只检查配置字符串 |
| WireGuard 网络条件 | 固定 1.14.3 在默认接口缺失时会暂停 WG；仅有监听和进程不能证明数据通路 | 第05批 A/B 保留只 lo 的失败；自有测试接口后两核心数据通过，不自动修改用户默认路由 |
| 双端配对 | 各端私有导入 JSON、逐端说明、无凭据状态 manifest；外部/本地 UDP 端口分开 | 只生成未应用；两端不能本地原子提交，需各自预览/应用/撤回，不接管 wg0/已有 Peer/路由/DNS |
| 固定/显式主备 | 保存应用层目标、失败/恢复阈值与冷却；仅 `health --apply` 累计，`--watch` 有限前台重复 | 真实选定路径探测、未知/取消/本机失败、冷却防抖、恢复、提交前绑定重核；共享核心重启不迁移现有 TCP |
| 主备报告与历史 | 独立 version1 报告/观测，探测预算 `measurement_budget_ms` 与事务 `apply_elapsed_ms` 分列 | 选择和观测写入失败分开；`selection_applied:null` 表示事务结果未知；不能将报告失败解释成配置一定未变 |
| 拓扑版本/恢复 | State schema4，旧1/2/3内存兼容、默认 direct；备份仍v1/v2，原材料保留 | 身份/旧URI、备份/回退、被引用删除拒绝或显式批量迁移、完整候选失败恢复；旧管理器不直接读取新格式 |
| 快照外层保护 | 拒绝重复字段及大小写/Unicode折叠别名，防止后值覆盖版本/拓扑；不改变保存核心配置内部语义，不升备份v1/v2 | 修前接受未来格式/State及拓扑覆盖的真实见证，修后拒绝；正常旧身份、明文核心证据与认证备份恢复对照独立记录 |
| 自动报告路径绑定 | direct 默认 Profile/Report v1；内部出口用显式 v2 `server_path_sha256`，只含摘要 | 入口客户端摘要相同而内部路径不同仍拒比；未用出口/未选备用不改实际路径摘要；不证明远端当前配置 |
| 平台与权限 | 既有 Linux 管理器/服务；独立 Linux/Windows helper 测试入口；WG用户态不需给整个服务 CAP_NET_ADMIN | 原生系统、Linux netns/veth、真实 systemd、ARM、GUI、两台公网主机分别验；无原生Android/iOS程序 |

第05批当时的restore/rollback写schema4，当前第10批写schema9；旧原件只供理解其格式的管理器或独立离线恢复验证，不提供自动降级。默认不安装Realm/GOST或系统WireGuard，不安装新内核或外部模块。固定上游接口与许可见 [THIRD_PARTY.md](../THIRD_PARTY.md)，命令、字段与撤回见 [TOPOLOGY.md](TOPOLOGY.md)。

第05批准确代码`91b6ea131da1588d381d432c17c1000e7dec35de`的full4实际完整结束：29项中28项退出0，唯一非零是原始Alpine安装器32/33；Ubuntu24.04标识夹具33/33单列通过，不当作真实Ubuntu。普通Go、全量race、vet、两核心真实中转/链/WG、UID65534、Mihomo与发行源码检查分别见BATCH05。Windows原生测试实际在079487ef退出0，后续37个相关Go源原始SHA未变，不移名成91b原生执行；真实systemd、原生ARM、GUI和公网仍未提供。最终包修订与运行结果以本批交付收据为准。

## 第 06 批：设备与订阅（未发行源码）

| 能力 | 实现边界 | 本批证据 |
| --- | --- | --- |
| 批量入口与设备绑定 | 三协议、明确用户/端点、多绑定/标签、稳定唯一名称；内部落地认证不导出 | targeted2及准确c89f7d1的full9解析/三协议TCP与序号UDP/关闭代理负例通过；历史full7证据恢复另列[BATCH06.md](BATCH06.md) |
| sing-box 1.14.0/1.14.3 | 完整配置、集合、Selector/URLTest；有序fallback与独立URLTest timeout明确拒绝 | targeted1两版解析、三协议TCP/UDP及自动容差通过；HTTP健康不证明UDP |
| Mihomo 1.19.30 | 完整配置/provider、select/fallback；完整auto因首成员容差缺陷默认拒绝，仅显式allow_degraded_auto带警告降级 | targeted1自动容差实际失败；targeted2三协议TCP/UDP、三阶段有序fallback及缺陷识别/默认拒绝/降级解析通过，不称auto防抖达标；YAML解析不证明FlClash界面 |
| 基础分流 | 默认global；可选内嵌RFC1918/RFC4193四网段direct，来源/embedded状态固定 | 不含地理广告规则、在线缓存或第三方转换 |
| 在线订阅 | 可选独立私有快照，256位令牌、失效/撤销/轮换、逐请求重核、无共享缓存 | full9静态/普通Go/race中受控TLS、并发、失败和真实UID/GID65534读取/HTTP/写拒绝通过；公网部署未验证，无计量不发流量头 |
| 首次快照创建 | 23dd99f新增CreateInitial同步候选+原子独占链接；已有空/非空快照均保留拒绝，nlink2崩溃材料读端拒绝 | targeted3同四项CLI红侧具体断言失败/绿侧全过；c89f7d1的full9静态/普通Go/race新四项CLI与三项底层回归通过，不在历史full8范围；遗失配置核验原0600备份同目录/GID恢复，无自动adopt |
| 设备停用 | 下载授权与代理认证独立；共享保护包含所有仍注册绑定，含已普通停下载设备，最后用户保留身份停节点 | full2漏检修订在full9静态/普通Go/race节点两路径及CLI四场景再次通过；State/代理/发布结果分开，恢复不复活撤销令牌 |
| Windows原生probe | 官方Windows sing-box1.14.3；仅probe/probecli/qingprobe三个包 | 精确3bf74bee实际15.422秒exit0，无FAIL/SKIP；两跳SOCKS与用户态WG HTTPS/序号UDP及错误/停止负例通过，不等于Windows管理器、Android/iOS或GUI验证 |

本批默认核心仍140，候选143不自动升级；现有服务权限不扩大，订阅使用另一个专用低权限用户，不把root-only State设为可读。targeted1、full1/2/3/4/5的失败、中断、超时和初始化失败全部保留，full6仅准备从未运行。旧d2c5c4c的full7/full8均完成31项退出，30项0、原生Alpine安装器32/33为唯一非零；普通Go/race/vet、两版核心、低权限、五包构建/契约通过。full7原提取失败保持complete=false、独立恢复另记；full8仅增加有界自有串口排空，原严格collector提取成功、complete=true，84证据/835哈希一致，不能称性能优化或31项全过。随后23dd99f的init重复覆盖修订不在这两轮源码。包含该修订的准确c89f7d1已完成full9：31项30项0/唯一原生Alpine1，无其他unexpected失败，原严格collector成功、complete=true；650源码/4测试二进制/80宿主输入/84证据等838项SHA一致。四项CLI与三项底层创建回归在静态、普通Go和race实际通过；普通/race持续TCP同PID72/76帧，不能等同systemd。最终五包原生命令与包级32项smoke按交付回执独立记录，不由源码构建推导。公网、GUI、原生ARM与systemd宿主未提供时明确未验证，证据以[BATCH06](BATCH06.md)和最终回执为准。操作说明见[SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)。
