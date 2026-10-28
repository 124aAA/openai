# HY2 与宿主网络性能：先测量，再显式修改

本页对应未发行的第 03 批源码。它给 Hysteria2（下称 HY2）保存独立的服务端策略和客户端选择，并提供有恢复材料的宿主参数操作。没有后台测速后自动改参数，也不把 VPS 的资源当成手机或桌面的资源。实际执行证据、实现提交和未验证项见 [BATCH_03.md](BATCH_03.md)。公开 v0.2.8 包不因此自动具备这些命令。

下文 `qingnode hy2/network/dns/export` 是 Linux 服务器管理器命令。独立 Linux/Windows `qingprobe` 负责测量和读取私有测试资料，不修改服务器 State、sysctl 或 DNS；桌面包附本页只是便于双方核对条件，不提供 Windows/Android 服务器管理能力。

先用[第 02 批网络测试](NETWORK_TESTS.md)取得同一发起端、目标、节点、地址族和预算下的原始结果。下载吞吐是收到的内容除以应用耗时，不是线路容量；下载期间 HTTPS 请求耗时不是纯网络 RTT。只有下载数据，不能推断客户端上传能力。没有可比较结果或没有可见收益时保留默认设置。

## 先分清设置作用在哪一端

| 名称 / 大白话 | 本项目保存字段 | 方向和含义 |
| --- | --- | --- |
| 服务端发送上限 | `server_up_mbps` | VPS → 客户端，即用户下载方向 |
| 服务端接收上限 | `server_down_mbps` | 客户端 → VPS，即用户上传方向 |
| 客户端预期上传 | `client_up_mbps` | 客户端 → VPS，Brutal 拥塞控制使用的预期速率 |
| 客户端预期下载 | `client_down_mbps` | VPS → 客户端，Brutal 拥塞控制使用的预期速率 |
| 自动 / 核心默认 | 字段未保存 | 不注入新的速率或 QUIC 默认值，保持旧节点语义 |
| 明确非 Brutal | `client_mode: bbr`；可另设服务端 `ignore_client_bandwidth` | 客户端不发固定速率；服务端策略与客户端选择分别保存，不能只改名称假装切换算法 |

这里的 Mbps 是十进制兆比特每秒，1 Mbps = 1,000,000 bit/s；接收窗口则用字节。服务端与客户端以各自的上行/下行为基准，因此同名 `up_mbps` 在两端方向相反。上游会结合对端申报与本端设置协商每条 QUIC 连接的发送行为；它不是整个 VPS 所有连接合计的硬流量整形器。[固定服务端实现](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/hysteria2/service.go)、[固定客户端实现](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/hysteria2/client.go)。

未保存的值与明确的 `false` 不合并。恢复自动使用清除字段；不把 0 当成新的固定带宽。固定客户端速率必须同时给上传和下载，范围为整数 1–1,000,000 Mbps；`bbr` 不与固定客户端速率并用，`brutal` 必须具备两方向速率。本项目的明确非 Brutal 服务端策略不与服务端固定速率并用，冲突在应用前拒绝，避免保存看似生效却走另一协商分支的选择。

`bbr_profile` 是 HY2 在用户态 QUIC 中使用的 BBR 档位，支持 `standard`、`conservative`、`aggressive`；只有实际使用该拥塞分支时才生效。它不等于 Linux 的 `net.ipv4.tcp_congestion_control`，也不能通过系统 BBR 状态推断 HY2 已经使用它。[sing-box 固定选项](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/hysteria2.go)。

## 少量方案与实际字段预览

方案只表达明确选择，不是对线路的评分。`core-default` 清除该节点全部 HY2 性能选择；`automatic` 只清除客户端两方向固定速率并明确使用不申报速率的 BBR，其它已选字段保留。`fixed` 只设置客户端双向预期，须登记方向明确的测量依据，不用服务器出站下载代替用户侧测量。`conservative` 只设置本机服务端 conservative BBR 和 1 MiB/4 MiB 接收窗口，不改未知资源的客户端，也不清除其它原有选择。`custom` 用严格类型 JSON 对象替换完整性能对象，不是局部合并。

```bash
qingnode hy2 show --id 节点ID
qingnode hy2 plan --id 节点ID --preset automatic --out automatic-plan.json
# 计划已审查、当前配置仍匹配时才显式应用；资料更新到客户端后再测。
qingnode hy2 apply --file automatic-plan.json
qingnode hy2 revert --file automatic-plan.json
qingnode hy2 plan --id 节点ID --preset conservative --out conservative-plan.json
qingnode hy2 plan --id 节点ID --preset core-default --out defaults-plan.json
```

多凭据节点用 `--user 凭据ID`。`plan` 只读当前配置并保存独立私有 version 1 JSON，不改 State/派生代/服务；文件含前后性能选择、实际生成的性能字段白名单、配置摘要、资源观测、影响与警告，不抄写节点凭据。计划最多 128 KiB，拒绝已存在输出路径，`apply/revert` 要求私有普通文件并重核当前节点/全局/服务器/客户端摘要和实际字段，防止旧计划覆盖后续修改。宿主服务端窗口方案要求本机可读有效可用内存至少为窗口的 8 倍且不少于 128 MiB，应用时再次核对；有效余额取宿主 MemAvailable 与当前管理进程可见 cgroup 各层“限额减使用量”的最小值。相关限制不可读时记未知并拒绝需要内存依据的设置；它不预留内存，不保证总 RSS，也不证明独立服务 cgroup 或远端客户端有足够额度。

固定速率必须已有独立的用户侧上传和下载依据。依据只填工具文字说明、文件名或 SHA 摘要，不粘 URL、分享链接、UUID 或凭据。以下数字和时间仅演示参数位置，必须换成本次实际数据；本工具只保存用户登记的依据，不冒充已核验外部测速：

```bash
qingnode hy2 plan --id 节点ID --preset fixed --up-mbps 10 --down-mbps 30 \
  --measured-at 2026-10-14T08:00:00+08:00 --initiator 家中Linux有线网络 \
  --upload-basis '受控上传记录文件与条件' --download-basis '受控下载记录文件与条件' \
  --out fixed-plan.json
```

自定义输入示例仅说明字段形状，不推荐这些值适用于所有线路。`server_up_mbps/server_down_mbps` 需要时独立显式给出；不填保持对应默认，不从客户端值倒推出服务端全局上限：

```json
{
  "client_mode": "bbr",
  "client": {"bbr_profile": "conservative", "disable_chrome_parrot": true}
}
```

```bash
qingnode hy2 plan --id 节点ID --preset custom --settings hy2-settings.json --out custom-plan.json
qingnode export --id 节点ID --format sing-box --client-version 1.14.3 --out client.json
qingnode export --id 节点ID --format mihomo --client-version 1.19.30 --out client.yaml
# 仅明确接受链接丢失性能选择时使用；警告不会被吞掉。
qingnode export --id 节点ID --format uri --allow-lossy
```

完整客户端导出中的地址、凭据和证书属于私有资料；`--client-version` 是明确声明目标版本，不是已经读取远端手机二进制的证据。实际测试助手启动本地核心时另核 SHA-256、版本和构建标签。未支持版本直接拒绝，不凭字段相似猜测兼容。

服务端设置改变实际入站配置时按第 01 批事务规则校验候选并按需重启；只改变客户端选择时保留服务器运行/停止、自启状态，并重新导出客户端资料。先预览服务器、客户端、服务及宿主影响；预览不会自动应用或修复中断事务。批量编辑仍是完整候选校验后一次 Apply，不能把性能设置绕过已有锁和恢复入口。

| QUIC 字段 | 本项目接受范围 / 约束 | 作用与限制 |
| --- | --- | --- |
| `stream_receive_window` | 64 KiB–256 MiB | 单流接收窗口；是本端接收方向，不能把窗口直接当成吞吐保证 |
| `connection_receive_window` | 64 KiB–256 MiB；同时设置时不小于单流值 | 一条 QUIC 连接接收窗口，不是所有连接的总内存上限 |
| `idle_timeout` | `1s`–`10m` | 空闲超时，不是握手时间或测速总预算 |
| `keep_alive_period` | `1s`–`2m`；同时设置时不大于空闲超时 | 保活间隔，会产生额外流量 |
| `max_concurrent_streams` | 1–4096 | 远端可发起的并发流限制，不等于本工具下载并发 |
| `initial_packet_size` | 1200–1452 字节 | 初始 QUIC 包大小，不改网卡 MTU |
| `disable_path_mtu_discovery` | 明确布尔或清除 | 路径 MTU 探测开关；保持原默认，不自动关闭 |
| `brutal_debug` | 明确布尔或清除 | 调试输出，不能据此声称性能改善 |
| `disable_chrome_parrot` | 仅客户端，明确布尔或清除 | 默认保留 Chrome QUIC 模拟；不是 TLS 证书校验开关 |

这些字段来自 sing-box 1.14.0/1.14.3 的实际 HY2/QUIC 选项。上游结构复用少量 HTTP2 字段，不代表可以把 HTTP/2 多路复用、传输或其它核心字段任意塞进 HY2。[固定 QUIC 选项](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/http.go)、[QUIC 字段文档](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/shared/quic.md)。

Chrome QUIC 模拟保持开启时，sing-box 将空闲超时固定为 30 秒，并以 Chrome 参数覆盖并发流与初始包；接收窗口从 Chrome 初始值增长到所选上限。因此“JSON 出现了字段”不证明该字段按填入值完整生效。预览和导出会说明这些覆盖，不为方便调参默认关闭模拟。[固定客户端文档](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/outbound/hysteria2.md)。

## 服务端和客户端分别校验

| 适配对象 | 接受和导出范围 | 不静默处理的差异 |
| --- | --- | --- |
| sing-box 服务端 | 已适配的正式 1.14.x；HY2 要求实际二进制具备 `with_quic` | 版本范围允许不等于所有补丁实测；不自动升级默认 1.14.0 或跨到 1.15 |
| sing-box 客户端 | 独立核对客户端版本和 `with_quic`；完整 JSON 导出 | 客户端版本与服务端不共用验证结果；Chrome 覆盖另有提示 |
| Mihomo 客户端 | 固定核对 `1.19.30`；`up/down` 明确写成 `N Mbps`；BBR 档位；接收窗口初始/最大值成对映射；明确原生 QUIC 可省略不存在的 Chrome 字段 | 明确要求 Chrome 模拟、Brutal 调试、空闲/保活/并发流/初始包/路径 MTU 字段或初始窗口语义不同，明确警告并默认拒绝有损导出；不伪造字段 |
| URI / 二维码 / Base64 | 只保存必要连接信息，二维码/Base64 包装相同 URI | 不能完整表达客户端性能选择；默认拒绝丢失，只有明确允许有损时连同警告输出，完整选择使用 JSON/YAML |

sing-box 在非 Chrome 路径将一个接收窗口值同时写入初始和最大窗口，Mihomo 用两个字段表达，故本项目成对导出。Mihomo 与 sing-box 的 QUIC 实现和启动阶段仍可能不同，不能据字段同名宣称完全相同的运行行为。[固定窗口实现](https://github.com/SagerNet/sing-quic/blob/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876/quic.go)、[Mihomo 固定适配器](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outbound/hysteria2.go)。

HY2 官方 URI 规范明确将带宽和客户端模式留给用户本机选择；其它客户端不保证理解私加 query 参数。本项目不会把完整配置静默压成一个看似等价的分享链接。[固定 URI 规范](https://github.com/HyNetworks/hysteria-website/blob/aa652ff62c9e0c920c43b9da65a8dae51a9d44f1/docs/docs/developers/URI-Scheme.md)。

## 宿主参数：先看实际值，再单独应用

```bash
qingnode network status
qingnode network status --json
qingnode network plan --tcp bbr --qdisc fq
qingnode network apply --tcp bbr --qdisc fq --preview
# 已审查计划且确实需要时才应用；不会自动加载内核模块。
qingnode network apply --tcp bbr --qdisc fq
```

`network bbr` 保留为显式应用 BBR+fq 的兼容别名。没有参数的 `network` 等同只读 `status`。可选 `--rmem-max`、`--wmem-max` 是字节上限，0 保持；每项允许 4096 字节–16 MiB，不能低于当前 socket 默认值，且不能超过有效可用内存的 1/16。状态把宿主 MemAvailable 与当前进程受可见 cgroup 约束的有效余额分开；限制存在但不可读时不会退回宿主较大内存冒充可用。资源不可读或受限时拒绝猜测。上游请求较大 UDP socket 缓冲不构成全机自动放大依据。

状态分别展示可用 TCP 算法、默认 TCP 算法、默认队列、实际接口队列、UDP 缓冲/错误计数、负载、可用内存、CPU steal 累计计数和可读的核心 RSS。`tcp_available_congestion_control` 只列已注册的算法；默认值作用于新 TCP 连接，现存 socket 不因此全部切换。`default_qdisc` 是新队列的默认值，不能代替 `tc` 看到的接口队列；本功能不运行 `tc` 改现有接口。命名空间 UDP 累计错误不能直接归因所选节点，CPU steal 累计值不是百分比。[固定 Linux v6.18 网络文档](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/Documentation/networking/ip-sysctl.rst)、[sysctl net 文档](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/Documentation/admin-guide/sysctl/net.rst)。

应用只写自有 `/etc/sysctl.d/90-qingnode-network.conf` 的允许字段，先在 `/var/lib/qingnode-host-network/` 保存私有原值/文件快照，逐项写入并读回。应用中失败尝试恢复，恢复失败保留 pending 与原始材料；只读状态不修复。与第三方同名文件、未知字段、无权限、内核/LXC 限制均明确拒绝，不覆盖 `/etc/sysctl.conf` 或别人的文件。

宿主格式与节点 State、测量报告分别版本化：原始 `snapshots/n-ID.json` 为 version 1，保留原文件字节、前值、应用摘要与前一 active 记录；`pending.json` 为 version 2，记录本次已尝试字段 `touched` 和恢复文件检查点 `restore_file`。正常应用后的 `active.json` 是 version 1；链式恢复若为保留外部手改而调整持久文件，则用 version 2 active 保存该文件检查点。恢复中断后只识别这些明确格式继续，不改原始快照、不猜未知版本或删字段伪装兼容。

```bash
qingnode network restore --snapshot n-完整快照ID --preview
qingnode network restore --snapshot n-完整快照ID
```

恢复仅在当前运行值仍等于本次写入值时回到原值，用户后来手改的值保留并列出。受管文件若已被外部修改，整体拒绝覆盖，先人工核对保留材料。宿主参数与节点 State 是两个事务：节点 rollback 不会替代 `network restore`；卸载不擅自恢复用户网络选择。网络应用不改 SSH、防火墙、默认路由、网卡 MTU或其它服务。

## DNS：耗时和内容正确性先分开测

```bash
qingnode dns show
qingnode dns diagnose --name controlled.example --family ipv4 --resolver system --samples 3 --timeout 3s --out dns-system.json
qingnode dns diagnose --name controlled.example --family ipv4 --resolver udp://192.0.2.53:53 --expected 192.0.2.0/24 --samples 3 --timeout 3s --out dns-candidate.json
qingnode dns set --resolver udp://192.0.2.53:53 --preview
# 将示例地址换成实际受控解析器，确认结果后才设置。
qingnode dns set --resolver udp://192.0.2.53:53
qingnode dns diagnose --name controlled.example --resolver project --samples 3 --out dns-project.json
qingnode dns reset --preview
qingnode dns reset
```

诊断只测命令所在机器到所选解析器的查询总时间，不能代替客户端经代理的独立 DNS 时间。每次 1–8 样本，单次 1 ms–10 s，全部样本预算最多 30 s；有缓存影响，不验证 DNSSEC。没有明确 `--expected` IP/CIDR 时，内容正确性未知；返回快不能证明内容正确。IPv4/IPv6 分开，NXDOMAIN/无对应地址、超时、取消和不符合预期分别报告。结果独立 JSON `version: 1`，不改节点或服务。

项目解析器只接受 `system` 或 `udp://字面IP:端口`，IPv6 地址加方括号；用字面 IP 避免解析器自身又依赖域名。设置只影响本项目服务器进程，按实际派生运行配置预览和应用，不写宿主 `/etc/resolv.conf`，不强制 DoH。客户端解析节点地址的 bootstrap DNS 保持自己的设置；服务器解析代理目标与客户端 bootstrap 是两条不同路径。[固定 UDP DNS](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/dns/server/udp.md)、[固定 dial/domain_resolver](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/shared/dial.md)。

## 对比和受控验收

普通 `probe compare` 继续要求相同配置摘要和其它条件。调参前后配置摘要会变化，必须使用本批保存方案关联的受控对比入口；它只允许计划声明的配置差异，其余目标、发起端、版本、地址族、预算仍需一致。不要手改 JSON 摘要骗过普通比较。方案关联不能证明另一台机器已经应用，也不能排除公网其它变化；不自动判断显著收益或自动回退。保留原始报告、中位数、p95、有效样本和失败结果，样本太少时只作本次观察。

```bash
qingnode hy2 compare --plan automatic-plan.json --before before.json --after after.json --out comparison.json
```

该入口读取计划和两份版本化报告，只另存指定的新结果文件；对比 envelope 为 version 2，内含 version 1 `controlled_change`、计划摘要、节点与前后配置摘要。普通相同条件 compare 结果仍 version 1。配置没有实际变化时使用普通 compare；不相容、失败或取消结果保留原因并返回失败，不将缺失值变为零。

仓库提供专用 Linux 网络验收 `TestOfficialCoreHY2ControlledNetwork`：自有 netns（隔离的网络空间）和 veth（仅本次使用的虚拟网卡），正常网络与双向延迟/丢包/限速下真实 HY2 → namespace 内 HTTPS/UDP；目标只绑定其中的回环接口。另测只阻断目标 UDP 时 HTTPS 仍通过，以及内核支持时的 128 MiB cgroup 实际内存约束。只清理自有进程、网卡、网络空间、cgroup，不改全局路由、生产配置或 sysctl。

```bash
sudo env SING_BOX_BIN=/绝对路径/已核验官方sing-box \
  QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/绝对路径/尚不存在的结果目录 \
  go test -mod=vendor ./internal/node -run '^TestOfficialCoreHY2ControlledNetwork$' -v -count=1 -timeout 5m
```

每个下载最多 2 MiB，每次报告最多 50 秒，保存原始样本、客户端/服务端 CPU 累计计数与 RSS、qdisc 前后实际计数和受控目标计数。2% 注入丢包是网络参数，不保证等于少量应用 UDP 样本丢包比例，QUIC 流重传也会改变观察。没有模块/权限或未委派内存控制器会明确跳过对应项；跳过不算真实网络或低内存通过。此入口不代表公网、手机客户端、原生 ARM、特定运营商或 MTU 黑洞已经验证；相关证据仅见本批实际记录。没有独立 MTU 黑洞观测时，不据此关闭探测或修改网卡 MTU。

本批 `b4e6bb0` 第四轮专项在两版核心完整执行，没有跳过 UDP-only 和 128 MiB 子项；实际摘要、CPU/RSS 口径和原始文件见 [BATCH_03.md](BATCH_03.md)。128 MiB 限额只约束服务端核心、受控目标与 helper 所在 cgroup，客户端在组外；不能把客户端 RSS 加到该组使用量。人为限速时下载约 1.8 Mbps、UDP 往返约 168 ms 只证明受控条件下测量方向符合预期，不表示调参提高公网速度，也不据本机差异给两个核心排名。

普通核心的监听就绪核对自有 PID 与实际 TCP/UDP socket；Mihomo 在建立端口后仍可能处于初始化阶段，本批互通 fixture 另使用固定官方 `-post-up` 在完整配置应用后写本次私有标记，再验证该 PID 监听，才发第一条真实业务请求。没有先失败再重试以制造首请求通过。配置解析、监听就绪、完整初始化和代理目标传输是不同证据。

State schema 1 由本批管理器读入后只在内存兼容；首次有意义写入和旧快照恢复均生成 schema 2，原始 schema 1 材料保留。`hy2 revert`、节点 rollback 与 restore 用于恢复选择和身份，不是旧管理器自动降级入口。不能手改 schema 数字或删新字段让旧二进制误读。

本批不默认开启多路复用、TCP Fast Open、MPTCP、0-RTT，不自动选择最大窗口、巨型 MTU 或所有激进参数。源码、解析、真实协议、宿主生命周期、资源受限网络和客户端 UI 各自验收，不合并成一项“测速通过”。
