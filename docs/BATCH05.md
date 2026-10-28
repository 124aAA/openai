# 第 05 批实施记录：中转、代理链与 WireGuard 落地

本批实现了 TCP/UDP 固定目标中转、远程代理链、用户态 WireGuard 落地、显式主备与隔离链路测试。默认核心继续锁定官方 1.14.0；1.14.3 单独验证，不自动升级。仍使用 Bash 引导、静态 Go 管理器、独立官方 sing-box 和现有轻量服务托管，没有引入 Realm、GOST、Docker、数据库或系统 WireGuard 数据面。

起点 `010c22a95902599b6c31984309b012caa84e1264`，分支 `batch/05-forwarding-egress-wireguard`。实现提交为 `1aa06141d8e5d75545e59d3a6b3f3253fc7df25b`、`66967800d9a311a786a2f2fd3bb8e4e9408cd789`、`079487ef1765a002ad0b24e5163a15f854a4d037` 和 `91b6ea131da1588d381d432c17c1000e7dec35de`。完整回归绑定最终代码91b6ea1；最终交付提交由收尾的实际文档提交绑定，两者间只允许已核对的文档差异。起点工作区干净；未推送、未创建 PR、未正式发行、未登录远端或部署生产环境。

## 实现与关键选择

| 本批能力 | 实际行为与边界 |
| --- | --- |
| 独立拓扑模型 | State schema4 保存 `Egresses`、`EgressPolicies`、`Forwards` 和 `Node.EgressID`。本地用户与远端认证分开；旧节点空出口保持 direct，普通编辑不轮换任何凭据。 |
| 三种入口 | 原代理节点、TCP/UDP 固定目标端口中转、入站绑定远程代理链。sing-box 自带 direct 入站已满足转发需求，不再引入另一数据面。 |
| 白名单远程出口 | SOCKS5、VLESS REALITY、SS2022、HY2 和用户态 WireGuard；严格字段，不接受任意核心 JSON。HY2 复用第03批客户端性能设置。 |
| 引用与应用 | 持久引用使用稳定 ID，只渲染真正用到的闭包。整批先校验，再持锁统一应用；无效项使整批拒绝。被引用出口不能直接删除，可在同批显式迁移引用后删除。 |
| 变更影响 | 未使用出口、显示名称或未选备用不改变实际运行配置时免重启。当前仍是共享核心；运行路径变化的一次统一应用可能重启整个核心并中断其他已有连接，不是每节点独立热更新。 |
| 防环与能力 | 校验缺失引用、出口链环、DNS 引导环、指回自身入口/隧道、TCP-only 路径承载 UDP。分别检查实际载荷与协议自身的运输能力；公共入口防环按物理 TCP/UDP 判断。 |
| 拨号位置 | 普通代理 detour 后的地址由相应远端处理，不能强迫用本机 DNS 或误把远端 loopback 当本机。WG peer 引导及其目标域名按固定核心的本地解析语义检查；远端 DNS、外部 NAT 与后续重绑定仍需链路验证。 |
| WireGuard 最小权限 | `system:false` 的用户态 endpoint，分别要求 `with_wireguard` 和 `with_gvisor`；不创建 wg0、不接管系统路由/DNS/其他 Peer，不永久提权整个代理。配对材料分端生成、分端应用、分端撤回。 |
| WireGuard 接收边界 | 主动出口只允许本端已发起流量的回复；对端主动新建 TCP/UDP 流按 endpoint 入站标签显式 reject。只有显式被动落地的 `ReceiveEgressID` 才授予接收路径。接收策略全部主/备候选均检查自回指，即使当前未选中也不能藏自环。 |
| 显式主备 | 经各出口的受控 HTTPS/序号 UDP 应用测试，显式失败阈值、恢复阈值与冷却。默认只读，只有 `health --apply` 才累计并应用；有限前台 watch 不安装永久守护进程。不暗中回落 direct，不迁移现有 TCP 会话。 |
| 有界探测与报告 | 单并发；每路径最多16KiB、每轮最多64路径、最多16轮、有效载荷最多16MiB；封装流量未知。探测及等待预算最多120秒，已开始事务完成/恢复的耗时另列。取消、超时、未知、本机失败与远端失败分开。 |
| 结果与私有文件 | `selection_applied` 为 true/false/null；null 表示事务报错后结果未知，不能谎报未变。结果文件保存失败仍输出实际选择并返回错误。固定私有父目录句柄，拒绝路径替换；失败只清理自有文件。 |
| 路径摘要与客户端 | direct 入口继续 Profile/Report v1；新拓扑用显式 v2 `server_path_sha256` 绑定导出时内部路径声明。最终客户端只含入口地址与入口凭据，不泄漏落地认证。摘要不是远端实时证明，手动 public-check 与自动历史独立。 |
| 快照恢复外层保护 | 新增仅快照第一层字段的重复键检查，按Unicode大小写折叠识别别名，拒绝后值掩盖未来格式/State或抹掉拓扑。State继续独立严格解码；单个旧兼容键不改，此扫描不深入保存的核心配置，也不删除其中未知或重复字段。备份格式/魔数不升版。修前/修后解析对照见envelope-ab2，最终准确代码门槛另见full4。 |

详细字段、实际命令和逐端步骤见 [TOPOLOGY.md](TOPOLOGY.md)。

## 实际测试与证据边界

全部轮次保留原始退出码、日志、源码清单及测试二进制摘要。开发快照写明基点和 dirty 状态；基点提交不冒充整棵树等同。源码编译、配置解析、真实传输、进程/服务、GUI 和公网分别记录。

两份前后对照另有只读源码绑定：安全A/B修后代码输入与079487ef除明确文本行尾外一致；恢复A/B修后621文件与91b6ea1有619个原始字节相同、2个仅CRLF/LF差异，无其他/缺失/额外差异。原始摘要与dirty标记保留，不把开发快照改称原始Git整树，也不把比对当新增产品执行。最终完整回归另用准确干净91b6ea1冻结源码。

### 准确代码 full4 门槛

准确干净提交`91b6ea131da1588d381d432c17c1000e7dec35de`，源码ZIP SHA-256为`68987adfedb4fb2afecd2615d9c16e543aa8661b77ee24bd171fd08ca0abb59f`。一次性QEMU Linux6.18.55、4vCPU/5GiB、无外部网卡；测试专用自有veth/default条件与生产宿主分开。Windows Go1.27.2编译静态测试，guest Go1.26.8执行普通/race/vet及构建；官方140/143自身构建Go版本分别是1.26.7/1.26.8，不混成同一工具链证据。

完整回归实际结束：29项检查中28项退出0，唯一非零是原始Alpine安装器32/33的exit1。`RUN_END`、全部开始/结束配对、guest证据提取及QEMU退出0齐全，收据`complete:true`且无额外失败。这里不是全零通过，也没有把受支持系统元数据夹具当成真实Ubuntu安装。

| 检查标签 | 实际退出码 | 证据与范围 |
| --- | --- | --- |
| `environment` | 0 | 匹配内核模块、cgroup2、一次性自有网络前置 |
| `static-node` | 0 | Windows Go1.27.2交叉编译的Linux节点测试实际执行 |
| `static-cli` | 0 | 同一冻结源码CLI静态测试实际执行 |
| `static-probe` | 0 | 同一冻结源码probe静态测试实际执行 |
| `go-test` | 0 | Linux Go1.26.8普通全项目 |
| `go-race` | 0 | Linux Go1.26.8全项目race，无DataRace |
| `go-vet` | 0 | 全项目静态检查 |
| `service-user` | 0 | 受限umask的State/服务用户文件权限检查，非systemd实机 |
| `netem-default` | 0 | 140延迟/丢包/限速、UDP阻断与128MiB cgroup回归 |
| `netem-candidate` | 0 | 143同一受控网络回归，保留原始测量状态 |
| `topology-default` | 0 | 140实际Server中转、三远端协议链、WG namespace、显式主备 |
| `topology-candidate` | 0 | 143同一拓扑/主备验收 |
| `graph-default` | 0 | 140隔离图、逐跳停用/错误认证/取消崩溃/主动WG新流拒绝 |
| `graph-candidate` | 0 | 143同一图验收 |
| `unprivileged-wg-default` | 0 | UID/GID65534，140用户态WG真实HTTPS/序号UDP |
| `unprivileged-wg-candidate` | 0 | UID/GID65534，143用户态WG真实HTTPS/序号UDP |
| `candidate-core` | 0 | 143原三协议、导出/ACME解析、Mihomo及新链/WG/恢复回归 |
| `shellcheck` | 0 | install.sh与全部scripts/*.sh |
| `bash-syntax` | 0 | 同一脚本集合Bash语法 |
| `installer-alpine` | 1 | 32/33；唯一既有不支持真实Alpine的在线安装用例失败，保留exit1 |
| `release` | 0 | 离线FakeGitHub发行测试38/38，未远程发布 |
| `maintenance-observer` | 0 | 持续流观测器自身3/3，不是systemd服务验收 |
| `build` | 0 | 冻结源码管理器Linux amd64/arm64构建，修订fallback为source |
| `build-probe` | 0 | 冻结源码助手Linux amd64/arm64、Windows amd64构建 |
| `archive-contract` | 0 | 这轮源码生成五归档的现有契约检查 |
| `capability-material` | 0 | 能力JSON与NAT验证材料，明确本地/外部端口 |
| `installer-host-read-fixture` | 0 | Ubuntu24.04标识元数据夹具中的单项host读取测试1/1 |
| `installer-supported-metadata-fixture` | 0 | Ubuntu24.04标识夹具33/33，554.352s；仍是Alpine guest，非Ubuntu实机 |
| `environment-cleanup` | 0 | 只清理并读回自有guest网络，恢复测试OS标识 |

普通Go的node138.061s、CLI26.978s、probe38.290s、probecli0.414s；全量race的node712.596s、CLI298.001s、probe50.335s、probecli3.386s，均在原15分钟每包超时内，没有改600000次PBKDF2或删断言。Alpine唯一失败是`test_online_install_reads_actual_host_os_release_without_overwriting_tag`，33项耗时564.801s；环境为未验收的Alpine3.24.2。发行38/38耗时7.076s，观测器3/3耗时0.151s，单项Ubuntu标识夹具1/1耗时8.263s。整套Ubuntu标识夹具33/33、554.352s退出0，自有环境清理退出0；只修改和恢复一次性guest的OS标识，不等于真实Ubuntu/systemd安装。收据为`batch05-full4-run-receipt.json`，完整原日志SHA-256为`f05ba93e97850214472c3f80e5161bfe7b67ac77314c40a997b6933121eb189e`；82份提取证据的逐文件摘要另列于该收据。

实际项目命令包括：

```bash
# 同一guest全局：SING_BOX_BIN=/sing-box MIHOMO_BIN=/mihomo
# GOTOOLCHAIN=local GOMAXPROCS=4 CGO_ENABLED=1；三个明确disposable开关仅在此guest
/node.static -test.v -test.timeout=10m
/cli.static -test.v -test.timeout=5m
/probe.static -test.v -test.timeout=5m
go test -p 1 -count=1 -v -timeout=15m ./...
go test -p 1 -race -v -count=1 -timeout=15m ./...
go vet ./...
go test ./internal/node -run '^TestStorePermissionsUnderRestrictiveUmask$' -v -count=1
env QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/evidence/netem-default go test ./internal/node -run '^TestOfficialCoreHY2ControlledNetwork$' -v -count=1 -timeout=5m
env SING_BOX_BIN=/sing-box-candidate QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/evidence/netem-candidate go test ./internal/node -run '^TestOfficialCoreHY2ControlledNetwork$' -v -count=1 -timeout=5m
/node.static -test.run '^TestOfficialCore(Topology|Failover)' -test.v -test.timeout=5m
env SING_BOX_BIN=/sing-box-candidate /node.static -test.run '^TestOfficialCore(Topology|Failover)' -test.v -test.timeout=5m
/probe.static -test.run '^TestOfficialCoreGraph' -test.v -test.timeout=3m
env SING_BOX_BIN=/sing-box-candidate /probe.static -test.run '^TestOfficialCoreGraph' -test.v -test.timeout=3m
python3 /run-unprivileged-wg.py /sing-box
python3 /run-unprivileged-wg.py /sing-box-candidate
env SING_BOX_BIN=/sing-box-candidate go test ./internal/node ./internal/probe -run 'OfficialCore|OfficialCandidate|Mihomo' -v -count=1 -timeout=10m
shellcheck install.sh scripts/*.sh
# 对install.sh及scripts/*.sh逐个执行bash -n
python3 scripts/test-installer.py
python3 scripts/test-release.py
python3 scripts/test-maintenance-harness.py
bash scripts/build.sh
bash scripts/build-probe.sh
python3 scripts/check-build.py
# 另执行capabilities/endpoint material与同一安装器的明确OS标识夹具
```

`full4`源码归档不带`.git`，构建脚本按既有规则写修订`source`；源码输入由冻结清单绑定91b，不能把这些构建包当作最终交付修订。最终五份预览包另由最终文档提交的独立本地Git目录构建，准确修订、归档契约及22项包运行以本批交付构建/冒烟收据为准；源码检查成功不等于最终包已经实测。

### 真实数据、持续流与测量失败

两核心实际通过纯TCP/UDP转发；SS2022入口分别经REALITY、SS2022、HY2远端出口收发HTTPS/序号UDP，逐一停止远端后失败且目标计数不增；双SOCKS图也用目标来源和逐跳停用证明确实过链。WG namespace目标看到落地源地址，普通目标数据、错误密钥和停落地分别检查。显式主备真实阈值/恢复/冷却、来源、旧会话中断与失败恢复通过；这些不是两台公网服务器或全部入口×全部出口组合的穷举。

下表列出full4同名持续流测试的全部摘要样本。都是官方核心进程PID和同一TCP连接，不是systemd MainPID；帧数只证明这段维护期间持续传输，不是吞吐排名。HY2测试客户端配置固定，不表示手机客户端在线重配置。停止状态编辑保持停止，运行改动重启和注入启动失败后的旧配置/状态恢复也通过。

| full4检查段 / 核心 | SS2022核心PID / 持续帧 | HY2核心PID / 8192字节完整帧 |
| --- | --- | --- |
| static-node / 140 | 630 / 138 | 1321 / 84 |
| go-test / 140 | 6028 / 138 | 6720 / 93 |
| go-race / 140 | 11493 / 158 | 12184 / 114 |
| candidate-core / 143 | 17535 / 210 | 18701 / 156 |

主动WG拒绝peer新流的同名真实Server测试在`static-probe`、`go-test`、`go-race`、`graph-default`各有一份140样本，在`graph-candidate`、`candidate-core`各有一份143样本；六份均为正常HTTPS=2、序号UDP=4，peer新流目标TCP/HTTP/UDP计数全0。原安全A/B中的修前目标TCP1/HTTP1/UDP2仍作为失败见证保留。

netem门槛退出0表示延迟、限速、失败分层和资源场景断言符合预期，不表示每份测量报告都是completed。全部8份原始报告状态如下；下载每项只有1个样本，UDP每项8个样本，不能用来给版本排性能名次。

| 核心 / 场景 | 报告状态 | UDP回包 | 下载Mbps（单样本） | 空闲/下载时HTTPS请求中位ms |
| --- | --- | --- | --- | --- |
| 140 baseline | completed | 8/8 | 137.541 | 3.913 / 6.614 |
| 140 delay-loss-rate | failed，udp_no_response | 6/8 | 1.839 | 170.269 / 331.913 |
| 140 udp-filtered | failed，udp_no_response | 0/8 | 未测 | 2.939 / 未测 |
| 140 memory-128MiB | completed | 8/8 | 139.281 | 3.214 / 25.152 |
| 143 baseline | completed | 8/8 | 96.199 | 3.493 / 20.694 |
| 143 delay-loss-rate | completed | 8/8 | 1.851 | 170.445 / 196.887 |
| 143 udp-filtered | failed，udp_no_response | 0/8 | 未测 | 2.985 / 未测 |
| 143 memory-128MiB | completed | 8/8 | 98.919 | 2.872 / 20.769 |

限速场景在自有两侧各加80ms、2%随机丢包、2Mbit/s；应用层8个UDP样本的6/8或8/8不等于内核配置丢包比例。两版UDP阻断场景HTTPS都成功8/8，报告仍failed，未被TCP通过掩盖。HTTPS请求往返包含代理/目标处理，不是独立网络RTT；独立DNS/TCP/TLS与CPU占用百分比未知。`netem-default/`、`netem-candidate/`保留原始样本、CPU累计/RSS、服务端namespace UDP计数、qdisc、受控目标计数和128MiB cgroup证据，不推算公网性能提升。

普通static/go-test/race及candidate-core中过滤掉显式netem开关时，`TestOfficialCoreHY2ControlledNetwork`保留SKIP；上述两个专用netem检查已真正执行。`TestHY2NetworkFixtureProcess`是仅由父测试启动的私有子进程入口，常规枚举保留SKIP。没有通过删断言、移除旧门槛或把未提供systemd环境标通过来消除跳过。

### 本批基线与问题复验

| 轮次 | 实际结果 | 解释 |
| --- | --- | --- |
| baseline1 | 起点010c22a冻结源码；node、CLI、probe、候选核心相关检查均0；RUN_END/QEMU0 | 本批真正运行的修改前基线。QEMU Linux6.18.55、4vCPU/4GiB、无外部网卡，Windows Go1.27.2 编译静态 Linux 测试。 |
| targeted1 | node1、CLI0、probe0、候选旧三协议0、candidate-graph1；完整闭合 | 新代断言仍硬编码schema3，改为真实schema4并保留版本验证；143 WG首次2秒请求超时保留。 |
| targeted2 | node1、CLI0、probe0、candidate-node1、candidate-graph1、候选relay0、低UID WG0；完整闭合 | 新Server测试在请求前因空CA夹具失败，修正辅助函数后仍严格验证证书；143普通WG首次超时仍未当通过。 |
| targeted3 | 默认node/CLI/probe、低UID WG及默认报文观察0；143 node/graph/relay/观察失败；完整闭合 | 两核心三种远程协议链与默认WG任意目标通过；143观察到零WG公开包和零目标TCP，转查核心网络暂停条件。 |
| targeted4 | 15项中14项0；唯一非零为只lo的 `wg-no-default-143:1`；RUN_END/QEMU0 | 只lo时140通过、143失败；只在一次性guest及自有namespace补可达默认接口后两核心路径通过，清理0。没有改2秒断言、重试或预热。 |
| security-ab1 | 修前140/143均1且真实保护目标TCP1/HTTP1/UDP2；修后两核心0、合法HTTPS2/UDP4、保护目标计数全0；单元检查/清理0；完整闭合 | 真实 `node.Server` 两端配置证明主动WG存在对端新入流边界，并验证显式reject的最小修复。修前失败如实保留，不改记0。 |
| envelope-ab1 | 环境检查1；修前/修后测试未运行；串口RUN_END/poweroff，主机QEMU退出码未知，收据生成又因缺before日志失败 | 外部initramfs未建立testdata嵌套父目录，属于测试材料准备失败，不是产品断言失败。原日志/stderr/材料保留，改用新编号AB2，不补造通过。 |
| envelope-ab2 | environment0、before-envelope1、after-envelope0；三项关键接受歧义见证、三组修复测试均齐；RUN_END/配对/证据提取/QEMU0 | 修前确有未来format/State和拓扑被后值覆盖，修后拒绝且旧身份/原始server证据保留。host写完已验证收据后打印长ſ名称遇GBK编码异常，主机总结退出非0单列，不掩盖显示错误或重跑产品断言。 |
| full1 | 仅干净1aa0614冻结、编译与actionlint0 | 未启动完整回归，不记运行成功。 |
| full2 | 干净6696780；environment、三个static包和完整go-test共5项0；go-race途中中断 | 无go-race EXIT、无RUN_END、无确认QEMU exit；不是全量race/vet或完整发行门槛通过。原日志和更正审计均保留。 |
| full3 | 干净079487ef；environment、三个static包共4项0；go-test未结束即核对归属后有意停止QEMU | 只读审计发现快照外层重复format/state可覆盖前值，先补恢复边界再执行新full4；qemu_exit4294967295、completefalse、无RUN_END，不算完整回归。 |

143 WG 的诊断依据固定 `route/network.go`：PostStart 同步默认接口状态，缺失时 NetworkPause，WG回调使设备Down。targeted4 的受控前后对照与零包观察相符。本次隔离QEMU没有外部网卡，自有 veth/default 仅补测试条件；没有替用户修改默认路由，也没有得出性能提升结论。

原生 Windows 官方143开发轮次也保留：windows1 使用127/8目标时WG超时；后续改用明确对端隧道地址，真实HTTPS/序号UDP、错密钥、停落地、双SOCKS源地址及逐跳停用、取消/崩溃清理通过。首轮没有采包证据，不能唯一归因。准确提交6696780的 `go test -mod=vendor -count=1 -v -timeout=3m ./internal/probe ./internal/probecli` 使用Go1.27.2及已核验的官方143 Windows核心退出0。这些不是Linux管理器、systemd或公网验收。

最终原生Windows源码测试实际运行于079487ef：`go test -count=1 -v -timeout=5m ./internal/probe ./internal/probecli ./cmd/qingprobe`退出0，probe12.075s、probecli0.892s，命令包无测试文件，无FAIL/SKIP，源码未变回读通过。随后91b6ea1只改Linux管理器的备份解析及对应测试；独立绑定收据核对37个portable相关Go源原始SHA全部未变。该原生结果仍按079记录，不移名为91b实际执行。最终归档修订、五包契约与包冒烟结果以本批交付构建/冒烟收据为准，源码通过不等于最终包已验证。

本批已执行的低成本门槛另有：离线发行测试38/38、Bash语法、actionlint1.7.12、Python AST、Markdown本地链接与明确文档白名单检查。发行测试中的“Formal release published”是 FakeGitHub 夹具输出，本批没有远程发行。最终准确91b6ea1的完整源码结果以本节full4表为准，未扩张为系统服务、GUI或公网结论。

### 可复现的项目命令

```bash
go test -p 1 -count=1 -v -timeout=15m ./...
go test -p 1 -race -count=1 -v -timeout=15m ./...
go vet ./...
SING_BOX_BIN=/verified/sing-box go test ./internal/node ./internal/probe -run 'OfficialCoreTopology|OfficialCoreGraph|OfficialCoreFailover' -v -count=1
sudo env "GO=$(command -v go)" SING_BOX_BIN=/verified/sing-box QINGNODE_TOPOLOGY_DISPOSABLE=1 sh -c '"$GO" test ./internal/node -run "OfficialCoreTopology" -v -count=1 -timeout=3m'
shellcheck install.sh scripts/*.sh
python3 scripts/test-maintenance-harness.py -v
sudo env "GO=$(command -v go)" python3 scripts/test-installer.py
python3 scripts/test-release.py
bash scripts/build.sh
bash scripts/build-probe.sh
python3 scripts/check-build.py
```

这些命令是复现入口，运行结果需核对本节的实际证据。netns/veth只在明确隔离且可重建的Linux环境启用；主备目标换成两端受控服务，不向公共测速站长期发流量。

## 迁移与恢复

State schema1/2/3只读加载时仅在内存兼容，不落盘迁移；旧节点身份、用户、UUID、密码、REALITY密钥、证书、监听和客户端端口、旧URI及默认direct保持。首次有意义写入保留原始旧代并生成schema4。未知字段、重复键、伪装字段和未来版本明确拒绝；旧二进制不能读取schema4，不能删字段或改数字伪装降级。

备份envelope v1/v2保持；本批管理器恢复旧备份仍生成schema4。应用失败恢复旧选择、派生文件与运行状态；恢复失败保留pending与前后代，先保留原件，再用理解schema4的管理器显式 `recover` / `rollback`。整份State损坏时先封存原件，在隔离目录核验已知备份，不猜字段。

快照外层字段重复（含大小写/Unicode折叠别名）直接拒绝，不能用后一个`state`掩盖前一个未来schema或完整拓扑；明文和认证解密后的恢复走相同入口。此检查只扫描外层，不删除或规范化保存的`server_config`原始证据，也不改变旧单个兼容键的读取行为。

跨主机不是一个原子事务。各端先备份，分别预览/应用并记录完成状态；撤回先在入口显式迁回原出口，移除引用后再删本项目出口，落地端独立删除自己的端点。配对配置生成不表示已应用、已握手或目标出口已验收。保留其他wg0、Peer、DNS、路由和服务。健康观测缺失/失效后保守重建；`selection_applied:null` 时先查询策略与doctor，再按需显式恢复。

## 未验证范围

本批未获真实远端访问，未登录两台公网服务器，未改变生产路由、云NAT或防火墙；没有把Linux隔离链路当成公网成功。真实systemd下的新拓扑生命周期/MainPID与持续流、真实Ubuntu发行安装、原生ARM运行、桌面/手机GUI、WG公网IPv6/NAT穿透与云厂商映射均需独立实机证据。受控namespace/veth、低UID数据与交叉构建各自只证明其范围。没有提供原生Android/iOS管理器或测速程序。

## 固定来源与后续接口

sing-box v1.14.0 / `0b8995879f29a9b98ee027bc17b75e101445b238` 与v1.14.3 / `7054cac5124465ffdb145870d7c01885566711b1`：direct入站、Dial/detour、WireGuard endpoint、入站标签、用户态栈、构建标签及默认接口暂停。WireGuard固定依赖 `8bd032a91a30` / `6731c7387c81`：独立UDP4/UDP6绑定及私钥导入机制，只核查不复制。GOST v3.2.6 / `340ba32ef0bebc7293908007cc423dd5f33dd88c`、Realm v2.9.3 / `2ab8e400cea3edf3f1103a0f0cc80c2665081c11`只比较主备/转发概念，两者MIT，本批不安装或复制其代码。官方核心GPL及附加条款保持独立程序边界；完整固定链接与许可见 [THIRD_PARTY.md](../THIRD_PARTY.md)。

后续复用 `BuildEgressGraph`、`ResolveEgressID`、`StateBindings`、`HasEnabled`、`NodeRouteDigest`、`PolicyHealthDigest`、`EvaluateFailover`、`NewWireGuardPair`、`NewGraphProfile`、`SetGraphResolver`、`StartGraphSandbox`。`GraphProfile`含远端凭据，只能作私密派生材料；自动报告只留摘要。后续扩展不得把客户端导出列表当服务端路由，不得把主备选择当连接迁移，不得把结果文件保存失败当未应用。
