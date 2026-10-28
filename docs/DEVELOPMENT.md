# QingNode 开发与验证

当前第10批State为schema9，旧1–8仅读入内存兼容，restore/rollback写schema9；平台边界与准确执行结果见[PLATFORMS.md](PLATFORMS.md)、[BATCH10.md](BATCH10.md)。第09批当时为schema8；AnyTLS/Trojan第一阶段521b9a7完整11/11项通过，SS AEAD/TUIC第二阶段ca0df8a定向25/25项通过，完整回归另列。开发须区分本机监听、承载业务、凭据、证书、构建标签和各客户端格式；基础URI不允许静默丢高级设置。协议说明见[PROTOCOLS.md](PROTOCOLS.md)，基线与各阶段准确源码结果见[BATCH09.md](BATCH09.md)。前批结果不替代当前源码验证。

第07批证书/迁移新增schema6与QNBK3，第08批真实API/到期字段升为schema7；该批接口与准确实测见 [CERTIFICATES.md](CERTIFICATES.md)、[MIGRATION.md](MIGRATION.md)、[MONITORING.md](MONITORING.md)、[BATCH08.md](BATCH08.md)。第08批当时恢复/回退写schema7、旧1–6内存兼容，第09批当时写schema8、兼容旧1–7，均为历史边界。新增字段要经DecodeState与CanonicalCertificates，不能让新State同时持久化旧node内联证书。只读观测不修复/签发，不恢复事务；独立监控政策不属于配置代，也未纳入QNBK3，发现时必须列明迁移缺项。

周期探测复用internal/probe，按整轮预算分配，不另造成功判定。节点Profile从同一State快照的独立副本构造，不在并发worker重新争抢管理锁或重新加载当前代；主动probe读取入口仍持锁并拒绝待恢复事务。核心API流量仅为当前启动生命周期观测，缺失、reset与采集间隙保留；不能将无序连接事件累加为计费或硬配额。新增外部通知和恢复能力各自显式启用，测试用受控接收器；systemd/OpenRC周期任务的本批实际证据见BATCH10，公网通知另验。

受控CA验收需要独立、摘要校验过的官方Pebble v2.10.1，不访问生产CA，也不改宿主信任/DNS。普通套件缺工具会明确SKIP；要取得签发证据必须显式提供两工具实际运行：

```bash
PEBBLE_BIN=/绝对路径/pebble SING_BOX_BIN=/绝对路径/sing-box \
  go test ./internal/node -run '^TestOfficialCoreACMEPebbleHTTP01StartupRenewalAndFailure$' -v -count=1 -timeout=5m
SING_BOX_BIN=/绝对路径/sing-box \
  go test ./internal/node -run '^TestOfficialCoreCertificateMigrationPEMRestoresIdentityAndHY2$' -v -count=1 -timeout=2m
SING_BOX_BIN=/绝对路径/sing-box \
  go test ./internal/node -run '^TestOfficialCoreCertificateACMEProviderSchemas$' -v -count=1 -timeout=2m
```

同PID自然续期是独立长测，不缩短核心十分钟ticker冒充自然行为，也不把该等待加进所有普通/race套件：

```bash
QINGNODE_ACME_BACKGROUND_TEST=1 PEBBLE_BIN=/绝对路径/pebble SING_BOX_BIN=/绝对路径/sing-box \
  go test ./internal/node -run '^TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess$' -v -count=1 -timeout=15m
```

5m/15m是测试总上限，不是把签发或续期改成固定等待。短入口保留普通12秒观察；仅当旧证书DER序列号含前导00、且实际日志匹配锁定Pebble2.10.1的ARI查找500缺陷时，才允许核心自身60秒和120秒退避重试的有界预算。后台入口同样保留核心真实十分钟ticker及同PID、证书更新、账户和前后流量断言，不修改官方核心或用手工重启冒充自然续期。新测试修订的实际通过与未执行范围仍以BATCH10准确回执为准。

完整迁移测试需要同时断言资产、State、原代理认证、权限和失败恢复，不能只比较解密后的JSON。对路径穿越、链接、父子条目冲突、未知格式、篡改、错误口令、资产漏项、journal中断、更新失败/保留策略都要有负例。确认停止的mock补错误分支；官方核心真实HY2数据与对应systemd/OpenRC停止证明分别记录。五个provider解析子例不签发、不代表DNS服务商或TLS-ALPN链路已验。显式证书导入/更新额外验证完整信任路径；旧State/备份读取不依赖当前宿主信任根，不能将两者合并成会阻止旧恢复的校验。安装器/构建/发布的文档白名单保持逐项声明，其余未知成员继续拒绝。

QingNode保留Bash安装入口、Go管理器、JSON State、官方sing-box与本机systemd/OpenRC托管。当前未发行源码批次见 [BATCH_01.md](BATCH_01.md)、[BATCH_02.md](BATCH_02.md)、[BATCH_03.md](BATCH_03.md)、[BATCH04.md](BATCH04.md)、[BATCH05.md](BATCH05.md)，架构与能力范围见 [ARCHITECTURE.md](ARCHITECTURE.md)、[CAPABILITIES.md](CAPABILITIES.md)；[TEST_REPORT.md](TEST_REPORT.md) 保留旧发行证据，不替代当前实测，版本改动见 [RELEASE_NOTES.md](RELEASE_NOTES.md)。

## 按现有边界放代码

| 层 | 本次含义 | 修改原则 |
| --- | --- | --- |
| 安装入口 `install.sh` | 下载、校验、安装账户与文件、失败恢复 | 保留非交互参数、所有权检查和重装语义 |
| CLI 与菜单 `cmd/qingnode` | 收集输入、确认影响、显示结果 | 不自行生成第二套凭据或直接写 State |
| 模型与协议 `internal/node` | 统一身份、校验、服务器及客户端配置 | 所有导出从同一 State 派生；协议适配器保持编译期注册 |
| Store | 状态锁、候选代、原子切换和回滚 | 修改通过 Apply；查询通过 Inspect，恢复由显式操作或写路径触发 |
| 系统后端 | 核心、服务、监听、防火墙与主机设置 | 外部效果有明确入口，出错保留恢复证据 |
| `internal/probe` / `cmd/qingprobe` | 有边界的网络测量、独立报告和桌面入口 | 不依赖 State 写操作；无 direct 失败回落；默认无公网目标，不设置系统代理或路由 |

这些是已有代码的职责边界，不要求为每项小改动新增包、服务或抽象。新增协议通常同时涉及适配器、参数入口、菜单和客户端导出，需要检查完整路径，不能仅以服务器 JSON 可解析作为完成证据。

## 保护现有节点

先读取已有 State，再修改目标字段。普通编辑、重复安装、重建派生配置不能重新生成 UUID、私钥、公钥、short ID、服务密钥、用户密钥或密码。节点与凭据按完整集合先找 ID、再找名称；不要把展示序号当成持久身份。

查询使用 Inspect，不能为了展示状态顺带恢复事务、切换 current 或重启服务。Inspect 仍可能由明确功能另存观测历史或写用户指定的导出文件。改变配置的操作使用 WithLock 与 Apply：候选校验、外部效果、提交和失败恢复需保持原有顺序；8 MiB 状态上限在读写两侧一致，超限候选必须在创建配置代前拒绝。

单项/批量预览使用 InspectExisting，不修复派生文件或事务，不联网、不调用核心检查或服务启停。批量在旧 State 解析每个目标，先构造和校验完整候选，再 Apply 一次；新增字段要接入实际运行配置/客户端输出/宿主效果比较，不能新增字段名免重启白名单。纯元数据、导出或仅 UFW 效果改变保持原服务状态；端口、凭据、核心等运行输入变更保留原启动/重启/全部停用行为。

State版本解码统一经DecodeState；第03批HY2/DNS为schema2，第04批连接端点为3，第05批拓扑为4，设备、证书和观测/到期分别为5、6、7，第09批新协议语义/选项为8，第10批firewalld语义为9。旧1–8严格解码后只在内存迁移，查询不落盘；旧连接端口和默认direct保持，首次有意义写入经新配置代保留原件。旧schema不能偷塞新字段（含null），未来schema/未知字段明确拒绝；合法schema7观测字段仍读取。身份夹具验证凭据、ID、证书与旧URI保持。当前restore/rollback写schema9，旧二进制拒绝新格式，不以删字段或降版本号伪兼容。配置事务version2保留影响分类与旧记录入口；恢复失败保留原件。runtime-identity仅是私有派生材料。

连接模型只有一个主入口事实来源：Host/ConnectPort，另有 AdditionalEndpoints。Listen/Port 始终用于本地入站、端口、防火墙与就绪，客户端统一经 EffectiveConnectPort/WithEndpoint 派生。新增导出或测试路径必须支持同一端点选择，不得重新把连接端口当监听端口；投影副本不是可直接持久化的新 State。TLS SNI、REALITY 握手目标和证书独立，普通端点编辑不得自动改它们。批量请求仍 version=1，省略保留，null拒绝，空额外端点列表明确清除。

菜单中的取消和输入结束应向上返回，不落入无限重试。无效数字可提示后重试；输入正确的最后一个参数也不能代替危险操作确认。删除、轮换、恢复、卸载等确认只针对明确展示的目标与影响。

## 逐层验证并保留证据

网络测试的基线、坏凭据、目标失败、DNS/IPv6/UDP、延迟/丢包、字节上限、取消、核心崩溃、临时清理和生产无变化分别验证。普通 HTTPS 成功不能覆盖 UDP 失败；HTTP 应用层时间不能改名为纯网络 RTT。模拟 transport 用于预算/统计故障覆盖，官方核心真进程用于协议路径/认证和清理，公网/手机客户端另验。命令、环境和实际结果写入 [BATCH_02.md](BATCH_02.md)，不要搬用前批结果；指标与外部 iperf3/IRTT 流程见 [NETWORK_TESTS.md](NETWORK_TESTS.md)。

在 Linux 上，从与修改有关的回归开始，再运行仓库要求的检查。回归应复现实际错误，并检查旧状态、凭据、current 和服务是否保持；不要为每个可逆的文案修改增加只重复实现的测试。

```bash
go test ./internal/node ./cmd/qingnode ./internal/probe ./internal/probecli ./cmd/qingprobe
go vet ./...
go test -race ./...
shellcheck install.sh scripts/*.sh
python3 scripts/test-maintenance-harness.py -v
sudo env "GO=$(command -v go)" python3 scripts/test-installer.py
sudo env "GO=$(command -v go)" sh -c '"$GO" test ./internal/node -run "^TestStorePermissionsUnderRestrictiveUmask$" -v -count=1'
```

安装器测试需要 root，必须在隔离测试环境中运行。权限测试验证专用账户的真实降权读取；普通非 root 单元测试不能替代它。项目使用 Linux 系统接口，Windows 下交叉编译成功只证明能生成目标文件，不证明 Linux 执行成功。`go test -race` 还依赖相应架构的 C 工具链。

第10批source18（`d94d03a33546eddd9caa6ba9c9e8592d2f332d1f`）已在隔离Linux实际通过完整Go、race、vet、50项安装器故障测试及发行保护，准确15项回执见BATCH10。安装器的宿主命令仍为模拟，用于真实Bash文件事务和故障窗口；systemd/OpenRC生命周期必须另跑空白VM。核心和独立附属服务的资源保护可先定向复验：

```bash
go test -count=1 ./internal/node -run 'Auxiliary|Removal|StoreRecoversInterruptedCoreRemoval'
go test -race -count=1 ./internal/node -run 'Auxiliary|Removal|StoreRecoversInterruptedCoreRemoval'
go test -count=1 ./cmd/qingnode -run 'Auxiliary|Monitor|Service|FullBackupRejects'
python3 scripts/test-platform-aux_test.py
python3 scripts/test-platform-firewall_test.py
python3 scripts/test-platform-flow_test.py
python3 scripts/test-platform-tls_test.py
```

等待服务时外部修改的回归必须在实际回调边界改变字节、权限或覆盖配置，并断言后续服务控制停止、外部内容与恢复材料保留；只在测试前放一个非受管标记不能覆盖这个窗口。附属恢复夹具必须观察真实CLI产生的prepared journal，再仅终止该次自有CLI进程组，使用产品`service recover`恢复。无待办的recover、人工造journal或手写unit不算这项真实中断证据。长期opt-in及未提供环境仍单列，不能把SKIP算通过。

官方核心测试需要经过摘要校验的文件。CI 用 `python3 scripts/fetch-test-core.py` 默认获取固定版本的 sing-box 和 Mihomo，并通过 `SING_BOX_BIN`、`SING_BOX_ARCHIVE`、`MIHOMO_BIN` 传给测试；本地运行须显式设置这些环境变量。ARM64 本地只取 sing-box 时使用 `--core-only`，并如实记录 Mihomo 未执行；CI与发布必须执行三协议YAML解析。没有这些文件时的 `SKIP` 必须单独记录，不能写成官方核心或客户端验证通过。

```bash
go test ./internal/node -run 'OfficialCore|OfficialArchive|Mihomo' -v -count=1
bash scripts/build.sh
bash scripts/build-probe.sh
```

官方核心的本机 TCP/UDP、ACME 配置语法、同进程持续 TCP 维护、双架构构建各自证明不同范围。观察器的本地 socket 负例只证明 EOF/中断/内容损坏可被检测；不替代真实核心或 systemd 验收。ACME 语法通过不代表证书已签发；ARM64 交叉构建不代表 ARM64 运行；本机通信不代表云防火墙、移动客户端或公网可用。测试记录应包含源码版本、环境、实际命令、结果、跳过项和未验证范围；第 01 批历史见 [BATCH_01.md](BATCH_01.md)，第 02 批当前执行见 [BATCH_02.md](BATCH_02.md)。

第 02 批新官方流量用例 `TestOfficialCoreBoundedProbeThreeProtocolsAndFaults` 和 `TestOfficialCoreProbeSandboxCancellationCrashAndConcurrentCleanup` 也匹配原 `OfficialCore` 门槛，不新设“只解析即可通过”的替代入口。测试助手包由 `build-probe.sh` 另存 `artifacts/probe/`，静态构建 Linux amd64/arm64 与 Windows amd64，附内外摘要、Go/vendor 许可和网络说明；0.3.0继续保留独立CI artifact，并将三探针与两管理器统一纳入schema2七项正式资产合同，发布前同样校验，不放宽未知文件限制。管理器包新增文档仍按明确白名单核验，未知文件继续拒绝；继承契约缺口与实际归档检查见 BATCH_02。

第 03 批的 `TestOfficialCoreHY2PerformanceTCPUDP` 分别验固定速率、非 Brutal/显式 QUIC 与保留 Chrome；`TestMihomoHY2PerformanceMapping` 是解析证据，`TestOfficialCoreMihomoHY2PerformanceInterop` 才是官方 Mihomo 客户端经 HY2 的 TCP/UDP 与代理停止负例。两者不能合称“客户端已验证”。新增 `TestOfficialCoreHY2ControlledNetwork` 需 disposable root Linux、ip/tc 和内核 netns/veth/netem，显式设置 `QINGNODE_NETEM_TEST=1`；UDP-only 过滤与实际 cgroup 128 MiB 子项各自要求内核支持，任何 SKIP 都单独记录。原始 CPU 累计计数/RSS、应用吞吐/请求时间、UDP 样本与 qdisc 计数存独立结果目录，复现命令见 [NETWORK_PERFORMANCE.md](NETWORK_PERFORMANCE.md)。

第 04 批需分别验证 schema 1/2/3 与旧加密备份、主 URI 逐字等价、内外端口独立、所有端点导出/摘要和免重启；地址占用应覆盖 TCP/UDP 共端口、不同具体 IP、同族通配以及宿主相关的 ::。核心 1.14.0/1.14.3 没有 v6only 入站字段，临时绑定不能用假 JSON 或全局 IPv6 修改绕过。受控转发须实际传输外 TCP 30000→内443及独立HY2 UDP，并保留禁用代理负例、发起端和日志。真实 TCP/UDP、解析、MainPID、GUI、公网分开记录，测试缺IPv6不让IPv4结果失败。

受控NAT用例 `TestOfficialCoreControlledNATEndpoints` 需显式 `QINGNODE_NAT_DISPOSABLE=1` 与隔离root Linux，CI独立sudo步骤不替代原有门槛。安装器新增 `--connect-port` 透传和宿主写操作前的非法值拒绝，原失败恢复测试保持。真实systemd维护观察器已加入公开端口与额外入口增删/恢复，必须同时观察同一PID和活跃校验流；本地没有systemd时写未验证，不能把脚本或mock当执行。

能力测试分别覆盖缺少proc、权限不足、只读/不存在目录、容器/cgroup、TUN缺失与IPv6失败/未知。`capabilities` 无State依赖、无持久写入，目录访问位的 `write_exercised=false` 不能写成实际可写证明；本机四种回环的绑定和数据面分别断言，不把远程 unknown提升为成功。当前接口与复现入口见 [ENDPOINTS.md](ENDPOINTS.md)，当前批次实际失败、复验和未提供环境单列 [BATCH04.md](BATCH04.md)。

真实夹具使用自有 PID fd inode 与 `/proc/PID/net` 核对监听，不靠固定 sleep。Mihomo 固定版本先监听后进入 Running，故额外用官方 post-up 标记完整初始化；不预热或重试业务请求。ALPN 回归在旧实现上先实际失败，修复后同一支持 h2 的 TLS 目标通过；不能通过降低目标能力掩盖生产错误。`TestOfficialCoreHY2ClientPerformanceKeepsProcessAndTCPStream` 观察 HY2 支撑的同一 TCP 连接及真实核心 PID，但测试客户端保持原配置，不当作在线重配置客户端或 systemd MainPID 证据。当前专项、全项目分轮结果和未完成项见 BATCH_03：全量 race 绑定 b4e6bb0，最后源码 b698d04 已单独通过普通全项目、相关 race、vet 与发行保护/五包契约，安装器元数据整套 32/32 通过，final2 有完整结束标记；两个修复前负例保留退出 1，不将旧提交的全量结果转记到新提交。Alpine 原环境的 31/32 与首轮外层 2400 秒超时保留；Ubuntu 24.04 元数据夹具不是 Ubuntu 实机。串口配对提取文本不等于 guest 原件，命令耗时取实际输出，不用会话中断的墙钟间隔推算性能。最终构建修订、架构、原生执行与包冒烟以交付目录 build-receipt / QA / 交付说明为准，不把编译当执行。

HY2 新字段只经模型白名单、版本/构建能力和协议适配器；服务端字段改变运行配置，客户端字段改变导出，仍由真实派生比较决定影响。宿主 sysctl 使用独立 `NetworkHost` 事务，不进入 State；测试故障注入和真实隔离宿主读回分开。DNS 诊断的预期答案缺失时内容正确性必须未知，系统缓存会影响耗时。改参数后普通报告配置摘要会不同，使用保存方案关联的 `CompareControlled`，不能手改报告或放宽其它条件。

## 第 05 批拓扑与链路验证

类型拓扑与客户端导出分开：Node.EgressID、PortForward、Egress、EgressPolicy 参与完整候选验证和真实派生比较，批量最多 256 操作、1 MiB 私有 JSON，禁止未知字段/重复/大小写伪装/null。被引用出口不能直接删，显式批量迁移引用和删除可统一提交。未用出口、名称编辑不应造成运行变更；共享核心的路径变化仍可能重启整个进程。纯转发/WireGuard 落地也应支持旧 start/stop/rollback 与元数据停止保持，不要求创建假代理用户。

Profile/Report v1 必须保持旧直连输出；非 direct 入口用显式 v2 的 `server_path_sha256` 绑定实际选择闭包、核心和 DNS，CA 覆盖、启动失败和正常测量均传递该摘要。`NodeRouteDigest` 不包含未用出口或未选备用；摘要只是导出时声明，不是远端实时配置证明。新字段不能带 v1，也不能降版本删字段给旧二进制读；不同服务端路径的报告拒比。GraphProfile 是独立内部白名单对象，不给公开 qingprobe 加任意图导入口。

真实核心新增 `TestOfficialCoreTopologyPureTCPUDPForwards`、`TestOfficialCoreTopologyEntryToRemoteProtocols`，以及 portable 图的 SOCKS5 链/WireGuard/停止/坏凭据/清理用例，均继续匹配原 `OfficialCore` 门槛。源地址、目标计数、停选定出口后失败与目标仍可直达控制请求分别留证。主备需另验证连续阈值、冷却、恢复、未知/取消、本机工具故障、探测后配置变化、Apply 与观测文件失败，不能仅靠 mock 声称真实切换或会话迁移。

独立网络空间与虚拟网卡验收只在明确可重建的 root Linux 使用下列入口；它要求 iproute2 与内核 netns/veth，创建、清理自己命名的资源，不改默认路由或已有 WireGuard：

```bash
sudo env "GO=$(command -v go)" "SING_BOX_BIN=$SING_BOX_BIN" QINGNODE_TOPOLOGY_DISPOSABLE=1 sh -c '"$GO" test ./internal/node -run "^TestOfficialCoreTopologyWireGuardNamespaceExit$" -v -count=1 -timeout=3m'
```

这与普通回环 WireGuard 对端本机服务不同：验收应实际穿过两端用户态 endpoint，到达独立非回环目标，核对目标看到的源 IP、路由、TCP/UDP、错误密钥和停落地负例。没有权限/内核/IPv6时单列未验证，不将握手、配置解析、原生 Windows 或交叉编译代替 Linux 链路。具体当前命令、原始失败和完成结果只记 [BATCH05.md](BATCH05.md)，不把前批成功搬来。

## 真实环境与发布门槛

`scripts/acceptance-vps.sh --disposable` 仅用于明确授权、可重建、没有现有 QingNode 的 root + systemd 主机。它会安装、修改和卸载节点；失败保留现场。第 01 批入口新增 `test-maintenance-flow.py`，同时观察真实 MainPID/启动身份、一条不重连的持续 TCP 校验流、元数据/导出/批量/重复/回退/派生修复，以及停止状态保持；运行端口变化和运行回退另外要求真实重启。本机验收不包含公网、ACME、BBR、防火墙、ARM64 或全部跨版本升级验证。无真实 systemd 的隔离环境必须写未验证；生产主机、SSH 登录、现有节点、公网测试和证书签发按授权范围另行执行。

CI 保留静态检查、race、root权限、安装器、官方三协议TCP/UDP、Mihomo解析、双架构包和真实systemd门槛，并在一次性 runner 的独立步骤显式 opt-in 拓扑/WireGuard netns 数据传输，明确安装 iproute2。发布 guard 要求该同名步骤成功；工作流源码增加步骤不等于远程已经运行。发行文档 TOPOLOGY.md/BATCH05.md 在安装器、两构建脚本、归档检查、发布保护和安装器夹具中逐项列入白名单，未知文档和链接仍拒绝。release/v*分支先验证候选；main/tag才在完整验收后发布。版本、准确提交、双架构摘要与RELEASE.json严格绑定；同名资产不符拒绝覆盖，草稿只有全部验证后才建立并上传，确认完整才转正式版。Git推送/发布与生产部署按用户授权范围分别处理，自动检查不代替人类或公网验收。

准备发布时核对版本、安装器版本、发行说明、包内文档和摘要；保留旧数据兼容与恢复路径。涉及凭据、schema、协议默认值或核心适配范围的变更，应先补迁移/回滚设计和专项证据，再决定是否发布。
