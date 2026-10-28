# 第 04 批实施记录：NAT VPS、双栈与连接地址模型

状态：本批代码与测试已本地提交，最后源码 `e153add1af37c6885ea3a6b357456a100e929d26` 完整回归已结束；本记录列明通过、实际失败和未验证范围。最终仅文档收尾的提交与五个预览包由交付回执绑定，不把交叉编译、解析或临时绑定当成真实服务/公网验收。

## 起点与边界

起点提交 `88c64d4c20b3a6a3d30d15f036c6426db4e7c0db`，原分支 `batch/03-hy2-network-performance`，本批工作分支 `batch/04-nat-dual-stack-endpoints`；工作区原先干净。已核对前置实际代码：第 01 批按真实派生输入分类与免重启、批量/原子应用/恢复；第 02 批只走所选代理的 TCP/UDP 隔离测试；第 03 批 schema 2、HY2/DNS/宿主事务。复用这些入口，不回退到调研快照 `70c0c277`。

保留 Bash 引导、静态 Go 管理器、独立官方 sing-box 和轻量 systemd 服务；没有必装 Docker、数据库、Web 面板或新代理协议。默认核心仍为 1.14.0，不因本批切换到 1.14.3 或其他兼容线。常规本地修改与提交属于本批；远程推送、PR、发布、生产部署未由本记录授权。

## 已实现

| 接口 | 结果与边界 |
| --- | --- |
| `Node.Listen/Port` | 单个本地 IP/端口，供服务器入站、冲突、就绪和防火墙；没有偷偷改旧监听 |
| `Node.Host/ConnectPort` | 主客户端地址/端口；默认端点 ID 为 `default`，与本地 Port 独立 |
| `AdditionalEndpoints` | 最多 16 个稳定显式 ID 的额外入口，同一监听/身份；IP/域名/端口校验、重复拒绝；声明不创建转发 |
| `endpoint list/add/edit/remove/material` | 额外端点管理、只读预览和版本 1 外部待验证材料；保留 unknown，不宣称云 NAT 已更改 |
| `init/add/edit --connect-port`、`wizard --nat`、Bash 安装参数 | 显式收集内外端口，不覆盖用户地址；安装器前置拒绝非法连接端口并透传；取消/错误整批不应用；协议 TLS/REALITY 选择独立 |
| `export/probe --endpoint` | 所有 URI/QR/Base64/JSON/YAML 和私密 Profile 指向明确端点；默认入口保持简单 |
| `clientInput` 派生比较 | 遍历所有端点和凭据；改公开入口仅影响客户端时免重启，保存新 State/历史，损坏派生仍修复 |
| 本地绑定模型 | TCP/UDP、具体 IP、同族通配、IPv6 等价与不确定双栈分别判断；必要时同时持有候选临时 socket 做真实绑定预检 |
| `capabilities` | 安装前只读本机报告，架构/init/内存/权限/容器/TUN/目录/内核值分项；临时回环绑定与小包收发分开，不当公网证明 |
| schema 3 解码入口 | schema 1/2 仅内存迁移、旧公开端口显式锁定；身份/原 URI 保持，旧原件留存；旧二进制拒绝新格式 |
| 文档与包契约 | 新端点说明/连续记录进入明确文档白名单；未知路径、软链接、摘要和发行门槛继续严格拒绝 |

用法、传输层映射、IPv6 语义与恢复步骤见 [ENDPOINTS.md](ENDPOINTS.md)。SS2022 单入口的外部 TCP 和 UDP 必须使用同一端口；本批不提供不同端口的组合表达。官方 1.14 没有入站 v6only 字段，`::` 采用核心自动双栈策略，不能声明保证双栈或严格 IPv6-only。本批没有改全机 IPv6、内核/路由、SSH、外部服务或云 NAT。

## 实际证据与结果

本批从修改前基线开始执行，没有把前批历史成功转记成本批结果。已完成的分轮日志与源码清单均保留，包括失败轮次。完整回归使用准确冻结提交 `e153add1af37c6885ea3a6b357456a100e929d26`，20 项检查均有配对退出码及 `RUN_END`，QEMU 正常退出 0。19 项检查退出 0；真实 Alpine 安装器退出 1，必须保留为失败，不能称全套通过。

Linux 实测环境是隔离 QEMU、`-cpu max`、4 vCPU、Alpine Linux / `6.18.55-0-virt`、无外部网卡，仅启用自有回环及测试命名空间。baseline/targeted 轮为 4 GiB 内存；full1 为 5 GiB。Windows Go 1.27.2 交叉编译的静态 Linux 测试二进制在该 Linux 环境真实执行；full1 的源码 `go test` / `-race` / `go vet` 使用 Linux Go 1.26.8。核心自身的构建环境另列：官方 1.14.0 为 Go 1.26.7，1.14.3 为 Go 1.26.8；Mihomo 1.19.30 为 Go 1.26.6。这些工具链不能合并成一个“本项目构建版本”。

| 轮次 / 源码绑定 | 实际命令或检查 | 已观察到的结果 |
| --- | --- | --- |
| baseline1 / 干净 `88c64d4c20b3a6a3d30d15f036c6426db4e7c0db` | 静态 node/CLI 定向基线、完整 probe 包、1.14.3 候选定向基线；精确正则见 `run-batch04-baseline.py` | `node-baseline`、`cli-baseline`、`probe-baseline`、`candidate-baseline` 均退出 0，存在 `RUN_END`。这是修改前基线 |
| targeted1 / 基于 `88c64d4` 的开发快照 | node 的端点/能力/迁移/绑定/三协议/解析/持续流量；CLI 定向项；probecli/probe 完整包；候选三协议/导出解析 | 五项检查均退出 0，存在 `RUN_END`。只覆盖该轮已存在且正则命中的测试，不能据此补记后来新增的受控 NAT 或单核心双栈测试 |
| targeted2 / 基于 `88c64d4` 的另一开发快照 | 加入真实受控 NAT；原有 node/CLI/probecli/probe 及候选定向项 | `node-targeted`、`candidate-targeted` 各退出 1，其余三项为 0；存在 `RUN_END`。两核心均在 HY2 UDP 样本的流量预算检查处失败，保留为失败轮 |
| targeted3 / `1ac96b5a6ca83f7eedf8a874b340d5515cad672b` 对应清单和静态二进制 | 复验 NAT UDP 预算，并执行关闭转发负例 | node、candidate 各退出 1，其余三项为 0；存在 `RUN_END`。关闭 UDP 转发后的实际结果为传输错误、未完成样本，不是已观察到的超时丢包 |
| targeted4 / `a082df1c90497f755aa2531830b29680fd1ccff8` | 完整静态 node/CLI/probecli/probe；候选定向；旧实现十进制回归负例 | node、CLI 各退出 1；probecli、probe、candidate 各为 0；`before-decimal` 退出 1；存在 `RUN_END`。真实双栈和两核心 NAT 子项已通过，但不能把该轮 node/CLI 总结果写成通过 |
| full1 / 干净 `e153add1af37c6885ea3a6b357456a100e929d26` | 静态 node `-test.v -test.timeout=10m`、静态 CLI `-test.v -test.timeout=5m` | 两项均退出 0；新十进制、旧生命周期/UDP 冲突修正和真实 UDP 跨族预检均通过 |
| full1 / 同上，Linux Go 1.26.8 | `go test -p 1 -count=1 -v -timeout=15m ./...` | 已退出 0：cmd/qingnode 26.568s、node 109.418s、probe 9.122s、probecli 0.393s；qingprobe/ui 无测试文件。包耗时描述本轮测试，不代表代理性能或安装时间 |
| full1 / 同上 | `go test -p 1 -race -v -count=1 -timeout=15m ./...` | 已退出 0：cmd/qingnode 286.255s、node 583.387s、probe 16.529s、probecli 2.885s；这是本批准确源码的完整 race 结果 |
| full1 / 同上 | `go vet ./...`；`go test ./internal/node -run '^TestStorePermissionsUnderRestrictiveUmask$' -v -count=1` | `go-vet`、`service-user` 均退出 0；后者 0.303s，实际降权 UID/GID 65534 核对文件访问契约，未启动 systemd 服务 |
| full1 / 同上 | 两核心分别设 `QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/evidence/netem-*`，运行 `TestOfficialCoreHY2ControlledNetwork` | 默认/候选均退出 0，30.043s / 32.623s；真实隔离 baseline/限速延迟丢包、UDP 过滤、128 MiB cgroup 子项通过，无该入口 SKIP；小样本不作性能提升或跨版本优劣结论 |
| full1 / 同上 | 设 `SING_BOX_BIN=/sing-box-candidate`，`go test ./internal/node ./internal/probe -run 'OfficialCore\|OfficialCandidate\|Mihomo' -v -count=1 -timeout=10m` | `candidate-core` 退出 0，node 94.163s / probe 10.305s；候选三协议/导出、实际 Mihomo 互通及隔离助手通过。该普通命令内 netem 跳过不影响前一行单列真实 netem 证据 |
| full1 / 同上 | `shellcheck install.sh scripts/*.sh`；全部 `.sh` 的 `bash -n`；`python3 scripts/test-release.py`；`python3 scripts/test-maintenance-harness.py` | ShellCheck、Bash 语法、发行保护 38/38、维护观察器 3/3 均退出 0；观察器夹具通过不是本批真实 systemd 运行 |
| full1 / 同上 | `bash scripts/build.sh`；`bash scripts/build-probe.sh`；`python3 scripts/check-build.py`；`capabilities` / 离线节点 `endpoint material` 文件输出 | 四项检查均退出 0，双架构管理器和三架构助手共五包构建、严格归档契约通过；能力/外部材料实际输出不把 unknown 提升为公网通过 |
| full1 / 同上，真实 Alpine 3.24.2 元数据 | `python3 scripts/test-installer.py` | 33 项中 32 项通过，564.096s，退出 1。`test_online_install_reads_actual_host_os_release_without_overwriting_tag` 读取真实 OS 后被现有平台门槛以“未验收的系统：alpine 3.24.2”拒绝；保留失败，不改平台白名单或测试断言 |
| full1 / 同上，隔离 Ubuntu 24.04 元数据夹具 | `InstallerTests.test_online_install_reads_actual_host_os_release_without_overwriting_tag`；之后完整安装器套件 | `installer-host-read-fixture` 单项退出 0；`installer-supported-metadata-fixture` 完整 33/33 通过、566.422s、退出 0，随后恢复原 Alpine 标识。只是同一 Alpine QEMU 内暂换 `/etc/os-release` 的 OS 读取夹具，不是真实 Ubuntu 24.04 安装 |
| Windows 原生 / `e153add1af37c6885ea3a6b357456a100e929d26` | `go test -count=1 -v -timeout=5m ./internal/probe ./internal/probecli ./cmd/qingprobe`，Go 1.27.2，官方 1.14.3 | 总退出 0，probe 3.296s、probecli 0.725s，qingprobe 无测试文件；真实 SS2022 隔离路径、不回落、取消/核心崩溃后的清理通过。仅原生 Windows 回环，不是 GUI、手机或公网结果 |
| Windows 原生初始构建 / 同上 | 两管理器与三助手构建、严格归档检查、actionlint 1.7.12、全部 Bash 语法、Windows 助手启动 | 五包构建/契约、actionlint、Bash、Windows 助手 version/help/local 启动冒烟通过；actionlint 本机未运行 ShellCheck，Linux ShellCheck 另列真实通过。只 Windows 助手在本机执行，未把 Linux/ARM 编译当执行；最终文档提交后的重建和包冒烟由交付回执记录 |

targeted1/targeted2 原始 manifest 的 `commit` 沿用了基线标签 `88c64d4`，它只表示起点，并不表示这两份源码等于该提交。`work/batch04-development-snapshot-receipt.json` 已明确标为 `dirty_development_snapshot=true`；实际源码和测试二进制由每文件 SHA-256 与 `$testinput/*` 摘要绑定。两个 manifest 的 SHA-256 分别为 `61ea3ed1b06b0a24521bdbeb85d3eee576553b82f50a73c03ac1635895f33f93`、`6c8f2be951352a13ef10c8352ae95559a92fa2cb78350ebe70f75f1867e11eb5`。保留原始清单，不用重写标签掩盖开发快照。

### 失败、修正与复验

- targeted2 的 HY2 NAT UDP 正例计划发两份 64 字节请求，测试夹具把总预算恰好设为 256 字节；探测器还须为安全辨认超长回包保留读取余量，因此第一份请求/回复通过后，第二份被 `byte_limit` 拒绝。日志实际是 sent=1、received=1、lost=0，整项仍失败。修正测试夹具使用已有受限默认预算，并继续严格断言两份请求/回复的数量、有效字节和目标计数；没有放宽探测器预算校验，也没有把预算失败当网络丢包。
- targeted3 直接关闭 UDP 外部端口，内核返回 ICMP 对应的 `connection refused`；实际报告 `udp_transport`、unfinished=1、lost=0、loss_percent=null。这证明传输失败，不能硬改成一个丢包或 100% 丢包。后续夹具保留“转发关闭”并在原外部端口用自有 socket 静默收包，确认包已到该端口但未转发，再等待真正的请求超时。targeted4 两核心均观察到 sent=1、received=0、lost=1、`udp_no_response`，目标 HTTP/UDP 计数不变；这是受控单样本负例，不是公网丢包估计。
- targeted4 的 `TestSS2022ReservesBothTCPAndUDP` 仍把 `::` 与 IPv4 的宿主相关双栈关系当成必然静态冲突；其“UDP 冲突必须拒绝”断言保留，夹具改成相同本地地址的确定冲突。同时新增 `TestProbeLocalBindingsActualDualUDPWildcardConflict`，先实际收发确认本机双栈，再真实同时绑定 `udp [::]` 和 `udp 0.0.0.0`，要求跨族冲突被预检拒绝。修正提交 `0962bb5e3caac62f408ea6d030c47962a5e5e8b2`，full1 静态和源码普通测试均通过。
- targeted4 的 `TestCLICompleteOfflineLifecycle` 把“修改本地 Port”仍当成“客户端导出端口也跟随变化”。保留导出必须为 8443 的原断言，改为明确同时输入 `--port 8443 --connect-port 8443`；另有端点测试继续要求仅改本地端口时客户端端口不变。修正提交 `e153add1af37c6885ea3a6b357456a100e929d26`，full1 静态和源码普通测试均通过。
- `before-decimal` 将最终十进制回归测试注入旧 `1ac96b5a6ca83f7eedf8a874b340d5515cad672b`，没有注入修复；`03000` 被旧接口按八进制解析，测试实际退出 1。这是预期发现旧缺陷的失败证据，不能记为退出 0 或整套成功。新实现提交 `a082df1c90497f755aa2531830b29680fd1ccff8` 使用十进制连接端口解析；相同测试在 targeted4 新 CLI、full1 静态 CLI 和源码普通测试均通过。旧二进制/注入测试 SHA-256 见 `work/batch04-regression-receipt.json`。

### 已实测的路径和证据边界

两核心的定向结果分别核对，不用“能解析”替代“能传输”：

| 能力 | 本批直接证据 | 不能推出的结论 |
| --- | --- | --- |
| 三协议与所选端点导出 | 官方 1.14.0 / 1.14.3 的三协议 TCP/UDP 回环；REALITY/HY2/SS2022 × default/v6/domain 共 9 种所选端点的官方 sing-box 和 Mihomo 1.19.30 解析通过；URI 地址/端口和身份由模型测试核对 | 用文档地址通过解析不表示该地址可连接，也不等于 Mihomo 手机 GUI 已加载 |
| 受控 NAT | 自有 TCP 30000→443、HY2 UDP 30001→443；真实 HTTPS/HTTP 载荷、序号 UDP 请求/回复、转发/目标计数；额外 IPv6 转发入口；关闭指定转发后的新客户端失败且目标计数不增加。targeted4 两核心相应子项通过 | 这是测试进程模拟的受控转发，不是云 NAT、iptables/nftables DNAT 或真实运营商链路 |
| 单入站真实双栈 | 一个 SS2022 服务端 `listen ::`，同一 PID/端口；分别以 `127.0.0.1`、`::1` 官方客户端完成 HTTP 载荷和 SOCKS UDP 回包。targeted4 默认核心 PID 753、候选核心 PID 2052，两族都通过；full1 默认核心静态和源码普通测试也通过 | IPv6 转发入口和该单入站测试是两种证据；本机双栈通过不保证任何 VPS/云厂商或公网也支持 |
| 端点编辑免重启 | 两核心的真实进程/同一持续 TCP 流量测试含客户端入口修改；targeted4 默认核心 PID 558 持续 141 帧、候选 PID 1935 持续 218 帧；原流量连接不重建。停止状态、派生文件修复、失败恢复另有测试 | 这是直接托管核心进程 PID，不是 systemd MainPID；不能声称真实 systemd 生命周期已验收 |
| 本机能力与权限 | IPv4/IPv6、TCP/UDP 分项临时回环收发；取消/失败释放自有 socket；State 不读写、路径不创建、危险读取源拒绝；schema 1/2→3 身份与字节/旧原件恢复测试通过 | 能力报告只代表当前进程/命名空间；UID/GID 65534 子进程验证文件可读/不可读契约，也不证明服务已启动或协议在该服务账户下传输 |

`TestOfficialCoreHY2ControlledNetwork` 在普通静态/源码测试中因未开专用 netem 开关跳过，fixture 进程入口本身也不是独立验收；full1 已用专用开关单列两核心 netem 并实际通过。该新结果不引用第 03 批历史数据。未提供真实 systemd、外部机器/运营商、DNS 服务商凭据或云 NAT、原生 ARM、手机/桌面 GUI、真实 ACME 签发环境；这些项目保持未验证。IPv4 和 IPv6 证据分开保存，不用域名回落 IPv4 的成功证明 AAAA 路径。

### 使用和恢复边界

- 本批保留既有 UFW 受管行为，默认 `Firewall=none`。`RequiredRules/Sync` 按本地 `Port` 与协议网络生成 `to any` 规则；修改外部 `ConnectPort` 不会开放该外部端口对应的本地 UFW。不同本地 IP 可绑定同端口，不表示已经实现按目的 IP 隔离的防火墙策略；精确 IP 策略由用户自行管理。本批未改规则格式或旧策略，也未提供 UFW 实机执行证据。
- `WithEndpoint` 只在导出、Profile 和探测时投影所选入口：返回值替换了用于本次客户端连接的 `Host/ConnectPort`，调用方不能把它存回 State 或用它替代原节点声明。持久编辑继续走显式端点命令、完整候选校验与事务。
- `probe` / `qingprobe` 的 `--family` 只约束被测目标的地址族，不强制代理入口同族。代理入口 IPv6 要以 IPv6 字面端点配合实际客户端验证；目标 IPv6 或域名回落 IPv4 成功都不能代替 AAAA 入口验证。
- 原 `public-check` 手动记录使用完整节点摘要。schema 迁移或端点字段变化可能保守地使其显示需要重验；原记录保留，不伪造新结果。新自动报告仍以实际所选用户/端点的规范化客户端摘要绑定，不能与手动摘要混作同一证据。
- typed State 合法但派生 `server.json` 损坏，与原 State 无效是两种恢复情况。前者的保原、候选检查、修复及旧快照/rollback 已在 full1 普通和 race 验证。坏 JSON、未知格式/字段、坏 PEM 或无效认证/额外端点可能在 Load/Decode、旧 State 校验或恢复预备份阶段就被拒绝；不承诺现有 restore 可以直接覆盖任意坏 State。先完整保管原状态目录、历史和事务材料，用已核验备份在隔离目录恢复核对，再走明确恢复；不猜测删字段，不只凭一个 MainPID 豁免未知监听。证书仅到期由日期检查单独报告，不等于 State 结构无效。

原始证据位置：`work/batch04-{baseline1,targeted1,targeted2,targeted3,targeted4}-linux.log`、各轮 `*-evidence/evidence/*.log` 与 `*-source-manifest.json`；当前 `work/batch04-full1-linux.log` 和准确源清单；Windows 的 `work/batch04-windows-linux.log`、`work/batch04-windows-receipt.json`；原生初始构建的 `work/batch04-native-initial-build.log`、`work/batch04-native-initial-build-receipt.json` 及源清单。Windows 官方 1.14.3 可执行文件 SHA-256 为 `5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf`。最终构建修订、架构、原生执行、包冒烟和交付文件摘要以交付目录的 build-receipt、QA 与交付说明为准；不把编译当执行。

以下入口可在具备相应环境时复现，命令存在不表示所有环境均已验证：

```bash
go test -p 1 -count=1 -v -timeout=15m ./...
go test -p 1 -race -v -count=1 -timeout=15m ./...
go vet ./...
SING_BOX_BIN=/已核摘要/sing-box-1.14.0 MIHOMO_BIN=/已核摘要/mihomo-1.19.30 go test ./internal/node -run 'OfficialCore|OfficialArchive|Mihomo' -v -count=1
SING_BOX_BIN=/已核摘要/sing-box-1.14.3 MIHOMO_BIN=/已核摘要/mihomo-1.19.30 go test ./internal/node -run 'OfficialCore|OfficialCandidate|Mihomo' -v -count=1
sudo env "GO=$(command -v go)" SING_BOX_BIN=/已核摘要/sing-box QINGNODE_NAT_DISPOSABLE=1 sh -c '"$GO" test ./internal/node -run "^TestOfficialCoreControlledNATEndpoints$" -v -count=1 -timeout=2m'
SING_BOX_BIN=/已核摘要/sing-box go test ./internal/node -run '^TestOfficialCoreSingleSS2022WildcardDualStackTCPUDP$' -v -count=1
shellcheck install.sh scripts/*.sh
python3 scripts/test-maintenance-harness.py -v
sudo env "GO=$(command -v go)" python3 scripts/test-installer.py
bash scripts/build.sh
bash scripts/build-probe.sh
python3 scripts/check-build.py
```

受控 NAT 和宿主网络入口仅在明确可重建的 Linux 环境使用，不对生产机执行；缺开关/权限/IPv6 等前置条件时，按原始跳过项记录，不能计入通过。`scripts/test-maintenance-flow.py` 已包含公开端口/额外入口变更、恢复后的真实 MainPID 和同一持续 TCP 流量观察；本批尚未提供真实 systemd 环境，脚本存在不能代替执行。

## 迁移与失败恢复

schema 3 有实际新增字段；schema 1/2 旧节点在内存克隆后写入 `ConnectPort=旧 Port`，保留原 Host、Listen、Port、节点/用户 ID、UUID/密码、REALITY 密钥、证书和时间戳。默认 URI、客户端及服务器语义等价，旧文件不因查询改写；首次有意义写入才保留旧原件并建立新代。旧 schema 包含新端点字段（即使 null）及未知字段明确拒绝，未来格式不能静默删字段。

旧二进制会拒绝 schema 3。节点 rollback 和旧 v1/v2 备份/快照恢复由本批管理器迁移后仍写 schema 3，不提供自动程序降级。先保留旧原件，处理 pending 事务须使用理解其格式的管理器；不要手改版本号或删除端点字段来伪造兼容。旧格式材料可供单独离线恢复验证，不能直接覆盖仍由新服务/事务维护的数据。

变更继续持锁、验证完整候选、原子切代并有条件恢复。只改公开端点不改变运行/停止和自启；本地监听、凭据、核心或实际运行输入变化仍按原规则应用，可能断流。端口绑定与真实启动之间仍有竞争窗口，启动失败沿旧配置和运行状态恢复；恢复失败保留事务。只读查询、能力和外部材料不修复事务、不启动服务、不调整参数。

## 固定来源与许可证

本批实现独立编写。只参考固定源码/文档的字段、地址族与套接字机制；不复制 GPL 面板、协议或其他管理器代码。

| 项目 | 固定 tag / commit | 核验机制与许可 |
| --- | --- | --- |
| SagerNet/sing-box | v1.14.0 / `0b8995879f29a9b98ee027bc17b75e101445b238`；v1.14.3 / `7054cac5124465ffdb145870d7c01885566711b1` | Listen/Dial/入站 TCP/UDP；无 v6only JSON；独立 GPL-3.0-or-later 核心及其命名附加条款，不随本项目包分发 |
| SagerNet/sing | `3f8f790b7a2968307bbf900544fc8030791c715e`；`0ad23b637bd49e7c2982640137df7598dde93ff9` | 两核心固定依赖的 NetworkFromNetAddr；GPL-3.0-or-later，只核对接口机制 |
| golang/go | go1.26.8 / `c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e` | 官方候选二进制构建元数据对应工具链；通配选族与 Linux IPV6_V6ONLY；BSD 3-Clause，不假称管理器也由此版本构建 |

详细链接与声明见 [THIRD_PARTY.md](../THIRD_PARTY.md)；固定来源核对不等于协议实测。WireGuard 的上游顶层 endpoint、接口绑定及 DNS 拨号策略只用于厘清概念，没有在本批实现 WireGuard 或链式拓扑。

## 后续批次可复用接口

- `EffectiveConnectPort(Node)`、`EffectiveEndpoints(Node)`、`WithEndpoint(Node,id)`：统一客户端选择；`WithEndpoint` 返回本次客户端投影，不能存回 State；服务器、端口、防火墙始终读本地 Listen/Port。
- `NormalizeEndpointHost`、`ValidateEndpoints`：新输入去 IPv6 外括号、保存原合法拼写、严格端点 ID/数量/重复/端口校验；旧 State 不重写地址文本。
- `DecodeState/MigrateState`：唯一 schema 1/2→3 入口；快照复用，不另开宽松解码或覆盖原件。
- `ProbeLocalBindings` 与 `ProbeCapabilities`：本机临时能力/候选绑定证据，不替代远程认证、UDP 和真实服务用户权限。
- `endpoint material` version 1、私密 Profile version 1 和自动报告 version 1 分开；后者摘要绑定实际所选入口。外部材料未知值不能提升为验证成功。

实现提交为 `1ac96b5a6ca83f7eedf8a874b340d5515cad672b`，十进制修正和真实 NAT 负例为 `a082df1c90497f755aa2531830b29680fd1ccff8`，最后源码/测试为 `e153add1af37c6885ea3a6b357456a100e929d26`。最终文档收尾提交不得改变这些已测源码；交付的 `build-receipt.json`、`DELIVERY.json`、QA 源清单和 `SHA256SUMS` 分别绑定最终构建、源码/文档提交、分轮测试与交付文件，不使用自引用校验和。五包与最终 Linux amd64 包冒烟的实际结果见交付说明及原始配对日志；未执行项不提升为通过。
