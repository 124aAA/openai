# 第 03 批实施记录：HY2 与宿主网络性能

状态：代码与专项实测已完成，最后源码为 `b698d041829eb6eba2b94594a60b5c796c3bb5eb`，尚未发行。首轮全项目回归在 `b4e6bb0` 完成普通 Go、全量 race、vet、候选核心及构建等检查，但整轮有 Alpine 系统识别用例失败，随后达到外层总预算；`b698d04` 已完整结束补丁复验，普通全项目、相关 race、vet、发行保护、五包构建/契约和 32 项安装器元数据夹具均通过，两个修复前负例保留预期退出 1。本文保留各轮失败、未完成项与提交边界，不把第 01/02 批历史成功当作本批重跑。

## 基线与改动边界

接续分支 `batch/03-hy2-network-performance`，起点已有第 01 批实际配置影响分类、批量预览、原子应用/恢复和能力矩阵，以及第 02 批隔离代理测试、原始报告、受控 UDP 和 `qingprobe`。起点提交 `9b09042d4f82ab2ee70a93359f4f1875291361bf`；此处只定位前置代码，不回退工作区，也不将前批验证重记为第 03 批。

本批新增实际持久字段，因此 State 从 schema 1 升为 schema 2。默认官方核心仍为 1.14.0；1.14.3 是同兼容线已补核的候选，不自动跨兼容线、不替换第三方核心。Bash、静态 Go、独立官方 sing-box 与 systemd 主干保持，无必装 Docker、数据库、Web 面板或常驻测速服务。

本批实现与固定来源的详细接口说明见 [NETWORK_PERFORMANCE.md](NETWORK_PERFORMANCE.md)，分层能力见 [CAPABILITIES.md](CAPABILITIES.md)，测量定义沿用 [NETWORK_TESTS.md](NETWORK_TESTS.md)。首个完整实现提交为 `eb3b3143e3b62085707e393af2457e5e30132d8d`；后续实际失败、修复提交与复验逐项补记，不以首轮局部成功覆盖最终代码。

| 实现提交 | 范围 |
| --- | --- |
| `eb3b3143e3b62085707e393af2457e5e30132d8d` | HY2 模型/方案/导出、DNS、schema 2、宿主事务和专项入口 |
| `dbcbb6127c91574e1d8ec1f314e0565ef8da169c` | 真实 ALPN 回归修复、自有监听就绪、netem 夹具清理与资源边界接续 |
| `a3d1b5894cf513794529306d2fc3e30932055c76` | 共享 probe 夹具实际监听就绪，继续保留首请求与协议断言 |
| `b4e6bb0b312360d5523fba0ded756fea8c19086a` | 拒绝可能阻塞的恢复输入、Mihomo 完整初始化屏障、HY2 同连接维护验证；第四轮专项和首轮全项目回归快照 |
| `b698d041829eb6eba2b94594a60b5c796c3bb5eb` | 最后源码：计划阶段拒绝无法按原权限恢复的 sysctl 文件；输出边界拒绝悬空受管软链接及其祖先。后续仅文档；普通全项目和相关 race 分轮复验，不声称此提交重跑了全量 race |

## 实现范围

- HY2 服务端上/下行策略、客户端两方向 Brutal 预期、明确非 Brutal、BBR 档位与有限 QUIC 窗口/超时/调试分别保存。未保存、明确 false 和明确数值不混为一个默认；普通编辑保留身份与凭据。
- 服务端、sing-box 客户端、Mihomo 客户端和 URI 分别适配。固定版本/构建标签验证不冒充实际流量；Chrome QUIC 覆盖和格式丢失明确提示，默认拒绝有损导出，只有明确允许才附警告输出。
- 自动、测量后固定速率、保守资源与自定义按实际派生字段预览；只影响客户端时沿第 01 批分类免重启，运行影响仍候选校验、按需重启及失败恢复。
- 独立宿主网络操作读取可用/默认 TCP 算法与实际接口队列，显示 UDP/CPU/内存/MTU 事实；显式应用有限字段，先快照、逐项读回，失败与显式恢复保留外部手改。
- DNS 先做有预算的解析耗时和预期答案核对，再显式选择项目局部 system/UDP 解析器。不改宿主 resolv.conf，不混淆客户端 bootstrap 与服务端目标 DNS。
- 原始网络报告保留；调参前后对比只允许方案声明的配置差异，其余测试条件仍需匹配，不自动归因、不自动调参。
- 新增 opt-in 真实受控网络验收：专用 netns/veth、双向 netem、HY2 HTTPS/UDP、UDP-only 过滤与可用时 128 MiB cgroup；没有环境支持就明确未验证。

## 本批实际执行证据

专项源码先在 Windows amd64、Go 1.27.2 下以 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -mod=vendor -c` 生成静态测试程序，再在下述隔离 Linux 实际执行。交叉编译本身不计协议或 Linux 通过；本节按实际运行结果记录。全项目、安装器和发行检查按末尾首轮与补丁复验分别记录，不将一个提交的通过转记给另一个提交。

修改前基线实际运行固定前置源码 `1db455d6ad36e2e5d77db62570c8623e46c3dae9`，QEMU TCG `cpu max`、4 vCPU / 4 GiB、Alpine `6.18.52-0-virt`、Go `1.26.8`。`go test -p 1 -count=1 -v -timeout=15m ./...`、`go test -p 1 -race -count=1 -timeout=15m ./...`、`go vet ./...` 与实际 1.14.3 `OfficialCore|OfficialCandidate` 候选测试命令均退出 0；包含 1.14.0/Mihomo 和降权权限基线。race 耗时 cmd/qingnode 278.706 秒、internal/node 315.090 秒、internal/probe 15.446 秒、internal/probecli 2.930 秒。完整命令与前置收尾见 [BATCH_02.md](BATCH_02.md)，日志 `work/batch03-baseline2-linux.log`。

该候选命令中的 `TestOfficialCandidateArchiveInstall` 缺匹配 1.14.3 归档而跳过；不计候选安装验证。此前 3 GiB/包并行基线 race 遭 guest OOM，失败日志 `work/batch03-baseline-linux.log` 保留；增加 VM 内存、`-p 1` 复验未改断言或原测试超时。这里是前置基线，不能覆盖第 03 批新代码、netem、cgroup、sysctl 事务或最终发行门槛。

首轮本批专项实际运行 `eb3b3143e3b62085707e393af2457e5e30132d8d` 的 Linux 测试程序，QEMU TCG、4 vCPU / 4 GiB、Alpine 内核 `6.18.55-0-virt` 与匹配 veth/netem/ingress/u32/gact 模块；日志 `work/batch03-targeted1-linux.log`、原始归档 `work/batch03-targeted1-evidence.tar.gz`。结果为 `node-new:1`、`cli-new:0`、`candidate-new:1`、`netem-default:1`、`netem-candidate:1`，整轮未通过。

- 官方 Mihomo 1.19.30 经 sing-box 1.14.0 和 1.14.3 的两个 HY2 互通 case 均实际通过：固定双向预期、原生 BBR/显式窗口，TCP 受控内容、SOCKS UDP 及关闭所选 HY2 后失败/目标计数不增。顶层分别 12.16 秒 / 12.62 秒；这不是 GUI、公网或性能收益证据。
- 1.14.3 候选归档安装已补实际匹配归档，固定 SHA-256 由测试核验，`TestOfficialCandidateArchiveInstall` 通过、7.08 秒，补齐上述基线跳过项。CLI 的 HY2/DNS/network 专项均通过。
- 两个 netem case 在未加形状的基线阶段就失败：UDP 均 8/8，HTTPS 空闲请求 0/8、下载 0 字节，服务端日志出现 `http2: ... bogus greeting HEAD ... HTTP/1.1`。实际发现生产 `probe.buildTransport` 关闭 HTTP2 handler 后仍从已用 transport Clone 继承 h2 ALPN，协商 h2 却发送 HTTP/1.1。不能用 UDP 成功掩盖 HTTPS 失败，也不能把未执行到的延迟/丢包/限速/cgroup 算通过。修复代码显式保留 HTTP/1.1 ALPN，并另补支持 h2 目标的真实 TLS 回归；测试服务端未降级为只支持 HTTP/1。
- DNS 和部分 sing-box HY2 case 使用固定睡眠后过早发请求，本机客户端监听尚未建立，出现 connection refused；DNS 查询未到达受控解析器，不计 DNS 正确性失败结论或功能通过。夹具改为核对真实配置需要的 TCP/UDP 监听与自有 PID 的 socket inode，最多 5 秒，进程退出立即失败；netns 使用 `/proc/PID/net`，不混用其它网络空间监听。
- 迁移夹具失败为专项 runner 未携带 `testdata/state-v1.json`，环境需补齐后原断言重跑。没有删除迁移断言或改为跳过。

ALPN 故障另在 `eb3b314` 旧生产实现上添加相同回归测试实际重现，`work/batch03-alpn-regression-before.log` 记录退出 1，支持 h2 的真实 TLS 目标出现同样协议错误；修复后同一断言在 Windows 和下述 Linux `probe-new` 通过。`dbcbb61/a3d1b58` 的监听就绪修复不重试业务请求。netem helper 去掉请求内同步写计数文件，改为内存计数并在退出保存；先停自有核心并等待，超时才清理本次进程组，异常退出明确报错。

第二/三轮 `work/batch03-targeted2-linux.log`、`work/batch03-targeted3-linux.log` 保留另一个夹具启动问题：1.14.3 与 Mihomo 的某个首请求偶发空 502、目标计数为 0，日志只有配置解析完成。固定 Mihomo 源码在建立监听后才完成 provider 加载/GC 并进入 Running；此前 tunnel 直接关闭请求，HTTP 代理转为无 WARN 的 502。配置解析成功和端口建立均不是完整初始化证据。这是测试过早发请求的窗口，不是本项目 HY2 导出字段错误。`b4e6bb0` 使用官方 `-post-up` 在完整 ApplyConfig/OnRunning 后写私有就绪标记，再核对该 PID 的监听；没有预热、重试或放宽 HTTP/目标计数断言。来源见 THIRD_PARTY。

### 第四轮专项：实际全部通过

源码 `b4e6bb0b312360d5523fba0ded756fea8c19086a`，Windows Go 1.27.2 交叉编译静态测试程序；实际运行环境为 QEMU TCG `cpu max`、4 vCPU / 4 GiB、Alpine `6.18.55-0-virt`，root，`-net none`，仅本机与自有网络空间。日志 `work/batch03-targeted4-linux.log`，原始文件 `work/batch03-targeted4-evidence/evidence/`，源码及测试二进制摘要在 `work/batch03-targeted4-source-manifest.json`。八项 `probe-new/node-new/cli-new/candidate-new/mihomo-repeat-default/mihomo-repeat-candidate/netem-default/netem-candidate` 均退出 0。

实际命令由 runner 在 `/repo/internal/node` 执行，`SING_BOX_BIN=/sing-box` 为官方 1.14.0，`MIHOMO_BIN=/mihomo` 为 1.19.30，`SING_BOX_CANDIDATE_ARCHIVE` 指向已核摘要的官方 1.14.3 归档；候选客户端/服务端为 `/sing-box-candidate`：

```bash
/probe.test -test.run 'HTTPProbe|HY2Private|ControlledComparison' -test.v -test.timeout=2m
env QINGNODE_HOST_NETWORK_DISPOSABLE=1 /node.test -test.run 'DNS|Network|HY2|SchemaOne|LegacyGeneration|StateVersion|LegacySnapshot|AvailableMemory|CoreListener|CoreOwnedListeners|WaitCoreListeners' -test.v -test.timeout=5m
/cli.test -test.run 'DNS|Network|HY2' -test.v -test.timeout=5m
env SING_BOX_BIN=/sing-box-candidate /node.test -test.run 'OfficialCore.*HY2|OfficialCoreProjectDNS|MihomoHY2|OfficialCandidateArchiveInstall' -test.v -test.timeout=5m
/node.test -test.run '^TestOfficialCoreMihomoHY2PerformanceInterop$' -test.count=3 -test.v -test.timeout=2m
env SING_BOX_BIN=/sing-box-candidate /node.test -test.run '^TestOfficialCoreMihomoHY2PerformanceInterop$' -test.count=3 -test.v -test.timeout=2m
env QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/evidence/netem-default /node.test -test.run '^TestOfficialCoreHY2ControlledNetwork$' -test.v -test.timeout=5m
env SING_BOX_BIN=/sing-box-candidate QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/evidence/netem-candidate /node.test -test.run '^TestOfficialCoreHY2ControlledNetwork$' -test.v -test.timeout=5m
```

普通 node/candidate 组中 netem opt-in 和私有 helper 的预期 SKIP 不冒充成功；专门的两个 netem 组均完整执行，UDP-only 和 128 MiB 子项没有跳过。Mihomo 两个 case 对两核心分别再次 `count=3`，首个正向请求、UDP 和禁用所选代理负例全部通过。

HY2 同连接维护实际保持官方 1.14.0 PID 654、1.14.3 PID 1014，均 starts=1；同一条 TCP 连接分别连续完成 89 / 126 个 8192 字节校验帧。客户端带宽/BBR/QUIC/导出选择、重复应用、客户端回退及损坏派生修复期间进程不变，原停止状态编辑仍停止。这是直接管理核心进程的证据，不写成 systemd MainPID；既有测试客户端保持配置不变，不代表正在使用的客户端可无损在线改参数。

限速场景为自有 veth 双向各 80 ms、2% 网络丢包、2 Mbit/s；每次最多 2 MiB 有效载荷、8 个 HTTPS 和 UDP 样本。原始报告、客户端/服务器 CPU 计数与 RSS、真实 qdisc、命名空间 SNMP、目标计数和 cgroup 文件均保留；UTF-8 摘要为 `work/batch03-targeted4-metrics-summary.json`。下表仅描述本次人工条件，小样本 p95 不作高置信估计，不比较两核心性能高低：

| 核心 | 场景 | HTTPS | UDP 收/丢 | 下载 Mbps | 下载期间 HTTPS 请求中位数 ms | UDP 往返中位数 ms |
| --- | --- | --- | --- | --- | --- | --- |
| 1.14.0 | 基线 | 8/8 | 8/0 | 133.594 | 26.283 | 2.720 |
| 1.14.0 | 延迟/丢包/限速 | 8/8 | 8/0 | 1.859 | 315.308 | 168.048 |
| 1.14.0 | 仅过滤目标 UDP | 8/8 | 0/8 | 未测 | 未测 | 无有效值 |
| 1.14.0 | 服务端测试组 128 MiB | 8/8 | 8/0 | 137.781 | 33.137 | 3.065 |
| 1.14.3 | 基线 | 8/8 | 8/0 | 106.345 | 7.543 | 2.769 |
| 1.14.3 | 延迟/丢包/限速 | 8/8 | 8/0 | 1.793 | 298.452 | 167.577 |
| 1.14.3 | 仅过滤目标 UDP | 8/8 | 0/8 | 未测 | 未测 | 无有效值 |
| 1.14.3 | 服务端测试组 128 MiB | 8/8 | 8/0 | 92.230 | 19.450 | 3.165 |

下载期间 HTTPS 时间包含代理和应用处理，不是纯网络 RTT。两核心的网络 qdisc 实际丢弃分别为主机侧/服务端侧 14/17、12/26 包；8 个应用 UDP 样本没有恰好碰到丢失，不能声称测得应用丢包率为 2%。UDP-only 过滤时报告 status=failed 是预期负例，HTTPS 8/8 不掩盖 UDP 0/8。两核心受控目标计数分别 35/36 个 HTTP、16/16 个 UDP，目标仅监听服务端网络空间回环。

| 核心 / 场景 | 客户端/服务端测后 RSS MiB | 客户端/服务端 CPU 累计计数增量 |
| --- | --- | --- |
| 1.14.0 基线 | 62.73 / 62.22 | 16 / 15 ticks |
| 1.14.0 延迟/丢包/限速 | 61.11 / 62.89 | 106 / 114 ticks |
| 1.14.0 128 MiB | 61.62 / 62.85 | 17 / 15 ticks |
| 1.14.3 基线 | 62.31 / 62.44 | 23 / 16 ticks |
| 1.14.3 延迟/丢包/限速 | 62.52 / 62.91 | 98 / 112 ticks |
| 1.14.3 128 MiB | 62.90 / 64.93 | 25 / 17 ticks |

RSS 是测后值，不是峰值；CPU 是进程累计 ticks 差，CPU 百分比未知，长短不同的场景不能据此宣称优化。128 MiB 限额实际约束服务端核心、测试目标与 helper 所在 cgroup，客户端在组外；`memory.max=134217728`，两轮 `memory.events` 中 oom/oom_kill 均 0。共享页的 cgroup 计费与进程 RSS 口径不同，不把两进程 RSS 相加冒充该组内存使用。

schema 1/null 大小写、未知字段、旧快照与身份、只读不落盘、保留原代和回退测试均在正确携带 testdata 的环境通过。宿主 v2 pending/active 接续、实际 Linux sysctl 读写/读回/恢复、部分失败、权限/文件冲突、外部手改、FIFO 不阻塞与 cgroup v1/v2 有效余额测试通过；实际内核写入仅在明确 disposable VM 内，生产网络未访问。

### 全项目首轮：已完成检查与外层超时分别记录

`final1` 实际运行源码 `b4e6bb0b312360d5523fba0ded756fea8c19086a`，QEMU TCG `cpu max`、4 vCPU / 5 GiB、Alpine `6.18.52-0-virt`、Go `1.26.8`，无外网。日志为 `work/batch03-final1-linux.log`，源码清单为 `work/batch03-final1-source-manifest.json`。以下是实际成对出现 BEGIN/EXIT 标记的检查，不是根据预定计划推断：

| 检查 | 实际结果 |
| --- | --- |
| 全项目普通 Go、全量 race、vet | 均退出 0；race 耗时 cmd/qingnode 287.103 秒、internal/node 431.901 秒、internal/probe 16.299 秒、internal/probecli 2.399 秒 |
| 1.14.3 `OfficialCore\|OfficialCandidate` | 退出 0；匹配候选归档实际核验与安装包含在本轮 |
| ShellCheck、Bash 语法 | 均退出 0 |
| 发行保护、维护观察器 | 分别 38 / 3 个测试，均退出 0；隔离测试中的模拟发布输出不代表进行了远程发行 |
| 管理器 Linux amd64/arm64、助手 Linux amd64/arm64 与 Windows amd64 | 两个构建命令和实际五包归档契约检查均退出 0；不代表 arm64 原生执行 |
| 安装器原始 Alpine 环境 | 32 个用例执行 549.164 秒，31 通过、1 失败，命令退出 1；失败仍保留 |
| `installer-host-read-fixture` | 已开始，外层超时时未出现 EXIT；未完成，不算通过 |

实际主要命令如下；单测原有超时与断言未放宽：

```bash
go test -p 1 -count=1 -v -timeout=15m ./...
go test -p 1 -race -v -count=1 -timeout=15m ./...
go vet ./...
env SING_BOX_BIN=/sing-box-candidate go test ./internal/node ./internal/probe -run 'OfficialCore|OfficialCandidate' -v -count=1 -timeout=10m
shellcheck install.sh scripts/*.sh
python3 scripts/test-installer.py
python3 scripts/test-release.py
python3 scripts/test-maintenance-harness.py
bash scripts/build.sh
bash scripts/build-probe.sh
python3 scripts/check-build.py
```

安装器失败为 `test_online_install_reads_actual_host_os_release_without_overwriting_tag` 读取真实 `/etc/os-release` 后，按既有支持范围拒绝 `alpine 3.24.2`，输出“未验收的系统”。它不是受支持 Ubuntu/Debian 的安装成功，也不能从整组结果中删掉。首轮随后仅在一次性 VM 改用 Ubuntu 24.04 的系统识别元数据夹具重跑单项；该单项进行时达到 **2400 秒外层总预算**，没有 `QINGNODE_RUN_END`。最后串口刷新已确认五包构建和契约检查完成，超时中断的是后续识别夹具，不能误记为构建失败或整轮通过。

`work/batch03-final1-harness-receipt.json` 保存 `incomplete_outer_timeout`、未完成检查与原串口 SHA。`work/batch03-final1-evidence/evidence/` 是从原串口成对 BEGIN..EXIT 正文提取的文本，标记 `source_serial_extraction`，**不是 guest 原始证据文件**；没有把未闭合单项补成完整结果，也没有生成缺失的 guest 归档。元数据夹具只用于核验 OS 识别读取和隔离安装流程，不等于真实 Ubuntu apt/systemd 验收。

### 最后源码补丁复验：已完成检查与安装器整套分别记录

收尾审查发现两个实际边界：旧宿主计划可以接受恢复校验会拒绝的原 sysctl 文件权限；旧输出边界把悬空软链接的 ENOENT 当作路径不存在，可能允许结果占用受管链接的目标。`b698d04` 在只读计划和输出边界阶段提前拒绝，不修改原文件、软链接或内核运行值。

`final2` 在上述最后源码冻结后启动。旧实现加新断言的 `/node.before` 已实际证明：`0666/0755/0620/0200` 四种不安全原权限均未被旧计划拒绝，四项断言失败；`0400/0600/0640/0644` 四种合法原权限完整应用/恢复通过。`/cli.before` 对悬空受管 root、file、ancestor 三种边界均实际失败。两组预期退出均为 **1**，仍记 `failure_observed`，不是最终修复代码失败，也不改写为全零退出。旧二进制摘要和新旧差异保存在 `work/batch03-review-regression-binaries.json`、`work/batch03-review-regression-before.diff`、`work/batch03-review-regression-after.diff`。

`work/batch03-final2-linux.log`、`work/batch03-final2-source-manifest.json` 绑定 `b698d041829eb6eba2b94594a60b5c796c3bb5eb`。本轮以下命令均已有实际退出 0 记录；外层预算为 3600 秒，不改变各测试的单独超时：

```bash
go test -p 1 -count=1 -v -timeout=15m ./...
go test -p 1 -race -count=1 -v -timeout=10m ./internal/node ./cmd/qingnode -run 'Network|ExternalOutput|ProbeRejectsManagedOutput|DNS'
go vet ./...
```

普通 Go 各包实际耗时为 cmd/qingnode 26.077 秒、internal/node 87.674 秒、internal/probe 10.014 秒、internal/probecli 0.415 秒；相关 race 为 internal/node 4.833 秒、cmd/qingnode 2.410 秒。完整普通 Go 也覆盖最后补丁的新断言，未复用修复前负例作为正向通过。发行保护 38 个测试、维护观察器 3 个测试、ShellCheck/Bash 语法、管理器两包/助手三包构建和实际五包归档契约均退出 0。耗时取各次命令输出，不把会话中断期间经过的墙钟时间当作测试性能。

完整 32 个安装器元数据夹具实际 **32/32 通过，546.813 秒，退出 0**，包含读取实际 OS 信息单项；该组只在隔离 Alpine VM 使用 Ubuntu 24.04 识别元数据，不等于真实 Ubuntu 安装或 systemd 生命周期。`final2` 的 13 个检查中，`before-node/before-cli` 两个旧实现负例按预期退出 1，其他 11 项均退出 0；QEMU 退出 0，存在 `QINGNODE_RUN_END`。本轮完整结束不把两个负例篡改为全零结果，也不抹去首轮 Alpine 31/32 和外层超时。

原始 guest 文件已从完整归档 `work/batch03-final2-evidence.tar.gz` 提取至 `work/batch03-final2-evidence/evidence/`；它们与 `final1` 的串口配对派生文本分开标识。补丁复验没有新增代码，继续绑定最后源码 `b698d04`。

本批全量 race 证据绑定 `b4e6bb0`；`b698d04` 的普通全项目与上述相关 race 均实际通过，不能声称最后源码重跑了全量 race。最终构建修订、架构、原生执行与包冒烟以交付目录的 `build-receipt`、`QA` 和交付说明为准；不把编译当执行，也不把 version/help/local 包冒烟当协议传输或服务生命周期。

原生 Windows amd64、Go 1.27.2 已执行 `go test -count=1 -v ./internal/probe ./internal/probecli ./cmd/qingprobe` 和对应 `go vet`，均退出 0；日志 `work/batch03-final-native-windows-probe.log` / `vet.log`，退出回执 `work/batch03-final-native-test-receipt.json`。该次执行绑定 `b4e6bb0`，probe / probecli 分别 2.807 / 0.665 秒；`b698d04` 只改 Linux 宿主/管理器边界，这些包源码未变。它不证明 Windows 上三协议/UDP 全部传输、客户端 UI 或 Linux 服务可用。

| 验收层 | 本批状态 | 证据边界 |
| --- | --- | --- |
| 模型、方向/单位、nil/false、格式拒绝、迁移身份与故障测试 | targeted4 实际通过 | 单元/注入不代替官方核心或宿主 |
| 官方 1.14.0 / 1.14.3 HY2 TCP/UDP、同连接维护与配置解析 | 两版本 targeted4 通过 | 进程 PID/持续帧不冒充 systemd MainPID；客户端没有在线换配置 |
| Mihomo 1.19.30 性能字段解析与 HY2 互通 | 两核心首请求/UDP/禁用负例及各 count=3 通过 | 等完整初始化后测试；不代表 GUI 或手机导入 |
| 真实 netem 延迟/丢包/限速及 UDP-only 阻断 | 两版本实际通过，无子项跳过 | 网络 qdisc 与应用样本丢包分开；不声称性能增益 |
| cgroup 128 MiB 低内存 | 两版本实际通过，无子项跳过 | 约束服务端测试组，客户端在组外；RSS 不冒充组使用量 |
| sysctl 真读写/读回、权限与冲突恢复 | disposable Linux 与注入场景均通过 | 不修改生产网络；内核/容器支持范围仍各自检查 |
| Go / race / vet / 候选核心 | b4e6bb0 全项目普通 Go、全量 race、vet、候选均退出 0；b698d04 普通全项目、相关 race、vet 退出 0 | 不声称最后源码重跑全量 race；各轮源码与命令分别绑定 |
| 安装器 / 构建 / 发行门槛 | b698d04 五包/契约、发行保护 38、维护观察器 3、ShellCheck/Bash 均退出 0；安装器元数据 32/32 通过，546.813 秒，final2 完整结束 | b4e6bb0 Alpine 安装器 31/32、外层超时未完成的历史保留；两个修复前负例退出 1；元数据不冒充真实 Ubuntu 安装或公开发行 |
| 最终预览包 | 最终构建修订、架构、原生执行与包冒烟以交付目录 build-receipt / QA / 交付说明为准 | 不把编译当执行；包命令冒烟不代替协议传输或服务生命周期 |
| 原生 Windows 测试助手 | b4e6bb0 probe/probecli/qingprobe 测试和 vet 退出 0，回执绑定提交；相关包在 b698d04 未变 | Windows 管理器/三协议全传输/GUI 不在此范围 |
| systemd、外部双机、公网/运营商、Android/iOS GUI、原生 ARM、真实 MTU 黑洞 | 环境未提供，未验证 | 不推算性能改善或远程成功 |

复现入口：

```bash
go test -mod=vendor ./internal/node ./cmd/qingnode ./internal/probe ./internal/probecli ./cmd/qingprobe
go vet ./...
go test -race ./...
SING_BOX_BIN=/绝对路径/官方核心 MIHOMO_BIN=/绝对路径/mihomo go test -mod=vendor ./internal/node -run 'OfficialCore|OfficialArchive|Mihomo' -v -count=1
sudo env SING_BOX_BIN=/绝对路径/官方核心 QINGNODE_NETEM_TEST=1 QINGNODE_NETEM_RESULTS=/绝对路径/新目录 go test -mod=vendor ./internal/node -run '^TestOfficialCoreHY2ControlledNetwork$' -v -count=1 -timeout 5m
```

以上为源码树复现入口；本批实际已执行范围由上面的绑定提交、命令、日志和结果限定，其余仍标未验证。

## 迁移和恢复

`DecodeState` 对旧 schema 1 严格解码，只在内存转换到 schema 2；查询不落盘、不建立新代、不启停。schema 1 中伪装加入 HY2/DNS 新字段（即使 null）、未知字段、未来 schema 明确拒绝。迁移不生成节点 ID、用户 ID、UUID、密码、REALITY 密钥或证书。

首次有意义写入仍经锁、候选验证和新配置代，保存 schema 2 并保留原 schema 1 代及恢复材料；重复查询/应用不为迁移制造重启。旧快照先经相同版本解码/迁移再恢复，恢复写入仍为 schema 2；`rollback` 同样不会自动降格式。因此恢复旧快照或回退节点不能用作“让旧管理器读取新 State”的降级步骤。本批没有自动降级管理器入口；原始 schema 1 代/快照字节保留供独立验证的离线恢复，不改 schema 数字、不删字段伪装兼容。先用理解当前事务的管理器显式 recover 并保留全部原件。

节点 rollback 恢复保存的性能和 DNS 选择，仍比较实际服务器与客户端配置，区分客户端回退与运行回退；失败保留旧服务状态和事务材料。宿主参数独立在 `/var/lib/qingnode-host-network/` 保存快照，使用 `network restore --snapshot ID`；节点 rollback 不擅自改全机网络。恢复只覆盖仍等于本次写入的运行值，用户之后手改保留；同名受管文件外部改变时拒绝覆盖，保留原始材料供人工核对。

宿主原始恢复快照 version 1 保持不变；pending version 2 明确记录已触及字段与恢复文件检查点。正常 active 为 version 1，保留外部手改后的链式恢复可生成含文件检查点的 version 2 active。未知格式拒绝，不用删除 `touched/restore_file` 伪装旧记录。只读 status/plan 不修复，失败材料与显式恢复语义保持。

窗口与 UDP 缓冲的资源检查读取有效可用内存：宿主 MemAvailable 与当前管理进程可见 cgroup v1/v2 各层剩余额度取最小值；限制不可读时未知，不能以宿主总量代替容器余额。它不预留内存、不保证总 RSS，不证明另一个服务 cgroup 或远端客户端资源。实际低内存流量验收与源码里的边界检查分别计证据。

## 来源与后续接口

固定 sing-box 1.14.0 / 1.14.3、各自 sing-quic、Mihomo 1.19.30、HY2 URI 规范与 Linux v6.18 的具体提交、机制和许可见 [THIRD_PARTY.md](../THIRD_PARTY.md)。没有复制 GPL 代理/面板实现或改称本项目 MIT 代码。

后续扩展复用 `HY2Performance` / `HY2Transport` / `HY2QUIC`、`DNSSettings`、`DecodeState` / `MigrateState`、实际配置影响分类与 `ExportWithCapabilities`。受控测量关联使用 `probe.ControlledChange`，不改写原报告。宿主操作使用独立 `NetworkHost.Plan/Apply/Restore/Status`：原始快照 version 1、pending version 2、active version 1/2 按上述条件识别，不塞进节点 State 或配置备份；再扩展格式须新增显式版本与迁移，不能让旧程序误读。

本批未启用全局 multiplex、TCP Fast Open、MPTCP、0-RTT 或巨型 MTU。下一批不得将尚未提供环境的验收项写成已经成功；继续保留自动报告和人工 public-check 来源差异。
