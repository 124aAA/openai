# 第 02 批持续实施记录：端到端测试与分层诊断

记录日期：2026-10-13。工作从分支 `batch/02-network-tests`、提交 `6ba4512` 接续第 01 批实际代码，没有回退到调研快照 `70c0c277aa8703a4bd2cf8268b6bdad09ae13fc2`。第 01 批分类、批量应用、恢复和能力矩阵复用；本批默认 sing-box 仍为 1.14.0，不根据网络测试自动改变节点行为。

## 实际代码提交

| 提交 | 对应实现 / 必要修复 |
| --- | --- |
| `2739790f48aec106bb182b07a538e6a365308fb1` | 第 02 批主体：分路径测量、隔离官方客户端、报告/对比、受控 UDP、服务器与桌面 CLI、来源和测试入口 |
| `e92a3380ae87d25162da7db110891c218ff942c4` | 修复 UDP 回应端点取消时的 read-deadline 竞争，并强化可重现夹具；保留取消、字节与进程清理断言 |
| `e12b98917b0bac080fb91da1dc4881afc88beb19` | 修复跨主机构建 tar 权限：Git Bash 的 chmod 无法可靠表达 POSIX 归档模式，改为标准 Python 显式写二进制/安装器 0755、普通文件 0644 和 uid/gid 0，原校验断言保持 |
| `54d0f83035e4339039d583db772fbd4d6b617021` | 修复 MSYS sha256sum 默认以 `*` 表示二进制模式而不满足原发行清单格式；`package-sums.py` 按原始字节计算 SHA-256 并写两个空格分隔，标准 Python tar 打包固定模式/归属与 gzip mtime 0，不放宽原解析 |
| `1db455d6ad36e2e5d77db62570c8623e46c3dae9` | 明确下载连接与探测共享的 HTTP 总连接上限；本批前置 Linux Go/race/vet 与真实核心复验绑定此提交 |
| `9b09042d4f82ab2ee70a93359f4f1875291361bf` | 将测试助手独立放入 artifacts/probe，与原严格管理器发行资产集合分开；后续打包/发行守卫验证单列，不借前一行结果冒充 |

完整快照回归绑定主体提交；后续独立修复另做接续验收。下方测试证据按这些范围记录，不把主体快照的成功自动扩展到后续代码。文档提交仅收尾本批结果，不代替实现提交或实测。

## 实现范围与设计

本批只增加有边界的网络测量与报告。Bash 引导、静态 Go 管理器、独立官方 sing-box 和 systemd 主干保持，没有必装 Docker、Web 面板、数据库或常驻监控服务；没有复制第三方代理协议实现。

- 分开记录本机只读诊断、命令所在服务器出站、客户端经所选代理和两台受控机器链路。发起端由用户明确命名，不把 VPS 测试推断成用户所在运营商质量。
- 代理测试使用只含所选节点出站的临时官方客户端，本机监听临时端口；HTTPS 通过明确的 HTTP CONNECT，UDP 通过 SOCKS5 UDP ASSOCIATE，失败不回落 direct，不修改生产节点、服务、系统代理或全局路由。
- HTTPS 正常验证证书，保留状态、首字节、空闲/下载期间请求、有限有效载荷吞吐与原始样本。不能独立观察的代理目标 DNS、外层握手和线路字节记未知，应用请求耗时不冒充纯网络 RTT。
- UDP 对受控版本化回应端点发送随机本次标识与序号，逐个计时和超时；输出实际已发/已收/丢失、RTT 与相邻成功序号的 RTT 绝对差。取消、预算结束和核心退出不会记通过。
- 轻量与下载模式分开；总超时、字节、样本与并发有硬上限，没有默认公共下载站。文本和独立 JSON `version: 1` 保留条件、版本、配置摘要、限制与错误，不含完整凭据或分享链接。
- 私有测试资料从原客户端导出派生，允许另一台 Linux/Windows 机器的 `qingprobe` 使用。没有提供原生 Android/iOS 程序；手机与可选 iperf3/IRTT 受控流程单列说明。
- 自动结果不混入原 `public-check` 管理员手动登记。对比只接受条件一致的有效自动报告，缺失值不当零，小样本不声明高置信。
- 修复第 01 批继承的打包契约缺口：`build.sh` 已复制 CAPABILITIES/BATCH_01，但安装器与发行校验仍只允许原七份文档，会拒绝新包。本批补齐明确的新文档白名单，未知文件仍拒绝，并保留实际归档核验；不通过放开任意文件制造成功。
- `scripts/build-probe.sh` 另存 `artifacts/probe/` 的 Linux amd64/arm64 与 Windows amd64 静态测试助手包、内外摘要及 Go/vendor 声明，不把它混入管理器安装包或原四项正式发行资产；独立 CI artifact 验收记录按实际收尾补齐。
- 临时 mixed 入站生成独立随机认证，UDP 按 RFC 1929 验证且不降级；就绪检测另外以 Linux socket inode/fd 或 Windows OWNER_PID TCP 表核验子进程归属。随机认证不冒充 PID 证明，不接管抢占临时端口的其他服务。

完整命令、指标定义、桌面/手机/受控机器流程见 [NETWORK_TESTS.md](NETWORK_TESTS.md)；能力分层见 [CAPABILITIES.md](CAPABILITIES.md)，实现边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。

第 02 批独立桌面包原带 NETWORK_TESTS/BATCH_02；第 03 批扩充同目录的 NETWORK_PERFORMANCE/BATCH_03，说明新性能选择与验证边界。能力矩阵、架构、第 01 批记录和实现源码仍从配套源码树读取，桌面包不包含服务器安装引导，也不使 qingprobe 获得服务器管理命令。

## 本批实际执行证据

本节只记录当前代码真实执行过的命令、环境、输出和跳过项。第 01 批或 v0.2.8 的成功不计入本批；mock/注入、官方配置解析、真实核心流量、Linux/systemd 服务、客户端 UI 和公网分别记录。最终交付提交和回归结果由本批统一验收后绑定。

截至本记录草稿，主体及接续修复已提交，整批最终实测仍在收尾；下方环境未提供项不以历史证据补齐。测试失败保留其原因和修复后的复验，不能删除断言或把跳过写为通过。

已执行的打包入口检查：Windows、Git Bash `5.3.9(1)-release`，`bash -n scripts/build-probe.sh` 通过；`bash scripts/build-probe.sh bad-version` 在调用构建前以退出码 2 拒绝错误版本。`git diff --check` 没有空白错误，源码文档相对链接已检查无缺失。它们只证明语法、输入与文档结构，不能替代实际 Linux 打包、Go 执行或核心流量。

原生 Windows amd64、Go `1.27.2`、官方 sing-box Windows `1.14.3` 已执行：

```powershell
$env:SING_BOX_BIN = '官方Windows归档解出文件的绝对路径/sing-box.exe'
go test -mod=vendor ./internal/probe -run '^TestOfficialCorePortable' -v -count=1
```

本次实际设置到工作目录的 `official-windows-1.14.3/sing-box-1.14.3-windows-amd64/sing-box.exe`。两个顶层用例通过，`qingnode/internal/probe` 输出 `ok`、2.233 秒：真实 SS2022 服务 → 本机受控 HTTPS 的两个请求通过；仅关闭测试 SS 服务后，直连控制仍能访问目标，代理请求失败且目标请求计数不增加。取消/核心崩溃后等待本次进程退出，Close 后监听与临时目录消失；报告不含 SS2022 两段密钥，私有报告写入通过。代码位于 `internal/probe/sandbox_integration_test.go`，没有导入 Linux manager 包。

这条证据仅是本批原生 Windows 测试助手的 SS2022/TCP 本机路径、失败回落与清理，不包括 Windows GUI、公网、Windows REALITY/HY2/UDP 或后续尚未复验的改动。Linux 三协议与整批最终回归仍单列；官方步骤须同时测试 `./internal/node ./internal/probe`，没有环境变量时的跳过不计成功。

随后在最新代码（包含实际监听 PID 核验和随机 mixed 认证）再次执行原生 Windows 的 `./internal/probe ./internal/probecli` 完整回归，日志 `work/batch02-native-windows.log`：两包通过，分别 2.783 秒 / 0.615 秒；包括上述真实官方 SS2022/TCP、归属 PID 负例、受控延迟/限速/UDP 回应注入、拒绝认证降级、总预算、取消和报告一致性。后面的受控 UDP/故障用例属于本机标准接口与注入测试，不能写成 Windows 三协议 UDP 已通过。

主体提交 `2739790` 的原生 Windows 再验日志 `work/batch02-native-windows-final.log`：`internal/probe` / `internal/probecli` 分别通过 2.954 秒 / 0.656 秒，vet 退出码 0。UDP 端点取消修复后的最终原生复验另记录，不能以主体这条成功代替它。

打包首次实测保留一个真实失败：从 Windows/Git Bash 构建的 tar 中二进制权限未达到原发行契约，校验正确拒绝。没有放宽校验；`e12b989` 显式标准化归档元数据，修复后的实际包/内外摘要和契约结果随后单列。

跨主机打包共保留三次初期失败日志，包含 POSIX 权限和 SHA 清单分隔模式不符；原归档/摘要校验正确拒绝。`54d0f8` 修复后，在原生 Windows、Go 1.27.2、Git Bash/Python 运行：

```bash
bash scripts/build.sh 0.2.8
bash scripts/build-probe.sh 0.2.8
python3 scripts/check-build.py
```

实际五个包均通过内容白名单、内层摘要及平台架构契约：管理器 Linux amd64/arm64 两包，测试助手 Linux amd64/arm64 与 Windows amd64 三包。真实产物检查日志为 `work/batch02-native-build.log`，收据为 `work/batch02-native-build-receipt.json`，源码标记 `54d0f83035e4339039d583db772fbd4d6b617021`。外层摘要由各自构建流程生成，Linux 接续验收另外检查。

随后实际解出并运行 Windows `qingprobe.exe` 的 help、version 与 `local --out`，通过；版本输出 `QingProbe 0.2.8 (54d0f83035e4)`，本机报告 version=1、completed、实际下载 0 字节，DNS/连接/TLS 未请求。这条 smoke 证明本机可执行与只读报告，不计公网或代理传输；Linux 两架构包仍为交叉构建，原生 ARM 未执行。

2026-10-14 前置收尾复验使用固定源码 `1db455d6ad36e2e5d77db62570c8623e46c3dae9`，QEMU TCG `cpu max`、4 vCPU / 4 GiB、Alpine Linux `6.18.52-0-virt`、Go `1.26.8`，官方 sing-box 1.14.0、Mihomo 1.19.30，root 环境执行：

```bash
go test -p 1 -count=1 -v -timeout=15m ./...
go test -p 1 -race -count=1 -timeout=15m ./...
go vet ./...
env SING_BOX_BIN=/sing-box-candidate go test ./internal/node ./internal/probe -run 'OfficialCore|OfficialCandidate' -v -count=1 -timeout=10m
```

日志 `work/batch03-baseline2-linux.log` 的 `go-test/go-race/go-vet/candidate-core` 退出码均 0。普通回归包含实际 1.14.0 三协议 TCP/UDP、Mihomo 解析、归档和真实降权读取；race 四包耗时分别为 cmd/qingnode 278.706 秒、internal/node 315.090 秒、internal/probe 15.446 秒、internal/probecli 2.930 秒。候选为官方 1.14.3，实际核心/隔离测试通过；但 `TestOfficialCandidateArchiveInstall` 因没有给匹配 1.14.3 归档而明确跳过，不能称为这次候选安装通过。该 VM 没有 systemd，不计真实 MainPID/生产生命周期。

此前 3 GiB、并行测试的基线 VM 在 race 阶段被内核 OOM 杀死 node.test，`work/batch03-baseline-linux.log` 保留 `go-race:1`，不能计通过。复验仅增加隔离 VM 内存并用 `-p 1` 顺序运行包，没有删除断言、跳过失败用例或放宽原测试超时。以上收尾只覆盖 1db 源码的前置能力；`9b09042` 发行接线和第 03 批新代码须独立验证。

## 数据格式、迁移与恢复

State 继续 `schema: 1`，节点 ID、用户 ID、UUID、密码、REALITY 密钥、证书、已选地址/指纹及服务运行/停止与自启状态保持。测试报告和私有测试资料是新独立文件，与 State、配置代、加密快照和手动 `observations.json` 历史没有格式迁移关系；旧管理器不会被要求读取它们。

本节描述第 02 批当时的格式。第 03 批因实际 HY2/DNS 字段升为 schema 2，其读取兼容、原件保留及“旧快照恢复仍写 schema 2、不能自动降级管理器”的限制见 [BATCH_03.md](BATCH_03.md)，不要用下述历史入口推断当前支持程序降级。

报告读取须按自己的版本入口检查；不支持的新报告或测试资料格式明确拒绝。旧 State、旧快照和第 01 批配置事务继续原恢复路径。降级管理器前，仍先用理解 version=2 配置事务的管理器完成显式 `recover`，保留原配置代和恢复材料；本批测试不会偷偷替它恢复。

报告/测试资料写到用户明确选择的新文件，不覆盖原件。正常结束、取消、总超时与核心退出后只清理本次自有临时进程和目录。强制 SIGKILL/断电无法执行退出清理；残留需先核对归属，不能批量杀死同名生产核心。删除自动报告不会改变节点，删除私有测试资料前保留自己需要的恢复/重测材料。

## 环境未提供而未验证

公网跨运营商路径、两台外部受控机器、真实限速/延迟/丢包网络命名空间、手机 GUI/TUN、Android/iOS 后台行为、原生 ARM、全部受支持发行版 systemd、ACME DNS 凭据与真实证书续期需各自环境。本批继续交付其余代码、隔离回环和可复现入口，不声称这些范围已成功，也不从本机吞吐推算公网性能提升。

上述是第 02 批当时未提供的环境；第 03 批已补隔离 netem 与 128 MiB cgroup 实测，结果单列 BATCH_03，不回填为第 02 批成功。公网、手机、原生 ARM、真实 systemd 与外部双机仍分别验收。

外部 iperf3/IRTT 操作流程属于文档入口；没有实际工具与受控主机执行记录时，不能称作本项目集成测试通过。没有独立时钟同步证据时，IRTT 的单向延迟未知。

## 固定来源与后续接口

本批补核 sing-box `v1.14.0` / `v1.14.3` 的 mixed/SOCKS5、route.final 与 domain_resolver 接口；既有三个协议出站复用，服务端字段不从 Hysteria 原生/Xray 配置拼入。可选工具说明固定到 iperf `3.22` / `926bd905501b792bd082d2200d1d1a84aa543e3a`、IRTT `v0.9.1` / `c5ed230a672f5233f4a87b2a28dd6d5c86b6feba`、blackbox_exporter `v0.28.0` / `5a059bee8d8ffa4e75947c5055fb0abeefc582e6`；精确机制、链接与许可证见 [THIRD_PARTY.md](../THIRD_PARTY.md)。固定版本检查不代表性能或公网实测。

后续批次复用 `internal/probe` 的预算、原始样本、统计、比较和 UDP 帧，不将它们改成 State 写入或调参入口。新增指标须保持缺失值、方向、发起端、样本量及流量口径；新增报告/资料字段遵循独立版本校验，不能让旧消费者误读新含义。自动结果与手动公网登记保持来源区分，网络测量不自动接受节点或改变运行策略。

未执行远程推送、PR、发布或生产部署。本地源码、文档和隔离回归属于本批授权范围；main/tag 可能触发正式发行，现有完整 CI/release 门槛需保留，发布须另有本会话授权。
