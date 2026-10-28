# 第 06 批：批量导出、设备订阅与客户端回退

本批从第 05 批最终提交 `987403e5a5afccb9650ca02e5073f66612c5ad22` 开始，使用独立工作分支 `batch/06-device-subscriptions`；没有回退到调研快照。默认核心继续 1.14.0，1.14.3 单独验证。源码尚未发行，公开 v0.2.8 包不因此包含本批。

## 已实现的边界

- State 实际新增设备 Profile 与节点标签，schema 升为 5；1/2/3/4 仅内存迁移，身份、NAT 连接端口、旧分享信息与内部拓扑保留，实际写入新代留旧字节。备份 envelope v1/v2 不变；旧二进制拒绝新 State。
- 每条设备绑定明确节点/用户/端点稳定 ID；支持同设备多节点、多用户、标签过滤和整体预览/应用，不以首个用户补缺。导出稳定名称/tag；只给最终客户端入口认证，不泄漏内部落地凭据。
- sing-box 与 Mihomo 分别适配完整配置/节点集合/手动；有序 fallback 仅 Mihomo，sing-box 明确拒绝。sing-box自动容差两版实测通过；Mihomo1.19.30首成员容差实测失败，完整auto默认拒绝，仅Profile `allow_degraded_auto` / CLI `--allow-degraded-auto`显式接受后每次带警告降级。provider/URI集合不受组缺陷限制。自动HTTP探测不证明UDP，客户端切换不承诺既有会话迁移。
- 默认全局代理，可选仅 RFC1918/RFC4193 的固定基础分流；没有外部规则抓取、在线转换、递归订阅或模板执行。规则来源和 embedded 状态明确，不假设在线缓存。
- 可选只读订阅服务读独立私有原子快照；256 位下载令牌与代理认证分离，到期/撤销/轮换逐请求生效，最小读取权限、大小/并发/超时约束和无共享缓存。管理写后发布失败单列，已提交 State 不伪装回滚。
- 设备可明确 `subscription_formats` 子集，省略继承发布器；Mihomo fallback 设备与 sing-box 设备可同实例发布。`subscription configure` 先整体检查后更新明确格式/版本/有损选择并保存旧配置，不自动改变目录/组；默认只读并发4，最多16，低内存可设1。
- HTTPS 复用用户已有反代或证书，不接管 80/443；签发公网链接前用系统信任检查，无 insecure 或公共第三方转换。无 HTTPS 时保留本地导出与私有令牌材料。
- 设备停用区分下载与代理认证；普通停用只撤销下载，显式停用独立代理认证才影响运行。共享保护包含已普通停用下载的其他设备；full2确认的漏检已修订，最终full9静态/普通Go/race的节点与CLI回归通过。最后用户保留身份并停用节点，下载撤销不因节点恢复而复活。
- 设备影响预览比较实际选中绑定/端点和协议适配器派生材料；标签改变成员时列出受影响设备/入口ID，仅Profile名称变化归展示。服务器/宿主派生不变时免重启；最终full9普通Go/race分别实测同一进程与连接连续传输72/76帧；这是核心进程证据，不是systemd生命周期。

完整命令、部署、手机使用与恢复见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)。模块接口为 `node.DeviceProfile/DeviceBinding`、`ValidateDeviceProfiles`、`ExportDeviceProfile`、`DisableDeviceCredentials`、`subscription.Snapshot/Record/Payload`、`CreateInitial/Publish/Read/NewHandler/Serve`、`Store.BeforeCommit`（先撤销移除/停用设备的下载授权）与`Store.AfterCommit`（提交后刷新发布）。订阅发布version1、设备批量输入version1，与State schema5独立版本；后续批次不得把它们混为同一格式。

## 本批实际证据

最终源码`c89f7d1f1a8d6422a5e948bef000bcd0141ce9ee`的full9已完整结束：31项中30项exit0，唯一非零为保留的原生Alpine安装器32/33；普通Go、全量race、vet、两版官方核心及客户端真实TCP/UDP、低权限、构建和包契约均通过。原严格证据提取成功、complete=true，独立审计838项SHA一致，无其他unexpected失败，不能写成31项全过。CreateInitial新修订已在该源码的静态、普通Go和race执行。首轮失败、旧d2的full7独立恢复/full8历史结果与全部中断轮次仍按原范围保留。最终安装包运行由独立回执记录，不用源码回归替代。

| 证据 | 精确源码与环境 | 实际结果 |
| --- | --- | --- |
| 改动前基线 `baseline1` | 明确 Git archive `987403e5a5afccb9650ca02e5073f66612c5ad22`；Linux6.18.55 / QEMU TCG，无外部 NIC，Windows Go1.27.2 编译 Linux 静态测试 | node/CLI/probe、143 官方核心/Mihomo/图路径与自有环境建立/清理共7项，均 exit0；RUN_END/QEMU0/检查配对/证据提取齐全 |
| 基线独立文件核验 | 原始源码621文件、3个测试二进制、8份证据和源码 ZIP | SHA256 全一致；ZIP `1bd2a5270aabd4736203a97d70f253218e234517f8eb724446f0afbee328125b` |
| 迁移测试开发编译 | 首次提交前的工作树；Go1.27.2 Linux/amd64 CGO0 | node测试包两次编译exit0；迁移实际执行另列targeted1 |
| 文档/发行名单离线检查 | 尚未提交工作树；Windows Python + Git Bash | `python scripts/test-release.py` 38/38、15.560秒、exit0（FakeGitHub模拟，不发布）；installer/build/build-probe 的 Bash 语法均0，85个本地Markdown目标存在，17个旧发行文档名全部保留且仅新增2项 |
| 新功能targeted1完整执行 | Git archive `55248b1bddee897627745fbd6e3d3e68c4daf5d0`；同隔离Linux/无外部NIC，官方sing-box1.14.0/1.14.3、Mihomo1.19.30 | 7项中3项exit0、4项exit1；RUN_END/QEMU0/检查配对/提取齐全，无SKIP，不等于功能全部通过 |
| target1通过的独立证据 | 两版核心分别执行Device官方集成；设备/迁移单元块 | 两客户端各三协议完整配置的TCP/UDP与代理停用后不得direct回落全部通过，共12个协议子项；解析矩阵通过（含sing有序fallback预期拒绝）；schema1/2/3/4身份/原字节、加密备份及回退测试通过 |
| target1自动选择实际结果 | 受控HTTPS目标与延迟中转，手动触发健康探测 | sing-box两版在三轮容差内保持首项、差值超容差后切第二项通过；未等待默认300秒定时器。这不测UDP。Mihomo两次在容差内切换，断言失败；失败轮具体时延未打印，不补造数值 |
| target1其他失败 | CLI、subscription、默认/候选设备集成 | 停用独立认证启动了原本停止的服务；发布文件worldread/symlink/hardlink/fifo保护断言失败；专用UID helper因permission denied未执行，不能称低权限成功；Mihomo fallback健康API504失败，共用闭包行号不能确定原始失败阶段 |
| target1独立完整性审计 | 源码643文件、4二进制、75 host inputs、8证据 | 749项SHA256比对一致，源码ZIP与证据tar逐条一致；独立审计明确product_acceptance_passed=false，保留全部失败 |
| 修订targeted2完整执行 | Git archive `ea9979be16c22fb6c32ab449fd2e7a8a8e58797a`；同隔离Linux/无外部NIC，官方sing-box1.14.0/1.14.3、Mihomo1.19.30 | environment/device-node/device-cli/subscription/device-default/device-candidate/environment-cleanup共7项均exit0；RUN_END/QEMU0/配对/提取齐全，无FAIL或SKIP；这是定向复测，不是全项目发行门槛通过 |
| target2客户端配置与真实传输 | 两核心分别运行官方解析、完整配置和停止代理负例 | 两客户端各三协议的TCP/UDP与不得direct回落共12个协议子项全部通过；sing有序fallback预期拒绝；Mihomo完整auto默认拒绝、显式降级后的真实解析通过 |
| target2主备三阶段 | `TestDeviceMihomoOrderedFallbackRealPrimaryFailure`，两核心分别执行 | 双入口存活200/200且首项被选；主项停止503/200且明确备用被选；两项停止503/503、组504为预期负例。切换前后分别完成受控HTTP载荷和序号UDP回应；全部停止后目标计数不再增加，无direct回落 |
| target2自动容差与已知缺陷 | sing自动容差测试及独立`TestDeviceMihomo11930FirstMemberToleranceDefectAndExplicitOptIn` | sing两版容差内3轮不切、超差切换通过；Mihomo两轮真实复现首成员差值38/39ms仍在300ms内切换，再验证第二成员内/外容差和明确降级。测试通过代表缺陷被正确识别、防护有效，不能说Mihomo防抖达标；未等待300秒定时器，HTTP不测UDP |
| target2低权限与订阅保护 | Linux专用UID/GID65534子进程；完整subscription包及CLI定向块 | 子进程实际读私有快照并提供认证HTTP成功，发布/直接写入均拒绝；文件worldread/symlink/hardlink/fifo等保护通过。令牌/撤销/轮换/并发、原子失败、二维码材料检查、无管理锁读取及设备影响测试通过；不把此夹具当作真实systemd部署或root State读取拒绝证据 |
| target2独立完整性审计 | 源码646文件、4二进制、75 host inputs、8证据 | 752项SHA256一致，ZIP与证据tar逐条一致；原始首轮失败材料保留 |
| Windows原生probe回归 | `3bf74bee49a66d476f4f9193de2dec4f5d231e7d`；Windows amd64、Go1.27.2、官方Windows sing-box1.14.3 | `go test -count=1 -v -timeout 10m ./internal/probe ./internal/probecli ./cmd/qingprobe`，exit0、15.422秒，无FAIL/SKIP；真实两跳SOCKS5与用户态WG的HTTPS+序号UDP、错误认证/密钥、停止落地负例和自有清理通过。这不是Windows管理器/systemd、手机UI、原生ARM或公网结果 |

targeted1四个失败门槛为`device-cli`、`subscription`、`device-default`、`device-candidate`；`environment`、`device-node`、`environment-cleanup`通过。原始日志SHA256为`4cc0e6dfcf79c9e46088b0a95edac32566a14374583fa1f725e93f27f94050c5`；源码ZIP为`ec612796f95af5bf3dd45dfed16878310eb85f7c46dc08d5c515cb45f17eb42b`；独立`batch06-targeted1-audit-receipt.json`为`028bce42a6e7e9c72b97b66665b4d362717b1eb06731c81d4e29b370065b5071`。所有原日志及失败收据保留。

首轮后修订：纠正CLI测试对“删除认证属于运行变更”的预期，保留原Apply按启用监听启动/重启的语义；未修改实现使此运行变更强制保持停服，普通元数据变更仍保持停止。另修订订阅文件保护/低UID夹具；fallback分阶段记录并把全部出口失效时的504作为明确负例；单独复现Mihomo首成员缺陷并验证默认拒绝/显式降级，不靠重排初始节点遮掩；新增二维码材料严格检查与派生设备影响预览。上述修订已在targeted2明确提交定向复测，不改变targeted1失败事实。

targeted2原始日志SHA256为`3b7beabb6d8d1a982532d0fb3b942d5ec55cae806b7a829a9a3ef27c672190c2`；源码ZIP为`8492967a4c1cc83cfe7cd37a5da08e3fc5a7989247c6dc2873e7b1433eceb64a`；独立`batch06-targeted2-audit-receipt.json`为`0a3bba292c6e586fc78e5afe5594acf36dbbc4b057cf4413f4477bcdd85c7925`。复现命令为`prepare-batch06-suite.py targeted2 --commit ea9979be16c22fb6c32ab449fd2e7a8a8e58797a`、`run-batch06-suite.py targeted2 --prepare-only/--launch`，沿同一未改suite runner。

targeted2之后另补URL的ForceQuery空`?`与RawPath边界及负例，未包含在ea9979be提交，不能借targeted2通过结果。full1准确源码冻结为`3bf74bee49a66d476f4f9193de2dec4f5d231e7d`；四个Linux静态测试包、actionlint和自有环境建立通过，`go-test`为exit1：原有`TestOfficialCoreBoundedProbeThreeProtocolsAndFaults/reality`中HTTPS两次成功而UDP结果失败。128字节接收含丢弃字节，不能推断两个有效回包；原日志未展开UDP样本，未确定是超时还是传输错误，不能归咎调度或核心。`go-race`仅见开始标记；恢复检查时外层和QEMU进程均已消失，无RUN_END、完整运行回执或证据提取，因此full1为中断未完成，不能报告31项通过。

诊断提交`7b1e23927a24a4d8464ebecf4b5e7a8f788bc771`仅给原失败分支增加4行UDP样本及受控目标计数日志，保留全部原断言、300ms单样本与5秒总期限；相关生产测量代码没有改动，不能称为修复UDP。下一轮完整复验使用新编号，原full1失败与不完整日志不覆盖。

full1独立部分审计为`batch06-full1-partial-audit-receipt.json`，SHA256`741f28f27f6057378dcfa988ea15b6673b12fa7237abc6346683563c5033abe2`；646份源码、四个测试二进制、80个宿主输入与冻结材料共736项SHA一致。原始日志`2920ed1dd066432fc72494f217ee7af98aadf1b8c615655f7ab02ffaad13161a`保留；部分审计没有创造完整run receipt，也没有把未执行的Alpine门槛算成已测。full2随后从干净提交`025d6ace834255faa0fe0715c712e43ea7eeeeca`重新冻结并启动，诊断测试代码承接7b1e239、其余仅文档；其实际主动中断与逐项范围如下。

full2第一次后台Python启动被full1残留的单VM锁拒绝，PID2308的启动回执不能证明VM已运行；对应stderr保留。管理员确认旧owner PID8656和QEMU均不在后，保留自有旧锁原字节，再直接调用同一冻结runner启动实际full2。实际VM状态只以新的Linux日志和最终运行回执为准，没有覆写首次启动材料或修改runner。

full2准确源码025d6ace运行时，双人只读确认`DisableDeviceCredentials`跳过`other.Disabled`属于实际缺陷：普通停用只撤销下载，B此前已下载的代理认证仍可能有效，A再停用共享认证会连带影响B。修订去掉该跳过，保护所有仍注册设备绑定，节点回归覆盖普通启用/已停下载两条路径，CLI覆盖先停B下载再拒绝A停共享认证；没有删除旧断言或用不同凭据掩盖此场景。该修订不在full2冻结源码，实际后续执行与full7验证见下表。

因该确定缺陷，管理员核对QEMU4696归本轮所有后主动终止full2。原runner如实生成`complete=false`、QEMU退出4294967295、无RUN_END/配对结束/证据提取；仅environment和四个静态包共5项exit0，go-test已开始无最终结果，其余26项不能称通过。`batch06-full2-partial-audit-receipt.json` SHA256为`b0947e0ef9de668e23beec2a364edddbcaa4bd82d9616bf5b3241b6b36e4cf85`；646份源码、四个二进制、80个宿主输入及冻结材料736项SHA一致，原始日志SHA`6df84f7aa30e3879c328e5e0046366adcf04fbdffaf67a9078656d776122dc17`。此主动终止与full1原因未知的中断分开记录，不能把退出码本身当作原因证明，也不能把尚未执行的Alpine门槛算作实测。

Windows原生probe独立审计核对538份原始Go/模块文件、官方核心与日志哈希；其中460份与full1源码归档字节相同，78份仅Git换行表示不同，保留各自原始SHA，不改写源码或冒称原始字节一致。官方Windows核心SHA256为`5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf`；日志为`921c1f8d8d9529f75cfff1bebe09f01d107abcb35e720894a486218ed747ceba`；`batch06-windows-probe-audit-receipt.json`为`b88225312e07085989853b7d86cbccec02f2606a6b746264f4e96f8061f4e80b`。只执行probe三个包，不把它当成CLI二维码URL新边界的Windows执行证据。

原始回执名：`batch06-baseline1-compile-receipt.json`、`batch06-baseline1-run-receipt.json`、`batch06-baseline1-audit-receipt.json`。基线 raw log SHA256 `b656b889d053bd8a101403b4c532b1d5e0cfdc75495ca98d9f85c4a8a0036e58`。这些是本批重新执行的旧代码基线，不是新能力验收。

可复现入口：`prepare-batch06.py baseline1 --commit 987403e5a5afccb9650ca02e5073f66612c5ad22`、`run-batch06.py baseline1 --prepare-only/--launch`。targeted1使用`prepare-batch06-suite.py targeted1 --commit 55248b1bddee897627745fbd6e3d3e68c4daf5d0`与`run-batch06-suite.py targeted1 --prepare-only/--launch`，冻结runner SHA256为`6a3a7bc491d3d3c6049cb34e17baee5680a932da24ddd38d7f46f37149a08f75`，不覆写。最终计划另存`prepare-batch06-final.py`/`run-batch06-final.py`，保留全项目Go/race/vet、安装器、发行、原有官方核心/服务用户和新订阅包，增加候选核心的显式DeviceOfficial/DeviceMihomo非空检查，共31项含环境/清理；Go/race原15分钟包超时不放宽。准备与编译不启动VM，启动回执只代表已启动，完整结果仍须RUN_END和每项退出码。实际外部runner、源码/工具/二进制哈希及每项命令随最终证据保存。

新能力验收入口包括`TestDeviceOfficialClientParserMatrix`、`TestDeviceOfficialFullConfigsTCPUDPAndNoDirectFallback`、`TestDeviceMihomoOrderedFallbackRealPrimaryFailure`、`TestDeviceOfficialAutoToleranceWithControlledRelayDelays`；修订增加`TestDeviceMihomo11930FirstMemberToleranceDefectAndExplicitOptIn`，已知缺陷复现与防护测试不能被解释为客户端容差达标。迁移夹具包含schema1/2/3/4、旧加密envelope和原字节保留。订阅包包含令牌、并发、私有文件、原子替换、TLS/取消/最小权限测试。这些入口在最终full9分别有实际执行证据，HTTP健康与UDP传输仍分开解释。

## 完整回归与未完成轮次

| 轮次 / 精确源码 | 实际执行与结果 | 保留的限制 |
| --- | --- | --- |
| full3 / `537d6e873b50c2b56dbb60a8fa407708aba4f79c`，TCG | environment、四静态包及普通Go共6项完成exit0；race节点包900.535秒触发原15分钟超时，堆栈在拓扑快照恢复的PBKDF2/HMAC/SHA256；随后probe开始但无race整体EXIT | 无RUN_END/完整回执，外层进程消失原因未知；其余未执行。加密v4迁移60.91秒、旧端点迁移121.26秒仅是该测试环境耗时，未降低600000次KDF或放宽15分钟 |
| full4 / 同537d6e8，WHPX初次参数 | `q35/max`出现Unexpected VP exit4，Linux未启动、零测试；核对自有QEMU6112后停止 | 原始错误、complete=false及独立部分审计保留；WHPX存在不等于此guest参数可启动 |
| full5 / 同537d6e8，WHPX兼容参数 | 31项结束、QEMU0、RUN_END和原自动证据提取齐全；27项0，普通Go、Alpine安装器、build、archive-contract四项1 | HY2首个HTTP失败及network changed日志保留；ARM64的Nlink类型编译错误导致管理器包缺失，后两项是真实发行失败，不能归Alpine平台例外；race通过不覆盖普通Go失败 |
| full6 / `702a716c4998b82d629385e9370dd91c04fdd267` | 仅准备、编译及计划，从未启动VM或执行检查 | 因后续生产类型修复另换来源，保留not-launched回执，不把编译当测试 |
| full7 / `d2c5c4c8ae997592ccf96761f3eb45686ba6c009` | 31项BEGIN/EXIT配对、QEMU0、RUN_END；30项0，只有原生Alpine安装器1。普通Go/race/vet、两版核心、权限、构建和包契约均0 | 自动证据提取失败使原run receipt仍complete=false；独立恢复84份证据后逐项验证，不覆写原回执。Ubuntu24.04标识夹具33/33是夹具，不是真实Ubuntu安装 |
| full8 / 同d2c5c4c，串口排空 | 31项BEGIN/EXIT配对、QEMU0、RUN_END，原严格collector提取成功且complete=true；30项0、原生Alpine安装器1，无其他unexpected失败 | 仅为旧d2源码的历史完整结果，不包含随后23dd99f的CreateInitial修订；原生Alpine32/33与支持标识夹具33/33继续分列 |
| full9 / `c89f7d1f1a8d6422a5e948bef000bcd0141ce9ee` | 31项BEGIN/EXIT配对、QEMU0、RUN_END，原严格collector提取成功、complete=true；30项0，仅原生Alpine安装器1，无其他unexpected失败 | 包含23dd99f首次快照独占创建修订；650源码/4测试包/80宿主输入/84证据共838项SHA一致。包运行、GUI、公网与真实systemd另列，不把构建冒充执行 |

full3/full4部分审计SHA分别为`f0557265fc7d3427882e91ea87b29ca5f8300202c9bac064c813297a407af6d3`、`67e439561f5c9cc79193f285d571d11fc17e0c3557c872bf8a79654783b614f9`；full5完整审计为`5e0c3fa345641927ea820525bb5f4fd74783e1736f7896ffe11f9875e2ad7cad`。full1/full2与targeted1原失败材料同样保留，不把取消或中断算通过。

测试执行环境的调整只在外部脚本：原final runner SHA`aca0cf536d45eac627d2a5d4933b73bec46801619583773510044f2fe91051fd`改用已有WHPX得到`276df0fe7a205c0ed4bcc15f1195ea48352b577cb7d6818d9c4317bc03570d7b`；再仅把guest机器改为`pc,kernel-irqchip=off`、CPU改为`qemu64`得到兼容runner`53120f861dc67b819b24ceef92cd4f0b9ecebce3fb8756282bd1c3ac565e170e`。原字节替换与CHECKS AST一致均单独核对；31项、4CPU、5120MiB、无外部NIC、Go/race15分钟、全部原断言与600000次KDF保持。未安装或开启宿主内核功能，这些guest参数试验不构成生产网络速度或性能改善的对照证据。

full5后修订分开说明：702a716c仅修测试夹具，监听出现不再被当作整个核心已启动；同一5秒预算内同时等待所属监听和完整INFO启动标记，新增假标记/取消/退出/缺条件负例，首个正向HTTP请求及其5秒限制、数据断言不变。d2c5c4c仅给Linux文件硬链接计数增加显式`uint64(s.Nlink)`转换，修复ARM64编译；Windows Go1.27.2的Linux ARM64交叉编译exit0仅证明编译，不能证明ARM实机运行。固定上游启动机制与许可见[THIRD_PARTY](../THIRD_PARTY.md)。

full7实际执行入口：`prepare-batch06-final.py full7 --commit d2c5c4c8ae997592ccf96761f3eb45686ba6c009`、`run-batch06-whpx-compatible.py full7 --prepare-only`和`--launch`。原生SDK为Linux Go1.26.8，静态测试包由Windows Go1.27.2交叉编译。源码ZIP SHA`37a8d79d2cd1ad714bc53f457d09b478933d1c6f6b6620c188880ae162ec4310`；原始日志SHA`87df632d37e4cc262b647ccfacd30196830450ac19bcbe7bef7f6b468a5d27ce`。主要实际命令与结果为：

| 命令 / 独立门槛 | full7实际结果 |
| --- | --- |
| `go test -p 1 -count=1 -v -timeout=15m ./...` | exit0，节点包128.402秒；含共享认证已停下载设备保护、迁移/备份、二维码URL边界、订阅失败/并发与三协议真实连接 |
| `go test -p 1 -race -v -count=1 -timeout=15m ./...`；`go vet ./...` | 均exit0，race节点包200.427秒；没有放宽超时 |
| 四静态测试包；官方候选核心及独立Device候选门槛 | 全部exit0；sing-box1.14.0/1.14.3和Mihomo1.19.30解析、三协议完整配置TCP/序号UDP、关闭代理负例、有序fallback三阶段分别验证。Mihomoauto仍是已知缺陷复现与明确降级保护，未称防抖达标 |
| 服务用户、两版受控netem、拓扑/图、UID65534用户态WG | 各独立门槛exit0；订阅UID/GID65534实际读快照和认证HTTP、发布/直接写拒绝；不等于真实systemd或公网 |
| `bash scripts/build.sh`、`build-probe.sh`、`python3 scripts/check-build.py` | 全exit0；管理器Linux amd64/arm64与probe Linux amd64/arm64、Windows amd64五个包契约通过；属于构建与包检查，不是ARM运行 |
| ShellCheck/Bash语法、`scripts/test-release.py`、维护观察器 | 全exit0；发行脚本38/38为FakeGitHub离线模拟，无发布 |
| 原生Alpine安装器；Ubuntu24.04标识夹具 | 原生32/33，唯一失败仍是读取实际host os-release的既知测试；支持标识夹具33/33单列通过，不隐藏失败或伪称原生Ubuntu |

持续TCP的真实进程测试含设备Profile/发布变更和订阅读取：静态、普通Go、race分别观察原PID保持79/74/79个连续帧，并验证运行变更重启及注入失败恢复。这是官方核心进程与活跃连接证据，不是systemd MainPID证明。常规静态/Go/race中受控netem与fixture helper按显式环境要求出现SKIP，原始清单保留；两版专门netem门槛另行实际通过，不能把helper跳过隐去或当成目标网络测试。

full7关机时两条内核日志插入Base64证据尾部，原runner正则拒绝整块，故原回执的自动提取失败保留。独立恢复仅精确移除这两条原样字符串、记录字节偏移，严格Base64解码、完整gzip CRC/ISIZE、tar路径/类型及成员字节验证通过；恢复tar SHA`92577c87f33cfa6bcf1eb793aa53e930618b6724190f2cf264a395b61d2b14ec`。恢复收据SHA`5df667b344341ca677d43560219cc4bc5d5f6886983046bdc9fd770799af9c2b`，独立`batch06-full7-recovered-audit-receipt.json` SHA`6c3321f5417b0c534cdd5eb350313b3f30c43304f8138a119d56c956c6175e19`核对647份源码、4二进制、80宿主输入和84证据共835项SHA一致。执行结束、原runner提取失败、独立证据恢复是三个分开的事实。

full8在同一d2c5c4c干净来源上冻结，以`run-batch06-serial-drain.py` SHA`6c0558746c00cc6ce1470ef7085f2a72b7d8deb1918ff15e98a52c566ea4382c`重跑；只在测试全部结束后为自有guest ttyS0增加两条各30秒上限的tcdrain，CHECKS与launch/严格collector AST均保持。实际31项退出齐全，原严格collector成功提取84份证据，835项哈希一致；这解决的是证据串口传输边界，不是代理网络性能参数。独立`batch06-full8-audit-receipt.json` SHA`861525af766e9a9413a58f86150f10935e47e07d1b6520bb79364bed761d2522`，原日志SHA`c68e32ff68e5e937241850558e1cb1e748683c2bdd60b39b9a8fe65765674910`，源码ZIP仍`37a8d79d2cd1ad714bc53f457d09b478933d1c6f6b6620c188880ae162ec4310`。普通Go/race节点包分别129.821/194.213秒，15分钟不变；连续TCP同PID分别72/76帧、真实UID/GID65534读取/HTTP及写拒绝再次通过。普通块的显式netem/helper跳过保留，两版专门netem门槛另行exit0。

full8运行期间代码检查另确认管理端阻断：`subscription init`合法复用已存在快照目录后仍无条件发布空快照，独立State或丢失发布配置后重用目录可能清空记录。这是特权误复用导致数据丢失的风险，不是远程未授权请求。修订`23dd99f5e0f7783aa66596a7f5ef67b160cb4623`将CLI改接`subscription.CreateInitial`：同步私有候选后通过原子且不覆盖的硬链接安装，已有空/非空快照一律保留拒绝，普通刷新仍走Publish。链接后崩溃可能留nlink=2，读端拒绝且保留候选/目标供核验恢复；不增加自动adopt接口。遗失publisher配置应从原0600备份核对相同目录/GID恢复，不能init覆写注册表。此提交的targeted3定向CLI红绿结果见下，历史d2/full8不包含修订；含文档的干净提交`c89f7d1f1a8d6422a5e948bef000bcd0141ce9ee`已完成full9，实际结果单列如下。

targeted3最初准备使用`-mod=readonly`，离线缺模块缓存且GOPROXY关闭使编译setup failed；该准备没有运行VM，不是缺陷红证据。保留原不完整compile receipt和日志，另用prepare2与仓库原vendor完成两份Linux静态CLI包编译。红侧是旧d2提交加唯一相同的`cmd/qingnode/subscription_init_regression_test.go`测试覆盖层（SHA`65c49ea73e699088dc073519711fdc02fe424b42337d800d5598eb2a4a58ffa2`），明确不是旧clean commit原样执行；绿侧为23dd99f。两侧测试列表同四项，均无SKIP：跨State复用、遗失publisher配置、已有空快照原时间/字节、并发两个State仅一方创建。红侧四项均以具体覆盖/授权丢失/两方成功断言失败、exit1；绿侧四项PASS、exit0。QEMU0、END、四检查配对与自动提取齐全，仅证明本次定向回归，不推导产品整体通过。原日志SHA`a44cd735eca9e54e9fae1af27c2a3b0a331eabecf8925043973ac3f2c828d71e`；入口`run-batch06-subscription-init.py --prepare-only --green-commit 23dd99f5e0f7783aa66596a7f5ef67b160cb4623`、`--launch`，实际runner和prepare2清单哈希保留在targeted3回执。

targeted3由另一代理独立审计：红/绿源码648/650文件、固定提交归档与唯一测试覆盖层、两个ELF、宿主输入、严格Base64/gzip CRC/tar五成员和磁盘证据全部一致。`batch06-targeted3-independent-audit-receipt.json` SHA`7f121b2d4158bc374963252d8ca7b64faae57cef7d772b1cd04e7ab6087a2ded`，审计脚本SHA`93ec73eb06adbe96176d33b5a823690d1fcc3f0e0f30d90b402d032527f87082`；原readonly准备失败材料仍分开保留。

## 最终源码full9实际结果

执行入口为`prepare-batch06-final.py full9 --commit c89f7d1f1a8d6422a5e948bef000bcd0141ce9ee`、`run-batch06-serial-drain.py full9 --prepare-only`与`--launch`，沿未改的31项与runner SHA`6c0558746c00cc6ce1470ef7085f2a72b7d8deb1918ff15e98a52c566ea4382c`。Linux6.18.55隔离guest使用原生Go1.26.8，四静态测试包由Windows Go1.27.2交叉编译；4CPU/5120MiB/无外部NIC、原15分钟包超时和600000次KDF不变。

| 实际命令 / 独立门槛 | full9实际结果 |
| --- | --- |
| `go test -p 1 -count=1 -v -timeout=15m ./...` | exit0，node128.327秒、CLI4.271秒；包含旧格式身份/恢复、共享认证保护、URL/二维码、订阅原子性及真实协议 |
| `go test -p 1 -race -v -count=1 -timeout=15m ./...`；`go vet ./...` | 均exit0，race node194.792秒、CLI29.200秒；subscription普通0.102秒/race2.139秒 |
| 四静态包；候选核心和独立设备候选 | 均exit0。默认140与候选143分别有解析、两客户端三协议完整配置TCP/序号UDP、停止代理无direct回落；Mihomo主备两项存活/主停/全停三阶段与组504负例通过 |
| 自动选择 | sing两版实测三轮容差内保持首项、超差切换。Mihomo1.19.30首成员39ms/38ms差仍在300ms容差内却切换的缺陷复现及默认拒绝/显式接受保护通过，不能称其防抖达标；手动触发HTTPS探测未等待300秒定时器，亦不证明UDP |
| 服务用户、两版netem、拓扑/图、UID65534用户态WG | 各独立门槛exit0；订阅真实UID/GID65534读取/认证HTTP成功且发布/直接写入拒绝，不当作真实systemd或公网 |
| ShellCheck/Bash语法、发行与维护观察器 | 均exit0；发行38/38是FakeGitHub离线模拟，无公开发布 |
| `bash scripts/build.sh`、`build-probe.sh`、`python3 scripts/check-build.py` | 均exit0；管理器Linux amd64/arm64和probe Linux amd64/arm64、Windows amd64五包构建及归档契约通过，仅证明构建与契约 |
| 原生Alpine安装器；支持系统标识夹具 | 原生32/33，唯一失败为`test_online_install_reads_actual_host_os_release_without_overwriting_tag`；Ubuntu24.04标识夹具33/33，不冒充真实Ubuntu机器 |

CreateInitial新增四项CLI回归和三项底层测试均在静态包、普通Go、race中实际PASS：跨State复用、配置遗失、已有空快照时间/字节、并发创建仅一方成功；首次完整私有快照、已有授权/未知格式/残缺/软链接/硬链接/FIFO保留拒绝和并发赢家完整性分别验证。文件链接拒绝夹具不等于实际断电测试；nlink2崩溃恢复仍按文档人工核验，不自动清理。

真实持续TCP在静态/普通/race分别同一核心PID传输75/72/76帧，涵盖设备/发布变更与订阅读取，并验证运行变更重启和注入启动失败恢复。这不替代systemd MainPID或跨网络会话验收。常规块显式netem/helper的SKIP原清单保留，两版专门netem门槛另行实际通过。

原始run receipt保持`complete=true`、QEMU0、RUN_END/31项配对及自动证据提取成功。源码ZIP SHA`d6c3d44c0f87fbfd945338706767a83ea9f1b67f30624f2a4b9d6f0e70bd3669`；原日志SHA`22c21e7c3bd31e103e1a7759ac2de81c18ce755baf84c6df399f851fd36ed92b`；证据tar SHA`d57b18d7f789a69d7cea8b6c019782bb110a5712ede73af6f36059aece3b2cc1`。独立`batch06-full9-audit-receipt.json` SHA`d11bc15ecd74f86100ea4f0cc233f226f9024f91a3a4c47db9b71991ece4dfc3`核对650源码、4测试二进制、80宿主输入与84证据等838项SHA及归档逐成员一致；30项0/原生Alpine1，无其他unexpected失败。历史失败没有被删除或改为跳过。

最终五包的原生命令、包级32项smoke与交付归档按交付目录的native/package-smoke/独立审计回执补充。包级入口`run-batch06-package-initial.py`保留原31项并新增init复用拒绝门槛；这份源码记录不提前声称后续包级检查已经执行，也不改变本轮原始31项结论。

## 未验证和恢复

真实手机/桌面客户端界面、公网 HTTPS 反代/证书部署、运营商路径、原生 ARM 与新订阅 unit 的真实 systemd 生命周期均需要对应环境，不能以 YAML 可解析或本地核心 PID代替。受控 UDP 与 HTTP 健康分开报告，不生成虚构流量配额或性能提升结论。没有推送、PR、发布、部署或远程登录。

Windows真实协议测试只属于上表的3bf74bee三个probe包；后续生产probe源码未改也不把结果改记到新提交。最终包的Windows helper仅按独立回执报告version/help/local等实际命令，不能当作重跑协议Go测试。最终五包的原生命令与安装包smoke按各自回执记录，不以源码构建替代执行。

用本批新管理器恢复旧 State/备份仍写 schema5；先保留旧二进制能理解的原始代及原快照，再考虑人工降级。不要删未知字段或改版本号。代理配置沿原锁、候选校验、原子应用及 recover/rollback；订阅发布独立版本、原子新快照失败保留上个有效版本。下载撤销不由 State restore/rollback 撤回；私有令牌材料及发布目录须单独保存或重新签发。

## 固定来源与许可证

sing-box v1.14.0 / `0b8995879f29a9b98ee027bc17b75e101445b238` 与 v1.14.3 / `7054cac5124465ffdb145870d7c01885566711b1`；Mihomo v1.19.30 / `ac017cdd246ce8bd547653d927e7bf77d7ee73d5`；S-UI v1.3.8 / `e84f7530e34a4769390007d37cb9f5e0f2ac01b2` 和独立 Wiki commit `798e4c542298fa74472a4eaba2901fff08dc8739`。本批原始固定文件16份及 Wiki 哈希保存在 `batch06-upstream-fixed-receipt.json`，机制/失败的读取入口详见外部 `batch06-source-notes.md`，项目内来源表见 [THIRD_PARTY.md](../THIRD_PARTY.md)。仅按公开接口生成配置并测试独立程序；没有复制 GPL 面板、代理协议或调度源码作为本项目 MIT 代码。
