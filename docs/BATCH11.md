# 第11批持续实施记录：交互整合与最终回归

基线为第10批本地交付提交`856fe6b88309e837b9f6a87e9018da81ccb90a55`，分支为`batch/11-interaction-acceptance`。本批不增加代理协议或State字段；State继续为9，默认官方核心继续为1.14.0，1.14.3仍需显式固定摘要。没有远程推送、正式发布或生产部署授权。

## 最终本地验收与候选（未发行）

完整测试提交为`9db2d6fa066a9e5422d36e612ba49b10e74db1e8`；它相对运行代码冻结`801e9fd`只有文档变化。`batch11-targeted15`保留全部22项原门槛、原断言及预算，实际22项退出0，QEMU退出0，END/检查配对/来宾归档长度与SHA256/安全提取/逐文件摘要和临时唤醒释放均通过独立核对。最终候选允许再有文档收尾，但打包器逐一比较全部非Markdown文件和实际受测程序字节；最终提交、五包摘要和原始样本投影见交付`MANIFEST.json`、`DELIVERY-SUMMARY.json`及`qingnode-batch11-public-proof.zip`。本地检查不是远程workflow已经执行，未推送main/tag、PR、正式发行或生产部署。

运行回执SHA256为`c779038f167a0d77357afcb3df177814aaeabbad17c448cb2a1687cab0a4c6b2`，来宾证据归档SHA256为`4ae4097e99878f837aa1bdc408b4cba74f02179cba3f42ff8dd40187f67111df`；124个原始文件逐项核对。专用ttyS1归档验证完整；原ttyS0在归档阶段出现一条soft lockup内核告警，发生于检查结束后，原日志保留，不能据此推断生产宿主长期稳定性。

| 实际执行 | 结果与边界 |
| --- | --- |
| 完整Go | 1686项测试/子测试通过，10项跳过；跳过不算通过。跳过名称：`TestLegacyInstallPreflightActualBinary`、`TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess`、`TestOfficialAnyTLSIdlePoolOwnedSocketsAndResources`、`TestOfficialCredentialExpiryExistingTCPAndNewAuthentication`、`TestLegacyV028RealBinaryMigrationAndBackup`、`TestOfficialCoreHY2ControlledNetwork`、`TestHY2NetworkFixtureProcess`、`TestOfficialCoreProtocolExpansionControlledNAT`、`TestOfficialCoreProtocolExpansionControlledNATIPv6`、`TestOfficialFinalCLIControlledPerformance` |
| 完整race | 1686项测试/子测试通过，10项跳过；跳过不算通过。跳过名称：`TestLegacyInstallPreflightActualBinary`、`TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess`、`TestOfficialAnyTLSIdlePoolOwnedSocketsAndResources`、`TestOfficialCredentialExpiryExistingTCPAndNewAuthentication`、`TestLegacyV028RealBinaryMigrationAndBackup`、`TestOfficialCoreHY2ControlledNetwork`、`TestHY2NetworkFixtureProcess`、`TestOfficialCoreProtocolExpansionControlledNAT`、`TestOfficialCoreProtocolExpansionControlledNATIPv6`、`TestOfficialFinalCLIControlledPerformance` |
| 官方1.14.3定向回归 | 114项测试/子测试通过，4项跳过；跳过不算通过。跳过名称：`TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess`、`TestOfficialCoreHY2ControlledNetwork`、`TestOfficialCoreProtocolExpansionControlledNAT`、`TestOfficialCoreProtocolExpansionControlledNATIPv6` |
| 安装器 | 53项顶层测试全部通过，无跳过；真实Bash/CLI加受控宿主命令，不代替真实init验收 |
| 实际终端 | 同一实际管理器的32/40/80列PTY、普通查询/完整私有输出、NO_COLOR/dumb/非TTY、取消/EOF/隐藏口令信号恢复；物理手机SSH另验 |
| 实际机器接口 | 13类实际管理器场景；另25项指定Go测试及全部子测试在完整Go和race中均无跳过/失败；监听成功不推造代理认证或公网成功 |
| 跨批次 | 固定真实v0.2.8旧程序产生State/URI/加密备份，再验证身份/原件/未来格式；8组迁移、持续流、七协议/NAT/IPv6、出口故障、订阅授权和监控停止契约 |
| 独立拓扑 | 受控WireGuard namespace真实目标流量测试明确pass，不能用可选skip替代 |
| Ubuntu真实服务 | 同字节管理器在Ubuntu24.04.5/amd64/systemd两轮MainPID与活跃流检查、非root443 TCP/UDP、TLS四项和aux十四项通过；不是公网、重启或GUI证明 |
| 发行 | Shellcheck/Bash语法、vet、服务权限、发行保护、维护观察器、五项构建及严格产物契约通过；arm64是交叉构建，不是原生运行 |

普通Go/race中的真实旧程序、HY2网络/CLI性能及NAT可选项，另在本轮专门门槛中通过；辅助子进程测试不作为独立链路证据。同进程ACME后台续期、AnyTLS空闲池资源专项及代理凭据到期后已有连接专项本轮未显式启用，仍为跳过，前批各自证据不改成当前实测。

### 本轮受控性能原始结果

使用第02批probe引擎及实际qingprobe CLI，固定隔离VM回环HTTPS/序号UDP目标，分开记录直接对照、指定SS2022代理及HY2 namespace；目标响应包含人为节流，不是公网测速。两版核心分别运行，完整18份报告保留各自时间、测点、目标、配置摘要、原始样本、成功率、预算与错误分类。每次并发1；正常CLI样本为8个空闲/UDP探测、20秒总预算、1MiB有效载荷预算；HY2受控下载为8个探测、50秒和2MiB预算。错误认证/停止代理负例用2样本、3秒和64KiB；UDP过滤用8样本、50秒和64KiB，均不要求执行下载。预算不等于实际消耗，逐样本及traffic字段保留实际字节。负例必须判失败。下面的p95只是小样本描述，不是高置信性能结论。

| 核心/条件 | 空闲HTTPS请求中位/p95 ms | 负载HTTPS请求中位/p95 ms | 吞吐中位 Mbps | UDP收/发、丢包%、RTT中位/p95 ms、抖动ms | 客户端CPU ticks增量 / RSS前→后 MiB |
| --- | --- | --- | --- | --- | --- |
| 1.14.0 / cli/proxy-baseline | 7.637/28.934 | 6.791/17.536 | 14.314 | 8/8、0、5.354/14.95、5.553 | 5 / 56.461→57.633 |
| 1.14.0 / cli/proxy-repeat | 9.18/32.974 | 8.033/15.622 | 13.781 | 8/8、0、5.094/8.886、3.324 | 8 / 56.25→57.586 |
| 1.14.0 / hy2-netem/baseline | 3.35/28.048 | 23.184/23.184 | 155.302 | 8/8、0、3.403/10.359、3.064 | 8 / 59.414→63.348 |
| 1.14.0 / hy2-netem/delay-loss-rate | 170.341/722.215 | 285.451/499.488 | 1.743 | 8/8、0、165.113/167.948、1.703 | 49 / 57.082→60.656 |
| 1.14.0 / hy2-netem/udp-filtered | 6.784/28.98 | 未知/未知 | 未知 | 0/8、100、未知/未知、未知 | 7 / 56.844→60.102 |
| 1.14.0 / hy2-netem/memory-128MiB | 8.741/50.831 | 43.536/65.219 | 68.299 | 8/8、0、3.361/21.428、5.232 | 14 / 56.336→60.422 |
| 1.14.3 / cli/proxy-baseline | 6.374/14.636 | 5.491/43.141 | 14.407 | 8/8、0、0.91/15.732、2.243 | 5 / 59.234→60.719 |
| 1.14.3 / cli/proxy-repeat | 6.03/26.161 | 6.628/12.904 | 14.913 | 8/8、0、0.946/6.422、1.881 | 4 / 57.734→58.93 |
| 1.14.3 / hy2-netem/baseline | 7.812/51.212 | 25.282/25.282 | 177.23 | 8/8、0、2.958/14.049、3.391 | 11 / 58.566→62.371 |
| 1.14.3 / hy2-netem/delay-loss-rate | 171.34/742.636 | 328.062/492.084 | 1.776 | 8/8、0、164.852/167.345、1.285 | 58 / 59.031→62.203 |
| 1.14.3 / hy2-netem/udp-filtered | 3.508/35.066 | 未知/未知 | 未知 | 0/8、100、未知/未知、未知 | 4 / 58.254→61.848 |
| 1.14.3 / hy2-netem/memory-128MiB | 12.717/46.894 | 22.058/22.058 | 171.744 | 8/8、0、2.063/8.906、1.956 | 13 / 59.422→63.668 |

HY2受控条件分别为基线、每方向80ms/2%丢包/2Mbit限速、UDP过滤和128MiB客户端内存上限；同机CPU调度、QUIC行为、单次下载和小样本会影响具体数字，不把两版的峰值差异称为升级收益。CPU ticks与RSS为该客户端进程观察，不是整机CPU百分比；未知值不填0。经代理的DNS/TCP/TLS独立握手时间、线速字节与公网入口仍未知，连接建立/HTTPS首字节只能按报告已定义的端到端范围解释。本批未改变性能参数，不由这些结果自动调参或宣称用户端变快。

本轮测量时间为2026-10-28约18:53–18:54（+08，报告保留UTC原时间）。每方向80ms场景的UDP RTT中位数分别为165.113/164.852ms，2Mbit限速下单次有效载荷吞吐1.743/1.776Mbps；配置2%随机丢包时8个UDP请求都返回，只能说明该8样本未丢，不能声称测准了2%。UDP目标过滤时0/8返回、HTTPS请求仍成功，但整体报告failed；错误认证和停止代理也都failed，无direct回落。HY2基线下载/负载测量各只有1个有效下载样本，128MiB条件下两版吞吐差异也不能推出版本收益。

### 未验证与恢复

未提供物理手机SSH、手机/桌面代理GUI、用户运营商测点/公网入口、生产CA/DNS凭据、原生ARM64、本轮重启自启和长期负载验收。前批Rocky/Alpine实测保持各自准确提交，本轮不扩大为它们的新全流程或所有发行版通过。相应可复现入口见GETTING_STARTED、NETWORK_TESTS、PLATFORMS与上方真实命令。

State仍为9，QNBK1/2及QNBK3规则不变。升级前先做配置备份和`backup --full --preview`，需要一致短停时显式`--quiesce`。配置/卸载中断用`recover`，完整迁移中断用`restore --recover-migration --yes`，附属服务用`service recover --name … --preview`；已完成配置上一代回退用`rollback`（直接应用、没有preview）。恢复备份须先指定实际私有文件和口令文件preview，再明确yes。旧程序不理解State9，降级需要原始旧格式恢复点及匹配旧程序，不删字段伪装兼容。完整命令及边界见MIGRATION。

后续复用：任务分组/条件建议、同锁候选预览、版本1公共投影、有界只读诊断、全局可选执行回执和实际CLI/PTY验收入口；不要捕获人类文字充当JSON，也不要把AfterCommit空列表推成未写入。固定上游tag/commit、机制、Unicode数据与许可证继续见THIRD_PARTY，本批未复制GPL面板/代理实现或新增TUI依赖。

## 实现与历史过程

以下保留各轮当时状态；旧段中的“正在/尚待”均指该轮历史，当前结果以上方最终验收为准。旧失败没有改写成成功。

当前运行源码冻结在`801e9fdab0223ea78a50112adca14bdbfb015c55`。该提交的实际管理器SHA256为`5d84e47d8231ba5cb28006d16a67179ba2a8713913999acd8f7504cc4698531f`，独立探针为`cff83c8c8be5f0695aa83d34840e835ffffd6ebf79beb27a169cf6735f98d93a`。`finalbuild12`五项构建各退出0；本地归档构建的版本文字仍为`0.2.8 (source)`，准确提交由清单绑定，不能从这段文字推断具体Git修订。

2026-10-28的`ubuntu7`已对这份实际管理器完成Ubuntu24.04.5/amd64、真实systemd验收。两轮独立生命周期中，改名、重复应用和名称回退各自保持同一MainPID且活跃TCP帧增加；非root低端口443的TCP/UDP、四项私有CA HY2检查、十四项订阅/监控/人工停止检查、安装→升级→失败回退→卸载均通过。独立审查同时验证六个证据文件、源镜像不变和临时唤醒请求释放；运行回执SHA256为`1949a7882e23379eaabf0bf4cf257b1df9d7168a11128b96a1732125f69276cc`，证据包为`81f9ef87c5282fbcbc8a9401ee51a58368020c821c7d6a93e1f66a947a547a6d`。本轮没有测试公网、生产CA、GUI、重启自启或原生ARM，不能以该VM结果扩大支持范围。

同提交的`targeted13`未完成：前7项退出0，包括实际终端和实际发行程序的13类机器接口；安装器最后一组中观察到错误，但没有该项完整结果或归档。宿主等待记录有约1801秒和12421秒的调度间隙，包含低功耗时间的两小时总截止在恢复调度后判定超时；poll不能单独证明休眠或安装器错误的唯一原因。原回执保持`complete=false`、QEMU退出1，原日志不覆盖；临时唤醒请求已释放。`targeted14`随后执行相同22项，安装器53项中1项错误：Debian13在线重复安装子场景超过原35秒；期间系统事件另证实合盖待机/休眠，不能单凭该事件证明唯一原因。17:26明确核对自有QEMU身份后停止该失败环境，Go检查未完成、无END/归档，回执仍为false，所有原件保留。`targeted15`在全新环境按原断言/35秒上限复验，53/53通过，用时1965.751秒；全部22门槛也通过。未为该超时修改生产代码或放宽断言。

2026-10-28续作提交`6a7a907d7a37e2626b21df8139aa76648c872d28`新增逐项`doctor/diagnose --json`、有界`ports --json`、DNS/HY2及端点/出口/设备/到期/订阅的公开JSON查询，并增加全局`--result-dir`私有执行回执。回执来自真实返回及Apply确认回调，不抓取普通输出或参数；错误仍可能发生在提交之后。完整迁移关闭回调等观察边界见[WORKFLOWS](WORKFLOWS.md)。冻结编译、actionlint及五项发行构建各退出0；24项定向Linux测试的程序退出0，但首次采集器因提示文字与结束行相连，只有23项被识别为正式pass，另一项没有机器结束事件；且范围JSON缺末尾换行导致一个串口退出标记未成独立行。因此`targeted9`整体失败，原断言、原始JSONL与归档保留。修采集器须使用Go自身要求的`-test.v=test2json`，补换行后重新执行，不删除缺失事件断言。它只是新CLI定向测试，不等于完整发行或独立管理器验收，不能称所有领域输出已统一。

后续边界核对补充：受支持schema内的无效State也在核心/网络检查前拒绝；畸形监听地址或端口不能视为完整查询；监听子进程收到取消后停止并回收；执行回执明确命令退出与最终结果发布的区别。此增量目前仅测试编译，尚待实际运行。

`targeted10`已对`3ace7caa530c986399dd59c7c8e6149b0cc61210`完成25项新CLI定向测试：所有指定测试与子测试无失败/跳过，机器结束事件完整；专用串口、原始归档与逐文件摘要独立核验通过。它是测试程序加隔离夹具的证据，尚不等于独立发行程序或完整回归。后续静态核对发现HY2公开名称仍只脱敏、未清理旧方向控制字符；现统一走公共文字清理并增加含凭据/Bidi旧名测试，不修改保存的名称。该修正需要新的同提交门槛，不借用targeted10结果。

旧`targeted8`使用`f6b2a09dae6b8c121aaaac781eae0208a0433294`，保留原20门槛和两小时总预算：前8项完成并退出0，包括安装器53项、实际PTY、Shellcheck与完整Go；race期间总时限到期，后续无结果、无END和归档，`complete=false`。等待记录有较长宿主调度间隙，poll本身不能证明休眠或唯一原因。临时唤醒请求已释放，自有QEMU已退出。原失败回执与日志不覆盖；WMI启动没有安装计划任务/服务或修改电源方案。

同一旧候选`f6b2a09`的`ubuntu6`真实Ubuntu24.04/amd64/systemd验收在2026-10-28完成并通过独立核验，管理器SHA256为`5ef3d9ecc3de6f620dd81a74666a23ec709e0b6f58b1ee8b941b6eb6f41f0a54`，证据包为`f1664064a690e5c761c77dd9fb31295f2e119f8624dedae8366988ce4903f610`。两轮改名/重复应用/元数据回退均观察MainPID不变与活跃TCP帧增加；实际非root低端口TCP/UDP、四项私有CA HY2检查、十四项附属服务/人工停止语义和完整生命周期通过。源镜像不变、临时唤醒请求释放；不证明新增JSON代码、公网、GUI、公共CA、重启自启或原生ARM。

- 七类任务入口复用已有节点、设备、证书、拓扑、监控与安装接口。协议条件建议是前提说明，不把服务器测点当用户端速度排名。
- 菜单修改在同一候选身份、同一持锁事务内显示真实派生影响；普通流程不增加重复确认，原高影响确认仍保留。
- 版本1的脱敏状态和命令帮助，明确本机观察、未测项、历史记录失效及下一条真实命令。机器JSON、配置、URI和二维码使用独立输出通道。
- 人类文本按真实终端宽度折行并清理终端控制序列；隐藏口令读取使用同步有界等待，中断时恢复原termios。没有引入Huh或常驻界面组件。
- 文档只增加明确命名的发行白名单，未知成员、链接、摘要和原有发行门槛仍拒绝。

## 关键接口与兼容变化

| 目标 | 实现与后续复用接口 | 边界 |
| --- | --- | --- |
| A/B：按任务完成操作 | `menu_tasks.go`七组任务，`menu_guidance.go`根据六项已知条件建议；原协议注册表及能力检查仍是来源 | 未知入站不写成通过，不新增测速排名；用户可改建议 |
| C：先校验再看影响 | `menuCommand`只在交互调用期间开启预览；`previewMenuMutation`在同一Store锁内调用真实`Store.Preview`，随后Apply同一候选 | 不二次生成身份；普通流程直接完成；宿主设置、高影响删除/恢复保留明确确认 |
| D/E：状态与脚本 | 版本1公共状态、诊断及对象查询；`edit/batch --preview --json`；全局可选`--result-dir 新私有目录`记录实际执行结果 | null/unknown不是0；回执与领域数据分开，不抓取stdout；出错可能已提交，缺少最终回执为未知；没有通用stdin/JSON隐式协议 |
| F/G：普通终端 | `internal/ui`实际TTY列宽、受限文本清理与Unicode15.1宽度表；隐藏口令同步Poll、信号后先恢复termios | 无新增TUI依赖、raw模式或常驻组件；机器JSON、URI、二维码、完整配置不折行；字体差异及物理手机另测 |
| H/I：指南与矩阵 | GETTING_STARTED七条短流程、WORKFLOWS机器契约、FAQ和CAPABILITIES分层证据 | 公开v0.2.8与本地候选不同；解析、流量、服务、GUI和公网分列 |
| J/K：跨批与性能 | `acceptance-final-regression.py`、`acceptance-final-performance.py`，复用既有Store/probe/核心夹具 | 旧程序、真实PID/活跃流、协议、NAT、权限、链路和受控性能分别记录；不以mock或吞吐峰值替代 |
| L：发行候选 | 保留现有门槛，CI/release增加真实PTY和机器接口检查；包内文档按明确白名单 | 本地执行与远程workflow不同；main/tag不推送，未正式发布 |

普通创建和安装不再自动输出完整URI，依赖旧摘要抓取链接的脚本应改用显式`export --out`或明确的`info --show-secrets`。旧URI正确性断言保留在显式导出路径，没有删除。节点、用户、REALITY、证书和订阅身份继续由原State保存，不因界面变化轮换。

默认`version`文字格式保留；归档环境本地构建的修订标签为`source`，确切提交由源码归档和构建/交付清单绑定，不能把该字符串说成自报Git提交。正式workflow在真实Git检出中仍按既有脚本嵌入修订。本批没有改变版本比较或公开发行号。

## 修改前基线

`batch11-baseline1`在准确基线提交上只观察到环境、菜单/向导/dashboard、完整probe三项退出0，QEMU虽然返回0但缺少结束标记、检查配对及证据提取；`complete=false`，不计为完整通过。原因尚未证实，原日志和回执保留。

`batch11-baseline2`使用同一准确提交和同一组既有断言，在guest原生Go1.26.8执行；9项检查全部退出0，QEMU0、END、检查配对和提取完整。覆盖菜单/dashboard/probe、迁移与持续连接、安装入口取消/非TTY、Shellcheck、40项发行保护和观察器。审查日志SHA256为`936da5baf2c33326f53587af307c4f8426c3faf299716e75ccfcca963572bdb7`。这属于改动前证据，不能替代新交互的验收。

## 本批验证状态

2026-10-27续作独立审查又发现安装顺序缺陷：已安装的`install`在解析创建参数前准备核心，首次脚本也在字段校验前安装依赖。当前修复把已安装路径拆为只读候选、拒绝未完成事务、无自动恢复的锁内重读及统一应用；同一候选保留原身份，并拒绝离线安装暗中下载，离线生成改用`init`。锁竞争、旧State显式空数组、预检后并发变化和证书IP SAN另有测试。新增`validate-install`只检查已填写字段，自动发现与真实链路仍未知；首次TLS表单复用原Go向导，先收集到0700目录中的0600版本化参数文件，取消/EOF不进入依赖安装，正式创建才生成身份。文件只含参数，不执行其内容，不包含生成的UUID或密码。

首次在线兼容旧0.2.8时，仅在已校验程序明确不认识新预检接口且版本匹配的条件下，用原程序在私有临时目录执行离线字段验证；未填写的自动发现值只用测试占位，另验PEM起止时间。缺校验工具、旧程序不支持的参数或无法确定的已有资源均明确拒绝。正常退出清理临时测试State；强杀或断电不能保证进程执行清理，临时目录不属于生产身份。旧版交互TLS收集没有新接口时要求匹配的完整候选包；不能把这段兼容逻辑称为已发布新版。真实旧程序及八种兼容正负例列为新的隔离门槛。

`targeted5`冻结源码为`36f3855e257f5c763a5f9d909d87550686dbe18a`；环境、程序绑定、交互、实际PTY、合同、Shellcheck及完整Go七项有退出0记录，日志停在race，没有END、归档及运行回执。恢复现场时wrapper/runner/QEMU均不存在；失效锁另存，独立中断审计保持`complete=false`。宿主有待机事件，确切进程消失原因未证实，不能将本轮算通过或归因于单一事件。当前安装修复晚于该冻结源码，必须重新验证。新验收器检查测试与tee两个退出状态，证据由专用串口传输并核对来宾长度、SHA及安全归档；原失败材料保留。

历史状态（`36f3855`阶段，后续接口已经补充）：当时目标E的全命令机器结果尚未完成，只有明确列出的状态、帮助、部分预览及既有报告入口。后续`6a7a907`起提供可选的私有执行回执，并为诊断和对象查询补独立JSON；这是执行结果与领域数据分开的接口，不是捕获普通文本伪装JSON。最终验证必须同时核对实际管理器、完整Go/race及回执边界，不能用这段历史缺口或旧成功代替当前验收。

安装修复冻结为`dbd83aff815b02b45969c0413e3314a91b188a36`，五项构建门槛通过；实际管理器SHA256为`5ef3d9ecc3de6f620dd81a74666a23ec709e0b6f58b1ee8b941b6eb6f41f0a54`。`targeted6`增加安装专项证明，原19项命令保留并将完整安装器前移；53项真实Bash/CLI配合模拟宿主命令的安装器测试全部通过，用时720.490秒，包含TLS表单取消/EOF/无效输入。实际PTY和脚本合同各自通过；交互单测、完整Go和Shellcheck已返回1，整轮仍在运行，不能称通过。Shellcheck只报告旧版PEM工具检测的SC2015条件写法，后续改用显式if；代码检查另发现新夹具直接使用`testing.TempDir`的编号子目录（0777受umask影响），不符合真实`mktemp -d`的0700条件，已显式设置测试目录权限而保留生产拒绝不安全目录的校验。交互失败的完整原始JSON仍需归档核对，不能仅凭此推断全部原因或宣称已修复。该轮不等于真实systemd或新平台生命周期验收。

第一候选为`25e33240d966497c51d953c29763592f0c500368`。`targeted1`输出、END及证据完整，但19项中只有16项退出0，不能把`complete=true`当作全部通过。完整Go、race、vet、32/40/80列实际PTY、服务用户、40项发行保护、WireGuard及两个核心的受控性能已各自退出0；安装器、跨批次和候选核心检查退出1，原日志与回执保留，审查日志SHA256为`236a24ee114e887eb1f944749478919f1c3faccf180596b3cec66252c8066078`。这些结果不替代修正后源码的最终验收。

运行源码修正`2d0515f6d9a0dff55f2b67d0d0b4347506748fbc`解决了离线状态页建议离线必拒命令的问题：现在明确说明须回原宿主或完成环境映射，先给出可执行帮助。它已完成独立五项构建检查，但当时尚未执行新的完整Linux回归。

`7ec2d2be78cb1aa6c90f430463b75ddd48120d09`修正下表三个测试夹具，并完成五项构建。其`targeted3`在环境、程序绑定、交互、实际PTY、脚本契约、Shellcheck六项退出0后，被明确取消：收尾核对发现普通人类`list/info/status`尚未接入清理和折行，不能继续把旧终端检查当作该路径已验收。该轮没有END或完整证据，`complete=false`；取消材料保留，自有QEMU、锁及临时线程唤醒请求已释放。

后续候选补齐普通查询与错误输出的真实TTY折行，先按完整行作State脱敏，再清理显示控制；查询不改原State。JSON独立输出，显式URI、UUID/密码/short ID/私钥使用原始字节路径，写入和最终Flush失败不能返回成功。实际PTY入口增加32/40/80列的普通查询、旧Bidi名称、长中文/emoji/IPv6/域名、私密输出原样和查询字节不变检查；不以单元替代PTY，也不以PTY替代物理手机。

该运行实现冻结为`16d012cea2294b7ed76a18d95d71bb5d4ff89c8a`。`finalbuild4`五项构建全0，实际Linux/amd64管理器SHA256为`c2b19be1499850a5b060b79386fadeb24cd84f0500e6e0e5032fb072d433a05c`，探针为`cff83c8c8be5f0695aa83d34840e835ffffd6ebf79beb27a169cf6735f98d93a`。`targeted4`中完整Go/race/vet、扩展实际PTY、跨批次、WireGuard、候选核心及两个性能入口各退出0，但安装器退出1；虽然结束标记及19项检查均有配对，内核信息插入串口归档导致原证据未提取，原回执`complete=false`，不能称整轮通过。

安装器唯一失败发生在SS2022交互安装，输出已到最终摘要，但测试在35秒内未收到进程结束。State记录时间与主机07:36:15因合盖进入待机、07:41:12恢复的系统事件和296秒调度间隙高度重合；这解释了需要重测，但不能证明进程退出或文件描述符的具体原因。原35秒上限和所有断言保留，不能把这一轮改记为通过。

原始串口SHA256为`fb59c3988c46f259a6c4dc53f97653852b5a6a7520dbb36421e99c0b25fd03c0`。其中37条内核watchdog记录插入Base64流；独立工具尝试按时间戳重建，严格验证Base64、gzip完整性、归档路径与内部摘要，并保留原始记录。原运行没有客体提供的整体归档SHA，因此重建结果只能作为明确标注的部分证据，不能改写原回执。后续隔离运行在客体生成归档前保存内核日志，传输前记录长度和SHA256，并限制客体console打印级别；不修改宿主网络或电源方案，不能因传输完整而掩盖测试失败。

`targeted4`的独立恢复已完成：原始串口中的19项检查标记与归档内相应日志对照，去除可识别的带时间戳内核打印并统一换行后内容一致；重建归档的124项中有116个文件，逐文件回读与重建归档一致。跨批8组JSONL、WireGuard结果、两个核心各9份性能报告以及所引用摘要已核对；普通Go和race各有1617个测试或子测试通过、9个跳过，候选核心有114个通过、4个跳过。跳过不算通过。重建gzip的SHA256为`4c1234ddd70338f3e8e372ada895918838913abf71248d79864d5ab76f3c0751`；gzip的CRC只能发现损坏，不能补出guest未提供的独立原归档摘要。恢复回执仍写`complete=false`，安装器失败原样保留；原始串口和私有测试材料不随公开产物发布。性能报告时间来自guest；没有独立同步的宿主与guest时钟记录，不能断言上述待机直接影响了后续性能时间戳或测量。

`ubuntu4`是同一运行源码`16d012cea2294b7ed76a18d95d71bb5d4ff89c8a`在可丢弃的Ubuntu 24.04 amd64、真实systemd中的独立验收，不是`targeted4`安装器失败的重跑。两次独立服务生命周期中，改名、重复应用和名称回退均观察到同一MainPID且活跃TCP帧持续增加；还验证了非root服务的低端口TCP/UDP、四项受管TLS检查、十四项附属服务检查和人工停止语义。guest退出0，独立审查报告状态为passed；运行回执SHA256为`90705dbbdcd6335e388de7cbe67ffba3bfe94278ceb8e042ca277d5c9e2c839a`，guest证据包SHA256为`d7c7bebf412419c716c14fcc6166f24bb7cf3e908dc92ed34ce88d7711b96346`。该环境只使用私有CA，未验证公网HTTPS、手机或桌面GUI、重启后的自启动和原生ARM64；这些结果不能替代其他系统的真实服务验收。

| 第一轮实际失败 | 已核实原因与处理 | 未完成部分 |
| --- | --- | --- |
| HY2安装摘要顺序断言 | 前置真实影响预览也含“节点”，旧断言误取首次出现；现按唯一8/8完成标记分段，分别检查预览/最终摘要次数、顺序、同一身份和秘密不泄漏 | 新断言需重新执行；原URI/State断言保留 |
| 旧v0.2.8迁移夹具末尾拒读断言 | 实际old CLI生成、身份、URI与加密恢复已走过；无实质修改的Apply依法不落盘，测试却把仍为schema1的文件当schema9；现先断言no-op保持字节/指针，再用标签修改触发真实写入，检查新格式、旧原件和旧程序拒读 | 不修改迁移生产实现，不轮换凭据；新测试需原生执行 |
| 1.14.3 ACME恢复后首次HY2 HTTPS被重置 | 核心日志为证书缓存尚未就绪；磁盘证书已存在不能证明新provider已加载。夹具增加同一进程下有界、严格TLS和认证的真实HTTPS就绪；原精确响应及序号UDP断言保留 | 两个官方核心与受控CA须重新验收；不以关闭校验或重启通过 |
| 安装器两个35秒超时 | 原断言与时间上限保留；不能仅因宿主休眠就认定这两个失败已解释或通过 | 原用例需重新运行，若重复则继续定位 |

宿主事件记录证实本地2026-10-27 00:27:53至06:28:02发生约六小时休眠。旧Windows进程等待不计低功耗时间，因此墙钟七小时不能解释成两小时活跃预算已生效。新外层隔离验收器使用包含低功耗时间的硬截止并记录调度间隙；不修改QingNode或生产宿主策略。依据为[微软等待接口语义](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)。第一轮休眠与失败保留，不能把它们改写成成功。

本机Windows/amd64的实际探针启动、帮助及无效私有Profile退出码检查通过3项；只属于原生CLI启动/输入拒绝，不是代理传输、GUI或性能验收。程序SHA256为`50d023fbf25c480b752f6351a5f68bb6716b79d2c0f4b025f047dc90f8f4b0e8`。脚本契约、交叉编译及开发性能预验收均保持独立证据级别。

真实终端入口为`scripts/test-terminal-workflow.py`，需要明确的Linux测试二进制绝对路径、SHA256和新报告文件；仅使用独立离线状态目录，不修改已安装服务。32/40/80列PTY模拟不能代替物理手机SSH或GUI验收。

性能入口为`scripts/acceptance-final-performance.py`，复用第02批标准Report与既有受控HY2网络夹具。目标、发起点、核心、工具、样本和流量预算须固定；回环与netem只是受控实验，不代表公网运营商质量。未完成、取消、缺少样本和不可比较条件均不得记为收益。

## 可复现的验收入口

`scripts/test-machine-interface.py`验证实际发行包内的管理器（不是Go测试程序）：只使用临时离线State、自有本机TCP/UDP监听和私有子进程夹具。13类检查含声明JSON与NAT/IPv6序列化、回执/重复应用、秘密输出原样、错误输入、pending保留、真实监听、取消/超时/容量与回收、结果冲突、并发修改。网络服务生命周期、代理认证、UDP业务、公网与GUI仍是独立门槛。便携合同测试`python3 scripts/test-machine-interface_test.py`本次在Windows执行5项通过；下方实际入口尚待Linux运行。CI和发行workflow已追加两者，未删除旧门槛。

```bash
python3 scripts/test-machine-interface.py --disposable --bin /absolute/path/qingnode --sha256 ACTUAL_SHA256 --out /absolute/path/new-machine-report.json
```

必须使用实际Linux/amd64候选与真实SHA256、新结果文件；报告仅含白名单检查结果，不打包临时State、参数或输出原文。机器结果JSON之外仍应核对进程退出码。此入口不安装服务、修改防火墙或替代实际手机SSH验收。

以下是在可丢弃Linux环境使用的真实入口，不是生产部署命令。需要固定摘要的官方核心、Mihomo、受控CA及原生Go；外层清单还绑定实际被运行的管理器/探针和旧版程序。普通Go测试中的可选跳过不能代替下面专门验收。

```bash
go test -p 1 -json -count=1 -timeout=15m ./...
go test -p 1 -race -json -count=1 -timeout=30m ./...
go vet ./...
shellcheck install.sh scripts/*.sh
python3 scripts/test-installer.py
python3 scripts/test-release.py
python3 scripts/test-maintenance-harness.py
```

真实终端使用`test-terminal-workflow.py --disposable --bin /qingnode --sha256 实际程序SHA256 --out 新报告绝对路径`。跨批脚本需要`--core/--core-sha256`及`--mihomo/--mihomo-sha256`；性能脚本需要`--core/--core-sha256`及`--probe/--probe-sha256`。两者都需要`--disposable`和新的绝对路径`--out`目录，并须在可丢弃root Linux内显式设置`QINGNODE_VM_DISPOSABLE=1`；完整参数以各自`--help`为准。性能另加`--with-netem`才运行受管namespace/cgroup场景；缺能力或跳过记受限并返回非0，不当通过。

跨批验收还须配对传入`--legacy-bin`和`--legacy-sha256`；旧程序来自固定`70c0c277aa8703a4bd2cf8268b6bdad09ae13fc2`源码的Go1.27.2静态重建，禁止用当前程序生成JSON冒充旧数据。该实际输入SHA256为`e1634d5bc24123c3c522e2904e8d9bc51fdf7501db778b64d84b5ca43bb99b75`，构建不带VCS自动探测，并显式嵌入版本0.2.8及完整研究提交。新旧程序和密码文件只在私有临时目录执行；身份/URI/备份原文、只读/no-op、实质写入及未来格式拒绝分别验证。

本机交叉构建用Go1.27.2；隔离Linux Go测试用原生Go1.26.8。实际PTY与探针CLI运行的是前者构建的真实发行payload，不能把后者测试二进制当成发行程序。arm64交叉编译、Windows探针启动、Linux真实核心传输和物理GUI验收分别计证据。

## 迁移、恢复与边界

本批没有提高State或备份格式。旧1–8仍只读内存兼容，写入保留原件；QNBK1/2和QNBK3沿用原校验。旧二进制不能直接读取State9。恢复命令、冲突材料、受限完整迁移和降级前置条件见[MIGRATION.md](MIGRATION.md)。菜单只是复用这些接口，不自动修复只读查询、轮换凭据或重新拉起人工停止的服务。

升级使用核对摘要后的本地完整候选包，运行包内`install.sh --reinstall`；如传`--core-archive`，须匹配原State已选核心版本及目标架构，不要用默认版本覆盖用户原选择。升级前先创建配置备份，并用`backup --full --preview`确认完整迁移资产及是否需要显式短停；备份口令用权限600的文件，不写命令行。

配置/核心回退通过菜单确认，或在已确认影响后执行`qingnode rollback`：它回退到上一代，不提供选择历史代的`history`命令，也没有`--preview`；执行会直接开始受管回退事务。中断的配置或卸载事务使用`qingnode recover`，中断的完整迁移使用`qingnode restore --recover-migration --yes`；命令与适用范围不能互换。迁移预检必须指定实际备份文件和口令文件，例如`qingnode restore --file /私有目录/complete.qnbk --password-file /私有目录/passphrase --preview`，再按目标环境映射选择恢复参数。它们不是格式降级工具。退回不理解State9的旧管理器需要对应的升级前原始恢复点，不能由当前`rollback`写出的新格式假装向后兼容；没有相应材料就保留当前管理器并排障，不删字段强行降级。

最终候选的提交、测试回执、性能条件、构建摘要、升级/回退和未验证清单在本批完成时补入本记录。main/tag工作流可能触发正式发行，本批只交付本地可审查候选。
