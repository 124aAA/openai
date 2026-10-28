# 第09批持续实施记录：协议扩展

本批基线为 `502cfda2952a97e243c8920eff3265417ea10ae2`，接续第08批，源码未发行，默认官方核心仍锁定1.14.0。AnyTLS → Trojan → 传统SS AEAD → TUIC 已分阶段实现与审查；各阶段的准确提交、失败与复验分别保留。接口、场景与字段见 [PROTOCOLS.md](PROTOCOLS.md)。

## 当前状态

| 项目 | 当前证据 |
| --- | --- |
| 基线 baseline1 | 准确502cfda的8/8项实际退出0；QEMU0、未超时、RUN_END及begin/exit配对完整、严格提取成功、unexpected_failures为空 |
| AnyTLS / Trojan第一阶段 | 1a7d58的targeted1完整11项10过，唯一CLI夹具端口冲突失败保留；修正测试端口后的521b9a7 targeted2完整11/11项退出0，两版官方核心与Mihomo真实TCP/UDP通过 |
| 定向编译 | 新适配器与测试的Linux amd64 CGO0交叉编译退出0；不称Linux执行通过 |
| 传统SS AEAD | 三方法、同监听独立多用户password、SIP002、CLI method/add/edit与服务密钥保护已实现；targeted5两版核心与Mihomo真实TCP/UDP通过 |
| TUIC | 独立UUID+密码、服务端/客户端选项、共享证书、完整导出和URI拒绝、probe接入已实现；targeted5两版核心与Mihomo真实TCP/UDP通过 |
| 本批构建与发行保护 | 准确d0fd58a的finalbuild6五步构建/离线发行保护全部退出0，7个本地产物及许可证经独立审计v2核对；原生ARM、生产安装不在此证据范围 |
| 完整回归 full1 | 准确d98b1c7的62项中60项退出0；go-race在15分钟超时、原生Alpine安装器断言失败均保留，不能写成全过；材料983项摘要独立核验通过 |
| 完整回归 full2 | 准确481113f的62项中60项退出0；完整go-race已退出0，static-probe受控吞吐短样本方向断言失败、原生Alpine安装器断言失败均保留；材料983项摘要独立核验通过 |
| 定向 targeted7 | 准确15eb21f的25/25项退出0；含Linux CLI菜单与探针复验、两版核心及Mihomo实传；独立审计889项摘要一致且业务验收为true |
| 最终定向 targeted8 | 准确d0fd58a的25/25项退出0；新增菜单只读/实际构建能力、出口引用/删除拒绝与字段分栏测试通过；独立审计891项摘要一致且业务验收为true |
| 最终补测 capability-linux1 | 同一d0fd58a的独立能力JSON字段单测在实际隔离Linux退出0；补齐targeted8筛选未选中的新测试，不替代全量回归 |
| native systemd、公网、客户端UI、ARM原生 | 本批未实测，不引用前批结果替代 |
| 用户实际接受 | 未验收，自动检查不代替用户接受 |

第一阶段AnyTLS/Trojan使用独立密码、稳定UserID和现有证书资源，不复用HY2性能参数；本地TCP监听与TCP/UDP业务承载分开。AnyTLS仅管理三项客户端空闲设置，省略保留默认与显式0有别；基础分享链接不表达高级设置，存在时明确拒绝。Trojan URI经固定Mihomo解析会默认Chrome指纹，静态Ed25519证书分享格式拒绝，完整原生TLS配置另验。没有协议速度排名或自动调优承诺。

## 第一阶段实际验收与保留失败

两轮均完整结束：QEMU退出0、未超时、RUN_END与11项begin/exit严格配对、证据严格提取成功。`complete:true`只表示收集完整，targeted1仍有真实非零项，不能写成11项全过。

| 轮次 / 准确提交 | 真实结果 | 源码ZIP SHA256 |
| --- | --- | --- |
| targeted1 / `1a7d58ab6aa5d95deff70064ff891fa92c020b30` | 10项0；static-cli退出1，新测试固定24443与base fixture监听冲突，原失败保留 | `9a9234d53fd26656d20fafc378574b83ef4a21e8f9254705d045a8ad952a9470` |
| targeted2 / `521b9a7dcd45307c0880cc3bc8b5a42c07ce4003` | 修测试端口后完整11/11退出0，unexpected_failures为空，隔离VM已正常退出 | `69f9e1fa07e722e6a4b378c71c0b51babed8bb0b42ad5734d9188acd5e331537` |

两版1.14.0/1.14.3的AnyTLS/Trojan真实双用户、错误认证、撤销、备份恢复与Mihomo TCP/UDP门槛均通过，旧三协议两版回归、schema/证书/单元、CLI、probe与环境清理按各标签记录；不扩大成第二阶段SS/TUIC通过、全量race、native systemd或公网/UI验收。

targeted1原始串口SHA256为 `4640f56e48986e3f5832c198d80e35d03c6d0ccd54655e1cbe614fdfe83b6bb6`，run receipt SHA256 `cc9c0fbd942fd36f960871bf0c0276cdab014057ee54da457ca0e7eea84ede56`。targeted2原始串口SHA256为 `4878e5e1d9793d387ec41fef11f667a0a3006c190fb4a38c61dc4368dd053755`，run receipt SHA256 `864b70af8edc0ad0a4f5cfb6ca79178a990e6a69f9a5622b5bc84e7dd78d6771`。完整文件为外层 `work/batch09-targetedN-{compile-receipt,run-plan,run-receipt}.json` 及对应evidence目录。

```text
python prepare-batch09-final.py targeted1 --commit 1a7d58ab6aa5d95deff70064ff891fa92c020b30
python run-batch09-tls.py targeted1 --prepare-only
python run-batch09-tls.py targeted1 --launch
python prepare-batch09-final.py targeted2 --commit 521b9a7dcd45307c0880cc3bc8b5a42c07ce4003
python run-batch09-tls.py targeted2 --prepare-only
python run-batch09-tls.py targeted2 --launch
```

## 基线实际运行记录

`work/batch09-baseline1-compile-receipt.json`从准确Git提交归档，不导入之后工作区修改。源码ZIP SHA256为 `cae3e4f23a2d6308f1abe87204bfc2a1950f46a56e9e7ebbb0bd15af4ec7f36d`。

实际8项为 `environment`、`static-node`、`static-cli`、`static-probe`、`static-subscription`、`candidate-node`、`candidate-probe`、`environment-cleanup`，全部退出0。静态包及候选1.14.3路径确实执行，但源码属于扩展前基线，不是新AnyTLS/Trojan成功证据，也不是全量race/vet/发行/systemd验收。

回执为 `work/batch09-baseline1-run-receipt.json`，SHA256 `ed67b470cee648c36f2867b985edc7371c4529485c58d8ca02ecac1d429f0642`；原始串口SHA256 `735bef09a58e5f4186370282fff42639ceca0c6f15afc23135b607875195266a`。保存9个提取文件，完整状态与各文件摘要以回执为准。

复现使用外层work中的既有驱动，在独立授权环境准备工具与新证据名称，不能覆盖原记录：

```text
python prepare-batch09-final.py baseline1 --commit 502cfda2952a97e243c8920eff3265417ea10ae2
python run-batch09-final.py baseline1 --prepare-only
python run-batch09-final.py baseline1 --launch
```

驱动在本批仅用于隔离VM，不修改生产服务。第一阶段准确提交与结果已列在上节；第二阶段的实传、身份、权限和解析证据见下节。缺工具导致的SKIP须单列，不能写通过。

## 模型、恢复与后续门槛

真实新协议语义使State从schema7升为8。旧1–7只读内存迁移，合法schema7的观测/到期字段继续可读；旧schema夹带新协议/AnyTLS或TUIC字段，包括null、大小写与Unicode异常拼写，明确拒绝。新管理器恢复旧快照仍写schema8，旧原件保留；不删字段或改版本号伪装降级。QNBK1/2和QNBK3 typed v1边界沿 [MIGRATION.md](MIGRATION.md)，monitor独立资产漏项仍须明确受限。

第二阶段已按固定官方接口实现传统SS三方法独立用户password，直接交给方法KDF，不套用SS2022的server:user组合；TUIC实现UUID+密码、分开的CC/心跳、仅服务端auth_timeout、客户端relay模式、h3与显式关闭0-RTT。Mihomo心跳写整数毫秒，TUIC URI明确不支持。设备包含TUIC或AnyTLS高级设置时，须明确subscription_formats=[sing-box,mihomo,provider]，不静默丢URI不支持的设置。targeted5真实QA已完成；当前没有新版本发布、生产部署或客户端UI验收。

## 第二阶段真实验收与保留的失败

`09f5bed1e251ae114b4ea26148efbb4854476388` 的 targeted3 在任务中断时未出现RUN_END，原部分串口和中断回执保留，不能计作完整验收。`98b2a86f29394bb7cbeea836c5128e42945f118a` 的 targeted4 诊断轮6项中4项退出0，传统SS/TUIC生命周期2项失败；独立审计确认材料完整但业务验收失败。日志定位到TUIC旧QUIC连接在服务端重启后3秒内没有重连，以及AnyTLS已结束HTTP请求后的API连接快照竞态。验收修订后用新客户端验证重启后保留身份，把HTTP连接保持到API快照完成；没有把旧连接无损恢复写成产品承诺。

准确 `ca0df8a0175dd88a196e947b7f163543e8663b97` 的 targeted5：隔离QEMU退出0，RUN_END、25组begin/exit与严格提取均完成，25项全部退出0，没有顶层真实协议SKIP。独立审计888项源码、输入、日志摘要一致，材料完整与业务验收均为true；审计回执SHA256为 `8f1ca88b7f5def8a4f35181fa2bb283fdb50085f38bb8587ab5b2cf95250a8a2`，源码ZIP SHA256为 `8ed3b2fbde8a5f96f1902dd39b83514fadaca95daa4c8a56e9672a7e6a7eceda`。外层 `work/batch09-targeted5-{compile-receipt,run-plan,run-receipt,independent-audit}.json` 与同名前缀证据目录保留原始结果。

两版官方核心1.14.0/1.14.3、Mihomo1.19.30分别完成传统SS三方法和TUIC双用户TCP与序号UDP、错误凭据、单用户撤销、新客户端保留身份、加密备份恢复和代理停用后不能直连的负例。API在活跃HTTP流期间记录稳定节点/用户标签与正字节，缺失标签仍为未知。AnyTLS连接池记录PID、连接数、CPU ticks及RSS样本，仅是隔离回环观察，未得出性能优劣。受控127.0.0.2与[::1]外端口转发验证新四协议连接及停转发失败；IPv6仅为外部入口，内部监听和目标仍为IPv4。混合五协议设备Profile分别经两版官方sing-box与Mihomo解析；解析不代替GUI验收。

```text
python prepare-batch09-final.py targeted5 --commit ca0df8a0175dd88a196e947b7f163543e8663b97
python run-batch09-protocols.py targeted5 --prepare-only
python run-batch09-protocols.py targeted5 --launch
python audit-batch09-run.py --prefix batch09-targeted5 --expect-commit ca0df8a0175dd88a196e947b7f163543e8663b97
```

## 完整回归与不扩大范围

准确 `d98b1c7e4cad28b7f3dd76b3cc4be022e9ed4a34` 的 full1 已跑到结束，QEMU退出0、62项begin/exit配对、严格提取完成。60项退出0；`go-race` 退出1，是15分钟整包超时，堆栈当时正开始后段WireGuard拓扑测试，未出现数据竞争告警；`installer-alpine`退出1，是前批记录的原生Alpine宿主识别断言，受支持系统元数据夹具单独退出0。原失败与日志保留，不改断言或跳过。原始串口SHA256 `8aa92d60739c045277b887d5c17b38d0ab931e905bf452110593ffbd4da77b29`，run receipt SHA256 `e4cfc3552438c9c6024f9a5e7cbda11e8d84deebfe493eef7c9fcc2283e68c1f`。独立审计v2对983处源码、工具、输入及日志摘要核对通过，业务验收仍为false；审计回执SHA256 `95e22b25b804e7ab84f81b03891b36e6017d04f29a3ad33d2d8ebfeca6e5fe0b`。首版审计脚本漏映射受保护的Go许可证，保留失败回执；v2补上同一文件的原始摘要验证，没有改原运行结果。

本批已将CI和发行工作流的整作业预算由30分钟调至90分钟，普通Go测试显式15分钟，竞态Go测试显式30分钟；VM复验驱动也将竞态预算从15分钟调至30分钟。测试集合与断言不变；full2的完整竞态轮次已退出0，full1的失败原样保留。

准确 `481113f1e1fdee6887df049ffa2f337973d85d8a` 的 full2 已完成：QEMU退出0、62项begin/exit配对、严格提取成功；60项退出0，完整`go test -race ./...`退出0，没有数据竞争告警。`static-probe`退出1：`TestControlledLatencyAndThroughputDirection`用8×25ms短人工限速时，在虚拟机调度噪声下观测到慢/快吞吐未超过原两倍断言；`installer-alpine`的原生宿主识别断言仍退出1。后续 `10c2f848fc6a61d6d22252cec8a92d6c54ce1816` 只把受控测试服务器慢速每块等待增至200ms，仍要求原两倍方向，不改产品吞吐计算、断言或跳过测试；后续targeted7/8已在Linux复验通过，原full2失败仍保留。full2原始串口SHA256 `f110520b1a31b7ae5ad03abcdf468253b9562bdbf62cbb06a937a5d3562e150d`，run receipt SHA256 `b1c0b263a285ee068297583f5a26146b3ca278424fd1da28c5d947122f52eb7c`；独立审计983项摘要一致，但业务验收false，审计SHA256 `02543ba11ee7a74ad4c2c6e6828721d202464fcdc8c9524904fa7a9e0b153db3`。原失败结果不覆盖。

同一d98b1c7冻结源码的本地五步构建：Linux目标`go vet`、双架构管理器、三目标探针、归档契约与离线发行保护均退出0；`work/batch09-finalbuild2-receipt.json`及五份日志哈希已核对，产物共7个。产物沿用仓库0.2.8文件版本名，不表示第09批发行。ARM为交叉编译，无原生运行证据。

独立CLI审查随后发现新四协议的交互完整配置导出未传目标客户端版本，故被本项目正常校验拒绝；`info`复制命令同样缺参数，传统SS用户菜单还误显示SS2022专属服务密钥动作。`b68b15143c307a58b14b08243ceafc57e21d7dc7`按格式传固定已核验版本、修正菜单与错误提示并加实际菜单导出/复制命令/凭据不变测试；`0bc0827c7b863bebf30ae199ee632cd31fc67a8a`补齐命令帮助。原三个协议的导出选择不变。Linux amd64交叉编译新CLI测试程序通过，但交叉编译不等于执行；后续targeted7/8已实际执行这些菜单测试，结果在下文单列。准确0bc0827的本地五步构建与发行保护全部退出0，39项离线发行测试通过；`work/batch09-finalbuild4-receipt.json`及独立审计核对747个源码、5份日志、7个产物摘要。无安装或发布。

随后以准确提交 `15eb21f5654d7b5fc4315b4025b8da7c6ad5fae7` 冻结 targeted7：隔离QEMU退出0、RUN_END与25组begin/exit完整，25项全部退出0，未跳过顶层真实协议测试。它实际执行了新增CLI菜单导出与info复制命令、传统SS菜单凭据保护、受控吞吐方向探针，并重复两版官方核心1.14.0/1.14.3与Mihomo1.19.30的协议传输、撤销/恢复、NAT/IPv6入口、混合设备解析与资源采样。`10c2f848`的探针修订因此已在Linux执行并通过，full2原失败不覆盖。独立审计889项源码、工具、输入、日志摘要一致，材料完整与业务验收均为true；审计回执SHA256 `90a95d16050cbaee3588a8e4bf4ca0fdb78193f73c8ac973f4c0ed7f90682533`，源码ZIP SHA256 `2ec7c9dc767691c7c26b67d197cce8e80bf1389c5932bf81a28652211b2eba06`，run receipt SHA256 `dad541af9aa885813119b3b9315c828e9a8f0ab4f9964f75f84156eba4060fa7`，原始串口SHA256 `e4fb7649b91b66e1503fed6547d296582a2ce348be54e01622ce600b9b82604a`。材料见外层 `work/batch09-targeted7-{compile-receipt,run-plan,run-receipt,independent-audit}.json` 与同名前缀证据目录。

```text
python prepare-batch09-final.py targeted7 --commit 15eb21f5654d7b5fc4315b4025b8da7c6ad5fae7
python run-batch09-protocols.py targeted7 --prepare-only
python run-batch09-protocols.py targeted7 --launch
python audit-batch09-run.py --prefix batch09-targeted7 --expect-commit 15eb21f5654d7b5fc4315b4025b8da7c6ad5fae7
```

同一准确提交的finalbuild5五步构建/离线发行保护全部退出0，39项离线发行测试通过，7个本地产物分别有SHA256；独立审计747个源码文件、5份日志和7个产物摘要一致。回执SHA256 `df565146a4d2fc77608f35d5a7b4e410528e0289fb07e7bca1cc0214b4177886`，独立审计SHA256 `b0bef4f94198e44b906360d3652a20800f040c62a61a8adad413c3e05b68984a`。这些是构建与离线门槛，未安装或发布，ARM64仅交叉编译。

原生Alpine失败经逐项核查：`scripts/test-installer.py`会读取测试宿主实际`/etc/os-release`，隔离机为Alpine 3.24.2；`install.sh`既有白名单只验收Debian 12/13和Ubuntu 22.04/24.04/26.04，因此正确拒绝。此断言与白名单早于第09批，未因本批改动。full2中改用一次性Ubuntu 24.04系统元数据夹具的完整安装器套件33/33退出0，但它不等于Ubuntu实机安装；若要整轮全绿，需要在真正受支持的宿主上再运行，不能放宽检查或把Alpine写为支持。

- targeted5已完成传统SS三方法和TUIC两版核心/客户端的多用户、错误凭据、精确撤销与幸存者重连；逐项原始日志、命令及版本在对应evidence目录。
- targeted5已完成混合新四协议+旧SS2022的DeviceProfile完整JSON/YAML官方解析、CLI与probe、AnyTLS连接池采样；解析不代替传输，采样不推成公网提速或资源保证。
- 受控NAT与IPv6入口转到IPv4目标已实测，只证明那条混合路径；不代表完整IPv6端到端、云NAT或公网可用。
- full2已完成完整Go竞态检查，finalbuild5已完成vet、双架构管理器、三平台helper、归档allowlist/内外摘要、许可与离线发行保护；原生Alpine安装器失败仍单列。ARM交叉编译不当ARM运行。

当前native ARM、真实systemd、公共网络/CA/通知、桌面或手机GUI均未验收；Windows helper不等于Windows管理器或手机应用。官方核心与客户端独立调用，GPL源码只核对接口，不复制或链接其实现。State8只读兼容旧1–7并保留原始恢复材料，旧QNBK1/2和QNBK3 typed v1边界继续保留；恢复并不自动降级管理器，monitor独立资产仍需列明迁移缺项。

## 最终补齐与冻结验收

代码冻结提交为 `d0fd58a8348c25eb68dc7e1e44a770bde38afb1d`，分支 `batch/09-protocol-expansion`。本地提交不表示远程推送、PR、发行或生产部署；当前工作流的main/tag推送可能触发正式发行，本批未执行这些操作。

最终审查补齐了三处边界：能力JSON新增 `client_outbound` 与 `server_egress`，旧 `outbound` 继续表示客户端导出；创建菜单只读核验已安装核心的摘要、实际版本与构建标签，缺核心仍可走首次安装，离线生成明确未验证；四新协议的稳定ID出口引用、未引用出口剪枝、内部凭据隔离、TCP-only出口与被引用出口删除拒绝加入专项测试。TUIC/AnyTLS的URI限制在导出菜单提前显示，可继续选完整配置。旧README的“TUIC尚未实现”改为明确区分公开v0.2.8与当前源码。

`targeted8`在同一准确代码提交实际完成25/25项，QEMU退出0、未超时、RUN_END与begin/exit配对、证据提取均完整；没有顶层真实协议SKIP。两版官方核心1.14.0/1.14.3、Mihomo1.19.30的双用户TCP/UDP、错误凭据/证书名称、撤销单用户、加密备份恢复、停用无direct回落、旧三协议回归、NAT/IPv6入口、API标签、AnyTLS连接池和混合设备解析均再次执行。新菜单与路由单测也实际通过。独立审计891项摘要一致、材料完整与业务验收为true；源码ZIP SHA256 `328d1fc6222326bd77ee639ba8c309cee542f1f42328ea5beb04725b1cea3ecb`，run receipt SHA256 `efa60162e27f41f1debfd7c00fd562bf058c7ffce0b77e456d272f243fe5b0b3`，原始串口SHA256 `941bc6afcd9249b829f8b4144d3d46addfc531179a8cf60834f03a7ace8c3acf`，独立审计SHA256 `d99b704b95bd08638f9580ecc62aec74283e3726f4dc89f64942774216ec0fcf`。文件在外层 `work/batch09-targeted8-*` 与evidence目录。

`TestProtocolCapabilitySeparatesServerEgressFromClientOutbound`未匹配targeted8的筛选式，因此另用同一冻结测试二进制在无外部网卡的隔离Linux执行，退出0、PASS与RUN_END均观察到，QEMU退出0。独立补测回执 `work/batch09-capability-linux1-run-receipt.json` SHA256 `7f8fbc6c70cbb5a7e0ecb8c57034a4d8dc87d788059330457bdfa31e6debbf63`；源码/二进制/VM工具摘要和准确命令见同前缀plan与日志。没有把未被选中的测试计作targeted8已执行。

同一提交的finalbuild6五步均退出0：Linux目标vet、双架构管理器、三平台probe、归档契约、39项离线发行保护。7个本地产物摘要已核对；独立审计v2核对749个源码文件、3个工具、5份日志、7个产物及122项包内校验，结果通过。构建回执SHA256 `b9a33c36443d76843e219463f81e8562934673c2ded6a781f945d4a3c9e3af25`，审计v2 SHA256 `612b4defb30593da6d6ce3cb6ce58fbf3d0eb0493b9eeb0ccf847f23fe7f1f02`。首版审计误取派生脚本作builder，并把生成后追加Go/vendor许可的THIRD_PARTY.md当成原样源码比较，原false回执保留；v2按实际构建脚本重建许可并核对内外摘要，不修改原构建结果。产物保留0.2.8文件名但内含本批源提交，不代表公开发行。

```text
python prepare-batch09-final.py targeted8 --commit d0fd58a8348c25eb68dc7e1e44a770bde38afb1d
python run-batch09-protocols.py targeted8 --prepare-only
python run-batch09-protocols.py targeted8 --launch
python audit-batch09-run.py --prefix batch09-targeted8 --expect-commit d0fd58a8348c25eb68dc7e1e44a770bde38afb1d
python run-batch09-capability-linux1.py --launch
python build-batch09-final.py --prefix batch09-targeted8 --output-prefix batch09-finalbuild6
```

这些外层驱动固定本机工具路径并拒绝覆盖旧证据；换机需先准备工具和新的证据名称。仓库内可复用的测试命令为 `go test -count=1 -timeout=15m ./...`、`go test -race -count=1 -timeout=30m ./...`、`go vet ./...`，以及设置明确官方 `SING_BOX_BIN` / `MIHOMO_BIN` 后执行 `go test ./internal/node ./internal/probe -run 'OfficialCore|OfficialAnyTLS|Mihomo|ProtocolExpansion' -v -count=1`。受控NAT/连接池等测试仍需各自显式环境开关，见测试源码；不自动操作生产网络。

完整Go/race结果属于full2的 `481113f`，最终 `d0fd58a`只补跑上述相关定向与构建检查，未声称最终提交重跑完整62项。原full1超时、full2探针失败、Alpine宿主不匹配、所有中断和审计修订仍保留。真实受支持systemd生命周期、原生ARM、完整IPv6目标链路、公网与手机客户端/桌面GUI仍需实机验收，当前不满足“正式发行全部门槛已通过”的结论。

## 交付接口与恢复边界

- 七协议继续走 `ProtocolAdapter`，监听网络和业务网络分别登记。`protocols list`为version1，只增明确字段；`server_egress=false`不影响节点引用已有出口，禁止按客户端出站能力绕过服务器Egress模型白名单。
- `protocols options`与批量操作使用私有State字段；AnyTLS `idle_session_min_keep`映射核心 `min_idle_session`，TUIC服务端与客户端参数独立，Mihomo心跳精确换算毫秒，0-RTT始终关闭。不要把能力表中的核心字段名直接注入State。
- 新四协议单节点完整导出需指定客户端版本；交互菜单选用已核验版本并说明。TUIC或AnyTLS高级参数的设备须显式选完整JSON/YAML/provider，URI不静默丢失。订阅令牌和代理凭据仍分开撤销。
- State8保存新协议与选项，旧1–7只读内存转换；备份、恢复、rollback使用新管理器，保留ID、UUID、密码和共享证书。QNBK1/2与QNBK3 typed v1仍读取；恢复旧包仍写State8，不能降版本号或删除未知字段。先保留加密原件，再用 `restore --preview` / `recover`核查，按现有事务恢复；具体参数见[MIGRATION.md](MIGRATION.md)。
- 固定来源、机制与许可见[PROTOCOLS.md](PROTOCOLS.md)和[THIRD_PARTY.md](../THIRD_PARTY.md)。本批使用官方协议能力，没有复制GPL面板实现，没有协议速度排名或公网提速承诺。
