# 第 07 批持续实施记录：证书与完整加密迁移

本批接续已完成的第 06 批 `30deb7e437223a532757bbaab33cfc308a895621`，分支 `batch/07-certificates-migration`。2026-10-13 调研快照仅供定位，没有回退。源码尚未发行，默认官方核心仍锁定 1.14.0；1.14.3 是独立候选。本记录只列第 07 批实际执行，不把前批或计划当成功。

## 实现与恢复接口

稳定证书资源、旧格式内存迁移、私有输入与共享引用保护见 [CERTIFICATES.md](CERTIFICATES.md)；QNBK3、停止证明、目标映射、恢复事务及保留策略见 [MIGRATION.md](MIGRATION.md)。State 因真实字段升为 schema 6，保留旧 1–5 与 QNBK1/2 读取，写入保留旧原件；没有删除字段伪装降级。

## 本批已执行的基线

2026-10-22 从准确 base `30deb7e437223a532757bbaab33cfc308a895621` 冻结 Git archive，在隔离 Linux QEMU 重新执行：

```text
python work/prepare-batch07-final.py baseline1 --commit 30deb7e437223a532757bbaab33cfc308a895621
python work/run-batch07-serial-drain.py baseline1 --launch
```

8 项全 0：environment、静态 node/CLI/probe/subscription、候选核心 node/probe、清理。串口收集闭合，QEMU 退出 0，RUN_END、配对、提取与 complete 均为 true。原串口 SHA-256 为 `697108922e5810e50ed69f784954b02ce3ab743acd2f3fd5d76cfdb8cd89fced`；独立审计另做严格 Base64/gzip/tar 核对及 761 项摘要，包括 650 源文件、4 测试二进制和 9 证据文件。它是基线 8 项，不是新实现验收或完整发行 31 项。新专项收集器在首次冻结前增加去空白后的 `validate=True`，原收集器与回执保留，其它继承命令、超时与 QEMU 参数不变。

## 首轮项目路径：targeted1（实际含失败）

源码 `86f9422d87dc164940b3173fa3a79e0b1b36616f`：

```text
python work/prepare-batch07-final.py targeted1 --commit 86f9422d87dc164940b3173fa3a79e0b1b36616f
python work/run-batch07-cert-migration.py targeted1 --prepare-only
python work/run-batch07-cert-migration.py targeted1 --launch
```

8 项退出齐全：6 项 0，certificate-node 与 certificate-cli 各为 1。QEMU 0、未超时、RUN_END/配对/严格提取/complete 均 true；`complete` 只表示运行及收集闭合，不表示断言全通过。原串口 SHA-256 `a984854229c3278a78218b81d5ab485f69e77b1dc5d20c8b287499e8edfbeeb4`，原件与 9 项证据保留。

实际通过的四项真实核心检查：默认 1.14.0 的项目生成 ACME 配置完成真实 HTTP-01 / P-256 域名 SAN 签发、20 秒到期后的启动续期、账户保持、CA 拒绝/错误端口失败及 HY2 HTTPS/序号 UDP，20.64 秒；候选 1.14.3 同项 19.99 秒。PEM 完整 QNBK3 在干净隔离目录恢复后，两版核心各 0.69 秒完成 HY2 HTTPS/序号 UDP，原节点/认证/证书 ID 与私钥保持，损坏派生配置重新生成，归档服务文本未执行。

实际失败为：`TestCertificateACMEExactCapabilitiesAndChallenges` 发现无效候选 Canonical 失败时 DNS 凭据未脱敏；`TestLegacyEndpointMigrationPreservesEverySavedFieldAndExport` 的 HY2 夹具、`TestSchemaOneExtensionsRejectedAndMigrationPure` 仍按内联证书比较旧结构，需精确适配新资源并保留身份/源内存断言；`TestMigrationCLISubscriptionPermissionMappingAndQuiescence` 发现预览“短暂停止”与明确“短停”提示不一致。后续修订另记，不将该轮写成全部通过。此轮真实迁移是 PEM，不能扩大成 ACME 账户资产已搬迁验证。

## 受控 CA 的原始发现

在项目路径的第二轮 `targeted2`（源码 `28e7e3c5b05e23a72c66fa6861dd7ee5336ae39e`）实际 7/8 项为 0，CLI 全部通过；唯一 certificate-node 非零为冲突测试夹具缺少已引用资源，提前报缺失引用，尚未进入它要断言的挑战端口冲突。后续只修合法夹具、先断言无冲突候选有效，保留原冲突拒绝和错误类别断言。原运行 QEMU 0、RUN_END/配对/严格提取/complete 均 true，串口 SHA-256 `630362d9b0bfda0a2a26de76ec95eb0142fcd96c2e574b9a1b812734109e8a74`，782 项摘要独立核对。

该轮新增的真实 ACME 存储往返也实际通过：1.14.0 为 20.52 秒，1.14.3 为 20.69 秒。签发后的核心先停止并等到子进程退出，持锁捕获其真实账户、证书、私钥与元数据；QNBK3 恢复到干净隔离目录，逐文件字节及节点身份相同，然后重新渲染并由官方核心建立 HY2 HTTPS/两条唯一标识序号 UDP。随后实际到期、启动续期、CA 拒绝及错误挑战端口负例通过。资产暂存阶段使用离线后端，不是 systemd 生命周期证明；后续真实核心数据面是另一份证据。后台同 PID 自然续期仍待长测，不能用启动续期代替。

官方 Pebble v2.10.1 与官方 Windows sing-box 1.14.3 的本机隔离夹具实际签发 HTTP-01 / P-256，HY2 HTTPS/UDP 成功，等待短证书真实到期后重启核心触发续期；ACME 账户密钥保持，证书序列与到期更新。CA 策略拒绝和错误挑战端口均失败，未关闭 CA 验证。第二次 23.0 秒通过的日志摘要为 `8851b2c4222ef270813a7c1a69477aa9ac28108ad7c4e6ae775e993a0996ba92`。

首轮日志 `batch07-acme-native1.log` 保留真实失败：夹具错误要求续期后的证书私钥不变，而固定核心正常会换叶证书私钥；修正的是测试假设，没有放宽代理认证、账户身份或数据传输断言。该原生夹具直接使用核心 provider JSON，不能冒充项目 renderer、Linux 服务或同 PID 自然后台续期证据。后续项目路径结果另记。

另一次`acme-native3`尝试用Windows Go原生执行项目`./internal/node`，实际在编译阶段退出1，日志摘要`0e4266b0a837392e4fa31e1a10b5a342ef9a42210646aa233cdb9de7f1cd745d`：现有Linux宿主能力模块使用`unix.O_NOFOLLOW/Faccessat`等接口，Windows包不可编译，未运行项目签发测试。没有把native2的独立核心成功算成Windows管理器支持；项目真实路径由后续隔离Linux执行。

## 定向修复闭合：targeted3

源码 `45d7bac72eb8ded060733d53a9a3ac998e5cb758` 的第三轮使用相同 prepare/专项 runner（mode 改为 targeted3），8/8 检查全部退出 0，没有 unexpected failure。QEMU 0、未超时、RUN_END/配对/严格提取/complete 均 true；串口 SHA-256 `7d1428239bba4488e5a6f0f253fd1db7bb7fe6c1f6d28b9f4d6d6d7c3a249412`。node/CLI 的旧迁移、错口令/篡改/未来格式、恶意条目、资源引用、权限/链接、失败恢复与保留测试通过，前两轮失败不覆盖。

两核心的真实 ACME 账户完整迁移、恢复后 HY2、真实到期启动续期及 CA/端口失败通过，分别 20.29 / 19.93 秒；两版 PEM 完整迁移后传输亦通过。默认核心新增 `TestOfficialCoreCertificateRSAHY2TCPUDP` 实际 0.19 秒通过 RSA-2048 的 HTTPS 与两条带唯一标识/序号 UDP，保留默认 Chrome QUIC 行为。P-256 另由上述 ACME 与 PEM 流程覆盖，算法选择不能只靠 X.509 解析下结论。

该轮之后还发现并单独补测恢复前自动完整包的保留登记：如果未标记 complete，后续普通配置备份成为 current 后可能清掉唯一完整恢复点。修订和混合保留场景将由下轮完整回归执行，不能把 targeted3 结果转记到这个新修复。

## 完整回归 full1：33/36，失败原件保留

2026-10-23 冻结源码 `b0cca6e7167fc92c5f7055d3d5cc63fdb2b206cd`，保留原31项回归，再增加5项本批真实核心门槛，没有缩短600000次备份密钥派生或原15分钟Go/race期限：

```text
python work/prepare-batch07-final.py full1 --commit b0cca6e7167fc92c5f7055d3d5cc63fdb2b206cd
python work/run-batch07-cert-migration.py full1 --prepare-only
python work/run-batch07-cert-migration.py full1 --launch
```

36项退出齐全：33项0，`device-candidate`、`installer-alpine`、`installer-supported-metadata-fixture` 各为1。QEMU退出0、未超时、RUN_END/配对/严格提取/complete均true；外层runner退出1，因为保留这些失败。原始串口SHA256 `abd03e625806e4c84f31fc66de68299c252a931605ae3f67b1d27e780c66dbaa`。不能写成全套通过或只有一个平台失败。

独立审计逐一核对865项摘要，包括675源文件、14测试输入（含4静态测试程序）、80宿主输入、89证据及清单/归档；重新生成的Git archive字节一致，严格Base64/gzip/tar及解出文件全部吻合。审计回执`batch07-full1-independent-final-audit.json`摘要为`1dce4c806166423a5160a276187a0d03ed317a9aca83291fb5e8b7aad8c417e5`，仍明确`all_checks_passed=false`。

实际通过：四包静态测试，`go test -p 1 -count=1 -v -timeout=15m ./...`、全项目同期限`-race`、`go vet ./...`；两版核心三协议及Mihomo配置/传输、元数据维护持续TCP、拓扑/用户态WireGuard、两个netem受控环境、专用服务用户文件权限；shellcheck/Bash语法、发行保护测试、维护观察脚本、管理器两架构与qingprobe三平台共五包构建及归档契约。发行测试使用隔离替身，不代表发生远程发布。Alpine guest不是受支持安装宿主，Ubuntu24.04步骤只改guest的OS识别材料，不冒充真实Ubuntu安装。

新增实际证据：默认1.14.0/候选1.14.3的真实HTTP-01签发、完整ACME账户/私钥/证书/元数据QNBK3往返、恢复后HY2 HTTPS/序号UDP、真实到期启动续期及CA/端口负例通过；分别20.68/20.54秒。两版PEM迁移后目标传输分别0.68/0.69秒。RSA-2048与P-256互通、旧Ed25519保留及显式原生QUIC客户端也通过，默认Chrome不兼容组合仍拒绝。恢复前完整备份登记与后续混合保留的新测试在静态/普通Go/race执行通过。

独立自然续期门槛 `TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess` 在候选1.14.3实际601.56秒通过：PID9490保持；序列号变化，到期从`2026-10-23 05:30:59 UTC`延长至`05:40:59 UTC`，账户密钥/代理认证保持；续期前后实际HTTPS与序号UDP通过。没有缩短ticker、发信号、强制签发或重启。普通套件对此长测明确SKIP，由该单独门槛补足；这不是贯穿全程的同一条活跃连接证据，不宣称所有连接零中断。

三项失败的具体范围与修订：

- `device-candidate`：Mihomo1.19.30有序主备测试，在停止主入口后，备用单次健康返回503/0ms；同轮静态/普通Go/race和candidate-core中同项实际通过。固定上游会把成功但不足1ms的请求截成0，API拒绝0；旧日志不足以唯一确定此次503原因。只为受控健康目标加入可取消5ms等待与实际命中计数，不重试，原200/正延迟/选中出口/TCP/UDP/全部停机不可达断言保留。
- 两个安装器套件都遇到旧测试直接读取`node.certificate`的KeyError；schema6实际已保存稳定`certificate_id`。修订改为核对唯一匹配资源，保留ACME模式、域名、协议、菜单/安装断言，并增加ID格式和邮箱断言。
- `installer-alpine`还包含原来不支持Alpine的host-OS断言失败；这项仍须保留，不能通过改识别或跳过断言制造原生安装通过。新夹具修订不改变这个平台边界。

## 最后收口代码与定向复核

源码 `70a664fd53d44e188e79761a1962c251ea21a2fa` 在上述完整源码之后，补齐只读状态只认当前资源/CA路径、单独父路径`..`拒绝、挑战端口真实进程/inode所有权、显式导入/更新完整证书路径校验，以及五种新ACME配置的两版核心解析入口。旧备份/State不因本机信任库变化而拒绝读取。两处上述回归夹具亦在此提交修订。`targeted4`只冻结准备过，未启动，不计实测。

`targeted5`使用独立17项收口门槛，源码与工具摘要重新冻结，单VM、无外部网卡，但本轮未闭合：会话中断后，日志停在`final-build-probe`，没有RUN_END、完整收集或原runner最终回执。14项已有退出（12项0、2项非零）：相关静态/Go/race/vet、两核心签发/迁移/解析、候选主备20次及Ubuntu识别夹具33项确有各自退出0；默认核心主备组前15次通过、第16次超时，组退出2，Alpine原生套件除既有平台断言外还有子进程超时。不能把这些部分结果写成17项通过。独立中断审计1466项摘要吻合，原件保留。

只读Windows System事件确认本轮期间13:30:53合盖待机、14:00:54附近休眠、14:25:17唤醒，之后又待机/休眠，18:39:42恢复（Asia/Shanghai）；同轮3分钟测试的超时栈显示单项已运行30分1秒，35秒安装器子进程也超时。宿主暂停确实发生，但不由此推断每个失败的唯一原因，也没有修改电源策略或放宽测试时限。原始部分日志和独立中断审计保留，最终复核使用原17项命令另开`targeted6`，测试代码仍是70a664f，文档记录单独提交。

### targeted6 最终闭合：16/17，唯一未支持平台负例保留

准确冻结提交`730bdd490944977fa54438b0dc147b61646945a4`仅比70a664f增加上一段实测记录，生产和测试代码相同。实际命令：

```text
python work/prepare-batch07-final.py targeted6 --commit 730bdd490944977fa54438b0dc147b61646945a4
python work/run-batch07-final-verify.py targeted6 --prepare-only
python work/run-batch07-final-verify.py targeted6 --launch
```

原17项/原时限不变，16项退出0，只有`installer-alpine`为1；该套件32/33通过，唯一失败是原有“不支持Alpine”的host-OS断言。Ubuntu24.04识别材料夹具33/33通过，单独host-read测试通过，不等于真实Ubuntu/systemd宿主安装。无unexpected failure、无超时，QEMU0、RUN_END/配对/严格提取/complete均true，guest自有网络清理读回通过。原串口SHA256 `65d7c708247d146ec5fe4e710ac1f8cf6f82b2fe0baf8c02cd431bcec1e12041`，18项证据保留；没有将这轮写成17项全部通过。

| 本轮实际门槛 | 结果与具体证据 |
| --- | --- |
| 相关node/CLI静态测试；`go test -p 1 -v -count=1 -timeout=10m ./internal/node -run 'Certificate\|Migration\|SnapshotStopProof\|HY2Ed25519'`，同命令`-race`，`go vet ./...` | 全0；完整链缺中间件/缺私有根拒绝、旧QNBK1/2仍可读、状态归属、`..`目录条目、资产/State中断恢复与保留保护实际执行 |
| 实际IPv4/default/IPv6挑战监听与`/proc`归属 | 全通过，IPv6未跳过；核心停止时外部占用、inode缺失/快照不完整/命名空间未核验、旧配置无此端口、同PID无关具体地址均拒绝；真实自有旧通配监听允许延期，关闭后空闲端口通过 |
| 官方1.14.0及1.14.3：HTTP-01、TLS-ALPN、alidns/cloudflare/acmedns | 两版各5个生产生成器配置均实际`check`通过；只代表解析，不冒充后4种挑战的签发或传播验收 |
| 两核心真实受控CA、完整账户存储迁移与PEM迁移 | 签发/恢复后HY2 HTTPS和序号UDP、真实到期启动续期、CA拒绝/错误端口失败通过；RSA/P-256及显式原生QUIC Ed25519实际连接，默认Chrome不兼容仍拒绝 |
| `/node.static -test.run '^TestDeviceMihomoOrderedFallbackRealPrimaryFailure$' -test.count=20 -test.v -test.timeout=3m`，分别指定两版官方核心 | 各20/20，合计40次通过；实际HTTPS目标命中、主入口停机后备份选择、TCP与UDP、全部停机无direct回落均保留，不重试/不放宽断言 |
| `python3 scripts/test-installer.py`及单独host-read，原生Alpine/Ubuntu识别材料分别执行 | 只保留上述原生Alpine1项平台断言；schema6资源引用/域名/邮箱/协议/安装行为断言通过，没有KeyError或子进程超时 |
| `bash scripts/build.sh`、`bash scripts/build-probe.sh`、`python3 scripts/check-build.py` | 全0；管理器Linux amd64/arm64、qingprobe Linux amd64/arm64及Windows amd64五包归档契约通过，交叉构建不算原生ARM运行 |

本轮是对70a664f收口代码的相关复核，不是重跑36项full1；全项目Go/race、发行保护、netem、持续TCP与自然后台续期的准确源码仍是上文b0cca6e。交付最后只补文档，不将旧源码结果改记成最终HEAD整套通过。审查材料同时保留baseline、targeted1–6、full1及native1–3的成功、失败、准备未运行和中断；源码包不包含生产State、证书/ACME私钥目录或外部工具。

独立收集审计确认本轮18份证据与严格Base64/gzip/tar全部一致，0个SKIP；冻结审计另核对679源码及输入。最终审计`batch07-targeted6-final-independent-audit-receipt.json`摘要`3b934abf8f5f1acbee2c088b17840e2bf83b3f3f13e6178c9d547b66bc84edaf`，明确`all_checks_passed=false`以保留Alpine非零；细项审计`batch07-targeted6-test-detail-independent-audit-receipt.json`摘要`4f515256c1d2a47188ab2f508a91e6fe922ad4cc3d49b8cc8702f2ea8164dc2a`。

## 环境未提供的范围

尚无域名/DNS凭据、公共CA staging、真实systemd宿主、原生ARM64、手机/桌面GUI或生产机器迁移，不宣称这些通过。真实CA验收使用本机受控Pebble，未在公共生产CA反复签发；三DNS提供者与TLS-ALPN的配置解析不等于真实服务商签发、端口转发和续期成功。服务账户权限、真实核心进程停止/Wait、mock的systemd/cgroup异常和真实systemd生命周期分别报告；当前没有后者。受控CA/回环成功也不代表公网DNS/NAT切换或客户端UI验收。

## 后续批次复用的接口

- 持久 State 为 schema6，`DecodeState` / `MigrateState` 负责1–5内存迁移；`CanonicalCertificates` 负责旧调用方投影与普通节点编辑独立复制，`ResolveCertificates` 给各节点独立内存副本。不要直接把节点投影当成新的共享资源覆盖。
- `CertificateResource` 的稳定 ID 与 `Node.CertificateID` 绑定；显式共享更新经 `PutCertificateResource`，引用删除由 `RemoveCertificateResource` 阻止。新协议若要复用证书，必须单独接入实际协议校验与渲染，当前绑定入口只允许 HY2。
- `ValidateForRestore` 只延后目标外部 file 引用的实际读取，其余模型/认证/PEM/ACME 结构仍验证；它不表示可运行。导入和 `Store.Apply`、后台 `Check` 继续执行文件、日期、权限与候选核心校验。sing-box 特定 Ed/Chrome 限制由 `ValidateHY2ClientCertificate` 检查，不能放回通用服务端/备份校验。
- 证书私有请求 version1，与 State schema分开；`InspectCertificateResource` 和 `SystemBackend.InspectCertificateJournal` 为只读证据，缺失事件留未知，不能借查询主动签发。新的 ACME provider 只生成被启用节点引用的资源；legacy无显式设置保留旧内联配置字节和存储路径。
- `PutCertificateResource` 的显式导入/更新额外验证完整服务器证书路径（本机根或明确附带自签根）；不要将该依赖当前信任库的检查搬进旧格式解码/备份读取。相邻签名校验本身不能证明链完整，其他客户端信任仍未知。
- QNBK3 内包 `MigrationVersion=1`、`MigrationManifest.Version=1`；旧 QNBK1/2 继续各自入口。`CaptureMigration` 要求管理锁与可证明的自有写入进程停止，双清单不能替代停止证明；离线后端不能据此复制生产 ACME 运行目录。
- `RestoreMigrationAssets` 和 `RecoverMigrationAssets` 必须在管理锁内调用，目标映射来自本机输入，旧资产先选对再恢复可能启动核心的事务。`MigrationPending` 是普通写路径的保护，不可绕过或自动删记录。订阅恢复授权与 State hook 的“已提交但发布失败”结果继续分开。
- 受管备份索引保护 current 和最近完整恢复点；恢复前自动生成完整包时也必须登记 `complete`，后续普通配置备份不能取消这层保护。包外用户文件与宿主网络参数快照不自动接管或跨机应用。

来源与许可固定记录见 [THIRD_PARTY.md](../THIRD_PARTY.md)。本批没有推送、建立 PR、发布或生产部署；所有这些动作与本地实现、隔离验收及本地提交分开。
