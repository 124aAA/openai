# 第08批持续实施记录：监控、观测与代理凭据到期

本批接续第07批源码，base `df6ae898c5beb00e2b7385d6aa2bd6aca2d1f888`，未发行，默认官方核心仍锁定1.14.0。实现接口与操作边界见 [MONITORING.md](MONITORING.md)。本记录将实现、自动检查、官方核心、真实宿主和用户验收分别记录，不把计划或前批成功当成本批通过。

## 当前实现

- 独立有限监控配置/状态/历史，分信号状态、预算、互斥测试锁、可选有限恢复和通知；默认只观察，定时器仅生成材料。
- 本机带秘密的官方API服务及标准库gRPC-Web只读客户端，生命周期累计差分与连接快照；未知归属/断流/回退明确，不作用户计费或配额。
- schema7真实保存API设置和稳定身份到期计划，旧1–6仅内存兼容并保留原件；精确用户/设备绑定停用、共享阻止、最后用户停节点保身份、一次事务与完成记录防误恢复。
- `monitor run --apply-expiry`为单独显式开关，默认不执行到期；监控目录尚未纳入QNBK3完整资产，发现时明确受限缺项。

## 本批证据状态

| 项目 | 当前记录 |
| --- | --- |
| Linux完整普通Go/race/vet | full1准确8e752238已完成：普通Go/race各7个有测试包退出0，vet退出0；整轮44项中43项0，唯一Alpine安装平台断言保留 |
| 官方1.14.0/1.14.3 API解析/鉴权/传输 | targeted3、full1两版通过；targeted5准确9b6bb79追加真实kill/wait/restart、旧API拒绝、新生命周期基线/缺口与重复计数门槛均通过 |
| 官方核心到期前既有TCP与到期后认证 | targeted3、full1和targeted5两版通过user/device-binding两范围；保存计划保持PID/活跃流，Apply重启断开到期和未到期旧流，新到期认证拒绝、其余新认证通过 |
| 有界引擎、通知与CLI受控故障 | targeted5整轮15/15退出0，含引擎/私有通知/CLI、真实UDP预检和错误凭据负例；控制接收器和服务替身不冒充公网通知或systemd |
| 安装/打包/allowlist回归 | full1保留原生Alpine32/33，支持系统metadata夹具33/33；准确9b6bb79的独立Windows构建5步骤/5包及39项离线发行保护通过，Windows助手version/help/local通过 |
| 真实systemd/MainPID、故障重启、timer生命周期 | 未执行；无systemd的隔离环境结果不能替代 |
| 公共Telegram/webhook、公网客户端、手机GUI、ARM原生 | 未执行 |
| 最新快照修补与最终包 | 91db289的targeted6两项真实失败保留；准确4bd1af9的targeted7窄9项全部0，相关race/vet通过；finalbuild3五步/五包与39项发行保护完成，独立审计通过，SHA见对应段落 |
| 用户实际接受 | 未验收，自动化不能写driver-accepted |

开发期间Windows Go对Linux目标交叉编译、两个独立包的Windows受控测试及vet通过，只证明对应范围。最终Linux证据以如下准确冻结轮次为准。

## 基线与专项实测（2026-10-23）

相关基线从准确base `df6ae898c5beb00e2b7385d6aa2bd6aca2d1f888` 冻结，8项检查全部退出0。静态node/CLI/probe/subscription和候选核心两包真实测试与环境清理实际执行；不是前批成功的转记。

```text
python work/prepare-batch08.py baseline1 --commit df6ae898c5beb00e2b7385d6aa2bd6aca2d1f888
python work/run-batch08.py baseline1 --prepare-only
python work/run-batch08.py baseline1 --launch
python work/prepare-batch08-final.py targeted3 --commit 8e7522380ebb5c14cab5c763ca873df7c58439a3
python work/run-batch08-final.py targeted3 --prepare-only
python work/run-batch08-final.py targeted3 --launch
```

targeted3准确源码 `8e7522380ebb5c14cab5c763ca873df7c58439a3`，14项配对退出均0，QEMU退出0、未超时、RUN_END与安全提取完成。6包测试由Windows Go1.27.2编译为Linux/amd64静态程序，隔离Linux6.18.55实际执行；guest无外部网卡，只建自有测试veth，清理退出0。官方核心1.14.0与1.14.3、Mihomo1.19.30各自有版本/构建标签和摘要材料，未自动改默认版本。

8项新增门槛分别为monitor-engine、core-api-default/candidate、monitor-node/CLI、expiry-core-default/candidate、rendered-api-candidate；另执行4包完整静态测试和环境两项。API真实传输、鉴权拒绝、稳定节点/用户标签和reset在两版官方进程验证；这不是客户端GUI或远端公网测试。普通套件明确跳过的长续期/netem/到期opt-in，由各独立门槛分别负责，不能把SKIP当通过。

到期测试的四个组合均观察到旧连接EOF/reset：本轮Apply至关闭约47–82ms，包含到期与未到期两条既有流；这是本机共享核心替换的观察值，不能推成公网性能保证或无损停用。

targeted3原始串口SHA256 `7e540f4dd896955ade288670369e535616eabb83c70bc08396cc2fa48f89c529`。独立核对1547项摘要，重新生成的准确Git archive逐字节一致、6包ELF静态属性、initramfs输入、严格Base64/gzip/tar及15份解出文件均一致；审计回执 `batch08-targeted3-independent-audit.json` SHA256 `c5bf3a6f829316e5e61afb1f34f56be911ae87bdd46a465896de7b00312f2d8e`。审计证明证据一致性，不替代业务断言。

## 保留的失败与中断

- targeted1冻结 `f9aa5768b7be811241d27ef4b6e4861ddcf37498`：引擎和两版API已退出0；跨地址族监听测试错误要求纯State校验判定未知双栈范围，实际应沿现有真实绑定预检。修订仍断言真实冲突被阻止，没有改变生产端口判定或放宽冲突规则。
- 同轮超时夹具等待未读完POST的请求context，导致测试服务器Close阻塞。root验证自有QEMU身份后停止本轮；原始日志和complete=false回执保留，不计整轮成功。夹具改为先读完请求，再等待取消，保留原测试时限。
- targeted2在冻结准备时因该夹具漏加io导入编译失败，没有启动虚拟机；修复导入后另开targeted3。失败准备材料未覆盖。

## 完整回归

full1冻结同一 `8e7522380ebb5c14cab5c763ca873df7c58439a3`，保留原有命令、断言与时限，并增加第08批门槛。44项全部有配对退出：43项0，唯一 `installer-alpine` 为1；QEMU退出0、未超时、RUN_END/配对/严格提取与complete均为true，unexpected_failures为空。`complete`只表示执行及收集闭合，不能写成44项全过。

```text
python work/prepare-batch08-final.py full1 --commit 8e7522380ebb5c14cab5c763ca873df7c58439a3
python work/run-batch08-final.py full1 --prepare-only
python work/run-batch08-final.py full1 --launch
python work/audit-batch08-full1.py
```

普通Go与race各7个有测试包实际成功，vet、专用用户权限、两版官方核心受控netem与128MiB组、三协议TCP/UDP、Mihomo解析/真实互通/主备与容差缺陷保护、拓扑/图/WireGuard、两架构管理器与三目标助手构建、五包归档契约、39项离线发行保护及3项维护观察器均退出0。受控网络原始JSON/qdisc/资源材料保留；这些结果不表示公网性能或ARM原生执行。普通套件中的SKIP仍为跳过，由各显式门槛另验。

唯一原生Alpine安装器失败为33项中32项成功，`test_online_install_reads_actual_host_os_release_without_overwriting_tag`实际读到 `alpine 3.24.2` 后因不支持的宿主系统拒绝安装。没有放宽该断言或改宿主伪称通过；另行Ubuntu24.04元数据夹具33/33、单项宿主读取夹具1/1只证明识别路径，不代表Ubuntu/apt/systemd真机验收。

候选1.14.3的自然后台ACME续期另实际等待601.23秒：`TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess`中核心PID10074保持，证书序列 `6503135872866076824` → `7229581276326203358`，有效期由2026-10-23 12:27:07UTC延至12:37:07UTC；原账户密钥及代理认证的HTTPS/UDP在前后可用。没有ticker覆盖、信号、强制签发或进程重启。这是本轮受控CA进程证据，不等于公共CA、真实systemd或所有版本的长期续期保证。

原始串口SHA256 `a1f4cb4e0fb1e2f46306d2f2061e983e6bc6c586fd9586c74ed1acc2958bce11`。独立审计核930项文件SHA，718个冻结源文件、814项输入manifest、6包静态测试程序、735个initramfs保护输入及97份证据一致，准确Git archive逐字节相同；回执 `batch08-full1-independent-audit.json` SHA256 `89fb1f657f5839dda855233200afb60b9c10948cbbace99a9a3cb2608bfbf84e`。该轮导出证据保留构建/归档检查日志，未导出五个成品包供host重哈希；后续独立五包构建另记。

## 真实重启计数、UDP与错误凭据补验：targeted5

准确源码 `9b6bb79bc226cf7244ddca0896fe6fcf4a5d5a13` 的targeted5实际15/15项退出0；QEMU0、未超时、RUN_END/配对/提取/complete均true，unexpected_failures为空。复现入口保持独立专项命令和时限：

```text
python work/prepare-batch08-final.py targeted5 --commit 9b6bb79bc226cf7244ddca0896fe6fcf4a5d5a13
python work/run-batch08-udp.py targeted5 --prepare-only
python work/run-batch08-udp.py targeted5 --launch
```

`TestOfficialCoreGRPCWebObservation`两版在同端口执行真实kill/wait/restart：1.14.0 PID598→608，StartedAt `1792759392096`→`1792759392143`；1.14.3 PID639→649，StartedAt `1792759392300`→`1792759392343`。进程死亡期间API拒绝；较低计数在新生命周期建立baseline/reset/gap且delta为0，旧连接历史消失，新生命周期下载差分63645字节且重复采样不增加。它补足真实重启，不能只用同进程重连或伪造epoch测试替代。

`TestOfficialMonitorUDPPreflightThroughRealCore`默认1.14.0与单列候选1.14.3实际通过：HTTPS成功且出口不支持UDP时保留 `failed/egress_does_not_support_udp`，预算128字节时保留 `unknown/udp_payload_budget_too_small`，均无UDP载荷发出。错误的内存远程凭据使代理TCP失败，而独立直连目标健康；认证保持未知/不可分离，UDP不支持状态保留，原远端PID和保存的密码不变。修复防止成功TCP结果合并覆盖UDP预检；没有把目标健康冒充代理认证成功。

该轮串口SHA256 `bf9d8743a3a017943e342a82d1a06b10fd58c76773951d7995ca88b4f7f5d15c`；16份解出证据和每项SHA见 `batch08-targeted5-run-receipt.json`。full1全量race/vet属于8e752238；targeted5是9b6bb79的专项/静态实测，不能宣称9b6bb79重跑了全部44项或全量race。

## 9b6bb79独立五包构建与Windows助手（历史已验范围）

该轮包只对应9b6bb79，尚未包含后续快照修补，不能当4bd1af9的最终包。`batch08-finalbuild-receipt.json`绑定9b6bb79，源码ZIP SHA256 `5c471eabf227751fbf51130767a1743da72a54bd289619e6c27b22eceb133a98`。在独立冻结目录使用Windows Go1.27.2，依次执行Linux目标 `go vet ./...`、`bash scripts/build.sh`、`bash scripts/build-probe.sh`、`python scripts/check-build.py`、`python scripts/test-release.py`，五步退出0，离线发行保护39/39。准确工具路径/命令/日志SHA与七项output SHA在原构建回执，未安装或发布。复核命令为 `python work/audit-batch08-finalbuild.py`，审计脚本拒绝覆盖既有结果。

独立审计747项SHA匹配，719个原始源文件与准确Git archive逐字节一致；2管理包各30文件、3助手包各19文件，内外校验、明确allowlist、普通成员/权限、源码文档及每包6段Go/vendor许可一致。四个Linux ELF64的amd64/arm64机器类型正确且无PT_INTERP/PT_DYNAMIC；Windows PE32+为amd64，导入kernel32.dll，不声称没有操作系统动态依赖。五包字节本次真实留存并逐包核对，区别于full1只导出构建日志。

验证过的Windows ZIP只提取 `qingprobe.exe`到新自有目录，实际 `version`、`help`、`local --out`三项退出0；版本0.2.8/source，local完成、目标为空、无UDP、载荷0，CPU/RSS不可读值保持未知。它只证明Windows助手三个本机命令，不计qingnode监控服务、网络代理、Android/iOS/UI或ARM原生运行。

审计回执 `batch08-finalbuild-independent-audit.json` SHA256 `c1bc715f3fd72c715f83d0b182581a45ebf6933e5583f79ae92edd03ac4de6b6`。首轮审计因构建生成两个Python `__pycache__`而保守停止helper执行；失败JSON/脚本保留，后续只将这两个精确文件名和SHA独立列为构建缓存，719个原始源码匹配要求未放宽。

## 快照并发补丁：targeted6失败与targeted7修复闭合

后续源码 `91db289911a06344f397c63c8848f3bc2048cedb`把并发monitor入口探测改为使用同一轮不可变State快照构造Profile，避免再次非阻塞取得管理锁或读入另一轮配置；主动probe仍由管理锁读取自己的快照。该版完成clean冻结、6包Linux静态交叉编译与host actionlint后，窄Linux targeted6实际9项中7项退出0、`static-cli`与`snapshot-monitor-race`各退出1；QEMU0、未超时、RUN_END/配对/提取/complete均true，unexpected_failures明确保留这两项。串口SHA256 `beb19be014e6b9c0505d2686aa7e77dff32b2acd3ad6e3728b0e1eb112abd560`，10份证据见 `batch08-targeted6-run-receipt.json`。complete不能抹去这次真实功能回归。

实际原因是抽取Profile构造helper时错误地把旧direct路径合法的空服务端路径摘要当成异常，返回空Profile却没有错误；并发测试发现配置/路径身份不一致，原 `TestProbeProfilePreservesStateServiceAndManualHistory`也因空身份失败。修复保留direct路径的完整v1 Profile，只在真实路径摘要存在时升级携带摘要；没有删除或放宽原断言。修复源码为 `4bd1af90bc7e41bee9d038244992a72e54ef5c64`，保留6原始失败材料，另开targeted7。

91db289的hostfinalbuild2虽有5步骤退出0，也只能证明该错误版本可编译/打包，不能宣称它功能正确或当成最终交付包。修复后的准确 `4bd1af90bc7e41bee9d038244992a72e54ef5c64` 另开targeted7，实际9/9项退出0：environment、static-cli、static-probe、snapshot-monitor-race、go-vet、core-api-default/candidate、monitor-udp-candidate和environment-cleanup。QEMU0、未超时、RUN_END/配对/严格提取/complete完整，unexpected_failures为空。

```text
python work/prepare-batch08-final.py targeted7 --commit 4bd1af90bc7e41bee9d038244992a72e54ef5c64
python work/run-batch08-finish.py targeted7 --prepare-only
python work/run-batch08-finish.py targeted7 --launch
```

新增并发回归在真实管理锁仍持有时同时运行8个worker，所有Profile配置/节点/路径身份一致，内存State、保存代和字节不变；原文件读取wrapper仍拒绝busy锁、transaction/uninstall待恢复记录，不修复或消费记录。targeted6失败的五项原CLI断言在7完整静态CLI中全部通过：端点独立端口/导出、HY2私有Profile规范摘要、内部路径且不泄露落地凭据、快照并发、Profile不改State/服务/手工历史。Linux `go test -race -count=1 -v -timeout=5m ./cmd/qingnode -run 'TestProbeSnapshot|TestProbeProfilePreserves|TestMonitor'`和 `go vet ./...`实际退出0；两版真实API与候选UDP门槛另退出0。

该轮串口SHA256 `c11cc46885560bf86c26cfac1bc23723ceee30b53d772e33c21cdc890e673123`；10份提取证据、输入与每项退出见 `batch08-targeted7-run-receipt.json`。独立核850项文件摘要、720份源码、严格Base64/gzip校验与安全tar提取均一致；审计回执 `batch08-targeted7-independent-audit.json` SHA256 `11004f93909e857a8b0edfb45903fcb7366d7ada7d52ade023c34c1f7e4559ae`。全44项及全量race仍属于8e752238，4bd1af9完成的是上述相关补验，并未宣称最终源码重跑全部44项。

## 4bd1af9最终独立五包：finalbuild3

`python work/build-batch08-final3.py`在独立冻结目录执行，准确源码为4bd1af9，源ZIP SHA256 `f5a0242f6e133ed36d741ba795342eb66fe5fe2aa5b16bc1283f0ee366bbed06`。原五步Linux目标vet、管理器构建、助手构建、实际archive contract和离线release tests全部退出0，管理器两包/助手三包实际生成，39项离线发行保护通过；`batch08-finalbuild3-receipt.json`记录工具、五日志和内外清单SHA，未安装或发布。

| 实际成品包 | 构建回执SHA256 |
| --- | --- |
| qingnode-0.2.8-linux-amd64.tar.gz | `a6d593893fb4bd76303e35c967057a8e3083634c2f41895e21afe80db9c52e47` |
| qingnode-0.2.8-linux-arm64.tar.gz | `d35536c1b9951f975253d14207c92ccd76623472e9bc3dab413021c124752dc1` |
| qingprobe-0.2.8-linux-amd64.tar.gz | `87202aa522b2a398f13984724d2ea9f5a9a8278258864ee705a5ab1e448806db` |
| qingprobe-0.2.8-linux-arm64.tar.gz | `250531705b959b2ebd536594168f7865d0758133ed68deb8c66ba505d103b808` |
| qingprobe-0.2.8-windows-amd64.zip | `e6d833f09230cde4ed9874203328cda915cd01c65e645aa211f75c155c612cc1` |

本段是最终实现4bd1af9的实际构建范围；9b6的finalbuild和91db的build2仍作为历史材料保留。独立核749项摘要、720份源文件、五包内外校验/明确成员/权限与六段许可全部一致，四个Linux ELF无动态解释器且架构正确；最终Windows助手的version/help/local实际退出0，无目标和UDP载荷。审计回执 `batch08-finalbuild3-independent-audit.json` SHA256 `d6e3d3f4e6986a6042b5ca9471ec4cc1034df88aacc0cba6d01a1afc6c6b0830`。交叉构建不计ARM原生运行，五包构建通过也不代替真实systemd、公网或UI验收。

收尾提交仅更新文档，保持4bd1af9的Go/安装器/工作流源码不变；上述成品包内文档属于4bd1af9冻结时点，不能用旧包SHA声称包含了后来补齐的测试记录。最终本地源码审查包另带最新文档、准确Git提交/bundle/补丁、各轮结果与失败材料，不包含发行二进制或生产秘密，也未推送/发布/部署。

## 迁移恢复与后续接入接口

schema7的API设置和到期计划属于State，沿既有配置恢复/候选验证保留稳定身份；已到期计划不会因查询自行执行，完成记录仍保护最后保留凭据。QNBK3的证书/账户与订阅权限恢复继续使用资产清单、私有暂存和显式恢复事务。独立monitor私有计划、通知授权和历史目前未打包：资产盘点发现该目录即明确列缺项，`backup --full`须 `--allow-incomplete`，恢复不能宣称带回监控策略/秘密。目标机需重新核对路径、权限、configure和timer，不能直接沿用来源机的自动恢复授权。

后续接入保留有限接口边界：`Collector`负责观察、`ActionVerifier`负责经策略确认的动作/复验，核心API以固定公开读契约和精确标签映射提供观测；到期helper只返回完整候选，调用者持锁单次提交。新增探测、通知或迁移资产须分别补预算、身份、权限、版本与真实执行证据，不从“已有API”推导持久用户账本/硬配额。详细命令和关闭/撤回见 [MONITORING.md](MONITORING.md)。

撤回自动动作先执行 `qingnode monitor disable --yes`，已手工安装timer时另执行 `systemctl disable --now qingnode-monitor.timer`。API可经 `monitor api disable --preview` 后显式 `--yes`关闭，属于运行配置变更。节点故障使用当前管理器的显式 `recover`或`rollback`；完整迁移中断使用 `restore --recover-migration --yes`，不删journal绕过。当前restore/rollback仍写schema7；旧管理器降级须使用保留的旧格式原件及匹配二进制，不能删新字段或改schema伪兼容。已移除的凭据/设备绑定需从原恢复材料明确恢复，删除到期计划不会自动复活它们。

## 重要边界

重启共享核心会影响所有既有连接；不宣称热更新/无损停用。动作后仅本机零载荷复验不能证明完整认证/TCP/UDP恢复，下一正常轮另验。核心API全局累计只在本生命周期内，事件没有可靠序号和持久用户账本；不承诺配额或计费，不把未知写成零。下载令牌失效与代理认证失效分开。默认监控不Apply、不Recover、不改节点，显式到期执行仍遵守事务/共享保护与时钟边界。
