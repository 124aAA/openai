# 第10批持续实施记录：平台安装与维护

当前分支 `batch/10-platform-adaptation`；基线准确提交 `da665aaa04c83290d3537b6dd203758f3d0666cf`。当前运行源码准确提交为 `d94d03a33546eddd9caa6ba9c9e8592d2f332d1f`（source18）；native18的15项隔离Linux检查、build18的5项构建检查和同源三平台完整维护复验均已通过。三平台各有新一轮准确回执，不拿旧提交的成功覆盖新改动。本批保留第01–09批节点ID、用户凭据、证书、出口、设备和协议语义。以下记录区分源码实现、编译、模拟故障、官方核心传输、真实init服务与公网/原生架构证据。未执行远程推送、PR、正式发布或生产部署；main/tag工作流仍可能触发正式发行。

## 已实现的内容

| 用户目标 | 本批实现 | 验收边界 |
| --- | --- | --- |
| A：本机能力 | `HostCapabilities` 补发行版/版本、架构、PID1、init工具与控制器、包管理、SELinux、防火墙、虚拟化；复用原内存、路径、UDP、IPv6、TUN和有效权限结果 | 查询不安装包或启动服务；工具存在不算服务可用，本机回环不算公网入口通过 |
| B：发行版与架构 | 保持Debian12/13、Ubuntu22.04/24.04/26.04候选；新增Rocky9系和Alpine3.24系；本批选Rocky9.8、Alpine3.24.2、Ubuntu24.04的amd64 VM | 没有该版本实际运行证据时只记候选；arm64交叉编译不算原生运行 |
| C/D：小边界与生命周期 | `internal/platform` 的包计划、服务管理与定义渲染；Bash只在引导边界选包/服务；监控调度复用原计划；防火墙保留UFW并增加firewalld | 不建立插件框架，不改变协议数据面；实际init不可用时明确拒绝托管 |
| E：OpenRC与权限 | 标准openrc-run/supervise-daemon、独立supervisor/child PID、专用非root账户、受管日志和精确runlevel；core低端口使用监督进程的ambient权限及no_new_privs | 不把代理改root；订阅不授绑定低端口权限；有效权限、443流量、监督与短停证明须实测 |
| F：Rocky宿主策略 | 保留SELinux状态，仅restorecon项目路径；可选firewalld的family/address/port/network rich-rule运行/持久分开写入并读回，带私有所有权与恢复材料 | 不关闭SELinux/防火墙，不执行全局reload/flush；规则列表通过不等于外部过滤链路通过 |
| G/H：依赖与官方核心 | 明确apt/dnf/apk包名，缺失依赖才安装，不运行系统upgrade；固定核心摘要、ELF架构/解释器、版本与构建标签逐层检查，失败保留旧core目录 | 管理器静态不代表core静态；Alpine兼容库仍需真实执行/解析/传输证据 |
| I：容器限制 | 显示init、TUN、有效权限、内存、IPv6等各自结果 | 缺TUN不阻挡不需要TUN的节点；不承诺修改LXC/OpenVZ宿主限制 |
| J：归属、事务与恢复 | 安装/卸载和独立附属服务在长时间命令前后重核文件、权限、来源及恢复材料；卸载首次查询前保存内存指纹；完整卸载拒绝辅助目录未知成员；OpenRC禁用按实际runlevel逐项移除并读回 | 外部修改不被旧副本覆盖，恢复材料保留；不宣称能抵御另一root在最后本地检查与替换之间的同时写入 |
| K：持续验证 | 保留原CI/发行/systemd门禁，新增容器只读能力边界与附属/防火墙脚本安全测试；提供统一丢弃式VM安装维护验收入口 | 容器、模拟、VM、原生ARM、公网证据分别登记 |

详细用法与候选矩阵见[PLATFORMS.md](PLATFORMS.md)。证书与完整迁移继续使用[既有机制](MIGRATION.md)，未另造加密格式或引入面板、Docker、数据库。

## 已运行的基线与中间回归

所有运行从准确Git提交归档；编译回执记录源码归档及测试二进制摘要。外层 `work/` 保存run-plan、compile-receipt、run-receipt及提取证据，失败轮次不覆盖。以下结果只属于表中的准确提交，不自动覆盖后续修复。

| 运行 | 准确提交 | 实际结果 | 解释与后续修复 |
| --- | --- | --- | --- |
| baseline1 | `da665aaa04c83290d3537b6dd203758f3d0666cf` | 隔离Linux QEMU 8/8退出0；QEMU0、结束标记、检查配对与证据提取完整 | 修改前基线；不能据此声称新增平台通过 |
| targeted1 | `8248f7869479f09535ffc02cf13031e6c236e279` | 12项中9项退出0；static-cli、installer-native、shellcheck失败；运行材料完整 | 旧CLI测试靠PATH假服务，新探测正确拒绝假init；夹具缺Go导致安装器断言未执行；Shellcheck检出3处条件链及trap变量问题。均保留原断言并修复测试接线/源码 |
| targeted2 | `30dd556305771b9231bba031a089e3754926864a` | 12项中11项退出0；平台、完整static-node/CLI/probe/subscription、发行、Shellcheck和官方1.14.0/1.14.3三协议检查均退出0；安装器41项中40项通过 | 唯一安装器失败是真实源码缺陷：apt update失败后仍执行install。已改为前一步成功才继续，补未知服务状态与归属测试；后来focused13及native18另行重新通过，未改写本轮失败 |
| finalbuild1 | `8248f7869479f09535ffc02cf13031e6c236e279` | 五项退出0 | Linux目标vet、两架构manager构建、probe构建、归档契约、离线发行测试 |
| finalbuild2 | `30dd556305771b9231bba031a089e3754926864a` | 同上五项退出0 | 只算该准确提交的构建/发行检查 |
| finalbuild3 | `4fea6829f2e7a5ff20376265135bbd9fcd01777b` | 同上五项退出0 | 不算最终代码的VM或原生ARM验收 |

baseline1原始串口SHA256：`449861fd71413c0dca86ec26564de1a3748e084aa44e06b2cfa0e0fc903b327e`。targeted1串口SHA256：`102633b723d0d55de9c605c8f396dc7c7682d5d68e5ce9b70001ca5470245577`。targeted2串口SHA256：`c6ba11a5c63b2305df22e0d597f3670cbaf39f024faa1706e407712355e8546c`。原始日志可能包含丢弃式夹具凭据；交付优先使用脱敏摘要，私有现场不当公共日志发布。

已实际执行的入口包括：

```text
python prepare-batch10.py baseline1 --commit da665aaa04c83290d3537b6dd203758f3d0666cf
python run-batch10.py baseline1 --prepare-only
python run-batch10.py baseline1 --launch
python prepare-batch10-targeted.py targeted2 --commit 30dd556305771b9231bba031a089e3754926864a
python run-batch10-targeted2.py targeted2 --prepare-only
python run-batch10-targeted2.py targeted2 --launch
python build-batch10.py --prefix batch10-targeted3 --output-prefix batch10-finalbuild3
```

这些外层封装在guest实际运行相应Go测试二进制、`python3 scripts/test-installer.py`、`python3 scripts/test-release.py`、`shellcheck install.sh scripts/*.sh`及固定官方核心。精确命令、工具/源码摘要、超时和退出码以对应回执为准；编译或配置解析不替代真实服务与传输。

## 真实平台试验发现的问题

Alpine采用官方3.24.2根文件系统和捕获的v3.24签名包，实际OpenRC为0.63.2-r0；原密钥验证包，不用allow-untrusted。真实OpenRC作为PID1，在有扩展属性的自有ext4根盘运行，宿主文件系统与网络不被改动。alpine1–7的QEMU参数、离线仓库、拆分依赖、版本收据、BusyBox命令及文本换行等问题分别保留失败材料；这些轮次不能当生命周期通过。

alpine8/9进一步暴露产品低端口方案缺陷：仅给官方core文件设置filecap后，gcompat再次exec musl，非root UID100的有效绑定权限丢失。在内核低端口阈值1024未改时，443真实绑定被拒绝。旧方案已停止采用；不能把getcap读回成功写成可绑定端口。

独立的 `alpine-cap2` 方案试验使用无filecap的官方core和OpenRC `capabilities="^cap_net_bind_service"`，真实musl进程的CapInh/Prm/Eff/Amb均为0x400、UID100、阈值1024，443受控TCP与UDP传输通过，停止后PID消失。它没有生产State，且NoNewPrivs=0、CapBnd保留继承集合；回执明确experiment_only=true和complete_and_passed=false。产品随后另加no_new_privs及实际监督程序选项检查，最终在alpine15重新验收；不能将这份独立试验本身补成产品成功。

Alpine10还暴露服务start_pre的实际调用错误：监督程序帮助选项必须带服务名，遗漏时在fork核心前失败。固定源码核对后修为带实际服务名的帮助探测。这不是ambient权限方案已经失败的证据；该失败轮次不算通过，后来由alpine15另行通过完整流程。

Ubuntu24.04官方cloud image已核签名及SHA，实际systemd PID1。ubuntu1暴露发行包Windows CRLF被保留的问题；构建封装已改为确定的LF字节。ubuntu2在测试器把程序放进noexec的/run时退出126；这是测试器路径问题，改用可执行的受控目录，不通过改宿主挂载选项绕过。两轮原镜像摘要均保持不变。ubuntu3进一步实际通过产品安装和check，之后持续流夹具用管理器status竞争同一State锁，导致改名时验收失败；已将夹具观察改用init只读接口。这个测试器故障不算维护无中断验收通过；ubuntu4修复观察器后继续暴露了下述监控控制锁问题，最终ubuntu5才通过完整流程。

Rocky9.8官方镜像同样核对签名与SHA；准备镜像不算SELinux、firewalld或安装成功。Ubuntu、Rocky基盘只读，运行写入独立受管overlay。ubuntu4/rocky3均实际走过安装、传输、升级回退等步骤，但监控oneshot（运行一轮便结束的服务）启动失败：附属控制命令拿着State锁等待服务，而服务自身也要读State。后来把附属生命周期锁与State锁分开，在启动前结束State检查，保留完整定义归属校验；最终普通平台流程见下一节。

Alpine11在安装看似完成后挂住，授权终止该自有VM，保留原盘、串口及中断回执，不当作通过。alpine12的90秒诊断器先后写同一个快照文件，丢失了超时前视图；这个诊断器疏漏已明确记录，不能用超时后进程表证明原因。alpine13改为分文件保留，超时前实际证明：安装器已经退出，OpenRC监督进程仍持有初始化stderr异步tee管道的fd63，孤儿tee又持有外层脱敏器写端，因此脱敏器一直等不到结束。真实核心已经是UID100、musl加载器、有效绑定权限0x400、NoNewPrivs=1。修复去掉初始化stderr的后台tee，并阻止子命令继承Bash的fd9安装锁；Go手动打开的锁补O_CLOEXEC（执行别的程序时自动关闭），附加真实子进程描述符回归。

Alpine14因此通过非root443持续TCP和UDP，新增HY2证书流量检查却在读取/proc的安全上下文时得到OSError。无LSM安全模块的Alpine可能有该路径却返回EINVAL；这项只读诊断不应冒充TLS失败。source12将它明确记为不可用，并记录检查步骤及错误编号。alpine15在相同生产Go和安装器下通过完整HY2与生命周期。外层超时始终另记失败；还补了验收入口SIGTERM/INT的非零退出，避免只有EXIT陷阱写下含糊的0。

native12基于source12计划执行16项回归，但安装器和Go测试分别退出1，随后在race阶段遇执行宿主工具中断；进程消失、没有END，另存 `batch10-targeted12-interruption-receipt.json`，不伪造完整run-receipt。安装器48项里，6个SIGTERM故障断言揭示安装器自身尚未把TERM/INT转入原恢复流程，另3项是早期init拒绝可在调用任何模拟命令前结束、夹具却假定命令日志必存在。`c7b8d3f0e7541b87e3437f6207a59eb445b847e0`补信号陷阱和日志缺失夹具处理，保留恢复断言；focused13重新实际执行48项安装器测试（含6个SIGTERM场景）全部通过。Go/受控ACME问题另行核查，不能用安装器定向通过代替全量Go或race通过。

交付核对还发现三份早先普通VM的 `capabilities.json` 中发行版和版本为空：安全读取拒绝了系统标准 `/etc/os-release` 符号链接。普通安装维护与流量结果仍有效，但这些报告不能证明Host发行版识别正确。`b024d58a896e18f3749fb121c408d1580ac5379c`仅允许标准 `/usr/lib/os-release` 别名及缺失时的回退，继续限制大小、拒绝其它链接目标；补5个正常与恶意路径用例，并在真实验收入口核对实际ID、VERSION_ID和init控制器。后来Ubuntu/Rocky的boot4、Alpine的boot5均用这个准确提交实际两次启动，Host字段与原系统一致；不修改旧报告空字段，也不把后来的修复倒记为旧轮次通过。

原生ARM64、真实公网入口、手机/桌面GUI、跨机器完整ACME迁移、附属服务跨重启及长期运行仍需独立证据。核心重启自启由后述独立双启动流程证明，不能从普通安装维护流程推定。

## 已完成的平台轮次与剩余验收

普通三平台流程使用的修复提交为 `713c9f84e07f73f81b6084d5d0e5170577079aec`（targeted11/finalbuild11）。Ubuntu5和Rocky4实际使用这个准确提交。Alpine15使用 `086f23ee73a2ee8e779c322ef91fe041b153e2cd`（targeted12/finalbuild12）：对11的差异仅为TLS测试器的缺失LSM诊断、对应测试，以及验收入口取消退出码；`cmd/`、`internal/`、`install.sh`、依赖均未改变。外层 `batch10-vm/final-platform-evidence-audit.json` 验证这些来源差异和三份普通VM回执，不把两个提交混成同一次运行。后续source13的安装器信号修复、source14的Host读取修复及其定向/构建结果单列；早先VM成功不自动覆盖后续差异。

| 最终检查 | 本批实际结果与边界 |
| --- | --- |
| Ubuntu24.04.5 amd64 / systemd，ubuntu5 | source11完整流程退出0；原基盘摘要未变；安装、SS2022低443持续同连接/PID与TCP/UDP、重装、停止/自启保持、备份恢复、核心1.14.3切换/check及回退、移除重装、最终卸载、外部数据保留均通过 |
| Alpine3.24.2 amd64 / OpenRC0.63.2-r0，alpine15 | source12完整流程退出0；签名包、真实PID1、独立ext4、结束标记及证据提取全部通过；受控入口94.03秒，无超时。两版官方核心musl环境version/check分别退出0，完整普通流程同上 |
| Rocky9.8 amd64 / systemd，rocky4 | source11完整流程退出0，原基盘摘要未变；全程SELinux Enforcing。实际核心UID994、安全域unconfined_service_t；仅使用系统已有标签，没有关闭或放宽SELinux |
| 受管证书及HY2真实流量 | 三平台均由真正非root受管核心读取导入PEM，监听UDP444；私有CA验证TCP、3个带序号UDP往返、HTTPS响应168字节，错误代理证书名称被拒绝且目标未收到请求。没有insecure绕过、没有公有CA；清理后State原字节一致 |
| 实际运行权限 | Ubuntu UID999、Rocky UID994、Alpine UID100；三平台SS端口443、内核低端口阈值1024。Alpine真实exe为musl加载器，CapInh/Prm/Eff/Amb为0x400且NoNewPrivs=1；bounding集合仍继承，未声称只剩一位 |
| 订阅、证书目录与周期任务 | 三平台auxiliary.json均通过5项真实检查：服务UID证书目录读写、订阅专用UID读快照但拒绝State、只回环及未授权拒绝/定义归属、实际timer或watch观察人工停止不拉起、代理State字节不变；精确清理无错误。公网订阅HTTPS未测 |
| Rocky firewalld | 显式测试环境先证明Enforcing并启动firewalld，产品只使用已经运行的服务；6条IPv4/IPv6、TCP/UDP规则在运行与持久存储读回，显式disable、重启用后purge、外部哨兵与XML保留、测试哨兵撤回均通过。实际外部包过滤路径与公网可达性仍未知 |
| 构建与归档 | finalbuild11/12/13/14/16各自5/5退出0；13准确绑定c7b8d3f，14绑定b024d58，16绑定cbf072e。包括Linux目标vet、两架构管理器、三目标probe、归档契约、离线发行检查。目标vet和交叉构建不算原生ARM执行或完整Linux Go/race |
| focused13安装器与辅助脚本回归 | 准确c7b8d3f，6/6退出0、QEMU0、END与检查配对完整、证据已提取；安装器48项含6个SIGTERM场景、发行夹具40项、Shellcheck/Bash语法、四组平台辅助脚本契约均通过。发行夹具未发布真实Release |
| 被中断的native12 | 准确086f23e，16项计划未完成；已有8个退出标记中installer-native=1、go-test=1，其余6个为0。race期间外部中断，无END，不计整轮通过；原失败与中断回执保留 |
| native15完整回归 | 准确`0818d35ee83fc781eb5f55be1cb5aca3477b8ebf`，12项检查完整结束、11项退出0。完整Go在Mihomo TUIC/quic用例超时退出1；race、vet、服务用户权限、原三协议、官方1.14.3候选和其它检查退出0。失败保留，不以race通过抵销普通Go失败 |
| native16新增附属事务回归 | 准确`cbf072ed9c86074bbbeda1e451caad167f44e90b`，已观察平台、附属node/CLI、Shellcheck、四组Python契约和完整Go退出0；race开始后执行进程消失，缺END与完整回执。不能计为整轮通过，后续准确源码仍须收齐门槛 |
| native17防覆盖回归（未完成） | 准确`d00d7507f762d3f48d9e22ae8d64287f9d7de5ae`，环境、平台、附属node/CLI、Shellcheck和Python契约6项退出0；QEMU退出0却没有END、检查配对或证据提取，Go未结束。回执明确complete=false；原因未证实，不把退出0当成功 |
| native18最终运行源码回归 | 准确`d94d03a33546eddd9caa6ba9c9e8592d2f332d1f`，15/15项退出0；QEMU0、END、检查配对及证据提取完整。包含完整Go、race、vet、50项安装器故障测试、40项离线发行保护、实际降权权限、观察器、Shellcheck/Bash语法、新附属/卸载故障与1.14.3候选官方核心检查。普通Go与race各1589个测试通过、7个原有opt-in跳过；候选114个通过、4个opt-in跳过；跳过不计实测 |
| build18最终运行源码构建 | 同一准确source18，5/5退出0：Linux目标vet、amd64/arm64管理器、Linux双架构及Windows amd64探针、归档契约、离线发行检查；不安装、不发布，不算ARM原生运行 |
| Host发行版与核心重启自启 | 准确b024d58/build14，Ubuntu/Rocky boot4、Alpine boot5各两次真实内核启动全部通过；三个Host报告与实际os-release/PID1/控制器一致。相同自有磁盘、不同boot ID，第二次探针没有启动核心或声明Wants/Requires；核心自动active/enabled、State字节相同，SS2022低443 TCP至少5帧与3个序号UDP通过。UID分别999/994/100，CapEff/Amb=0x400、NoNewPrivs=1、低端口阈值1024；精确purge、外部SSH配置、基盘/rootfs不变。附属服务跨重启另验 |
| 被中断的targeted7 | 平台、完整static-node、static-cli与环境四个退出标记为0，但进程在go-test中外部中断，没有END或完整提取；保留interruption-receipt，不能计为整轮通过 |
| 原生ARM64、其余发行版本 | 没有本批原生硬件/对应版本完整流程；amd64 VM和arm64产物不能代替 |
| 附属服务跨重启、公网/NAT/客户端UI、同PID十分钟后台ACME续期及跨机器完整ACME迁移 | 独立待验；核心双启动、普通VM流程、受控CA启动续期及私有PEM测试不能补作这些成功证据 |

三份普通VM回执均有完整结束与受限证据；准确日志SHA256如下。native18一项为宿主输出与独立串口合并的审查日志，其原始串口及宿主输出各有单独摘要；原始私有夹具不随公开结果展开：

| 运行与回执位置（外层work/） | 准确提交 | 日志SHA256 |
| --- | --- | --- |
| `batch10-vm/run-ubuntu5/run-receipt.json` | `713c9f84e07f73f81b6084d5d0e5170577079aec` | `8fe62d7a30eb21e8f1612f84a1a3c98670c994e40ca4590ce66c0c14889ba9ad` |
| `batch10-vm/run-rocky4/run-receipt.json` | `713c9f84e07f73f81b6084d5d0e5170577079aec` | `3369bb6857d27bad2c770dd0258823f25319d97117e9b166374c3c8236b9147f` |
| `batch10-alpine-vm/runs/alpine15/run-receipt.json` | `086f23ee73a2ee8e779c322ef91fe041b153e2cd` | `261e640daddbaf00836b8ff46de2c31d7373434e75d6da01e6dfbe6ca662f7d2` |
| `batch10-targeted13-run-receipt.json`（focused13） | `c7b8d3f0e7541b87e3437f6207a59eb445b847e0` | `6b6ce8ac30967834b9537cb955b3aded71fa737aaa60c3b7dfdf65e0f54da273` |
| `batch10-targeted12-interruption-receipt.json`（未完成） | `086f23ee73a2ee8e779c322ef91fe041b153e2cd` | `a12d3b6cf12878a9abf123d10bb983e5ae22b9b14d4cf83180a2c6b1fb74889a` |
| `batch10-targeted15-run-receipt.json`（完整运行但Go失败） | `0818d35ee83fc781eb5f55be1cb5aca3477b8ebf` | `eb15ef09d82c4c6841c2b2d870cc2c5b56a6048569e01804fe9f9d1e3a41edc6` |
| `batch10-targeted16-interruption-receipt.json`（未完成） | `cbf072ed9c86074bbbeda1e451caad167f44e90b` | `643737fe2c4e4e527992bbf36bc663a55f7088561d3cbd646917d76c3915e075` |
| `batch10-targeted17-run-receipt.json`（complete=false） | `d00d7507f762d3f48d9e22ae8d64287f9d7de5ae` | `00fc6f8d69ec0df3da91166e18b4350313a580d502ea26aa28e8b2dbe937c815` |
| `batch10-targeted18-run-receipt.json`（完整通过） | `d94d03a33546eddd9caa6ba9c9e8592d2f332d1f` | `ab19ad1d22c79cc4fc9b5d1dbb3ac4838c8b9efbb7116e8fd43decfc1711876f` |

### source18完整平台复验

这一轮使用同一source18、build18及固定的1.14.0/1.14.3官方核心归档，三个目标都执行完整`acceptance-platform.sh`，不能用只测附属服务的补充脚本替代。`aux18`是本轮外层材料名称，验收范围包含安装到最终卸载的完整流程。新附属检查通过产品CLI安装、移除和恢复，不再手写unit模拟产品能力。

| 实际轮次 | 本轮结果 | 串口SHA256 |
| --- | --- | --- |
| Ubuntu24.04.5 amd64 / systemd，aux18-ubuntu | 完整流程退出0、QEMU0、证据完整、基盘不变。真实SS443非root UID999、阈值1024、TCP/UDP通过；受管HY2私有CA HTTPS168B、3个序号UDP、错SNI拒绝且State恢复。管理器重装、停止/禁用保持、配置备份恢复、1.14.3更新/check及回退、核心移除重装、完整purge与外部数据保留均通过。14项新附属检查包括实际prepared移除事务的CLI进程组中断及显式产品恢复、日志、service/timer完整移除、人工停止保护和State字节保持，清理错误0 | `995d27281394d234ba2bc36d5c8acf10c5f96867eec9619d36c1e991a62125ee` |
| Rocky9.8 amd64 / systemd，aux18-rocky | 完整流程退出0、QEMU0、证据完整、基盘不变；全程SELinux Enforcing。SS443 UID994、阈值1024、TCP/UDP通过，HY2私有CA四项验证及State恢复通过；安装到卸载的完整流程、新14项附属检查与真实prepared中断恢复通过，清理错误0。firewalld的6条双地址族TCP/UDP运行/持久规则、禁用清理、重新启用、purge及外部规则/XML保留均通过；宿主策略保留，外部包过滤与公网仍未知 | `cb81165b6e504cfa7e1dc6f26117eff63d52738ab18f7c2a349eb4f4cf239aaf` |
| Alpine3.24.2 amd64 / OpenRC0.63.2-r0，aux18-alpine | 完整流程退出0、QEMU0、6个外层条件及END/证据提取通过，136.482秒；真实openrc-init、签名APK与独立ext4根盘。SS443 UID100/GID101、musl实际进程、CapInh/Prm/Eff/Amb=0x400、NoNewPrivs=1、阈值1024、TCP/UDP通过；bounding集合保持继承。HY2私有CA四项、State恢复、两核心version/check、1.14.3升级回退、停止/禁用保持、备份恢复、移除重装和purge保留外部数据均通过。14项新附属检查与实际prepared中断恢复通过，清理错误0 | `988bb3145bf071b47bc03d31edca43db318118b1f8c50568c31d4e7cfe013c49` |

Ubuntu和Rocky本轮回执分别位于`batch10-vm/run-aux18-ubuntu/run-receipt.json`与`batch10-vm/run-aux18-rocky/run-receipt.json`，Alpine为`batch10-alpine-vm/runs/aux18-alpine/run-receipt.json`；各自`evidence/auxiliary.json`明确写出`actual-prepared-cli-process-group-interrupted-and-product-recovered`。测试只终止该次独立CLI进程组，不终止init管理的订阅进程组；真正的新journal未捕获时会失败，不制造恢复输入。无待办recover仍单列为no-op，不能代替该中断恢复。三平台均完成后，`batch10-aux18-serial/run-receipt.json`记录3项验证通过、无失败。此证据不证明附属服务跨重启、公网订阅HTTPS、客户端UI或公开CA。

source18的三平台完整流程都实际观察持续TCP的原PID和帧继续增长，包括改名、重复应用和回退；Alpine PID1067的三段帧范围为8→146、150→201、206→331。它证明这些服务器元数据维护没有打断该受控活跃流，不表示任意运行配置更新或既有TCP会话迁移都无损。Host发行版、版本、包管理与真实init报告也逐项与目标系统核对。

本轮实际调用的串行入口：

```text
python run-aux18-serial.py --prepare
python run-aux18-serial.py --launch
```

此前由`prepare-full-round.py --name aux18`按source18/build18准备，两个归档的真实绝对路径、SHA256、六份完整脚本、基盘/内核/工具、超时与固定准备命令均在私有`full-prepare-aux18/prepare-receipt.json`及各plan里。串行入口只依次调用固定Ubuntu、Rocky、Alpine runner，不安装计划任务，也不自动重试失败轮次。可移植的产品验收入口另见下文，不把脱敏替换的路径称为原样运行命令。

三份核心双启动回执均为 `complete_and_passed=true`，两次QEMU退出0且无超时；回执保存两个boot ID及各次串口摘要。第二次启动串口SHA256如下，准确提交均为 `b024d58a896e18f3749fb121c408d1580ac5379c`：

| 回执位置（外层work/） | 第二次启动串口SHA256 |
| --- | --- |
| `batch10-vm-reboot/run-ubuntu-boot4/run-receipt.json` | `62e8ffbfe3f2f4ad6d29ae5b74e8c09ee5ea6771ca07c0691fbc608e386f165b` |
| `batch10-vm-reboot/run-rocky-boot4/run-receipt.json` | `c7260581f69ab9624df8eb43b1e2eed8d1dd63d38a6b360d2fd0531dca171338` |
| `batch10-vm-reboot/alpine-alpine-boot5/run-receipt.json` | `51c01edd1a5e580528287eb4093cdc0ae908caf6ce9f49714becdfc09b8c12fe` |

实际启动命令（准备阶段的固定包、镜像、候选核心、脚本和构建收据摘要均在各plan内）：

```text
python batch10-vm/run-cloud4.py launch --plan batch10-vm/run-ubuntu5/plan.json
python batch10-vm/run-cloud4.py launch --plan batch10-vm/run-rocky4/plan.json
python batch10-alpine-vm/run-final.py launch --name alpine15
python run-batch10-focused13.py --launch
python build-batch10.py --prefix batch10-targeted13 --output-prefix batch10-finalbuild13
python build-batch10.py --prefix batch10-targeted14 --output-prefix batch10-finalbuild14
python batch10-vm-reboot/run.py launch --plan batch10-vm-reboot/run-ubuntu-boot4/plan.json
python batch10-vm-reboot/run.py launch --plan batch10-vm-reboot/run-rocky-boot4/plan.json
python batch10-vm-reboot/alpine-run.py launch --plan batch10-vm-reboot/alpine-alpine-boot5/plan.json
```

Rocky的成功报告和证据POST完成后，测试器主动poweroff，打断了cloud-init后续SSH指纹模块的收尾，串口保留SystemExit:1堆栈。它发生在产品验收退出0之后，不当作QingNode失败；也不隐去这项测试关机边界。重启验收另外记录，不从本轮快速关机推断。

### 后续回归、ACME夹具与ARM产物

native18没有改原Go测试时限、删除断言或取消发行门槛。普通Go和race各运行1596个测试/子例，1589个通过、7个跳过，8个有测试的包通过，另2包没有测试；候选组运行118个测试/子例，114个通过、4个跳过，3包通过。包级pass和无测试包不重复算进测试通过数。安装器保留原48项，再加2组等待期间外部修改回归，50项实际耗时789.685秒。核心卸载回归覆盖第一次来源查询、停止/禁用、恢复加载/启用/重启期间改服务、权限、管理器、辅助脚本和轮换文件，以及辅助目录未知成员；独立附属事务覆盖24种等待期间外部修改组合、主记录丢失见证、共享service/timer成员、原始记录字节身份及历史冲突。模拟命令用于这些故障窗口，不冒充真实init生命周期。

普通Go与race原有7个未启用测试为：`TestOfficialCoreACMEPebbleBackgroundRenewalSameProcess`、`TestOfficialAnyTLSIdlePoolOwnedSocketsAndResources`、`TestOfficialCredentialExpiryExistingTCPAndNewAuthentication`、`TestOfficialCoreHY2ControlledNetwork`、`TestHY2NetworkFixtureProcess`、`TestOfficialCoreProtocolExpansionControlledNAT`及其`IPv6`用例。候选组的4个跳过是其中后台ACME、HY2网络模拟和两个新协议NAT用例。跳过涉及独立长测或专用场景；新source18本轮不声称完成这些验收。原三协议及新增协议的普通官方TCP/UDP与Mihomo检查实际执行成功，不能替代这些专门场景。

native18使用独立串口文件和关闭的显示/监视控制台收集证据，宿主日志与原始串口分别保留摘要；没有向测试机注入控制台输入。此前native17意外结束的原因仍未知，换运输方式不构成根因证明。native18的临时Windows防休眠请求在结束时解除，没有修改电源计划；采样未观察到超过90秒的宿主调度间隙。原始Go JSON独立保存在guest证据文件，`batch10-native18-json-audit.json`核验行有效性、通过/跳过和摘要，不依赖串口换行推断成功。

本轮实际命令（外层封装仅准备隔离材料和收据，源码与工具摘要均固定）：

```text
python prepare-batch10-targeted.py targeted18 --commit d94d03a33546eddd9caa6ba9c9e8592d2f332d1f
python run-batch10-final18.py --prepare-only
python launch-batch10-background.py batch10-targeted18
python build-batch10.py --prefix batch10-targeted18 --output-prefix batch10-finalbuild18
```

guest实际运行的主要检查为：

```bash
go test -p 1 -json -count=1 -timeout=15m ./...
go test -p 1 -race -json -count=1 -timeout=30m ./...
go vet ./...
python3 scripts/test-installer.py
python3 scripts/test-release.py
python3 scripts/test-maintenance-harness.py
shellcheck install.sh scripts/*.sh
env SING_BOX_BIN=/sing-box-candidate go test -p 1 -json \
  ./internal/node ./internal/probe ./internal/coreapi \
  -run 'OfficialCore|OfficialArchive|Mihomo|OfficialCandidate' -count=1 -timeout=10m
```

这份guest另提供摘要校验过的默认1.14.0、候选1.14.3、Mihomo与Pebble，实际环境和精确路径见run-plan。离线发行夹具里的“发布成功”文本来自模拟GitHub接收器，不表示创建了公开Release；工作流源码保留和本地通过不表示远程CI已执行。

native15的原始guest Go JSON另保留在提取证据中，独立审计`batch10-native15-json-audit.json`确认没有损坏JSON行。普通Go的唯一未结束用例为Mihomo TUIC/quic，期间观察到1800.198秒事件间隙，最终超时；是否由宿主暂停造成尚未证实，不能据此豁免。race同一用例通过且全量退出0；七个原有显式opt-in测试仍未启用，分别涉及后台10分钟ACME续期、AnyTLS空闲池、存量连接到期、HY2网络模拟与新协议NAT/IPv6。没有删除断言、扩大原Go门槛或把跳过计为本批实测。

受控Pebble2.10.1的普通启动/迁移/续期/失败测试在native15、race及候选核心组中实际通过，包含账户身份、HTTPS和序号UDP断言。早先CA 500已定位到固定上游ARI证书编号的DER正数填充差异；`0818d35`仅在实际遇到该错误且编号满足条件时等待核心原生60/120秒重试，不更改生产核心、CA或普通12秒等待。后台同进程10分钟续期属于独立opt-in，本批没有重新运行，不能用启动续期替代它。

ARM64仅做官方固定tag产物的摘要和ELF只读检查，`batch10-arm64-abi/receipt.json`完整。1.14.0归档SHA256为`04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088`，与项目固定值一致；1.14.3候选为`29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e`。两者都是ELF64小端、EM_AARCH64，实际需要`/lib/ld-linux-aarch64.so.1`及libdl/libpthread/libc；即使Go构建元数据写CGO_ENABLED=0，也不能称核心静态。没有执行ARM核心的version/check、musl或服务/协议验收；默认核心仍为1.14.0。

## 可复现的真实验收入口

以下是会执行变更的入口，只能用于专门准备、可重建的空白VM。不得在已有生产QingNode上运行。Python仅为验收工具，不成为代理运行依赖。

```bash
sudo bash scripts/acceptance-platform.sh --disposable /绝对路径/解压发行包 \
  --core-archive /绝对路径/sing-box-1.14.0-linux-amd64.tar.gz \
  --candidate-archive /绝对路径/sing-box-1.14.3-linux-amd64.tar.gz \
  --candidate-sha256 e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
```

入口检查空白自有路径并使用实际init；串行执行安装、非root443 TCP/UDP、持续流改名/重复应用/回退、受管HY2与私有CA证书验证、重装、停止/禁用保持、加密备份恢复、core更新回退、移除重装、附属服务和最终purge。恢复点/口令/客户端配置留在私有WORK，公开证据目录仅输出脱敏结果。可选 `QINGNODE_PLATFORM_FIREWALL_TEST=1` 还要求实际firewalld已运行且SELinux enforcing，执行规则与归属验收，不负责关闭策略或启动全局防火墙。

`test-platform-aux.py` 真实fork降UID检查，不用root的access结果代替服务账户权限；仅回环订阅测试使用合成HTTPS来源，不能证明公网HTTPS部署。systemd定时器和OpenRC watch分别观察人工停止；已有TCP会话不承诺无损迁移。防火墙验收保持外部哨兵规则，记录runtime/permanent与卸载回收；未执行外部包过滤试验时保留未知。

## 迁移、恢复与后续接口

State升为9仅因为新firewalld语义；读取1–8在内存显式转换，不落盘迁移，写入保留原始恢复材料。旧格式夹带新值、未知字段、未来版本均拒绝。节点/用户/密钥不轮换；不要改schema号或删字段让旧二进制直接读取新State。

配置备份QNBK1/QNBK2、完整迁移QNBK3 typed v1继续沿用。来源服务文件仅作证据，目标机器按实际systemd/OpenRC渲染；不执行包内命令，不把core可执行文件随包覆盖。迁移预检要重核端点、本地端口、账户属组、路径、core与init；证书运行存储仍要求持锁、一致短停及停止证明，unknown不能当停止。监控私有计划/历史仍沿前批缺项规则，不因本批平台适配声称完整打包。

安装失败保留旧管理器/core、原服务定义、自启runlevel与运行状态；恢复失败保留私有恢复目录并报告恢复命令。显式 `recover`、`recover-migration` 与 `rollback` 语义不改。外部修改过的服务、配置覆盖或未知文件权限先拒绝，不能用重新安装覆盖。OpenRC已无自启项时禁用为已证明的no-op，有项则逐项删除并读回，不把工具警告伪装成功。

后续批次复用以下入口：

- `platform.ProbeHost(HostProbeOptions)` / `HostCapabilities`：只读本机事实；与原RuntimeCapabilities并列。
- `DependenciesFor` / `InstallDependencies`：显式发行版/版本/架构包计划；不被只读探测自动调用。
- `platform.Manager`：安装材料、start/stop/restart/status/enable/disable/logs、定义来源和runlevel；检测失败必须保留unknown。
- `node.BackendActivity` / 可选 `ActivityBackend.ActiveState`：写事务可靠观察；旧隔离fake可保留bool接口，生产SystemBackend不得吞错误。
- `node.ServiceDefinition` 与附属服务渲染：从本机类型化数据生成，不接收归档或外部任意命令。
- `node.AuxiliaryControlLease`：只串行控制自有订阅/监控服务；启动oneshot前释放State检查锁，服务本身仍按原State锁读取，不能把控制锁横跨成自死锁。
- `node.NewAuxiliaryServicePlan` / `PreviewAuxiliaryService` / `ApplyAuxiliaryService` / `RecoverAuxiliaryService`：固定monitor/subscription的类型化定义、只读预览、私有v1部署事务与显式回到before；不接收任意unit或命令。`PendingAuxiliaryService`与`AuxiliaryServiceMigrationGaps`将待恢复记录/冲突见证和未打包部署资料纳入卸载与迁移保护。
- `Removal`与安装器恢复：文件指纹只在本轮内存保存，旧卸载记录格式不变；发现外部改动停止，不另建基线去认领它。新功能不要复用不受保护的直接文件覆盖路径，或把运行时指纹误当跨机器可信清单。
- `Firewall.Sync` / Store effects：UFW或已运行firewalld的精确归属事务；不修改全局宿主策略。
- `monitor timer --manager`、`monitor watch`：复用第08批预算、单实例与恢复判定，不另外建立cron逻辑。

## 来源与许可证

收尾逐条核对D项时发现：早期辅助VM夹具直接写入和删除unit/timer，不能证明产品具有附属安装、删除和事务恢复；systemd监控的enable还错误指向静态oneshot服务。随后补固定两个附属对象的 `service install/remove/recover --preview|--yes`、timer映射、附属日志与完整迁移缺项盘点。新事务不改State schema9，使用私有v1安装/恢复记录，恢复重渲染固定类型，拒绝未知字段、重复键、外部定义、异常链接和未知状态；失败恢复保留原运行、自启及OpenRC runlevel。实际验收脚本也改为调用产品入口。准确source18的native18已通过完整Go/race及这些故障检查，aux18三平台也各自通过新产品安装/移除及真实中断恢复；这些是新的独立证据，没有借旧辅助流程补记成功。

固定版本、提交、机制和许可证见[THIRD_PARTY.md](../THIRD_PARTY.md)。外层 `batch10-service-sources.md`、`batch10-host-firewall-sources.md`、`batch10-installer-sources.md` 保留早期研究；早期filecap与广泛rc-update del构想已被本批真实失败及最小修复取代，不应继续当当前实现说明。Alpine原包/索引、OpenRC源码和监督程序、Ubuntu/Rocky镜像各有独立摘要及签名回执。来源核对只证明接口依据，不产生测试成功或性能结论。未复制上游GPL数据面、Xray安装器或面板代码。
