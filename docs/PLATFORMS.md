# 发行版、架构与服务托管

第10批继续使用Bash引导、静态Go管理器、独立官方sing-box和本机init，不安装面板、Docker或数据库。平台适配代码和实际验收分别登记；实现候选不等于全平台支持承诺。准确提交、命令和失败见[BATCH10.md](BATCH10.md)。

| 目标 | 服务/包管理 | 代码路径 | 当前实机证据 |
| --- | --- | --- | --- |
| Debian 12/13，Ubuntu 22.04/24.04/26.04 | systemd / apt-get | 保留既有事务和核心unit | Ubuntu24.04.5 amd64 source18完整流程及产品附属安装/移除/中断恢复通过（aux18-ubuntu）；b024d58另通过核心双启动与Host报告；其余列出版本本批未实测 |
| Rocky Linux 9，验收选9.8 | systemd / dnf | 新增受限依赖映射、SELinux检查与可选firewalld | Rocky9.8 amd64 source18完整流程及新附属事务通过（aux18-rocky）；Enforcing、6条运行/持久规则与精确卸载保留外部资产通过；b024d58另通过核心双启动与Host报告，外部包过滤路径未测 |
| Alpine 3.24，验收选3.24.2 | OpenRC / apk | 新增supervise-daemon、用户/权限和兼容库 | Alpine3.24.2 amd64 / OpenRC0.63.2-r0 source18完整流程及新附属事务通过（aux18-alpine）；真实musl非root443、NoNewPrivs=1、HY2证书通过；b024d58另通过核心双启动与Host报告 |
| amd64 / arm64 | 对应官方核心和管理器 | 架构、ELF、版本、构建标签分别核对 | ARM64管理器交叉编译通过；两版官方ARM核心摘要/ELF已只读核对，未执行ARM程序、解析或原生服务/流量 |

## 先看本机能力

```bash
qingnode capabilities --json --skip-loopback
qingnode capabilities
```

报告保留版本1原有字段，新增 `host`：发行版/版本、安装候选、包管理器、PID1、服务工具是否存在与控制器是否可用、SELinux、防火墙和虚拟化。原 `runtime` 本机字段仍报告内存、有效权限、TUN、sysctl、目录写权限、IPv4/IPv6绑定与小包回环；未知保留null，能力不等于真实链路通过。查询不安装包、不修复事务、不启动服务、不改内核参数。普通容器只有systemctl/rc-service命令时仍可能不可用。

早先ubuntu5/rocky4/alpine15的Host发行版/版本字段实际为空，不能以这些报告宣称识别通过。source14（b024d58）修复系统标准os-release链接及回退；Ubuntu/Rocky boot4、Alpine boot5已另行两次真实启动，报告与实际系统字段一致，准确回执见BATCH10。只允许标准别名，不读取任意外部链接。

LXC/OpenVZ的TUN、CAP_NET_ADMIN、sysctl与IPv6取决于宿主授权。本项目不安装新内核、不修改宿主限制；普通直接节点不要求TUN或CAP_NET_ADMIN。OpenRC低端口由实际supervise-daemon的 `capabilities="^cap_net_bind_service"` 授予继承/环境权限（Linux在执行子程序时保留的那一位绑定权限），并启用 `no_new_privs` 防止通过其他程序获得更多权限。实际监督程序必须支持这两个选项；代理仍为非root，订阅不授低端口权限。保留继承的bounding集合，不能把它声称为只剩一位；真正运行核心的有效权限与443传输已在上述Alpine VM实测；不代表原生ARM或公网。核心文件不设置filecap，避免gcompat再次执行musl时丢失授权。

## 服务、附属进程与权限

```bash
qingnode service status
qingnode service unit --manager systemd
qingnode service unit --manager openrc
qingnode service start
qingnode service disable
```

systemd保留原unit与沙箱，服务端账户仍为qingnode。OpenRC使用标准openrc-run和supervise-daemon；root supervisor的PID与非root工作进程PID分别处理，重启有次数/时间窗口，日志和PID路径仅属于本项目。没有通用reload/无损重载承诺。OpenRC日志通过受管logrotate按大小保留；主机调度器未实际运行时不能宣称已经轮转。

先生成可审查的监控服务材料：

```bash
qingnode monitor timer --manager systemd --out /已有审查目录
qingnode monitor timer --manager openrc --out /已有审查目录
```

systemd沿oneshot+timer；OpenRC沿独立 `monitor watch`，串行读取同一监控计划与预算，不修改全局cron、不追赶错过轮次。监控因读取私有State和执行已授权管理动作需要管理权限；代理及只读订阅仍为非root。默认不安装/启用任务、不自动开启恢复或到期停用。先审查定义再显式安装；停止服务及 `monitor disable --yes` 分别控制调度与计划。

只读订阅使用独立qingnode-sub账户和独立发布目录：

```bash
qingnode service unit --manager openrc --name qingnode-subscription --public-url https://sub.example.net
qingnode service unit --manager systemd --name qingnode-subscription --public-url https://sub.example.net
```

模板只监听127.0.0.1:8389并依赖用户已有、验证过的HTTPS反向代理。不接管80/443，不把State设为订阅账户可读；模板生成不证明HTTPS成功。附属服务控制要求与本机受管定义精确一致，外部修改和conf.d/drop-in明确拒绝。

附属账户、私有订阅快照或监控计划准备好后，使用产品事务安装，不必自行写入或删除服务文件：

```bash
qingnode service install --name qingnode-monitor --preview
qingnode service install --name qingnode-monitor --yes
qingnode service install --name qingnode-subscription --public-url https://sub.example.net --preview
qingnode service install --name qingnode-subscription --public-url https://sub.example.net --yes
qingnode service enable --name qingnode-monitor
qingnode service start --name qingnode-monitor
qingnode service logs --name qingnode-monitor --lines 50
qingnode service remove --name qingnode-monitor --preview
qingnode service remove --name qingnode-monitor --yes
qingnode service recover --name qingnode-monitor --preview
qingnode service recover --name qingnode-monitor --yes
```

新安装默认停止、禁用；重装保存原运行和自启状态，不改变监控恢复授权或代理State。systemd监控将service与timer作为一组：enable/disable只修改timer自启，start/stop/restart控制调度与工作服务。OpenRC仍使用独立watch。失败或进程中断保留私有版本1恢复记录，显式recover返回操作前定义与状态，不执行恢复材料中的任意命令。没有待恢复事务时recover只报告无待办，不能当作故障恢复实测。完整卸载须先用remove清理已安装的附属服务；残留timer、安装记录或待恢复事务会阻止删除管理器。迁移不执行这些服务文件，部署记录未打包时明确列为缺项，目标机需重新预览和安装。

附属事务在每次调用服务控制器的前后、每次文件修改前后重核完整定义、权限、安装记录和恢复记录。等待服务停止或启动期间发现外部修改就拒绝继续，不用旧快照覆盖管理员的新内容；原恢复记录保留。恢复记录本身被改动或删除时，另外以独占创建的`.conflict.json`保存原始类型化材料，阻止后续事务、完整卸载和迁移；`recover`不会猜哪一份应生效。管理员须先对照原件和外部修改处理冲突，不能通过删除唯一恢复副本来“修复”。历史归档不覆盖同名外部文件。最后一次检查与本地文件替换之间，另一root进程仍能制造竞态；这些检查不宣称抵御恶意root的全局原子性。此项新增防覆盖检查的实际测试以准确提交回执为准。

## 防火墙与SELinux

```bash
qingnode firewall status
qingnode firewall enable --backend firewalld
qingnode firewall sync
qingnode firewall disable
```

旧 `firewall enable` 仍选择UFW。firewalld须已经运行，只支持单个默认活动zone；多zone策略保留手动管理。以明确IPv4/IPv6、目的地址、TCP/UDP、端口的rich-rule分别写运行和持久状态并读回，不执行全局reload、flush或runtime-to-permanent。项目XML、私有所有权/恢复材料及锁用于精确清理；同形外部规则、文件碰撞和外部删改拒绝接管。管理员同时更改同形规则无法与本项目事务实现跨进程原子性，修改防火墙时应避免并行操作。切换UFW/firewalld需先显式停用旧项目模式。

Rocky保留SELinux enforcing，不自动关闭或放宽全局策略。安装器检查本机SELinux工具并对本项目路径应用系统已有标签；不能解决的策略拒绝启动并保留旧版本。对应enforcing与真实firewalld验收必须单列，模拟命令不作证据。

## 核心ABI、恢复与验收

管理器静态不表示核心静态。当前官方1.14.0/1.14.3 amd64 ELF声明glibc加载器 `/lib64/ld-linux-x86-64.so.2`；Alpine明确安装gcompat/libgcc/libstdc++等兼容包后，仍需真实version/check/流量验收。架构不符、加载器缺失、摘要错误、构建标签缺失和启动失败均拒绝替换；不把musl兼容库存在当成功运行。其他版本/架构检查实际产物，不硬套amd64结论。

本批还实际读取两版官方ARM64归档：ELF64小端、EM_AARCH64，加载器为`/lib/ld-linux-aarch64.so.1`，依赖libdl/libpthread/libc。构建信息中的CGO_ENABLED=0不能推翻实际ELF依赖。摘要与来源见BATCH10；这只证明产物选择和文件结构，Alpine ARM64的ABI执行、配置解析、开机启动和TCP/UDP仍未验收。

State因新firewalld语义升为9；旧1–8只在内存迁移并保留恢复原件，旧格式不能夹带firewalld。QNBK1/2及QNBK3 typed v1继续读取；来源服务管理器可记录openrc，恢复按目标平台重新生成定义，不执行备份中的服务脚本。身份与协议行为保持，不能删字段或降schema伪装向后兼容。

`scripts/acceptance-platform.sh --disposable`只允许可重建空白环境，真实执行安装、非root低端口TCP/UDP、持续流改名、重装、停止/自启保持、备份恢复、核心更新/回退与卸载。原systemd门禁不删除。容器用于包映射/配置/文件故障，VM用于init/权限/生命周期，原生ARM和公网单列。命令、证据及尚未完成范围见[BATCH10.md](BATCH10.md)。

固定来源：初步核对OpenRC0.62.1，实际Alpine版本另核 [0.63.2 / b3a99e01](https://github.com/OpenRC/openrc/blob/b3a99e01c8bda7e5c2b9a8975a6d36ec3eff370e/src/supervise-daemon/supervise-daemon.c)，BSD-2-Clause；[libcap2.78的IAB语义](https://kernel.googlesource.com/pub/scm/libs/libcap/libcap/+/a1fef85d27d0ee12729a64d1c9b2183c6007e56a/doc/cap_iab.3)，BSD-3-Clause或GPL-2.0-only；firewalld [1.3.4 / 83d46a9f](https://github.com/firewalld/firewalld/blob/83d46a9f8c4f01da463cf426c083c69e79bf008a/doc/xml/firewall-cmd.xml.in)，GPL-2.0-or-later。只参考命令、监督、权限和运行/持久分离机制，未复制实现；完整来源、实际包与上游源码的区别见[THIRD_PARTY.md](../THIRD_PARTY.md)。

本批Alpine早期试验已证实：仅给core文件加 `cap_net_bind_service=ep` 会在gcompat再次执行musl后丢失，UID非root且内核阈值1024时443绑定被拒绝。因此该试验方案不属于支持版本。旧试验文件的精确权限只在显式核心安装中识别并通过新候选目录替换，原inode/xattr保留恢复材料；未知权限拒绝覆盖，查询不修复。完整服务定义被外部修改时安装/卸载均拒绝接管，不能靠保留标记覆盖命令。

实际Alpine3.24.2仓库的OpenRC为0.63.2-r0，另核对其固定tag监督源码和官方APK的cap_iab/no_new_privs、child_pid与降权日志语义。独立权限试验的TCP/UDP成功仅证明方案可行，最终完整生命周期见批次记录。服务控制器断开或状态不完整时，安装、写配置、卸载和完整迁移拒绝把unknown记为停止；用户原有运行、自启状态仍分别保存。

## 安装依赖与维护边界

Bash必须已可运行；它是引导入口，不通过删除发行版检查来宣称通用安装。apt/dnf/apk按显式包映射仅补缺少的实际命令与必需兼容库，不执行系统upgrade。仓库、锁或下载失败时终止，不在apt update失败后继续install。Rocky的SELinux工具与Alpine的GNU校验/归档语义分别核对；BusyBox同名命令不自动算支持所需参数。

`service unit`只生成材料；安装、更新、卸载核对完整本机定义与加载来源。保留受管标记但更换命令、添加OpenRC conf.d或systemd drop-in、异常权限/链接均拒绝接管。已disabled的OpenRC禁用是读回证明后的no-op；有自启项则逐个删除并再次读取，失败恢复按原runlevel恢复，不能偷偷改为default。

source18把核对延续到服务命令的等待前后。安装器只接受安装前原件或本轮确实已经写入的候选文件，重核管理器、服务文件、辅助脚本和适用的日志轮换文件；发现外部改动便停止后续恢复和服务控制，保留私有原件。核心卸载在第一次服务来源查询前记录文件完整权限、属主、属组、链接数、长度和SHA256，之后始终比较同一份内存指纹；原路径与本轮暂存路径之间的搬移不重建基线。完整卸载拒绝`/usr/local/lib/qingnode`内除`.qingnode-owner`与`install.sh`之外的未知成员，不能凭目录标记递归删除管理员新增文件。新的安装/卸载故障检查在native18实际通过，真实平台流程与准确提交另见BATCH10。

失败后有三类不同材料：安装器报出的私有原件目录、核心卸载的`uninstall.json`及暂存文件、独立附属服务的v1 journal/冲突见证。不要删除它们来绕过保护，也不要用重新安装或轮换凭据试错。核对方式、准确恢复命令与旧记录兼容边界见[MIGRATION.md的人工恢复说明](MIGRATION.md#安装卸载及附属服务的保留材料)。本轮文件指纹只在内存保存，没有为此再改State9或旧卸载记录格式；最后本地检查与替换之间仍不能与另一root写者实现全局原子互斥。

服务正在activating/deactivating、控制器断开、缺失PID或自启状态无法完整保存时，写操作拒绝把未知记为停止/禁用。只读状态仍报告unknown。持续流免重启与失败恢复继续复用Store影响分类；没有reload或TCP会话无损迁移的承诺。

跨平台恢复前重核本地监听/外部端点、core ABI/标签、账户属组、可写证书目录、init和防火墙。来源unit/init脚本只作证据，按目标平台重新渲染；完整迁移的证书一致性与监控缺项仍遵守[MIGRATION.md](MIGRATION.md)。

本批普通VM实际通过受管SS2022端口443与HY2端口444：持续TCP观察PID和帧、3个序号UDP往返、私有CA校验证书的HTTPS及错名称拒绝；清理TLS夹具后State字节一致。三平台真实订阅账户隔离、证书目录读写与周期监控人工停止保护也通过。来源版本、命令、回执、失败保留和准确提交见BATCH10；source12对source11仅改测试器与取消退出码，二者生产Go/安装器字节相同。随后source13另补安装器信号恢复、source14另补Host识别；各自证据不可混用。source14三平台另行通过同一自有磁盘的真实双启动、核心自动启动后SS2022低443 TCP/UDP及State保持；没有由探针执行start替代。source18另有完整Go/race及官方核心回归；受控CA启动/迁移续期不替代本批未重跑的同PID十分钟后台续期。公网入口、外部firewalld过滤路径、客户端UI、原生ARM、附属服务跨重启与长期运行仍要各自验收。
