# 配置备份与完整加密迁移

第10批当前State9只因firewalld新语义升级，旧1–8只读内存转换并保留原件；旧格式不能声明新防火墙模式。完整包来源清单可记录OpenRC，服务文件仅保留来源证据，恢复按本机systemd/OpenRC路径重新渲染，不执行归档脚本。当前写入恢复仍为State9，不表示可以自动降级旧管理器。对应平台、权限、SELinux/firewalld与实测见[PLATFORMS.md](PLATFORMS.md)、[BATCH10.md](BATCH10.md)。

第09批新增协议语义和AnyTLS设置时将State升为schema8，旧1–7只在内存转换并保留原件；合法schema7观测字段继续可读，旧schema夹带新协议/新选项明确拒绝。该批当时的管理器恢复旧快照写schema8，当前管理器则写schema9；不能改版本号或删字段伪装降级。QNBK1/2、QNBK3 typed v1和monitor独立资产缺项边界保持；第09批协议恢复/实测状态见[PROTOCOLS.md](PROTOCOLS.md)、[BATCH09.md](BATCH09.md)。以下格式段落沿用前批机制，当前State版本以上方第10批说明为准。

迁移接口在第07批加入，第08批继续复用；证书操作见 [CERTIFICATES.md](CERTIFICATES.md)，对应实际证据分别见 [BATCH07.md](BATCH07.md)、[BATCH08.md](BATCH08.md)。备份口令通过无回显输入或权限 0600 的 `--password-file` 提供，不放入命令行。包含代理、核心API与 DNS 秘密，必须加密保存，不上传到在线转换站。

第08批新增的独立 `monitor/` 私有计划、通知秘密与历史尚未纳入完整迁移。盘点发现该目录时明确列缺项，必须显式 `--allow-incomplete` 才能保存受限包；恢复后需在目标机器重新配置监控，不能宣称完整搬回恢复授权。State内的API设置与代理凭据到期计划随配置备份保存，读取或预览不执行到期停用，详见 [MONITORING.md](MONITORING.md)。

第10批附属服务事务的私有v1安装记录同样单独盘点；存在时列明部署设置和运行/自启材料未打包，只能显式保存受限包，不能默默称完整。即使只有订阅服务、没有monitor目录也会提示。待恢复附属事务直接阻止完整备份、资产恢复和完整卸载，先通过 `service recover --name 对应服务 --preview` 核对，再显式恢复。目标机器按本机init重新执行 `service install`，不照抄来源服务脚本，也不从记录中执行命令。

| 模式 | 保存范围 | 对服务的影响 |
| --- | --- | --- |
| 默认配置备份 QNBK2 | State、生成配置与服务来源材料；旧 QNBK1/QNBK2 继续可读 | 查询与快照不启动、不修复、不暂停服务；ACME 运行目录、订阅下载权限不因此完整搬走 |
| `--full` QNBK3 完整迁移 | 配置快照、受管 PEM/私钥、ACME 账户与存储、拓扑、设备/订阅权限及版本来源 | 受管运行资产需一致性短停，显式 `--quiesce`；完成后恢复原运行/停止状态，不调用 enable/disable |
| `--full --allow-incomplete` | 明确列出外部引用或缺失资产的受限包 | 不能标成完整；恢复仍需显式接受受限范围并补齐外部资产 |

## 先预检，再生成

```bash
qingnode backup --preview
qingnode backup --file /私有目录/config.qnbk --password-file /私有目录/passphrase
qingnode backup --full --preview
qingnode backup --full --quiesce --file /私有目录/complete.qnbk --password-file /私有目录/passphrase
```

预览显示受管资产、外部缺项、当前运行状态和短停范围，不写包、不修复旧事务。存在未完成配置或迁移事务时先明确处理，不能把未确认版本当恢复点。完整迁移持QingNode管理锁并停止其自有核心。systemd须确认MainPID/ControlPID为零、unit已停止；有控制组时还须确认本组及子组无进程。OpenRC须明确报告停止、监督进程已不存在，并完成有权限的/proc进程清点，排除残留核心及经musl兼容加载器运行的核心。任何查询失败、进程不可读或状态不完整都不能当作停止，无法取得证明时不创建一致快照。

目录快照还做两次内容清单/摘要核对，但该核对本身不能证明跨文件一致。必须使用项目专用存储，不允许其它进程同时写 ACME 目录；无法控制外部写入者时只能受限处理。`--offline` 没有生产核心的停止证明，不能据此声明运行中 ACME 目录一致；它用于隔离材料验证，不用于绕过生产短停。核心内部每张证书的签发锁不等于整个目录快照锁。普通可重建缓存、大量日志、核心可执行文件与整个宿主系统不打包。

用户文件引用不会被偷偷移动或纳入项目所有权。完整模式缺少必需资产时失败；`--allow-incomplete` 的包带缺项清单，恢复不能掩盖此限制。原始一次性订阅令牌明文不在发布快照中，完整包保存当时的授权哈希及内容，使用原始链接的设备仍需自己保管链接。

## 目标机器预检与提交

先在隔离目标准备受支持的服务管理器、项目账户以及可信官方核心。核心仍按版本、架构、标签和归档摘要校验；迁移包中的服务文件只是来源证据，按目标环境重新生成，不执行包内命令，也不覆盖可执行文件。

尚未安装的目标机应使用本批本地构建包中的安装器，不能使用尚不包含新功能的公开旧包。现有安装器会初始化首个节点；可在已授权的干净目标上先创建仅监听回环的临时SS2022节点，以准备服务用户、本机服务定义和官方核心，再停止、预检并恢复原包。目标必须符合[平台矩阵](PLATFORMS.md)的发行版、真实init和依赖条件；本批普通VM分别验证了Ubuntu、Rocky及Alpine的配置备份恢复，未把它扩称跨系统完整ACME资产迁移通过：

```bash
# 在本批完整管理器包的解压目录执行；24443若被占用，明确选择另一个空闲本地端口。
sudo bash ./install.sh --protocol ss2022 --server 127.0.0.1 --listen 127.0.0.1 --port 24443 \
  --core-archive /绝对路径/已校验的官方核心归档.tar.gz
sudo qingnode stop
```

安装器的本地归档入口固定为默认 1.14.0。若迁移预览显示源包显式使用 1.14.3，应先完成上述默认安装，再单独准备该候选版本；摘要必须来自对应架构的可信官方归档，不能拿其它版本或架构的摘要代替：

```bash
sudo qingnode core install --version 1.14.3 --sha256 对应官方归档的64位十六进制SHA256 \
  --archive /绝对路径/sing-box-1.14.3-linux-对应架构.tar.gz
sudo qingnode stop
```

切换核心会应用临时节点的运行配置，可能重新启动该回环服务，因此这里再次显式停止。此步骤只准备已适配的指定版本，不用自动更新命令跨兼容线；目标最终导入仍会再校验核心摘要、版本、构建标签与候选配置。

该临时节点不会对公网监听；它的临时身份在恢复前也会被加密保存，源节点身份从迁移包恢复。安装器会启用目标服务自启，这与源机器是否启用自启是两回事；恢复保持目标现有自启状态，不复制源机的systemd运行记录或OpenRC runlevel。确认导入和外部映射后显式 `qingnode start`，按目标用途使用 `qingnode service enable` / `qingnode service disable` 设置自启；顶层 `enable/disable` 是节点操作。缺少真实可用init的隔离离线还原只验证材料，不能称完成此部署流程。

```bash
qingnode restore --file /私有目录/complete.qnbk --password-file /私有目录/passphrase --preview
qingnode restore --file /私有目录/complete.qnbk --password-file /私有目录/passphrase --quiesce --yes
```

包中有订阅权限时，预览会要求另外指定：

```bash
qingnode restore --file /私有目录/complete.qnbk --password-file /私有目录/passphrase --preview \
  --subscription-directory /srv/qingnode-subscriptions --subscription-group 目标服务组ID
qingnode restore --file /私有目录/complete.qnbk --password-file /私有目录/passphrase --quiesce --yes \
  --subscription-directory /srv/qingnode-subscriptions --subscription-group 目标服务组ID --restore-subscriptions
```

`--restore-subscriptions` 明确允许恢复包中当时有效的下载权限，可能重新允许备份时尚未撤销的令牌。普通配置恢复沿用原来的撤销保护，不默认复活订阅。目标发布目录必须独立于 root-only State，已有目录需项目所有权标记；按本机实际组号设置，不沿用源主机 UID/GID。不要把整个 State 设置为服务可读。

监听、连接端点、TLS 名称、NAT 映射与公网 DNS 是不同条件。迁移保留节点身份和原端点；需要换地址时用已有批量编辑/端点预览明确修改，再重发受影响的客户端配置。包不能替用户切换域名、云 NAT、外部反向代理或远端 WireGuard；跨机器完成情况分别核对。缺少 IPv6、低端口权限或目标核心时应给出具体限制，配置解析通过不能替代目标链路验证。

恢复先解密、限制条目并验证，随后暂存资产、候选校验，保存目标机原版本的加密恢复材料，再提交。资产目录切换与 State 事务有独立恢复记录；失败先选回原资产再恢复服务。查询不越过该记录自动修复。

## 中断、回退与降级

```bash
qingnode doctor
qingnode restore --recover-migration --yes
```

若存在 `migration-restore.json`，普通写入会拒绝继续；显式恢复依照记录判定 State 是否已提交，选择相应资产后恢复原运行状态。恢复失败时保留记录与旧资产，不手工删除后盲目启动。配置已提交但订阅发布失败会明确报告，需要修复发布，不能只倒退一半资产。

### 安装卸载及附属服务的保留材料

这三类材料与加密迁移包不同，必须按对应入口处理：

| 保留材料 | 含义与恢复方式 |
| --- | --- |
| 安装器报出的私有临时目录与安装日志 | 原管理器、原服务定义等安装前副本；按当次日志核对来源、原路径和权限后人工处理，没有任意临时目录导入接口 |
| `/var/lib/qingnode/uninstall.json`、文件旁的`.qingnode-uninstall`及`/var/lib/qingnode/.uninstall-cores` | 核心卸载/恢复记录与暂存原件；排除外部修改后用可信管理器执行`qingnode recover`，该命令不接受`--yes`或`--preview` |
| `/var/lib/qingnode/.auxiliary-名称.journal.json`、`.installed.json`、`.recovery-ID.json`及可能的`.conflict.json` | 独立监控/订阅的私有v1记录；用`service recover --name 对应服务 --preview`核对，再以`--yes`显式恢复；不能替代核心卸载记录 |

source18的安装器只接受原文件或本轮已经写入的候选，重核字节、权限、属主、属组、链接数及服务加载来源。核心卸载在第一次服务查询前保存同类文件的长度和SHA256等内存指纹，后续查询、停止/启用/重启、搬移均比较同一份基线；恢复加载定义后不重新认领文件。等待期间发现外部变化，自动恢复也停止后续控制并保留外部内容。完整卸载拒绝辅助目录中除`.qingnode-owner`和`install.sh`之外的未知成员，不凭目录标记删除管理员新增文件。指纹只在本轮内存中保存，没有改变旧`uninstall.json`或State9格式；显式恢复旧记录仍须先核实当前原件的来源。

附属`.conflict.json`是冲突见证：原主记录被改写或删除后，已授权的写操作以独占创建方式保留原始事务字节。单独见证仍会阻止部署、完整卸载和迁移；`service recover`不会猜哪一份应生效，不自动重建主记录或删除见证。不要先删除唯一恢复副本来让检查通过。历史归档及恢复搬移拒绝覆盖已有目标，不支持必要原子操作时保留材料并报错。

处理顺序是：暂停并行维护，记录当次报错和原运行/自启状态；给现有外部文件与全部恢复材料保留独立私有副本；只读检查文件类型、权限、属主、链接及摘要，再在本机核对完整内容和服务来源；由管理员明确决定保留哪套外部设置后，才排除冲突并使用可信管理器恢复。不要执行怀疑已被改写的管理器、OpenRC服务脚本或归档中的任意命令。`before-uninstall-*.json`是可能含完整代理凭据的私有State快照，不是完整加密迁移包，不应贴到日志或工单里。

以下例子只读固定路径的元信息和摘要，不显示State、私钥或订阅内容；缺失路径跳过：

```bash
sudo bash <<'QINGNODE_READONLY'
for path in /var/lib/qingnode/uninstall.json \
  /etc/systemd/system/qingnode.service /etc/systemd/system/qingnode.service.qingnode-uninstall \
  /etc/init.d/qingnode /etc/init.d/qingnode.qingnode-uninstall \
  /usr/local/bin/qingnode /usr/local/bin/qingnode.qingnode-uninstall \
  /usr/local/lib/qingnode/install.sh /usr/local/lib/qingnode.qingnode-uninstall/install.sh \
  /var/lib/qingnode/.auxiliary-qingnode-monitor.journal.json \
  /var/lib/qingnode/.auxiliary-qingnode-monitor.conflict.json \
  /var/lib/qingnode/.auxiliary-qingnode-subscription.journal.json \
  /var/lib/qingnode/.auxiliary-qingnode-subscription.conflict.json
do
  if [[ -e $path || -L $path ]]; then
    stat -c '%F %a %u:%g links=%h bytes=%s %n' -- "$path"
    if [[ -f $path && ! -L $path ]]; then sha256sum -- "$path"; fi
  fi
done
QINGNODE_READONLY
```

systemd还可只读运行`systemctl show qingnode.service --no-pager --property=FragmentPath,DropInPaths,ActiveState,SubState,MainPID,UnitFileState`。OpenRC脚本与`conf.d`尚未核实时，不通过执行该脚本的status来代替文件核对。已核对来源与冲突、准备恢复时才执行：

```bash
sudo qingnode recover
sudo qingnode service recover --name qingnode-monitor --preview
sudo qingnode service recover --name qingnode-monitor --yes
# 订阅服务使用同一入口，名称为qingnode-subscription。
```

已安装管理器损坏或被卸载时，改用已核实架构、版本与摘要的本地发行包管理器绝对路径。`uninstall.json`消失但暂存文件残留可能表示卸载已提交、清理未完成，不能编造记录强行回退；没有待办的recover也不证明残留已恢复。恢复后仍要核对服务来源、运行/自启、身份与真实连接。最后一次本地检查与替换之间，另一root仍能同时改写，保护不构成跨root的全局原子事务；维护时避免并行修改同一资源。

State在第07批因证书资源升为schema6，第08批因真实API/到期字段升为schema7，第09批因新协议语义和选项升为schema8，第10批因firewalld语义升为schema9。旧1–8严格读入后只在内存转换，保留ID、代理凭据、证书材料、原ACME路径及旧URI；第一次有意义写入保留旧配置代。旧QNBK1/2继续读取；完整包为QNBK3，包内类型版本为1，未来版本明确拒绝。当前管理器恢复旧快照写schema9，不能拿rollback/restore当成旧管理器降级工具；不要删未知字段、改版本号来伪装兼容。真正降级须停止服务，使用保留的旧格式原件与匹配二进制，在隔离环境验证后恢复。

QNBK3 沿用 AES-GCM 与 PBKDF2-HMAC-SHA256（600000 次）的既有保护，未降低口令强度。内部是有类型、无压缩的条目清单，无 tar 解包或可执行条目。限制：加密包至多 96 MiB、资产总量 64 MiB、单文件 16 MiB、1024 条；State 仍受 8 MiB 限制。拒绝路径穿越、绝对条目、反斜线/驱动器别名、重复条目、未知根/类型/字段、文件/目录冲突、符号/硬链接、不合规权限和摘要不符。受管 ACME 存储作为核心数据保留，不执行其中任何文件；订阅目录只允许明确的标记和快照文件。没有压缩步骤，避免压缩膨胀；每项资产仍由外层认证加密保护。

包内版本清单单独为 v1，记录来源 OS/架构、管理器版本与可用的修订号、核心版本与来源摘要、服务管理器；没有安装核心或没有摘要时保持未知，不推造证据。来源清单不强迫目标使用同一个二进制文件；目标仍从可信官方发行按架构/版本/标签准备。文件引用的结构可解密和预览，即使目标尚未有这些外部文件；实际导入、生效仍必须通过 SAN/私钥配对/有效期/权限强校验。

## 受管备份保留

```bash
qingnode backup --prune --retain-count 10 --retain-age 720h --retain-bytes 268435456 --preview
qingnode backup --prune --retain-count 10 --retain-age 720h --retain-bytes 268435456 --yes
```

只清理项目私有备份索引确认拥有且摘要匹配的备份，不按扩展名扫描删除用户文件。份数至少 1；当前恢复点和最近完整迁移点都受保护，即使后续普通配置备份成为 current，也不能删掉证书资产的最近完整恢复包；因此两点不同时可能保留至少两份，并暂时超出时间/容量上限。恢复前自动生成的完整包同样登记保护。先预览待清理清单；损坏索引、外部改动或无法确认所有权时拒绝，不能误删唯一可恢复材料。其它目录中的手工备份不自动纳入保留策略。
