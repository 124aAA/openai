# QingNode 0.3.0 架构

第11批把已有功能整理为七类任务入口：快速建节点、管理节点/用户、导出/订阅、测速诊断、证书与备份、进阶网络、系统维护。分组仅调用原CLI和事务，不另建状态来源或协议配置器。State继续为9，默认官方核心继续为1.14.0；本批不新增协议、持久字段或TUI依赖。当前实现与最终实测分开记录在[BATCH11.md](BATCH11.md)，短流程和脚本契约见[GETTING_STARTED.md](GETTING_STARTED.md)、[WORKFLOWS.md](WORKFLOWS.md)。本批同字节Ubuntu/systemd VM与完整22项本地门槛的准确证据见实施记录；手机SSH/GUI、公网和原生ARM仍未验证。

第10批将宿主探测、包依赖、服务生命周期/定义、计划任务和防火墙效果集中到小型适配边界：`internal/platform`与既有node后端。systemd原unit保留，OpenRC使用标准supervise-daemon，订阅/监控共享服务管理接口。当前State9只因新的firewalld值升级，旧1–8只在内存迁移；协议与身份不改变。实现/实际平台证据见[PLATFORMS.md](PLATFORMS.md)、[BATCH10.md](BATCH10.md)。下方各前批描述保留历史范围。

未发行第09批新增AnyTLS/Trojan/传统SS AEAD/TUIC，当时State为schema8，旧1–7只在内存兼容；适配器、监听/业务能力登记与共享TLS证书投影接入现有事务。该批代码d0fd58a的定向25/25项、独立能力补测与五步构建通过；完整回归的准确提交与保留失败另列，详见[PROTOCOLS.md](PROTOCOLS.md)、[BATCH09.md](BATCH09.md)。各前批格式和结果保留历史范围，当前State以上方第10批为准。

架构仍为轻量Bash/Go/sing-box与本机systemd/OpenRC。第08批结束时State因观测API与凭据到期字段变为schema7，当时旧1–6只读内存兼容；第09批当时为schema8，第10批当前为schema9、兼容旧1–8。默认配置备份保持 QNBK1/2 可读，完整迁移另用 QNBK3 typed v1。前批实现与证据见 [BATCH_01.md](BATCH_01.md)、[BATCH_02.md](BATCH_02.md)、[BATCH_03.md](BATCH_03.md)、[BATCH04.md](BATCH04.md)、[BATCH05.md](BATCH05.md)、[BATCH06.md](BATCH06.md)；当前证书/迁移接口见 [CERTIFICATES.md](CERTIFICATES.md)、[MIGRATION.md](MIGRATION.md)，监控/到期接口见[MONITORING.md](MONITORING.md)；第07批实际执行见[BATCH07.md](BATCH07.md)，第08批准确源码与环境边界见[BATCH08.md](BATCH08.md)。版本/客户端/平台边界见 [CAPABILITIES.md](CAPABILITIES.md)；v0.2.8 历史证据不代替当前实测。

## 保留的主干

Bash引导 → Go管理器 → 统一JSON State与配置代 → 官方sing-box → 本机systemd/OpenRC。保留语言、JSON持久化和轻量服务运行模式，不引入必装Docker、面板或数据库服务；格式变化使用明确schema。

| 模块 | 职责 |
| --- | --- |
| install.sh | 系统识别、依赖、发行包校验、账户与文件安装、捕获失败回滚 |
| cmd/qingnode/main.go | 参数分派、全局选项、核心安装/更新 |
| nodes.go / menu.go / menu_tasks.go / menu_guidance.go | 节点与凭据生命周期、七类任务入口、客户端/证书/公网条件建议；不以服务器探测排名用户体验 |
| menu_preview.go / batch.go | 同一持锁候选的派生影响预览，复用Store.Preview与Apply；不重新生成身份 |
| status_report.go / cli_output.go | 版本1公共状态/帮助/版本与脱敏错误；JSON保持独立机器格式，不输出State认证 |
| doctor_report.go / ports_report.go / query_reports.go | 独立版本1诊断、受限监听及公开对象声明；未知、未测与失败不归为通过；不拼接普通文字到JSON |
| execution_report.go | 全局可选私有执行回执，实际观察Apply确认与派生发布回调；开始/结束分文件、原子不覆盖发布，不复制stdout、参数或State；错误不等于未提交 |
| terminal_password.go / internal/ui/terminal*.go | 实际TTY宽度、受限文本清理和隐藏口令读取；中断恢复原termios |
| diagnostics.go / operations.go | 状态、诊断、日志、服务及卸载 |
| dashboard*.go / internal/node/overview.go | 只读本机总览、独立观测历史、显式更新查询与公网实测登记 |
| backup.go / system.go | 快照 CLI、网络、防火墙、管理器更新 |
| internal/node/model.go / endpoints.go | 当前schema=9 State、稳定 ID、独立本地/客户端地址、结构校验 |
| certificates.go / certificate_chain.go / certificate_files_linux.go / certificate_observation.go | 稳定证书资源、独立节点投影、显式导入完整路径验证、真实文件身份与权限、限量只读证书/日志观测；旧格式读取不依赖当前信任库，客户端指纹兼容另验 |
| migration*.go / quiesce.go | QNBK3 typed资产、来源版本清单、停止证明、暂存/恢复journal、严格路径与自有备份保留；沿用既有认证加密 |
| cmd/qingnode/certificates.go / migration_preflight.go | 私有证书输入、引用/共享影响预览、本机目标环境与路径映射；不在查询中签发或修复 |
| topology*.go / failover.go / wireguard_pair.go | 独立远程出口、固定目标中转、引用/环/UDP 校验、实际图派生、主备决策和双端材料 |
| state_format.go | State 显式版本解码入口，拒绝未知格式/字段，读取不落盘迁移 |
| protocol_*.go / protocols.go | 各协议认证、校验、配置、URI、客户端格式与网络类型 |
| store.go | 所有权、互斥锁、配置代、事务和回滚 |
| impact.go / impact_runtime.go | 实际展示/导出/服务器/宿主影响，外部核心与受管服务文件校验材料 |
| cmd/qingnode/batch.go | 原状态解析批量目标、整体候选校验、单次应用及只读预览 |
| internal/probe / cmd/qingprobe | 独立版本化网络报告、预算/统计/对比、SOCKS5 测试及受控 UDP 回应；桌面助手不加载服务端 State |
| core.go / releases.go / internal/platform | 官方下载、摘要、版本与本机systemd/OpenRC服务后端 |
| port_bindings.go / capabilities.go | 候选监听实际绑定预检、安装前本机能力；与远端链路证明分开 |
| cmd/qingnode/endpoints.go / capabilities.go | 显式连接入口管理/外部材料、只读能力报告 |
| cmd/qingnode/topology.go / egress_health.go / wireguard_pair.go | 严格拓扑批量、隔离出口图探测、显式主备应用与逐端配对材料 |
| firewall.go / host.go / removal.go | UFW 效果、BBR、事务卸载 |
| internal/ui/catalog.go | 简体中文菜单文本及稳定键 |

协议注册表是编译期适配，不从任意路径加载脚本。当前七协议仍各自接入参数创建/交互和测试，没有宣称完全插件化；完整英文尚未实现。能力登记的outbound指客户端配置导出，远程Egress由独立受限类型处理，仍只有SOCKS5/REALITY/SS2022/HY2/WireGuard，不由七协议注册表自动扩展。

## 交互与机器输出边界

菜单建议只使用用户已知的客户端能力、域名/证书、TCP/UDP公网条件、NAT和资源条件，允许未知与修改选择。字段及候选校验先于应用，菜单的修改通过同一Store锁内生成的同一候选调用真实派生影响比较，展示节点、本地监听、客户端入口、重启及宿主效果；原有高影响动作的明确确认保留。创建表单取消、EOF或字段错误不提交半个节点；已经进入Apply的中断仍按原事务和显式recover处理，不能当作表单撤销。

`help --json`、`version --json`、`overview --json`、`status --json`、`info --json`、`list --json`使用各自版本1公共投影。`edit`和`batch`只有同时指定`--preview --json`才输出变更影响。未知、陈旧或配置摘要不匹配的历史不能变成通过；服务状态、本机观察和管理员手工公网记录分别标明。只读加载不修复事务或启动服务。其他已有命令的JSON和文件契约仍按各自帮助，不增加通用的隐式`--json`或stdin约定。

普通创建、安装完成摘要和默认节点信息不展示认证与完整链接；显式`export`、`info --show-secrets`等私有输出仍按原授权接口取得。版本化JSON不含节点用户密码、私钥或内部出口认证，不把root-only State开放为公共视图。普通错误清理控制序列并隐藏无效参数值中的潜在秘密，导出内容不经过人类文本折行器。

人类菜单、总览和提示使用真实TTY宽度，中文宽字符与常见组合emoji按Unicode15.1表处理；NO_COLOR、TERM=dumb和非TTY使用纯文本，非TTY机器输出保持原结构。终端字体对模糊宽度仍可能不同。表单输入有字节上限，`:cancel`明确取消；隐藏口令同步等待并在SIGINT/SIGTERM后先恢复原termios，再返回130/143。程序不依赖raw模式、动画或隐藏光标。32/40/80列PTY、物理手机SSH和客户端GUI是三种独立证据，当前状态见本批记录。

## 状态与身份

State 保存 core_version、可选核心归档摘要、Firewall 模式、Nodes、项目 DNS，以及独立 Egresses、EgressPolicies、Forwards。Node 保存稳定 ID、名称、协议、本地 Listen/Port、主客户端 Host/ConnectPort、可选 AdditionalEndpoints、Enabled、Users、出口 EgressID、协议参数及可选创建/更新时间。空 EgressID 保持旧 direct。主端点 ID 为 default，最多 16 个额外显式 ID。`WithEndpoint` 只生成某次导出/探测用的客户端投影，返回值不能持久存回 State；原节点声明仍是编辑与事务的来源。旧节点迁移显式固定原 Port 为 ConnectPort；新 CLI 创建也显式保存。0.1.0 的历史创建时间未知时不虚构补填。

REALITY 以 X25519 私钥、公钥、short ID、SNI、握手目标和 fingerprint 存储；flow=xtls-rprx-vision 与 TCP 由适配器派生，避免重复来源。SS2022 保存固定方法、独立服务密钥和每个用户独立密钥，用户客户端口令组合为 server:user。HY2 保存密码与 certificate_id，Certificates 统一保存 PEM、用户文件引用或 ACME；旧 Node.Certificate 仅读入内存投影，schema6不重复持久化私钥。普通节点编辑独立复制资源，共享资源更新显式影响所有引用；用户文件与ACME运行存储所有权分别处理。

首次生成后持久保存；普通修改复用身份。时间戳仅在有意义的节点变更时更新。同一份 State 生成服务器、URI、二维码、sing-box JSON 与 Mihomo YAML。使用标准序列化器和进程参数数组，无 eval。

节点和凭据选择先在完整集合中匹配稳定 ID，再按名称匹配。名称与其他对象的 ID 相同不会改变 ID 的含义；原有名称查询仍可使用。状态文件读写共用 8 MiB 字节上限：正好达到上限的单份 JSON 可以读取，超限和额外 JSON 均拒绝；候选 State 编码超限时，在创建候选代之前退出，保留原状态、current 和服务。

## 文件与权限

| 路径 | 用途 / 权限 |
| --- | --- |
| /var/lib/qingnode/.qingnode-owner | 所有权标记，root 600 |
| .lock | 状态互斥锁，root 600，拒绝符号链接 |
| generations/g-ID/state.json | 含完整凭据，root 600 |
| generations/g-ID/server.json | 核心必需配置与私钥，root:qingnode 640 |
| generations/g-ID/core-version | 核心版本，root:qingnode 640 |
| generations/g-ID/parent | 上一代名称，root 600 |
| generations/g-ID/runtime-identity | 运行输入校验材料 format=1，root 600；旧代缺失可在写操作验证后补入新代 |
| current | 受控相对符号链接，只允许指向合法配置代 |
| transaction.json / uninstall.json | 持久事务记录，root 600；配置事务新增 version=2 envelope 并兼容旧记录 |
| observations.json | 首页观测历史，root 600；不属于 State、配置代或备份 |
| cores/版本/sing-box 与 .sha256 | 官方核心及本地完整性摘要 |
| acme | 服务账户可写，750；不在默认配置快照，完整迁移须取得一致停止证明后纳入 |
| backups | 加密快照，目录 700 / 文件 600 |
| /usr/local/lib/qingnode | 带所有权标记的安装辅助脚本 |
| /var/backups/qingnode | 卸载前明文快照，目录 700 / 文件 600 |

systemd核心unit继续使用嵌入源文件 `internal/node/qingnode.service`；OpenRC定义由 `internal/platform` 的类型化服务参数生成。安装器通过 `qingnode service unit --manager` 取得对应内容，不执行外部任意脚本。代理使用专用非root用户，不读取root-only State；systemd沙箱与OpenRC监督/ambient权限机制不同，真实有效权限及限制见[PLATFORMS.md](PLATFORMS.md)。订阅另用只读账户，监控管理权限单独说明。

## 配置事务

持锁 → 读取 State → 比较实际派生运行配置、客户端对象、核心与受管服务输入、项目防火墙效果，并检查磁盘派生文件 → 写候选代并 fsync → 校验核心摘要/配置一致性/官方语法/证书日期/端口 → 再核对外部输入 → 写版本化事务记录 → 有宿主规则变化时添加所需项目 UFW 规则 → 原子切换 current → 有运行输入变化时按旧应用规则启停并核对 MainPID socket inode 与监听地址/端口 → 有宿主规则变化时删除过时项目规则 → 提交。

展示/导出与服务器运行/宿主效果分开比较，名称影响 URI/Mihomo 显示名，客户端 server/fingerprint 按实际导出对象识别。服务器和运行输入相同时，保存新 State 和历史却不调用 Activate/Stop，原本运行或停止、自启状态保持。运行变更仍按原规则应用：有启用节点、中转或用户态 WireGuard 监听时会启动/重启，即使此前临时 stop；所有受管监听停用或移除则停止。单独项目 UFW 规则变化同步规则，不单独重启核心。

外部输入校验材料记录核心路径/内容 SHA-256、受管 unit 文件来源/内容摘要和固定核心调用参数。它只覆盖本项目管理的 unit 文件，不声称核验已加载的全部 systemd 属性或管理员额外 drop-in；这些仍需真实宿主检查。元数据编辑不会重写 unit 或执行 daemon-reload。旧代缺失材料时，查询不写入；首次写入先校验候选再保存新代，避免第一次改名为了补材料重启。

原状态和派生文件均未改变时不新建配置代、不换参数；派生文件损坏时仍完整检查并用保存的身份重建，原损坏代留作恢复材料。元数据回退与运行回退复用相同分类。失败候选未被事务引用则清理。提交前出错按影响回退指针、UFW 和之前的运行/停止状态；若恢复也失败保留记录并报告。断电后下一次写操作恢复未提交事务。

新事务用 `transaction_v2` envelope 保存 version=2、前后指针、原运行状态、运行/宿主变化。旧事务按旧重启/效果语义恢复；新记录不给旧管理器可误解的旧 top-level 指针，因此旧版拒绝 pending 新事务。降级前先用本批管理器恢复并确认无未完成记录，不删未知字段伪装兼容。第01/02批State为schema1；第03批HY2/DNS为2，第04批连接端点为3，第05批拓扑为4，第06批设备/标签为5，第07批证书资源为6，第08批观测API/凭据到期为7，第09批新协议语义与选项为8，第10批firewalld语义为9。当前旧1–8解码只在内存升级，restore/rollback写9。默认配置备份仍v1/v2，完整迁移使用QNBK3 typed v1与单独资产恢复记录。

普通查询 list、info、export、render、check、core check、firewall status，以及 status、logs、doctor、overview 使用 Inspect 读取节点状态，不创建核心目录、不自动恢复或重启。节点选择菜单也走只读路径。部分查询发现事务记录会提示管理员显式执行 recover；查询读取 current 指向的状态并提示它尚未确认提交，不把打开信息页面当成恢复授权。写操作继续持 WithLock 锁，在修改前恢复未完成事务；显式 recover 也使用这个路径，可能恢复 current、项目防火墙规则及原服务状态。

这里的“只读”指不改变节点配置或服务；导出可以写用户指定的输出文件，doctor 完成后在同一锁内另存自检历史。状态损坏不会伪报数据库正常。严重损坏的数据库/历史代不能凭空恢复，拒绝猜测参数。

## 首页与观测历史

首页只读 State、私有 observations.json、/proc 与本地文件系统；systemd 属性查询最多等待 650ms。服务状态与客户端公网结果分开渲染。资源缺失显示未知，证书从 PEM 解析，ACME 实际签发期限未知时不猜测。

自检、成功备份、显式更新查询、管理员登记公网测试分别更新观测文件，在 Inspect 或已有操作锁内以 0600 原子写入，不改变配置代。读取拒绝符号链接、宽松权限、超限文件及未知字段。自检绑定完整 State 摘要；公网记录绑定节点、核心和 Firewall 模式，配置变化提示重验。历史不进入备份，不作为配置恢复依据，也不代表持续可用。

check-updates 在释放管理锁后并行查询两个固定 GitHub Release API，再持锁合并结果。首页仅显示缓存；失败保留上次成功内容并标记最新失败，不会触发升级。

## 系统边界

网络测试与生产配置事务分开。`internal/probe` 不依赖 Store，不执行 Apply、recover、systemctl、UFW 或 sysctl；服务器 CLI 只读选择节点和用户，从现有官方客户端导出生成私有测试资料。代理测试启动独立官方 sing-box，目录和端口临时分配；普通入口测试只保留一个所选代理出站，内部出口图测试只保留明确的 detour 依赖闭包。两者失败均不改用 direct，不设置系统代理/TUN/全局路由。HTTPS 使用明确的本机 HTTP CONNECT transport，UDP 保留 TCP association 并发送标准 SOCKS5 UDP 帧，实际代理协议传输由官方核心负责。

隔离核心的临时 mixed 入站使用独立随机用户名/密码；SOCKS5 UDP 按 RFC 1929 完成认证且拒绝降级。随机认证只保护本机入口，不代替进程归属证明。就绪检测另要求该端口属于本次子进程 PID：Linux 读取监听 inode 和 `/proc/PID/fd`，Windows 查询 OWNER_PID TCP 表，失败拒绝测量；它与生产 systemd MainPID 检查是两个入口，不接管其他进程。

自动测量使用独立 Profile/Report 格式，普通直连保持 `version: 1`；含内部出口的入口 Profile 和报告使用显式 `version: 2`，增加 `server_path_sha256`。它只绑定导出时实际选择的出口及 detour 闭包、核心和项目 DNS，不带落地凭据，也不能证明远端现在仍使用该配置。`NewProfile` 默认 v1，`WithServerPathDigest` 显式升级；CA 覆盖和启动失败报告均保留绑定，摘要不同拒绝直接对比。v1 不能夹带新字段，旧二进制拒绝 v2，未知版本不降级解析。

报告不进入 State、配置代、备份或 `public-check` 手动历史。JSON 保留原始样本、错误、条件、预算及有效载荷消耗，未知数值为 null；目标只记录 HTTPS 源地址与完整 URL 摘要，不泄露路径/查询串，也避免不同隐藏目标被误比较。测试资料含入口凭据，按私有文件保护，不能公开为报告。清理只覆盖本次进程、监听和临时文件；强制终止/断电后的清理边界单独说明。

端口检测读取本地 Listen/Port/协议，既检查实际可绑定性，也通过 `/proc` 对照 systemd MainPID 的 socket inode，避免将其他服务误判为本项目就绪。确定冲突按传输层、具体 IP 和通配范围校验；不确定的跨族通配语义交给同时持有候选 socket 的实际绑定预检，无法核实旧 socket 时拒绝冒险。SS2022 同时预留 TCP/UDP。预检关闭后仍存在抢占窗口，由启动失败回滚处理。

监听地址按 IP 实际含义比较，IPv6 展开与压缩写法视为相同，自有监听键统一但不重写 State。比较仍要求同一所属进程、传输层与本地端口。固定核心的 0.0.0.0 使用 IPv4 绑定；:: 采用通用 TCP/UDP 的自动双栈策略，没有 v6only JSON 字段，不能只看全局 bindv6only 或 proc 的 tcp6/udp6 保证真实族行为。本机/公网各地址族需分别收发验证。

客户端 URI、QR/Base64、sing-box、Mihomo 与 Profile 统一读取所选 Host/ConnectPort；额外端点只投影客户端副本，不增加服务器入站或修改 SNI/REALITY 目标。影响分类遍历全部端点×用户，公开端点变化使客户端摘要/手动历史失效；服务器与项目规则相同时不调用服务重启。外部映射按协议列为待验证声明，不管理云 NAT；SS2022 单入口仍要求同一外部端口 TCP+UDP。

`ProbeCapabilities` 独立于 State：读取架构、init、可见资源、权限/容器、TUN 与固定路径/内核值；默认分 TCP4/UDP4/TCP6/UDP6 临时绑定与 32 字节回环，全部自有 socket 退出关闭。不实际写目录、创建 TUN、加载模块或调参。available 与 exercised、远端 unknown 分开；能力报告不能证明代理认证、服务沙箱或公网路径。

UFW 自动管理仅针对已启用 UFW 中可识别的本项目注释标签；绝不调用 flush/reset/enable，不覆盖外部规则注释。先增后删，每次按编号删除前重新核对内容。SSH 端口和不确定规则保留。复杂混合防火墙策略、云安全组和共享 TCP 80 人工处理；外部并发改规则或后端不可用仍可能要求人工完成恢复。

宿主网络是独立显式事务，`NetworkHost.Plan/Apply/Restore/Status` 只允许有限 TCP 算法、default_qdisc、rmem_max/wmem_max。原 `network bbr` 是 bbr+fq 的应用别名；计划只读，应用前保存原始文件与运行值、逐项写回核验。恢复仅在运行值仍等于本次值时回到原值，外部手改保留；受管文件遭外部编辑则拒绝覆盖。自有 sysctl 文件与私有原始快照不进入节点 State/配置代，节点 rollback 不擅自恢复宿主参数，卸载不改变用户网络选择。TCP BBR 与 HY2 用户态 QUIC BBR、默认 qdisc 与实际接口队列分别展示。

宿主原始快照 version=1 不可变；pending version=2 持久记录 touched/restore_file，避免失败恢复改动从未尝试过的字段或误认本次已恢复的文件。正常 active version=1；保留外部手改的链式恢复用 version=2 active 记录调整后的文件检查点。只识别明确的格式组合，未知版本拒绝。有效内存由 `AvailableMemory` 取宿主 MemAvailable 和当前进程可见 cgroup v1/v2 祖先余额的最小值，约束证据缺失则未知，不把宿主 RAM 冒充容器可用内存；它不预留内存、不保证总 RSS，也不测量远端客户端或独立服务 cgroup。

## 第 03 批的持久选择与适配

`Node.HY2` 保存 HY2 两端不同方向的带宽/拥塞选择和有限 transport 参数，`State.DNS` 保存仅服务器进程的局部 resolver。可选数值/布尔使用指针表达“未保存”与明确值，空配置保持旧生成语义。`HY2Performance` 校验方向组合、范围与约束；适配器分别生成入站、sing-box 出站和 Mihomo 对象，URI 不增加假性能 query。导出经过版本/构建能力和格式损失检查，显式允许有损时返回 warnings；Chrome 覆盖也明确提示，不擅自改变原默认。

新字段参与真实服务器配置与客户端输出比较，复用 Store 锁、候选校验、原子代切换和恢复。客户端性能变化保存一致新 State/历史而不启动或重启服务；服务端/DNS 改变实际运行配置时沿原服务规则应用。普通编辑不生成新凭据，损坏派生文件不因客户端变化而跳过完整检查。方案关联的前后报告只允许已保存方案声明的配置摘要变化，不修改原样本或绕过其它条件。

schema2–9分别对应实际字段或新语义。当前 `DecodeState` 严格读取schema1–9，旧1–8通过 `MigrateState` 仅在内存升级；schema1/2每个节点显式保存原连接端口，schema1/2/3保持旧direct，schema1–4不凭空增加设备绑定，schema1–5的内联证书转为稳定资源且保留原ACME存储，不改Host/Listen/Port、身份或原URI。任何查询不写新代；首次实际写入保留原旧代和字节材料。旧schema偷塞新字段（含null）或未知字段明确拒绝；schema6起不再持久化重复的节点内联证书。未来格式须新增解码/迁移，不降schema数字骗旧二进制。旧快照经同一入口恢复且身份保持。

第09批当时恢复旧快照和节点rollback写schema8，第10批当前写schema9，不会自动降成旧管理器可读格式。原始schema1–8代/快照保留作独立离线恢复材料；不提供自动降级管理器的事务。新旧二进制、State与外部服务效果必须一同验证，不能把恢复旧节点参数当成已验证程序降级。

DNS 诊断独立报告 version=1，记录查询端、地址族、预算、原始地址/耗时与可选 expected 匹配；无 expected 不判断内容正确，不将缓存影响解释成线路改善。`ProjectDNS` 仅生成服务器 sing-box 的 local/UDP DNS，字面 UDP resolver 避免 bootstrap 循环；客户端 bootstrap 不沿服务器设置自动改写，宿主 resolv.conf 不写。

卸载先记录运行/自启状态，将固定项目路径改名保留，成功完成服务操作后提交删除；中断时恢复原路径。目录初始化让位于卸载恢复，避免提前创建空 cores 挡住原目录归位。完整卸载保留专用账户，避免误删账户资源；同时写入私有账户归属记录，供重装时精确核对 passwd/group，未知或身份变化的账户拒绝接管。

Bash 安装器有独立引导锁，替换管理器/unit 时也持状态锁，捕获错误后恢复旧文件。SIGKILL、断电及文件系统故障不在 Shell EXIT trap 保证范围内，可能需要重跑已验证安装包。没有事务能够保证外部 systemd/UFW 持续失效时仍自动恢复成功。

## 第 05 批的服务器拓扑

本地代理入站、固定目标 PortForward、远程 Egress 与 EgressPolicy 分开保存。服务器生成仅使用启用监听引用的出口闭包；普通客户端导出只使用入口地址与原入口用户。`direct` 入站的 override_address/override_port 承担纯 TCP/UDP 中转，本身不提供用户认证；本批无需增加 Realm/GOST 数据面。未引用的出口编辑不改变运行配置，引用它的节点与中转按实际派生图展示影响；共享核心仍可能整体重启。

远程 SOCKS5/REALITY/SS2022/HY2 凭据与本地 Users 独立，WireGuard 私钥/Peer 另有受限类型。持久引用只用稳定 ID；detour 只引用真实出口，不把可切换策略塞进链中。校验包含删除引用、环、DNS 引导、入口/隧道自身回流、实际载荷与各链段自身需要的 TCP/UDP。既有协议节点可能承载 UDP，因此不能绑定只声明 TCP 的完整路径。只允许模型字段，拒绝任意 JSON、脚本、Dial 参数注入或隐式 direct 备用。

WireGuard 使用 sing-box 顶层 endpoint，固定 `system:false`，要求 `with_wireguard` 与 `with_gvisor`。服务保持原专用用户与低端口绑定权限，不创建 wg0/TUN、宿主路由或 DNS。固定监听的 UDP4/UDP6 是两只独立 socket，就绪和预检分别核对，不套用普通 `::` 单 socket 的自动双栈推断。落地 endpoint 的入站 tag 明确选择接收出口，配对默认显式 direct；AllowedIPs、MTU、保活与真实目标数据分别验证，不把握手当落地成功。

`egress health` 使用严格私有 GraphProfile 和独立临时官方客户端，记录各出口及其上游路径；公开 qingprobe 不接受任意图 JSON。默认只测量，不累计或切换；显式 `--apply` 才按 HTTPS/可选受控 UDP 结果保存观测并应用，`--watch` 只在有限前台预算内重复。观察绑定两条候选的实际图、核心、DNS 和健康条件，写入锁内重核，未知/取消/本机工具失败不冒充远端失败。失败阈值、恢复阈值和冷却共同控制主备，不迁移已建立会话。

`egress-health.json` 是独立的私有 version 1 观测，不进入 State 或备份。选择成功但观测写入失败必须分别报告；事务结果无法确认时不能声称未改变。恢复后缺失/失效观测重建保守窗口。探测/等待预算与已开始事务的完成或恢复耗时分别列出。手动公网历史只绑定当前入口的实际出口闭包及关联策略，未用出口/无关中转不会使记录失效；仍是管理员历史登记，不是自动链路证明。

WireGuard pair 只生成两个私有导入文件、分端说明和无凭据 manifest，不自动登录远端。两端不是本地原子事务，分别预览、应用、测试、撤回。节点备份保存完整类型拓扑，恢复仍走候选验证与原子应用；已有宿主 WireGuard、路由和其他 Peer 不在本项目所有权内。

## 备份与版本

v2 加密快照包含 State、服务器配置、受控服务定义和管理器版本；服务器 JSON 损坏时按原始字节保存证据。兼容 v1 状态备份。恢复前自动备份，恢复输入只取经类型校验的 State；不执行快照中的 systemd 文本。卸载的明文 v2 快照必须显式 `restore --snapshot` 并满足私有文件权限。

默认 backup 使用 InspectExisting：根不存在时拒绝且不执行回调；已有目录核对所有权并取得管理锁，再检查 transaction/uninstall/迁移记录。存在记录或无法确认就拒绝备份，不恢复、换配置或启停服务；正常配置备份仍保存加密文件和独立历史。完整迁移显式允许受管核心短停、确认停止后捕获运行资产，并恢复原运行状态；不是普通查询的附带效果。恢复仍经候选与服务事务，资产先暂存并使用独立 migration-restore.json；普通写入不能越过未完成资产恢复，显式恢复先选回正确资产再处理可能重启服务的事务。详见 MIGRATION.md。

核心通过官方 HTTPS Release 下载，HTTP 错误、尺寸上限、SHA-256、版本/构建能力均检查；二进制与摘要一起就位。默认锁定 1.14.0，最新稳定查询也受 1.14.x 适配范围约束。更新保留旧版本及配置代，跨版本需适配后才能启用。

ACME 缓存/账户/已签发证书、全机防火墙、BBR、核心二进制不包含在配置快照中；这不是整机迁移。单进程重启可能短暂断流。此次减少维护中断依靠没有运行影响时免调用重启，不承诺任意配置热重载或零中断；同连接/PID 的真实核心验证与 systemd MainPID 的实机验证分别记录。后续新增字段和效果复用版本解码与实际派生比较入口。

## 第 06 批设备导出与独立订阅

State 新增 Devices（明确 NodeID/UserID/EndpointID 绑定、标签筛选、客户端策略、可选订阅格式子集）和 Node.Tags；schema5 的严格解码只读迁移旧1/2/3/4，拒绝旧schema偷塞这些字段（包括null/Unicode别名）。设备批量输入version1与State版本分开，整体候选验证后沿既有Store事务。Profile/tag只影响客户端时，真实服务器及宿主输入比较不变则不重启；停用实际代理凭据仍按运行影响处理。

`internal/node/device_profile.go` 保存/校验绑定与精确停用；`device_export.go` 复用协议适配器生成入口集合、完整sing-box/Mihomo配置；`cmd/qingnode/devices.go` 提供批量、预览与私有导出。sing-box URLTest与Mihomo url-test/fallback分别适配，不伪造字段或把HTTP测量当UDP验证。实测Mihomo1.19.30存在首成员容差缺陷，完整auto默认拒绝；Profile仅在auto可显式allow_degraded_auto，降级导出每次警告，provider/URI集合不受组限制。sing-box自动容差两版另行通过。基础分流仅内嵌RFC1918/RFC4193四网段，无外部规则抓取或在线模板。

`internal/subscription` 无State/管理/路由依赖，只读version1 Snapshot；`cmd/qingnode/subscription.go` 在管理端生成和原子发布私有快照，服务以专用用户仅组读发布目录。HTTP请求不持管理锁、不启动代理；公开请求只有GET/HEAD，并有尺寸、并发、超时及no-store边界。默认并发4/最多16，逐设备可选发布格式子集与全局发布器能力分别校验；configure保存原配置并只修改明确选项，失败结果分开。TLS直接监听或明确loopback反代二选一；公开链接先经系统信任检查，不强制占用80/443。

首次发布用`subscription.CreateInitial`，同步私有候选后以原子且不覆盖的硬链接安装，已有空/非空快照一律拒绝并保留；普通后续刷新才用`Publish`原子替换。链接后的崩溃可能留下`nlink=2`与两个自有名称，读取拒绝并保留恢复材料，不自动接管或删除。管理配置遗失只能从原私有0600备份核验同目录/同GID恢复，不能靠init覆写注册表。此23dd99f修订已由targeted3同四项CLI红绿回归验证；准确c89f7d1的full9已在静态、普通Go和race执行四项CLI与三项底层测试通过，不借历史full8背书。

`Store.BeforeCommit` 在提交前撤销已移除/停用设备的下载权限，后续代理事务失败或回退不复活撤销；`Store.AfterCommit` 在成功提交后刷新已启用发布，失败明确State已提交并保留旧完整快照。令牌只保存SHA256于独立发布记录，原值一次性私有交付；下载撤销不由State恢复复活。代理凭据停用另行明确授权，共享保护扫描所有仍注册设备绑定，包括只停下载的disabled Profile；整批拒绝连带停用，最后一用户保留身份并停节点。首轮失败与各次中断保留，targeted2/full9实际结果及历史full7证据恢复边界分别记录；迁移、接口、部署与证据见[SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)、[BATCH06.md](BATCH06.md)。


## 第08批有限监控与到期执行

`internal/monitor`独立持久化version1私有计划/状态/有限历史，`monitorAdapter`提供有预算的procfs/核心API/既有probe观察与显式try-restart；既有probe与周期任务共用measurement锁。普通读写计划不恢复State事务，不启动timer。只有保存restart政策且两组独立本机故障、阈值/冷却/滚动预算满足时才尝试动作；远端失败不当本机重启依据。动作前策略/State/derived config/core digest再核验，动作后本机验证与下一轮完整链路验证分开。

`internal/coreapi`用标准库独立实现固定官方gRPC-Web读契约，不链接或复制GPL上游。观测服务仅显式loopback+秘密，不开公网UFW规则；启停服务为真实运行输入变更。流量全局累计按核心生命周期基线/差分，连接reset和无序事件仅观测，不能用户计费或硬配额。

`credential_expiry.go`按稳定NodeID/UserID及可选DeviceID生成全批只读计划；共享设备凭据阻止整批，精确移除绑定并保留其它绑定。用户模型没有Enabled，非最后凭据精确删除、最后凭据保留并停节点，完成记录防普通enable复活。helper仅返回candidate，CLI持锁一次Apply；查询永不执行。`monitor run --apply-expiry`独立显式允许执行，默认off，上轮FinishedAt及DisabledAt用于拒绝时钟倒退。

State保存API配置和到期计划，monitor目录的通知秘密/政策/状态/历史独立私有保存；当前完整迁移发现该目录时记录漏资产，需--allow-incomplete，不宣称覆盖。完整命令/固定来源见[MONITORING.md](MONITORING.md)，当前证据状态见[BATCH08.md](BATCH08.md)。


### 第08批执行证据与当前收尾边界

8e752238的full1已完整执行44项：43项0，唯一原生Alpine宿主识别断言失败保留；普通Go/race各7个有测试包、vet、两版核心netem/三协议/Mihomo/权限与五包构建契约实际通过。候选1.14.3受控CA自然续期601.23秒保持PID10074、账户和HTTPS/UDP前后可用；它不代替真实systemd或公共CA。9b6bb79的targeted5专项15/15另证明真实kill/wait/restart计数基线，以及UDP预检与错误凭据不能被成功目标见证覆盖。9b6bb79独立五包构建/许可/摘要与Windows助手version/help/local已核；ARM只交叉构建。准确日志、回执SHA、失败与复现命令见[BATCH08.md](BATCH08.md)，不称最新源码已重跑full44。

91db289新增从同一轮不可变State快照构造并发monitor Profile，主动probe另持管理锁读快照。该版targeted6窄Linux9项中7项0、CLI/static与snapshot-monitor-race两项1，真实暴露helper错误拒绝direct路径合法空摘要、返回空Profile的回归。4bd1af9保留完整direct v1 Profile并仅对非空路径摘要升级，原断言保持；准确targeted7窄9项全部退出0，8个worker持真实管理锁时配置身份一致且State/保存代不变、原wrapper busy/pending保护保持，相关Linux race/vet通过；最终hostfinalbuild3五步/五包及39项离线发行保护完成。91db的build2步骤成功、9b6的既有五包或前轮通过均不替代修复后功能验收。观察器Collector、动作/复验ActionVerifier、固定核心读API与到期候选helper为后续接入点，各自保留预算/身份/权限/版本门槛。

迁移时State仍含API秘密和到期计划，monitor目录的独立通知授权、政策与历史尚无受管QNBK3资产类型，发现即列缺项并要求--allow-incomplete。目标机重新审查configure/timer及恢复授权，查询不执行到期、不恢复事务；资产journal与服务事务沿既有显式恢复入口处理。第08批当时没有真实systemd/timer证据；第10批对应systemd/OpenRC平台验证见BATCH10，不能倒填为前批成功。公网通知、移动UI与原生ARM仍单列未验证。


最终修复源码为4bd1af90bc7e41bee9d038244992a72e54ef5c64，targeted7原始串口SHA256为c11cc46885560bf86c26cfac1bc23723ceee30b53d772e33c21cdc890e673123。full1的全44项/全量race属于8e752238，最终只做相关补验；独立审计回执另补，不把源版本混合成“最终全套重跑”。最终包SHA、复现命令、保留失败和未验证范围统一见[BATCH08.md](BATCH08.md)。
