# QingNode 0.2.6 架构

## 保留的主干

Bash 引导 → Go 管理器 → 统一 State 与配置代 → 官方 sing-box → systemd。第二阶段没有更换语言、持久化格式或服务运行模式，也没有引入 Docker、面板、数据库服务。

| 模块 | 职责 |
| --- | --- |
| install.sh | 系统识别、依赖、发行包校验、账户与文件安装、捕获失败回滚 |
| cmd/qingnode/main.go | 参数分派、全局选项、核心安装/更新 |
| nodes.go / menu.go | 节点与凭据生命周期、分级交互 |
| diagnostics.go / operations.go | 状态、诊断、日志、服务及卸载 |
| dashboard*.go / internal/node/overview.go | 只读本机总览、独立观测历史、显式更新查询与公网实测登记 |
| backup.go / system.go | 快照 CLI、网络、防火墙、管理器更新 |
| internal/node/model.go | schema=1 State、稳定 ID、结构校验 |
| protocol_*.go / protocols.go | 各协议认证、校验、配置、URI、客户端格式与网络类型 |
| store.go | 所有权、互斥锁、配置代、事务和回滚 |
| core.go / releases.go | 官方下载、摘要、版本与 systemd 后端 |
| firewall.go / host.go / removal.go | UFW 效果、BBR、事务卸载 |
| internal/ui/catalog.go | 简体中文菜单文本及稳定键 |

协议注册表是编译期适配，不从任意路径加载脚本。新增协议还需小幅接入参数创建/交互和测试，现阶段没有宣称完全插件化。TUIC、普通旧式 Shadowsocks 和完整英文未实现。

## 状态与身份

State 保存 core_version、可选核心归档摘要、Firewall 模式、Nodes。Node 保存稳定 ID、名称、协议、Host、Listen、Port、Enabled、Users、协议参数及可选创建/更新时间。0.1.0 的历史创建时间未知时不虚构补填。

REALITY 以 X25519 私钥、公钥、short ID、SNI、握手目标和 fingerprint 存储；flow=xtls-rprx-vision 与 TCP 由适配器派生，避免重复来源。SS2022 保存固定方法、独立服务密钥和每个用户独立密钥，用户客户端口令组合为 server:user。HY2 保存密码及 PEM/ACME 参数。

首次生成后持久保存；普通修改复用身份。时间戳仅在有意义的节点变更时更新。同一份 State 生成服务器、URI、二维码、sing-box JSON 与 Mihomo YAML。使用标准序列化器和进程参数数组，无 eval。

## 文件与权限

| 路径 | 用途 / 权限 |
| --- | --- |
| /var/lib/qingnode/.qingnode-owner | 所有权标记，root 600 |
| .lock | 状态互斥锁，root 600，拒绝符号链接 |
| generations/g-ID/state.json | 含完整凭据，root 600 |
| generations/g-ID/server.json | 核心必需配置与私钥，root:qingnode 640 |
| generations/g-ID/core-version | 核心版本，root:qingnode 640 |
| generations/g-ID/parent | 上一代名称，root 600 |
| current | 受控相对符号链接，只允许指向合法配置代 |
| transaction.json / uninstall.json | 持久事务记录，root 600 |
| observations.json | 首页观测历史，root 600；不属于 State、配置代或备份 |
| cores/版本/sing-box 与 .sha256 | 官方核心及本地完整性摘要 |
| acme | 服务账户可写，750；不在快照中 |
| backups | 加密快照，目录 700 / 文件 600 |
| /usr/local/lib/qingnode | 带所有权标记的安装辅助脚本 |
| /var/backups/qingnode | 卸载前明文快照，目录 700 / 文件 600 |

服务单元只有一份嵌入源文件 `internal/node/qingnode.service`，安装器调用 `qingnode service unit` 取得内容。服务使用专用用户，只有低端口绑定 capability，限制写入、设备、内核和提权；不会读取 root-only State。

## 配置事务

持锁 → 读取 State → 比较真实派生文件 → 写候选代并 fsync → 校验核心摘要/配置一致性/官方语法/证书日期/端口 → 写事务记录 → 添加所需项目 UFW 规则 → 原子切换 current → 启动并核对 MainPID socket inode 与监听地址/端口 → 删除过时项目规则 → 提交。

原状态和派生文件均未改变时不新建配置代、不换参数；只有派生文件损坏时可用保存的身份重建。失败候选未被事务引用则清理。提交前出错回退指针、UFW 和之前的运行/停止状态；若恢复也失败保留记录并报告。断电后下一次写操作恢复未提交事务。

status、logs、doctor、overview 使用 Inspect 读取节点状态，不创建核心目录、不自动恢复或重启；doctor 完成后在同一锁内另存自检历史。状态损坏不会伪报数据库正常。严重损坏的数据库/历史代不能凭空恢复，拒绝猜测参数。

## 首页与观测历史

首页只读 State、私有 observations.json、/proc 与本地文件系统；systemd 属性查询最多等待 650ms。服务状态与客户端公网结果分开渲染。资源缺失显示未知，证书从 PEM 解析，ACME 实际签发期限未知时不猜测。

自检、成功备份、显式更新查询、管理员登记公网测试分别更新观测文件，在 Inspect 或已有操作锁内以 0600 原子写入，不改变配置代。读取拒绝符号链接、宽松权限、超限文件及未知字段。自检绑定完整 State 摘要；公网记录绑定节点、核心和 Firewall 模式，配置变化提示重验。历史不进入备份，不作为配置恢复依据，也不代表持续可用。

check-updates 在释放管理锁后并行查询两个固定 GitHub Release API，再持锁合并结果。首页仅显示缓存；失败保留上次成功内容并标记最新失败，不会触发升级。

## 系统边界

端口检测既检查实际可绑定性，也通过 `/proc` 对照 systemd MainPID 的 socket inode，避免将其他服务误判为本项目就绪。SS2022 同时预留 TCP/UDP。仍存在端口检查与绑定之间的固有竞争窗口，由启动失败回滚处理。

UFW 自动管理仅针对已启用 UFW 中可识别的本项目注释标签；绝不调用 flush/reset/enable，不覆盖外部规则注释。先增后删，每次按编号删除前重新核对内容。SSH 端口和不确定规则保留。复杂混合防火墙策略、云安全组和共享 TCP 80 人工处理；外部并发改规则或后端不可用仍可能要求人工完成恢复。

BBR 是独立选择，只设置系统内核 bbr 与 fq，失败恢复原值和项目文件。卸载不擅自改变用户已选择的网络策略。

卸载先记录运行/自启状态，将固定项目路径改名保留，成功完成服务操作后提交删除；中断时恢复原路径。目录初始化让位于卸载恢复，避免提前创建空 cores 挡住原目录归位。完整卸载保留专用账户，避免误删账户资源；同时写入私有账户归属记录，供重装时精确核对 passwd/group，未知或身份变化的账户拒绝接管。

Bash 安装器有独立引导锁，替换管理器/unit 时也持状态锁，捕获错误后恢复旧文件。SIGKILL、断电及文件系统故障不在 Shell EXIT trap 保证范围内，可能需要重跑已验证安装包。没有事务能够保证外部 systemd/UFW 持续失效时仍自动恢复成功。

## 备份与版本

v2 加密快照包含 State、服务器配置、受控服务定义和管理器版本；服务器 JSON 损坏时按原始字节保存证据。兼容 v1 状态备份。恢复前自动备份，恢复输入只取经类型校验的 State；不执行快照中的 systemd 文本。卸载的明文 v2 快照必须显式 `restore --snapshot` 并满足私有文件权限。

核心通过官方 HTTPS Release 下载，HTTP 错误、尺寸上限、SHA-256、版本/构建能力均检查；二进制与摘要一起就位。默认锁定 1.14.0，最新稳定查询也受 1.14.x 适配范围约束。更新保留旧版本及配置代，跨版本需适配后才能启用。

ACME 缓存/账户/已签发证书、全机防火墙、BBR、核心二进制不包含在配置快照中；这不是整机迁移。单进程重启可能短暂断流。下一步应先实机验收和完善 ACME 迁移/历史保留，再扩展新协议与订阅。
