# 按任务使用与脚本接口

当前候选的常用入口按任务组织。菜单是人类交互入口，自动化使用下面的真实CLI；协议、客户端、系统与各层验收见[能力矩阵](CAPABILITIES.md)。完整从安装到验收的七个短流程见[新手指南](GETTING_STARTED.md)，不要把公开旧发行入口和本地候选混为一谈。

| 想完成的任务 | 先看什么 | 真实命令入口 | 影响 |
| --- | --- | --- | --- |
| 快速建节点 | 客户端、域名/证书、TCP/UDP、NAT与资源条件 | `wizard`、`add --help`，安装用候选包`install.sh` | 向导校验后预览实际影响；直接add按完整参数校验应用，不自动预览；可能启动共享代理 |
| 管理节点和用户 | 稳定节点/用户ID、原凭据保留 | `list`、`info`、`edit --preview`、`user-add`/`user-delete` | 普通改名不轮换认证；删除与轮换按明确确认处理 |
| 导出/订阅 | 指定凭据、目标客户端版本、完整配置/provider区别 | `export --out`、`device`、`subscription` | 导出含秘密；下载撤销与代理认证停用分开 |
| 测速与诊断 | 测量位置、路径、样本/时间/流量预算 | `probe local`、`probe run`、独立`qingprobe` | 不改生产策略，不以服务器出站替代用户体验 |
| 证书与备份 | 资源引用、资产覆盖、一致性短停 | `certificate`、`backup --full --preview`、`restore --file 备份文件 --password-file 口令文件 --preview` | 证书共享更新和恢复可能影响多个节点；缺资产不能标完整 |
| 进阶网络 | 监听与公开端点、出口引用、受控链路 | `endpoint`、`forward`、`egress`、`route`、`wireguard`、`network` | 高级功能逐项显式应用；不接管SSH、全局路由或其他人的服务 |
| 系统维护 | 安装/运行/自启分开，未完成事务先保留 | `status`、`service`、`core`、`recover`、`uninstall` | 按当前init和资源归属处理，遇外部修改保留恢复材料 |

## JSON入口逐项选择

JSON不通过人类文本换行器，也不混入进度动画。消费者检查版本并读取退出码；不要根据服务active推造公网通过。不是所有命令都有同一`--json`，帮助才是完整参数表。

| 命令 | stdout含义 | 说明 |
| --- | --- | --- |
| `help --json` | version1的用法、退出码与已登记JSON入口 | 不读取State、不创建服务 |
| `version --json` | version1管理器版本/修订信息 | 不表示对应上游核心已安装 |
| `overview --json`、`status --json` | version1脱敏本机状态 | 安装、运行、节点声明、测量位置与未知项分开；不联网或恢复事务 |
| `info --json`、`list --json` | version1公共节点视图 | 不输出用户认证、私钥、内部落地凭据；用显式export取私有配置 |
| `edit --preview --json`、`batch --preview --json` | version1真实变更影响 | 必须同时preview；不保存候选、修复事务或启动服务 |
| `capabilities --json` | 已有version1本机/运行权限能力 | 工具存在与控制器可用分开，标签/解析/传输分开 |
| `protocols list` | 协议能力JSON | 已有接口本身为结构化输出；不需猜额外全局JSON参数 |
| `probe ... --out 新文件` | 人类摘要，文件为版本化JSON报告 | 测量失败也可留下真实失败报告，取消不记成功；输出必须新路径 |
| `endpoint material --out 新文件` | 外部待验证材料JSON | 只声明地址/映射要求，DNS、TCP/UDP公网可达保持未知 |
| `doctor --json`、`diagnose --json` | version1逐项诊断 | 缺失/未来格式/持锁失败也输出单份失败或未知报告，不以默认State假测；offline不联网，不修复事务 |
| `ports --json` | version1本机监听观察 | 8秒、4MiB、4096项上限；缺少进程权限为null，不能把监听当作认证、公网或UDP业务通过 |
| `dns show --json`、`hy2 show --json` | version1本项目解析器和性能设置声明 | 保留默认值与上下行含义；不改变宿主解析器，不证明性能收益 |
| `dns diagnose --json` | 已有标准DNS测量报告 | 复用同一诊断与流量预算；失败保持真实失败，`--out`可另存同一结果 |
| `hy2 plan ... --out 新文件 --json` | 已保存的version1私有性能计划 | stdout不追加文字；计划保存失败不得当应用成功，仍须显式apply |
| `endpoint list --id ID --json` | version1监听与连接端点声明 | 本地端口、NAT外端口及IPv6分别保留，公网保持unknown |
| `egress list/show --json`、`egress policy list --json`、`forward list --json` | version1公开拓扑声明 | 不含远程密码/密钥；UDP为声明，不是实测；查询不切换出口 |
| `device list/show --json`、`expiration list --json` | version1设备绑定及精确身份到期计划 | 不输出认证、私有健康URL或下载令牌；查询不执行停用 |
| `subscription status --json` | version1下载授权状态 | 只含设备/令牌ID、撤销、到期和发布格式数，不包含原始令牌、链接或伪造流量 |

例如：

```bash
qingnode help --json
qingnode version --json
sudo qingnode overview --json
sudo qingnode info --id NODE_ID --json
sudo qingnode edit --id NODE_ID --name new-name --preview --json
sudo qingnode batch --file /root/edits.json --preview --json
```

## 全命令执行回执

全局 `--result-dir` 可用于明确的CLI命令，参数放在命令前。它提供命令执行结果，领域数据仍使用上表或各自明确的私有文件；回执不把stdout文字包装成JSON，也不复制命令参数、原始错误、State或分享链接。

```bash
install -d -m 0700 /root/qingnode-results
qingnode --result-dir /root/qingnode-results/status-1 status --json
qingnode --result-dir /root/qingnode-results/edit-1 edit --id NODE_ID --name new-name
```

目标必须是尚不存在的新目录，且在节点/宿主网络受管目录之外。目录0700，文件0600。开始时写`started.json`（status=running、exit_code=null）；结束才以不覆盖已有文件的原子方式发布`result.json`。父路径被替换、结果冲突或无法落盘会返回错误；如果命令已经执行，不会为生成回执重新执行命令。长运行服务在退出前没有最终文件；强杀、断电、外层超时后只有started或没有完整结果，都保持未知。回执模式不默认进入菜单。

`status`与`exit_code`报告回执发布前的命令返回；`exit_code_scope`明确这一范围，消费者还须核对实际进程退出码。结果文件写出后仍可能发生目录同步等输出错误，此时进程返回1，不能只看文件中的0当作完整成功。canceled/interrupted/failed/help都不能作为一次完整业务验收。`apply_confirmations`只记录确实到达AfterCommit回调的Apply确认，包括不产生新代的重复应用，并区分派生发布回调失败；完整迁移暂时关闭该回调、自动恢复或宿主服务/网络动作不在此观察范围。确认列表为空不等于没有写入。非零退出可能发生在配置提交、权限撤销或宿主修改之后，**不要据此自动重试写操作**；先检查`status --json`、中断事务和命令各自的恢复材料。回执最多保留64条确认并另记实际数量和截断标志，不将连接或计费状态凭空补成成功。

## 退出、取消与输入文件

成功和帮助退出0；普通参数、校验、应用或测量错误退出1。隐藏口令输入收到SIGINT退出130、SIGTERM退出143并恢复原终端状态。菜单正常返回/表单取消与EOF不提交半个节点；进程已经进入事务应用时中断则保留恢复材料，不能按表单取消处理。独立qingprobe的普通失败为1；不要假设它与管理器有完全相同的信号处理接口。

全局参数在命令前：`qingnode --offline --root 独立目录 命令`。离线模式只生成配置，不证明实际连接，不操作宿主服务。菜单需要TTY；无TTY使用完整参数。CLI输入文件各有独立版本、所有权、权限和大小约束：

| 输入 | 已有约束与处理 |
| --- | --- |
| 设备/证书/拓扑/批量JSON | 固定各自envelope版本、未知字段/重复键/不合法引用拒绝；按各命令上限读取，不能任意JSON注入 |
| 私有Profile、认证与口令文件 | 私有普通文件、相应权限和大小限制；口令至少12字节，不放命令行或示例明文 |
| `--file -`、重定向stdin | 不是通用约定；只有命令明确支持时才可用，不把一段stdin自动当State或任意模板 |
| 导出/报告输出 | 用户显式新路径，私有文件原子或独占写入；已有文件拒绝覆盖，不通过stdout动画破坏JSON |

所有错误与普通信息默认脱敏，显示控制序列被清理。`export`、私有Profile和订阅二维码仍然是明确的秘密输出；不要把它们作为诊断附件。实际文件上限、字段和负面测试保留各模块指南，机器帮助也不执行文档中的命令。

## 终端文本与完整配置分开

菜单、状态和普通错误按真实TTY宽度折行，不截断中文、长IPv6或常见组合emoji。NO_COLOR、TERM=dumb及非TTY路径保持纯文本，不使用动画、raw模式或隐藏光标来维持界面。宽度使用Unicode15.1 W/F表并对组合符/常见emoji作终端取舍；不同字体对模糊宽度/复杂文字仍可能不同。32/40/80列PTY与真实手机SSH应用是独立证据，本轮记录见[BATCH11](BATCH11.md)。

JSON、URI、二维码和客户端配置保留原始机器格式，不接入折行器。窄终端看不全或二维码被客户端换行时，用`export --out`取完整私有文件，不从截断截图拼回配置。无需为分组菜单新增Huh等依赖；当前继续用已存在x/term处理终端能力及隐藏口令，没有引入常驻前端组件。

维护者用`scripts/test-machine-interface.py --disposable --bin 绝对路径 --sha256 实际摘要 --out 新绝对路径`验证真实候选的JSON和回执。它只创建临时离线数据、本机监听及自有测试子进程；不会启动生产代理。结果的CLI、监听、代理传输、服务生命周期和公网验证仍分层记录。
