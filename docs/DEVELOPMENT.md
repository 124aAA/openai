# QingNode 开发与验证

QingNode 保留 Bash 安装入口、Go 管理器、JSON State、官方 sing-box 和 systemd。改动以小范围、可回退为优先；本轮架构与执行证据分别见 [ARCHITECTURE.md](ARCHITECTURE.md) 和 [TEST_REPORT.md](TEST_REPORT.md)，当前未发布改动见 [RELEASE_NOTES.md](RELEASE_NOTES.md)。

## 按现有边界放代码

| 层 | 本次含义 | 修改原则 |
| --- | --- | --- |
| 安装入口 `install.sh` | 下载、校验、安装账户与文件、失败恢复 | 保留非交互参数、所有权检查和重装语义 |
| CLI 与菜单 `cmd/qingnode` | 收集输入、确认影响、显示结果 | 不自行生成第二套凭据或直接写 State |
| 模型与协议 `internal/node` | 统一身份、校验、服务器及客户端配置 | 所有导出从同一 State 派生；协议适配器保持编译期注册 |
| Store | 状态锁、候选代、原子切换和回滚 | 修改通过 Apply；查询通过 Inspect，恢复由显式操作或写路径触发 |
| 系统后端 | 核心、服务、监听、防火墙与主机设置 | 外部效果有明确入口，出错保留恢复证据 |

这些是已有代码的职责边界，不要求为每项小改动新增包、服务或抽象。新增协议通常同时涉及适配器、参数入口、菜单和客户端导出，需要检查完整路径，不能仅以服务器 JSON 可解析作为完成证据。

## 保护现有节点

先读取已有 State，再修改目标字段。普通编辑、重复安装、重建派生配置不能重新生成 UUID、私钥、公钥、short ID、服务密钥、用户密钥或密码。节点与凭据按完整集合先找 ID、再找名称；不要把展示序号当成持久身份。

查询使用 Inspect，不能为了展示状态顺带恢复事务、切换 current 或重启服务。Inspect 仍可能由明确功能另存观测历史或写用户指定的导出文件。改变配置的操作使用 WithLock 与 Apply：候选校验、外部效果、提交和失败恢复需保持原有顺序；8 MiB 状态上限在读写两侧一致，超限候选必须在创建配置代前拒绝。

菜单中的取消和输入结束应向上返回，不落入无限重试。无效数字可提示后重试；输入正确的最后一个参数也不能代替危险操作确认。删除、轮换、恢复、卸载等确认只针对明确展示的目标与影响。

## 逐层验证并保留证据

在 Linux 上，从与修改有关的回归开始，再运行仓库要求的检查。回归应复现实际错误，并检查旧状态、凭据、current 和服务是否保持；不要为每个可逆的文案修改增加只重复实现的测试。

```bash
go test ./internal/node ./cmd/qingnode
go vet ./...
go test -race ./...
shellcheck install.sh scripts/*.sh
sudo env "GO=$(command -v go)" python3 scripts/test-installer.py
sudo env "GO=$(command -v go)" sh -c '"$GO" test ./internal/node -run "^TestStorePermissionsUnderRestrictiveUmask$" -v -count=1'
```

安装器测试需要 root，必须在隔离测试环境中运行。权限测试验证专用账户的真实降权读取；普通非 root 单元测试不能替代它。项目使用 Linux 系统接口，Windows 下交叉编译成功只证明能生成目标文件，不证明 Linux 执行成功。`go test -race` 还依赖相应架构的 C 工具链。

官方核心测试需要经过摘要校验的文件。CI 用 `python3 scripts/fetch-test-core.py` 获取固定版本，并通过 `SING_BOX_BIN`、`SING_BOX_ARCHIVE` 传给测试；本地运行须显式设置这些环境变量。`MIHOMO_BIN` 用于可选的客户端配置解析。没有这些文件时的 `SKIP` 必须单独记录，不能写成官方核心或客户端验证通过。

```bash
go test ./internal/node -run 'OfficialCore|OfficialArchive' -v -count=1
bash scripts/build.sh
```

官方核心的本机 TCP/UDP、ACME 配置语法、双架构构建各自证明不同范围。ACME 语法通过不代表证书已签发；ARM64 交叉构建不代表 ARM64 运行；本机通信不代表云防火墙、移动客户端或公网可用。测试记录应包含源码版本、环境、实际命令、结果、跳过项和未验证范围；本轮结果以 [TEST_REPORT.md](TEST_REPORT.md) 为准。

## 真实环境与发布门槛

`scripts/acceptance-vps.sh --disposable` 仅用于明确授权、可重建、没有现有 QingNode 的 root + systemd 主机。它会安装、修改和卸载节点；失败保留现场。这个本机生命周期验收不包含公网、ACME、BBR、防火墙、ARM64 或全部跨版本升级验证。生产主机、SSH 登录、现有节点、公网测试和证书签发必须按已授权范围另行执行。

CI 保留静态检查、race 单元测试、root 权限测试、安装器隔离测试、官方核心三协议 TCP/UDP、双架构构建以及真实 systemd 生命周期门槛。发布工作流在这些步骤完成后才上传发行包；推送 main 或版本 tag 可能触发发布工作流，因此 Git 提交、推送、打 tag、部署和发布需要分别确认授权范围。通过自动检查不等于管理员已经验收，也不能据此修改旧版历史结论。

准备发布时核对版本、安装器版本、发行说明、包内文档和摘要；保留旧数据兼容与恢复路径。涉及凭据、schema、协议默认值或核心适配范围的变更，应先补迁移/回滚设计和专项证据，再决定是否发布。
