# 第 01 批：兼容基线、变更影响与减少维护断流

本批保留 Bash + 静态 Go + 官方 sing-box + systemd，增加实际派生配置影响分类、只读预览、批量统一应用、历史/恢复分类和最小格式入口。默认核心保持 1.14.0；1.14.3 的源码、构建标签和官方归档已补核，解析/流量与真实宿主恢复分别记录，不用版本范围代替测试。

实施基线：`70c0c277aa8703a4bd2cf8268b6bdad09ae13fc2` / v0.2.8，2026-10-13 开始。已实现代码提交：`ab14c74102f161ec80ebc33f514c5aba6d714180`；本文件是该提交之后补记的执行证据，后续仅文档提交不替代被测试的实现提交。最终 QEMU 日志开头的 `QINGNODE_SOURCE_COMMIT` 和逐文件摘要清单均绑定该 SHA。本地未推送、未发布、未操作生产 VPS；历史发行成功不计本批实测。

## 实现与关键决定

| 接口/文件 | 本批行为 |
| --- | --- |
| `Store.Preview` / `ChangeImpact` | 比较展示来源、实际 URI/sing-box/Mihomo 导出对象、实际服务端 JSON、核心选择、服务输入和归属防火墙规则；结果可同时属于多类 |
| `Store.Apply` | 输入有效才建立候选；仍完整检查候选核心、证书、端口与派生配置。运行输入不变时提交新代但免重启；完全相同且派生完整时不新建历史 |
| `RuntimeIdentityBackend` | 给配置代保存受管运行输入的校验材料，识别同路径核心或服务输入的外部替换；候选检查期间再次核对，避免用过时分类应用 |
| `edit --preview` | 复用普通编辑输入，展示节点/客户端/服务器/宿主/修复影响；不保存、不恢复、不启停服务。预览不选择随机端口 |
| `batch --file ... [--preview]` | 从同一旧 State 解析所有目标，允许名称和端口互换；全量修改、整体验证、只调用一次 Apply。无效项或重复实际节点拒绝整批 |
| `recover` / `rollback` | 保留显式恢复与历史回退。元数据回退免重启；运行回退按实际输入分类；损坏派生文件仍检查并重建新代，不覆盖原损坏材料 |
| `DecodeState` / `state_format_test.go` | 保持 `schema: 1`，集中按版本分派；未来版本和未知字段明确拒绝，不删字段伪装兼容；旧 State 和 v1/v2 快照夹具保持身份 |
| `scripts/test-maintenance-flow.py` | 只接受 root + 真实 systemd 的可重建主机，观察 MainPID 与 `/proc` 启动身份，同时验证一条不重连的持续 SS2022 TCP 流 |

名称会影响 URI/Mihomo 展示标签，所以通常同时属于展示和客户端导出变化。客户端 `server` 和 REALITY `fingerprint` 不会自动改变服务端监听；仍要实际比较派生结果后才免重启。修改 SNI/握手目标、监听、端口、认证、证书、启用状态或核心可能改变服务端/宿主效果，不能按字段名字猜测。

停用节点虽然不能用 `export` 导出，`info --show-secrets` 仍会显示其 URI，所以其已保存的客户端定义与导出可用性也纳入比较。停用节点的客户端地址或名称改变不会被误报为“无客户端影响”，也不会仅因此重启服务器。

宿主防火墙规则变化与代理运行配置变化分开处理：只同步归属规则不应单独重启代理。没有运行输入变化的元数据/导出编辑和仅 UFW 效果变化保持原停止状态和自启设置；端口、凭据、核心等运行变更沿原有 Apply 规则，有启用节点时可启动原本停止的服务，全部节点停用则停止。这一边界保留旧 enable/disable 行为，不能把“保持停止”扩大到全部编辑。`start`、`stop`、`restart` 和 `service enable/disable` 仍为显式操作。

本批没有新增备注字段或扩展代理协议。元数据编辑使用现有字段；后续扩展应接入统一派生比较和格式入口，不能借此提前提高 State schema。

## 可运行的批量接口

保存 `edits.json`，用 `list` 得到的稳定节点 ID 替换下方示例：

```json
{
  "version": 1,
  "edits": [
    {"id": "节点ID一", "name": "新展示名", "server": "node.example.com"},
    {"id": "REALITY节点ID", "fingerprint": "firefox"}
  ]
}
```

```bash
sudo qingnode batch --file edits.json --preview
sudo qingnode batch --file edits.json
sudo qingnode edit --id 节点ID --name 新展示名 --preview
```

请求 `version: 1` 与持久 State `schema: 1` 是不同版本边界。每项使用 `id` 加一个或多个字段：`name`、`server`、`listen`、`port`、`fingerprint`、`sni`、`target`、`cert`、`key`、`acme_email`、`enabled`。`cert`/`key` 是现有编辑命令同义的本地文件路径，协议不适用的字段仍拒绝；省略字段保留旧值。禁止 null、空字符串、重复 JSON 键、未知字段、多余 JSON、重复实际节点和空修改项；最多 256 项/1 MiB。不支持批量随机端口或凭据轮换。

所有 ID/名称都按修改前状态匹配；自动化宜使用稳定 ID。预览只是当时的只读说明，不锁定随后应用；实际应用重新取得锁并校验。预览不联网检测 REALITY 目标、不执行核心配置检查、不恢复未完成事务；有事务时拒绝并指向显式 `recover`。实际 SNI/target 编辑复用原在线检查规则。

## 格式、升级与恢复

State schema=1、备份 envelope v1/v2 均保持；`DecodeState` 只在内存解码兼容旧可选字段，不因查询落盘迁移。未知新版本/字段拒绝时保留原件，须使用理解该格式的管理器处理，不能删字段后用旧程序读取。

配置代增加私有 `runtime-identity`（运行输入校验材料）format=1 派生文件；旧代缺失时，首次写入经候选验证补充新代，查询不补写。材料核对实际核心路径/内容摘要、受管 unit 文件来源/摘要和固定核心调用参数；不声称覆盖管理员额外 drop-in 或已加载的全部 systemd 属性，元数据编辑不执行 daemon-reload。`state.json` 仍 0600；服务可读 `server.json`、`core-version` 仍 0640，受管目录可由服务组遍历；runtime 校验材料不需要服务读取。

事务记录实际新增 v2 envelope：`{"transaction_v2":{"version":2,...}}`，保存此前/候选代、此前运行状态，以及是否有运行/宿主影响。旧版事务继续读取并按旧语义恢复。新 envelope 不提供旧版 top-level 指针，旧管理器不能误把免重启事务解释成旧重启事务；降级前先用本批管理器完成 `recover` 并确认没有 `transaction.json`/`uninstall.json`。旧 State 可由支持其字段的旧管理器读取，但旧版不会具备本批减少中断的行为。

失败处理：候选验证失败不切换 `current`；切换后的失败按已记录影响恢复旧指针、项目规则和原运行状态；恢复失败保留事务与新旧配置代并明确报错。不要手工删除事务或损坏代，先保留现场、运行 `doctor`，再使用 `recover`。`rollback` 取上一代 State，重新通过同一候选流程生成；快照恢复仍先保留恢复前备份，不执行备份中的服务文本。核心原件、ACME 缓存、全机防火墙和 BBR 不在 State 快照中，必须分别保留。

## 本批实际执行记录

本批在 QEMU TCG 隔离 Linux amd64、4 CPU/4 GiB、Alpine 运行环境、内核 `6.18.52-0-virt`、Go 1.26.8、gcompat 中执行，只有回环网络。实现提交为 `ab14c74102f161ec80ebc33f514c5aba6d714180`。完整运行已结束，原始日志及源码摘要清单随交付保存。安装器读取真实系统标识的用例在 Alpine 被正确拒绝，另用明确的 Ubuntu 系统标识夹具复验；两类结果分别保留，没有改产品系统范围或测试断言。

| 命令/检查 | 已发生的结果 | 边界 |
| --- | --- | --- |
| GitHub 固定 tag + Release API + 下载 SHA-256 | v1.14.3 tag/两架构归档摘要一致 | 下载验真，不等于二进制运行或恢复验收 |
| `go test -count=1 -v -timeout=15m ./...` | Linux 全项目退出 0；官方 1.14.0 三协议 TCP/UDP 回环、服务器/客户端配置、ACME 语法、默认归档幂等、Mihomo 三协议 YAML、真实降权权限及业务/故障回归通过 | Linux 实际运行；不是 systemd 或公网验收 |
| `env SING_BOX_BIN=/sing-box-candidate go test ./internal/node -run 'OfficialCore\|OfficialCandidate' -v -count=1 -timeout=10m` | 退出 0；官方 1.14.3 三协议 TCP/UDP 回环、服务器/客户端配置、ACME 语法、候选归档安装及运行维护测试通过 | 候选恢复使用真实官方进程与注入启动故障；不是 systemd 恢复 |
| `TestOfficialCoreMetadataKeepsProcessAndTCPStream`，1.14.0 | 实际 PID 3662，在同一条连接上后台持续传输并校验 81 帧，元数据修改/重复/回退/派生修复期间 PID 保持；运行端口变更重启和停掉旧进程后注入启动失败的恢复通过 | 真核心、真 TCP；进程由测试直接管理，不能称作 systemd MainPID |
| 同一测试，1.14.3 | 实际 PID 4002，同一条连接持续传输并校验 127 帧；同样的运行重启与故障恢复通过 | 帧数是此轮观察记录，不是吞吐或性能提升结论 |
| `python scripts/test-maintenance-harness.py -v` | Windows 本机 3 项实际 socket 观察器测试通过；碎片/EOF、中断、内容损坏都可识别 | 仅证明验收观察器能识别故障，不是代理或 systemd 验收 |
| `python scripts/test-release.py` | Windows 本机 38 项发行保护测试通过 | 模拟 API 的离线检查，不代表发布或远端 Actions 成功 |
| `actionlint` 1.7.12 | CI 与 release 工作流静态检查退出 0 | 不代表工作流实际执行 |
| `python -m py_compile scripts/test-maintenance-flow.py scripts/test-maintenance-harness.py` | 通过 | Python 语法 |
| `bash -n scripts/acceptance-vps.sh` | 通过 | Shell 语法 |
| `go test -race -count=1 -timeout=15m ./...` / `go vet ./...` | Linux 两项退出 0 | 并发读写错误检查与静态检查；QEMU 中实际运行 |
| `shellcheck install.sh scripts/*.sh` / 全部 Bash 的 `bash -n` | Linux 两项退出 0 | 脚本静态和语法检查 |
| `python3 scripts/test-installer.py` | 未改系统标识的 Alpine 上 32 项中 31 项通过；唯一失败为读取真实 `/etc/os-release` 后正确拒绝 Alpine 3.24.2 | 安装器规则未放宽；全部主机命令与下载仍使用原隔离模拟 |
| `python3 scripts/test-installer.py InstallerTests.test_online_install_reads_actual_host_os_release_without_overwriting_tag` | 临时 Ubuntu 24.04 系统标识夹具下，原失败用例退出 0；八阶段完成及发行 tag 保持的断言原样保留 | 只改变一次性 QEMU 中该用例的输入文件，之后恢复 Alpine 标识；不等于 Ubuntu 实机安装 |
| `python3 scripts/test-release.py` / `python3 scripts/test-maintenance-harness.py` | Linux 分别 38 项 / 3 项通过，均退出 0 | 发行 API 模拟和真实 socket 观察器，不是远程发布或 systemd 验收 |
| `bash scripts/build.sh` | Linux 退出 0，生成 amd64 与 arm64 两架构包，包含新增文档 | 无 Git 的快照环境包内 revision 显示 `source`，源码由日志及清单绑定实现提交；构建不证明 ARM 原生运行 |
| 交付预览二进制 | Go 1.27.2、CGO_ENABLED=0 交叉构建两架构，ELF 无动态解释器；amd64 在 Linux 实际跑通版本核验及离线 init/batch-preview/batch/apply/rollback | 显示 `0.2.8-batch01 (ab14c74102f1)`，不是正式发行安装包；ARM 未原生执行 |
| `sudo bash scripts/acceptance-vps.sh --disposable ...` | 当前环境无真实 PID 1=systemd 宿主，未执行 | 保留 CI/release 的真实入口；不得把 mock/历史 Actions 计入本批 |

初轮验证暴露并修正了两项测试问题，最终实现提交重新运行通过。备份恢复原断言仍要求旧式“每次恢复都重启”，与本批元数据免重启契约冲突；调整为精确检查 1 次旧事务恢复 activation 和 1 次元数据候选 Check，同时保留并增强凭据、历史与恢复前备份断言，没有用少检查来制造通过。真实客户端启动原用固定 sleep，QEMU 下会遇到监听未就绪；改为有截止时间的监听就绪等待，只允许建流前等待，已建立的持续 TCP 连接禁止重连。最终 81/127 帧均来自修改期间后台传输，不能用初轮失败或旧成功代替。

候选验证可在 Linux amd64 上按以下接口复现。两个官方归档都须先按 [THIRD_PARTY.md](../THIRD_PARTY.md) / 内置摘要核验；`SING_BOX_BIN` 选择本次解析/传输用二进制，`SING_BOX_CANDIDATE_ARCHIVE` 只供候选安装测试，`SING_BOX_ARCHIVE` 仍必须为默认 1.14.0 归档，不能三者混用：

```bash
export SING_BOX_ARCHIVE=/绝对路径/sing-box-1.14.0-linux-amd64.tar.gz
export SING_BOX_CANDIDATE_ARCHIVE=/绝对路径/sing-box-1.14.3-linux-amd64.tar.gz
export MIHOMO_BIN=/绝对路径/mihomo
SING_BOX_BIN=/绝对路径/sing-box-1.14.0 go test -count=1 -v -timeout=15m ./...
SING_BOX_BIN=/绝对路径/sing-box-1.14.3 go test ./internal/node -run 'OfficialCore|OfficialCandidate' -v -count=1 -timeout=10m
```

默认 `scripts/fetch-test-core.py` 仍获取 1.14.0 与固定 Mihomo，不自动把候选升为默认。未设置官方工具环境变量时的跳过必须单独记录；源码编译不能替代上述实际执行。

真实维护脚本要求修改前流量已在传输，每步观察 PID、进程启动身份、自启设置与递增校验帧；改名、客户端地址、REALITY fingerprint、批量预览/应用、重复应用、元数据 rollback、损坏派生修复均使用同一 TCP 连接，不自动重连。另测运行端口变更/运行 rollback 的真实重启，以及停止后的元数据修改/回退保持停止。失败退出并保留现场，不报告通过。

未提供而未验证：真实 Debian/Ubuntu systemd 持续流量维护与核心更新恢复、原生 arm64、实际公网 TCP/UDP/IPv6/NAT、客户端 UI、ACME 签发/续期、真实 UFW/BBR。本批未升级默认核心，待候选三协议和真实恢复门槛均通过后更新默认锁定；本次用户已授权门槛通过后的锁定，不需要再次确认方案。

## 来源和后续批次接口

能力矩阵见 [CAPABILITIES.md](CAPABILITIES.md)。上游固定源码/许可/采用机制见 [THIRD_PARTY.md](../THIRD_PARTY.md)。本批独立实现差异分类和事务，没有复制 GPL 面板代码、重写协议或引入面板/数据库运行依赖。

后续新增数据必须经过 `DecodeState` 版本入口；新增运行字段、导出格式和宿主效果必须接入 `ChangeImpact` 的实际派生输入；服务外部输入应更新 `RuntimeIdentityBackend` 的校验材料；批量请求升级与 State schema 升级分别处理。持锁、完整候选检查、版本化事务、原子 current、恢复材料及只清理自有资源的规则继续生效。

源码编译、解析、回环协议流量、真实服务生命周期、客户端 UI、公网实测、人工接受、推送和发行都是独立结果。下一批复用本记录与能力矩阵时，应绑定它实际接手的提交并重查差异，不能把本文件的待验收事项当成已有能力。
