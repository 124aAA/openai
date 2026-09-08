# QingNode 青节点

轻量 VPS 代理节点管理器。保留原有 Bash 安装器、Go CLI、官方 sing-box 和 systemd 架构，没有 Docker 或 Web 面板。

**当前版本：0.2.1 开发验收版。** 本地回归、安装器故障模拟、官方配置解析已通过；真实 systemd VPS、公网 TCP/UDP、ACME 和 ARM64 执行尚未验证。完整证据与限制见 [测试报告](docs/TEST_REPORT.md)，改造依据见 [审计与第二阶段计划](docs/AUDIT_STAGE2.md)。

## 快速安装

以 **root** 登录 VPS 的 SSH 终端，运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/124aAA/openai/main/install.sh)
```

只有 wget 时也可以：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/124aAA/openai/main/install.sh)
```

首次运行自动下载对应架构的发行包，校验后进入中文安装向导。已有 QingNode 时进入管理菜单。以后直接运行 `qingnode` 即可查看链接、管理节点和诊断故障。

安装脚本固定从本仓库的 [GitHub Releases](https://github.com/124aAA/openai/releases) 下载指定版本，不在 VPS 上编译。发布流程通过测试后才上传发行包；若显示 HTTP 404，先检查该版本是否已发布，其他下载失败可查看安装日志。不会自动切换第三方镜像。

也可以下载对应架构的发行包，上传 VPS，解压并进入目录后运行 `sudo bash install.sh`：

| CPU | 安装包 |
| --- | --- |
| Intel / AMD / x86_64 | qingnode-0.2.1-linux-amd64.tar.gz |
| ARM / Ampere / aarch64 | qingnode-0.2.1-linux-arm64.tar.gz |

安装器识别 Debian 12、13，Ubuntu 22.04、24.04、26.04，要求 PID 1 为 systemd。识别列表不代表这五种系统均已实机验收；其他系统会明确停止。缺少的基础依赖通过系统 apt 安装，正常输出分八个阶段，错误日志保存在 `/var/log/qingnode-install-XXXXXXXX.log`，权限 600。

安装完成自动显示节点信息和分享链接。再次运行 `sudo qingnode` 或无参数的已安装 `install.sh` 进入分级管理菜单。完整发行包中的 `sudo ./qingnode` 也可调用同目录的已校验安装器。

非交互安装示例，地址和域名必须替换成自己的实际参数：

```bash
sudo bash install.sh --server 203.0.113.10 --sni example.com --port 443
sudo bash install.sh --protocol ss2022 --name SS-01 --server 203.0.113.10 --random-port
```

`--server` 是客户端连接地址；REALITY 的 `--sni` 是你选择的 TLS 握手目标。交互向导可查询公网 IPv4/IPv6，失败后允许手动输入。默认端口被占用时，交互安装可选择新端口；CLI 返回错误与查看进程的建议。随机端口避开已有节点、实际监听和已识别的 SSH 端口。

管理器运行无需 Go、Python 或 qrencode。二维码在静态 Go 程序内生成，不调用外部网站。

## 下载和重复安装

默认核心锁定官方 sing-box 1.14.0，验证官方归档 SHA-256 后才执行。GitHub 不通时不会切换未知镜像，可上传本架构官方归档并使用：

```bash
sudo bash install.sh --core-archive /root/sing-box-1.14.0-linux-amd64.tar.gz
```

已有其他 sing-box 不会被接管。重新安装管理器保留已有节点、核心版本、UUID、密码、REALITY 密钥、short ID、端口和服务的运行/停止状态。无参数进入菜单；强制重新安装使用 `--reinstall`。

默认发行仓库为 `124aAA/openai`。需要指定仓库或版本时，使用 `install.sh --repo 124aAA/openai --version v0.2.1`。本地完整发行包优先使用相邻文件；本地包损坏或缺少部分文件时会报错，不会悄悄改为在线下载。

## 菜单与 CLI

主菜单分为节点管理、链接与导出、服务管理、维护、系统工具，每层保持少量选项。普通查看不反复确认；删除、恢复、轮换密钥和卸载需要明确确认。

| 任务 | 命令 |
| --- | --- |
| 初始化 / 添加 | `init` / `add`，或 `install` 安装核心并初始化 |
| 查看节点 / 凭据 | `list` / `info --id main` / `info --id main --show-secrets` |
| 查看 REALITY 私钥 | `info --id main --show-private` |
| 修改 / 启用 / 停用 | `edit --id main ...` / `enable --id main` / `disable --id main` |
| 删除单个节点 | `delete --id main --yes` |
| 查看服务与监听 | `status` / `ports` |
| 服务运行 | `start` / `stop` / `restart` |
| 开机自启 | `service enable` / `service disable` |
| 诊断 / 日志 | `diagnose`（等同 `doctor`）/ `logs` |
| 配置检查 / 回退 | `check` / `rollback` / `recover` |
| 备份 / 恢复 | `backup` / `restore --file 文件 --yes` |
| 核心版本 / 更新 | `core versions` / `update` |
| 管理器更新 | `self-update --version v0.2.1` 或 `self-update --bundle 新版解压目录` |
| 网络 / 防火墙 | `network status` / `network bbr` / `firewall status` |

以上命令前加 `sudo qingnode`；每个命令附 `--help` 查看参数。`--debug` 是全局参数，应放在命令前，例如 `sudo qingnode --debug diagnose`。非交互执行使用 CLI，不会等待菜单输入。环境变量 `NO_COLOR` 或不支持颜色的终端会禁用颜色。

`restart` 不改变开机自启设置。临时 `stop` 不改变节点 Enabled 字段，之后应用节点变更可以重新启动服务；持久停用使用 `disable`。

## 节点和协议

当前支持 REALITY（VLESS + XTLS Vision / TCP）、Shadowsocks 2022 和原有 Hysteria2。TUIC 尚未实现。

```bash
sudo qingnode add --name JP-Reality-02 --protocol reality --server 203.0.113.10 --sni example.com --random-port
sudo qingnode add --name SS-01 --protocol ss2022 --server 203.0.113.10 --random-port
sudo qingnode edit --id main --port 8443 --name JP-Reality-01
sudo qingnode edit --id JP-Reality-01 --sni new.example.com --fingerprint firefox
sudo qingnode user-add --id SS-01 --name laptop
sudo qingnode export --id SS-01 --user laptop --format uri
```

SS2022 使用 `2022-blake3-aes-256-gcm`，服务密钥与每个用户的密钥均为独立 32 字节 Base64 密钥。客户端 Password 为 `服务密钥:用户密钥`，URI 按 SIP002 对 AEAD-2022 userinfo 做百分号编码。该节点同时占用 TCP 和 UDP 端口。

名称改变不改变节点 ID；普通编辑不轮换身份。只有以下明确操作才使已有链接失效：

```bash
sudo qingnode rotate --id JP-Reality-01 --short-id --yes
sudo qingnode rotate --id JP-Reality-01 --keys --yes
sudo qingnode rotate --id SS-01 --user laptop --yes
sudo qingnode rotate --id SS-01 --server-key --yes
```

REALITY 私钥轮换保留 short ID；short ID 轮换保留密钥。修改 SNI 保留自定义握手目标，仅当旧目标由旧 SNI 默认生成时同步更新它。SS2022 服务密钥轮换影响该节点的全部客户端。

## Hysteria2 证书

可选择 ACME HTTP-01 自动签发，或导入已有可信 PEM 证书：

```bash
sudo qingnode add --name HY2-01 --protocol hysteria2 --server hy.example.com --sni hy.example.com --port 443 --acme-email you@example.com
sudo qingnode add --name HY2-02 --protocol hysteria2 --server hy.example.com --sni hy.example.com --port 8443 --cert /root/fullchain.pem --key /root/privkey.pem
```

ACME 域名须指向本机，TCP 80 可达且未被占用；节点另需放行 UDP 端口。不会停止现有网站。签发和续期由 sing-box 1.14 certificate provider 负责，首次签发超过就绪等待时间可能触发回退。实际签发续期未验证。

PEM 导入会复制证书与私钥，原文件续期后须再次用 `edit --cert ... --key ...` 导入。不会关闭客户端证书校验。TCP 443 的 REALITY 与 UDP 443 的 HY2 可以共存；SS2022 同时使用 TCP/UDP，不能再占用同一监听范围的相同端口。

IPv6 字面地址默认监听 `::`；域名默认监听 IPv4。使用双栈时显式设置 `--listen ::`，并核对系统 IPv6、AAAA 和防火墙。

## 链接、二维码和配置导出

```bash
sudo qingnode info --id main --show-secrets
sudo qingnode export --id main --format uri
sudo qingnode export --id main --format qr
sudo qingnode export --id main --format sing-box --out /root/client.json
sudo qingnode export --id main --format mihomo --out /root/client.yaml
```

支持 `uri`、终端 `qr`、`base64`、完整 `mihomo`、只有 proxies 列表的 `provider`、sing-box 1.14 JSON。多凭据节点用 `--user` 指定设备。Base64 是内容，不是在线订阅地址。导出文件权限 600，拒绝覆盖已有文件。

链接、二维码和客户端文件包含连接凭据；不会导出 REALITY 服务端私钥。官方 Mihomo 1.19.30 与 sing-box 1.14.0 已验证配置解析，Android 应用导入和真实连接未验证。客户端仅提供本机 mixed 入口与单节点转发，不附加 TUN、复杂分流或系统 DNS 接管。

## 事务、诊断和日志

统一数据库位于 `/var/lib/qingnode/current/state.json`，权限 600。核心运行配置为 root:qingnode 640，供专用服务账户读取。修改前保留旧配置代；候选配置先执行官方 `sing-box check`，再切换、启动、检查实际进程拥有的监听。校验失败不切换，启动失败恢复原配置和运行状态；`recover` 处理已记录的中断事务。

重复初始化不会改变时间戳与身份；若保存的身份完整而派生配置被破坏，`init` 或有效快照恢复会重新生成派生文件，保持密钥。不要手工修改 state.json 或服务器 JSON。数据库本身严重损坏、未知 schema 或恢复所需的旧核心缺失时，会停止并报告，需先找回有效历史数据或核心，不会猜测新凭据。

诊断检查核心及摘要、配置、凭据、证书、systemd、PID 所属监听、端口冲突、IPv4/IPv6、DNS、时间同步及 REALITY 目标 TLS1.3/HTTP2，并给出正常/警告/错误和处理建议。状态和诊断不会自动恢复事务或重启服务。故障或 debug 时输出最近 40 行脱敏日志。公网 IP 查询失败与 IPv6 不可用会单独提示，不把仅 IPv4 VPS 当成安装失败。

单个核心进程承载多个节点，应用配置可能使连接短暂中断。systemd active、端口监听和配置检查均不等于客户端认证或公网连通验证。

## 防火墙与 BBR

默认防火墙采用手动管理，`firewall status` 检测 UFW、firewalld、nftables、iptables 并报告需要的端口。

已启用且规则可识别的 UFW 可用 `firewall enable` 启用**本项目规则管理**；此命令不会执行 `ufw enable`。后续改端口、禁用、删除和卸载会同步项目带标签的规则，先添加新规则，服务成功后删除旧规则；失败尽力回滚。已有外部规则不改标签、不删除，不清空规则，SSH 端口受到保护。`firewall disable` 移除项目规则并转手动模式；`firewall sync` 修复项目规则漂移。

其他后端、多个防火墙管理器共存、复杂自定义策略、IPv4/IPv6 规则不对称以及云安全组须人工核对。共享 ACME TCP 80 不自动管理；查询到端口规则也不保证云端放行。UFW 自动变更仅经过模拟测试，实机未验证。

`network status` 查看拥塞算法和队列规则；`network bbr` 仅使用系统内核 BBR + fq，写入项目专用 sysctl 文件，失败恢复原值，已启用时不重复修改。不安装第三方内核，不改 SSH、路由或 DNS。真实内核行为未验证。

## 备份、恢复和卸载

```bash
sudo qingnode backup
sudo qingnode restore --file /root/backup.qnbak --yes
sudo qingnode uninstall --yes
sudo qingnode uninstall --purge --yes
```

`backup` 默认按时间保存到状态目录的 backups。v2 快照包括 State、实际服务器配置、systemd 定义、管理器版本、节点/防火墙模式，以及导入的 PEM。AES-256-GCM + PBKDF2-SHA256 600,000 轮，至少 12 字节口令，不回显。非交互用权限 600 的 `--password-file`；v1 加密备份仍可恢复。

恢复前再次加密备份当前配置，口令与此次恢复所用口令相同。恢复仅从类型校验后的 State 生成配置，不执行快照中的任意 systemd 内容；验证或启动失败回滚。跨机器需先安装匹配版本的核心，并调整地址和防火墙，可用 `--manual-firewall` 恢复为手动模式。

**不包含 ACME 账户/证书缓存、核心二进制、全机防火墙和 BBR 系统设置。** ACME 恢复可能重新签发并受 CA 限制。不是整机备份。历史代和旧核心保留，尚无自动清理策略。

默认卸载仅删除本项目核心，停止服务并禁用自启，保留管理器和节点；`core install` 后可重新启动。`--purge` 删除本项目管理器、服务、辅助脚本、节点及核心，保留专用系统账户和明确启用过的 BBR 设置，避免误删账户资源或擅自改回系统网络策略。完整卸载会在卸载备份目录保存权限 600 的账户归属记录；重装仅在当前账户与该记录完全匹配时复用。旧版本此前卸载留下的无记录账户仍需人工确认，不会自动接管。

卸载前在 `/var/backups/qingnode` 自动保留权限 600 的**明文** JSON 快照，其中含凭据。重装后可恢复：

```bash
sudo qingnode restore --snapshot --file /var/backups/qingnode/before-uninstall-实际文件.json --yes
```

此时输入的口令用于恢复前的加密备份。请将重要加密备份复制到 VPS 之外，并妥善保管口令。

## 更新与 0.1.0 迁移

`core versions` 显示当前及官方最新稳定版；`update` 获取官方 Release，校验归档并保留旧核心，通过配置检查和服务就绪后提交。只接受已适配的 1.14.x 正式版，不会自动跨版本。也可显式指定 `core update --version ... --sha256 ... --archive ...`；降级需 `--allow-downgrade`。

管理器使用 `self-update --bundle /绝对路径/新版解压包`，或 `self-update --version v0.2.1` 从 `124aAA/openai` 下载指定版本，不覆盖节点、凭据和备份。可加 `--repo owner/repo` 显式指定其他发行仓库。建议 0.1.0 用户先备份，再运行新包 `install.sh --reinstall`；旧的 State 字段和 v1 备份兼容，新字段按需补充，历史未知创建时间保持为空。使用 0.2.0 新字段后，0.1.0 会拒绝读取未知字段，不能直接降级管理器。

配置及卸载事务有持久恢复记录。安装器能处理可捕获的步骤失败；机器断电或 SIGKILL 中断二进制安装仍可能需要重新运行安装器或使用已验证归档修复，不承诺所有外部系统失败都可自动恢复。

## 开发和验收

```bash
go test -race ./...
go vet ./...
shellcheck install.sh scripts/*.sh
sudo env GO="$(command -v go)" python3 scripts/test-installer.py
python3 scripts/fetch-test-core.py
SING_BOX_BIN="$PWD/artifacts/test-core/sing-box" go test ./internal/node -run OfficialCore -v -count=1
bash scripts/build.sh 0.2.1
```

构建需要 Go 1.25+、Python3、GNU tar，本次使用 Go 1.27.1。vendor 随源码提供。安装器测试使用临时路径、真实 Bash/CLI 与模拟系统命令，不操作测试机账户和服务。`scripts/acceptance-vps.sh` 是显式空白 VPS 验收入口，本轮仅验证其拒绝非 systemd 环境，完整流程未验证。

CI 与 tag 发布流程保留真实核心 TCP/UDP 测试门槛；本地路由订阅被拒绝时该测试确实失败，不会作为通过结果。仓库尚无远端，本轮未执行 GitHub Actions 或发布 Release。

协议适配集中在 `internal/node/protocol_*.go` 和注册表；UI 文本集中到 `internal/ui/catalog.go`。后续增加协议仍需注册、参数创建/菜单入口和测试，无需修改配置事务、备份或服务模型。TUIC、完整英文翻译、在线订阅、链式出站和 ACME 缓存迁移留待后续。

自有代码 MIT；第三方许可证见 THIRD_PARTY.md 与 vendor。sing-box 独立下载并遵循其自身许可。
