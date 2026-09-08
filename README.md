# QingNode 青节点

[![CI](https://github.com/124aAA/openai/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/124aAA/openai/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.2.1--preview-blue)](https://github.com/124aAA/openai/releases/tag/v0.2.1)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**一条命令安装，中文菜单管理，随时找回节点链接。**

QingNode 是基于官方 sing-box 的轻量 VPS 代理节点管理器，支持 VLESS REALITY / XTLS Vision、Shadowsocks 2022 和 Hysteria2。安装、节点维护、客户端导出、备份与故障诊断都可以通过 SSH 完成，适合管理自己的个人 VPS。

安装入口使用 Bash，管理程序为静态 Go CLI，服务由 systemd 托管。VPS 上无需编译 Go，也无需安装 Web 面板。

> 当前版本为 **v0.2.1 预发行版**。GitHub CI、15 组安装器隔离测试及三协议核心 TCP/UDP 集成测试已通过。真实 VPS 安装、云防火墙、ACME、BBR、ARM64 执行和公网客户端连接仍未验证，详见[验证范围](#验证范围)。

[快速安装](#快速安装) · [功能一览](#功能一览) · [菜单与 CLI](#菜单与-cli) · [客户端导出](#链接二维码和配置导出) · [备份恢复](#备份与恢复) · [更新](#更新与-010-迁移) · [常见问题](#常见问题) · [反馈](#反馈与许可)

## 快速安装

以 **root** 登录 VPS 的 SSH 终端，运行：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/124aAA/openai/main/install.sh)
```

系统只有 curl 时也可以：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/124aAA/openai/main/install.sh)
```

首次运行自动下载对应架构的发行包，校验后进入中文安装向导。已有 QingNode 时进入管理菜单。以后直接运行 `qingnode` 即可查看链接、管理节点和诊断故障。

```bash
qingnode
```

普通 sudo 用户可先运行 `sudo -i` 进入 root 终端，再执行安装命令。下面的系统管理命令也需要 root 或 sudo。

### 安装条件

| 项目 | 要求 |
| --- | --- |
| 系统识别范围 | Debian 12、13；Ubuntu 22.04、24.04、26.04 |
| 服务管理 | PID 1 必须为 systemd |
| CPU | x86_64 / amd64 或 aarch64 / arm64 |
| 网络 | 能访问 GitHub 与系统 apt 软件源，有客户端可达的服务器地址 |
| 下载工具 | 首次下载入口需要 wget 或 curl；其他基础依赖由安装器检测并补装 |
| 节点端口 | 未被其他服务占用，主机防火墙与云安全组允许所需 TCP / UDP 流量 |

只有 IPv4 的 VPS 可以使用。NAT VPS 需要自行确认外部端口映射，脚本不负责配置上游 NAT。系统识别分支通过测试不代表这些系统均已完成真实 VPS 验收。

### 安装向导怎么填

| 参数 | 填写说明 |
| --- | --- |
| 节点名称 | 自己容易辨认的名称，例如 `JP-Reality-01` |
| 协议 | 根据客户端支持情况选择 REALITY、SS2022 或 Hysteria2 |
| 服务器地址 | 客户端实际连接的 VPS 公网 IP 或指向 VPS 的域名 |
| 端口 | 使用未占用的端口；遇到冲突可换端口或选择随机端口 |
| REALITY SNI | VPS 能访问且满足握手要求的目标域名，不要原样照抄示例域名 |
| HY2 证书 | 提供对应域名的证书，或满足 ACME 自动签发条件 |
| UUID、密码和密钥 | 首次创建时自动生成并保存，无需手工编造 |

安装完成后，核对显示的地址与端口，将分享链接导入客户端并测试连接。服务显示“运行中”不等于云安全组和公网链路已经可用。

### 手动下载与非交互安装

安装脚本固定从本仓库的 [GitHub Releases](https://github.com/124aAA/openai/releases) 下载指定版本，不在 VPS 上编译。发布流程通过测试后才上传发行包；若显示 HTTP 404，先检查该版本是否已发布，其他下载失败可查看安装日志。不会自动切换第三方镜像。

也可以下载对应架构的发行包，上传 VPS，解压并进入目录后运行 `sudo bash install.sh`：

| CPU | 安装包 |
| --- | --- |
| Intel / AMD / x86_64 | [qingnode-0.2.1-linux-amd64.tar.gz](https://github.com/124aAA/openai/releases/download/v0.2.1/qingnode-0.2.1-linux-amd64.tar.gz) |
| ARM / Ampere / aarch64 | [qingnode-0.2.1-linux-arm64.tar.gz](https://github.com/124aAA/openai/releases/download/v0.2.1/qingnode-0.2.1-linux-arm64.tar.gz) |

压缩包外层校验清单：[SHA256SUMS](https://github.com/124aAA/openai/releases/download/v0.2.1/SHA256SUMS)。包内另有文件级清单，安装器会验证完整性。

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

## 功能一览

| 能力 | 当前实现 |
| --- | --- |
| 安装与交互 | 系统/依赖检测、八阶段进度、中文分级菜单、CLI |
| 多节点管理 | 添加、查看、修改、删除、启用、停用，独立节点 ID 与设备凭据 |
| 参数维护 | 修改地址、端口、SNI、fingerprint；显式轮换 REALITY 密钥和 short ID |
| 客户端导出 | 分享 URI、终端二维码、sing-box JSON、Mihomo YAML、provider 片段 |
| 服务管理 | 启动、停止、重启、开机自启、运行状态、进程与监听检查 |
| 配置保护 | 参数持久化、历史配置代、候选配置检查、失败回退、中断恢复 |
| 长期维护 | 加密备份与恢复、核心更新、管理器更新、分级卸载 |
| 系统工具 | 一键诊断、脱敏日志、防火墙检测、受限 UFW 管理、系统 BBR + fq |

### 协议支持

| 协议参数 | 协议组合 | 服务端监听 | 使用条件 |
| --- | --- | --- | --- |
| `reality` | VLESS + REALITY + XTLS Vision | TCP | 可用的 REALITY 握手目标；无需给 VPS 申请 TLS 证书 |
| `ss2022` | Shadowsocks 2022 / `2022-blake3-aes-256-gcm` | TCP + UDP | 客户端支持该加密方式与多用户密码格式 |
| `hysteria2` | Hysteria2 | UDP | 可验证的 TLS 证书，或满足 ACME 条件 |

三个协议均提供分享 URI、sing-box 和 Mihomo 导出。实际导入能力取决于客户端及其内核版本。TUIC、传统 Shadowsocks 加密方式、在线订阅服务和自动链式出站尚未实现。

## 菜单与 CLI

主菜单分为节点管理、链接与导出、服务管理、维护、系统工具，每层保持少量选项。普通查看不反复确认；删除、恢复、轮换密钥和卸载需要明确确认。

| 编号 | 主菜单 | 主要操作 |
| --- | --- | --- |
| 1 | 节点管理 | 添加/修改/启停/删除节点，设备凭据，REALITY 与证书 |
| 2 | 链接 / 二维码 / 配置 | 选择节点与凭据，查看链接或导出文件 |
| 3 | 服务管理 | 状态、启动、停止、重启、开机自启与日志 |
| 4 | 备份与更新 | 备份、恢复、更新、回退、中断恢复、卸载 |
| 5 | 网络与诊断 | 诊断、端口、防火墙、BBR |
| 0 | 退出 | 结束菜单 |

### 常用命令速查

**下表中的 `main` 是示例节点名称。** 先运行 `sudo qingnode list`，再换成自己的节点 ID 或名称。`--id` 同时接受两种标识；改名后 ID 保持不变，自动化中宜使用 ID。

| 任务 | 命令 |
| --- | --- |
| 打开菜单 / 查看版本 | 无参数运行 / `version` |
| 查看总帮助 | `help` |
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

名称改变不改变节点 ID；普通编辑不轮换身份。修改地址、端口、SNI 或认证参数后，都应重新导出并更新客户端。以下操作会显式重新生成所选凭据，需要重新导入受影响节点：

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

复制完整分享 URI，在兼容客户端中使用“从剪贴板导入”或同类入口；也可以扫描终端二维码。导出的 JSON/YAML 需先下载到自己的设备，再通过客户端的本地配置入口导入，不要把文件路径当作订阅网址。

| 格式 | 用途 |
| --- | --- |
| `uri` | 单个分享链接 |
| `qr` | 在终端显示分享链接二维码 |
| `sing-box` | 完整客户端 JSON，默认本机 mixed 端口 2080 |
| `mihomo` | 完整客户端 YAML，默认本机 mixed 端口 7890 |
| `provider` | 只有 `proxies` 列表的片段，供已有配置引用 |
| `base64` | 分享内容的 Base64 编码，不提供在线订阅地址 |

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

## 备份与恢复

```bash
sudo qingnode backup
sudo qingnode restore --file /root/backup.qnbak --yes
```

`backup` 默认按时间保存到状态目录的 backups。v2 快照包括 State、实际服务器配置、systemd 定义、管理器版本、节点/防火墙模式，以及导入的 PEM。AES-256-GCM + PBKDF2-SHA256 600,000 轮，至少 12 字节口令，不回显。非交互用权限 600 的 `--password-file`；v1 加密备份仍可恢复。

恢复前再次加密备份当前配置，口令与此次恢复所用口令相同。恢复仅从类型校验后的 State 生成配置，不执行快照中的任意 systemd 内容；验证或启动失败回滚。跨机器需先安装匹配版本的核心，并调整地址和防火墙，可用 `--manual-firewall` 恢复为手动模式。

**不包含 ACME 账户/证书缓存、核心二进制、全机防火墙和 BBR 系统设置。** ACME 恢复可能重新签发并受 CA 限制。不是整机备份。历史代和旧核心保留，尚无自动清理策略。

上面的 `/root/backup.qnbak` 是示例路径，恢复时应换成实际备份文件。建议设置至少 12 位的强口令，将重要加密备份复制到 VPS 之外；忘记口令无法通过管理器找回。

## 卸载

菜单入口：**4 备份与更新 → 7 卸载**。CLI 的 `--yes` 表示已确认操作，请按需要选择一种方式：

| 方式 | 命令 |
| --- | --- |
| 只移除核心，保留管理器与配置 | `sudo qingnode uninstall --yes` |
| 完全卸载本项目 | `sudo qingnode uninstall --purge --yes` |

默认卸载仅删除本项目核心，停止服务并禁用自启，保留管理器和节点；`core install` 后可重新启动。`--purge` 删除本项目管理器、服务、辅助脚本、节点及核心，保留专用系统账户和明确启用过的 BBR 设置，避免误删账户资源或擅自改回系统网络策略。完整卸载会在卸载备份目录保存权限 600 的账户归属记录；重装仅在当前账户与该记录完全匹配时复用。旧版本此前卸载留下的无记录账户仍需人工确认，不会自动接管。

卸载前在 `/var/backups/qingnode` 自动保留权限 600 的**明文** JSON 快照，其中含凭据。重装后可恢复：

```bash
sudo qingnode restore --snapshot --file /var/backups/qingnode/before-uninstall-实际文件.json --yes
```

此时输入的口令用于恢复前的加密备份。请将重要加密备份复制到 VPS 之外，并妥善保管口令。

## 更新与 0.1.0 迁移

`core versions` 显示当前及官方最新稳定版；`update` 获取官方 Release，校验归档并保留旧核心，通过配置检查和服务就绪后提交。只接受已适配的 1.14.x 正式版，不会自动跨版本。也可显式指定 `core update --version ... --sha256 ... --archive ...`；降级需 `--allow-downgrade`。

管理器使用 `self-update --bundle /绝对路径/新版解压包`，或 `self-update --version v0.2.1` 从 `124aAA/openai` 下载指定版本，不覆盖节点、凭据和备份。可加 `--repo owner/repo` 显式指定其他发行仓库。建议 0.1.0 用户先备份，再运行新包 `install.sh --reinstall`；旧的 State 字段和 v1 备份兼容，新字段按需补充，历史未知创建时间保持为空。使用 0.2.0 新字段后，0.1.0 会拒绝读取未知字段，不能直接降级管理器。

核心与管理器是两个独立更新：

| 想更新什么 | 命令 |
| --- | --- |
| 查看 sing-box 当前及官方最新稳定版 | `sudo qingnode core versions` |
| 更新已适配的 sing-box 稳定核心 | `sudo qingnode update` |
| 安装或重新安装管理器 v0.2.1 | `sudo qingnode self-update --version v0.2.1` |
| 用本地完整包更新管理器 | `sudo qingnode self-update --bundle /root/qingnode-release` |

未来更新管理器时，先查看 [Releases](https://github.com/124aAA/openai/releases)，再指定实际目标版本。菜单中的“更新管理器”目前使用本地包目录；在线指定版本使用 CLI。更新完成后重新打开 `qingnode` 菜单。

配置及卸载事务有持久恢复记录。安装器能处理可捕获的步骤失败；机器断电或 SIGKILL 中断二进制安装仍可能需要重新运行安装器或使用已验证归档修复，不承诺所有外部系统失败都可自动恢复。

## 常见问题

遇到故障，先运行一键诊断：

```bash
sudo qingnode diagnose
```

| 现象 | 处理方法 |
| --- | --- |
| wget 或 curl 找不到 | 改用另一条入口命令；两者都没有时，先通过 apt 安装其中一种 |
| 下载报 HTTP 404 | 检查指定版本与发行资产是否存在，确认使用本仓库的安装地址 |
| 下载超时 / DNS 错误 | 核对 VPS DNS、GitHub 连通性和软件源；也可使用完整本地包与官方核心归档 |
| 端口被占用 | 运行 `sudo qingnode ports` 查看进程，选择新端口或随机端口 |
| 找不到 main 节点 | 运行 `sudo qingnode list`，把示例名称换成实际节点 ID 或名称 |
| 服务运行但客户端连不上 | 核对服务器地址、端口、协议、链接是否更新，以及主机防火墙和云安全组 |
| REALITY 目标连接失败 | 核对 SNI 和握手目标，确认 VPS 能访问目标，检查时间同步 |
| HY2 无法连接 | 检查 UDP 放行、证书域名和有效期；ACME 签发还需检查 TCP 80 |
| 提示 IPv6 不可用 | 仅 IPv4 VPS 可继续使用 IPv4；不要填写不可达的 IPv6 地址 |
| 菜单需要交互终端 | 在正常 SSH 终端运行；自动化使用 `status` 等具体 CLI 命令 |
| 二维码显示错位 | 调整终端大小或改为复制 URI，无需重新安装 |
| 导出提示文件已存在 | 换一个文件名，或先核对并移动已有文件 |
| 更新或修改中断 | 查看诊断和日志；有未完成事务时运行 `sudo qingnode recover` 或使用菜单的恢复入口 |

进一步查看状态和脱敏日志：

```bash
sudo qingnode status
sudo qingnode logs
sudo qingnode --debug diagnose
```

修改端口后，手动防火墙和云安全组要自行同步；只有已经启用项目 UFW 管理时，脚本才会同步对应规则。不要通过清空防火墙、修改 SSH 或盲目重装来排查节点。

## 数据保存位置

| 路径 | 用途 |
| --- | --- |
| `/usr/local/bin/qingnode` | 管理器命令 |
| `/usr/local/lib/qingnode/install.sh` | 已安装的更新辅助入口 |
| `/etc/systemd/system/qingnode.service` | 本项目 systemd 服务 |
| `/var/lib/qingnode/current/state.json` | 当前节点数据库，权限 600 |
| `/var/lib/qingnode/current/server.json` | sing-box 运行配置，root:qingnode 640 |
| `/var/lib/qingnode/generations` | 历史配置代 |
| `/var/lib/qingnode/cores` | 按版本保存的核心 |
| `/var/lib/qingnode/backups` | 手动备份与恢复前备份 |
| `/var/backups/qingnode` | 卸载快照与保留账户归属记录 |

链接、二维码、私钥和备份都应按凭据保管。不要手动清空状态目录来“重置”安装，也不要公开未加密快照。

## 验证范围

v0.2.1 的 [发布工作流](https://github.com/124aAA/openai/actions/runs/34218805367) 和 [CI 工作流](https://github.com/124aAA/openai/actions/runs/34218805375) 均已实际执行并成功。

| 项目 | 验证情况 |
| --- | --- |
| Go 业务回归与静态检查 | race 测试、go vet、ShellCheck 已通过 |
| 安装器隔离测试 | 15 组通过；使用临时目录与模拟宿主命令 |
| REALITY / SS2022 / HY2 核心流量 | GitHub Ubuntu 24.04 runner 上，本机 TCP/UDP 往返通过 |
| 官方配置解析 | sing-box 1.14.0 与 Mihomo 1.19.30 解析通过 |
| 发行包 | amd64 / arm64 构建、公开下载及包内外 SHA-256 已核验 |
| 五种系统的实际 VPS 安装和卸载 | 未验证；系统标识模拟测试不能替代实机验收 |
| 公网客户端、移动端、云安全组 | 未验证 |
| ACME、真实 UFW / BBR、ARM64 执行 | 未验证 |

开发容器中曾因路由订阅权限受限导致核心流量测试失败，随后在 GitHub runner 上通过。具体测试、历史记录与限制见 [测试报告](docs/TEST_REPORT.md)。

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

CI 与发布流程保留真实核心 TCP/UDP 测试门槛，成功后才上传发行包。普通 Go 测试未设置外部核心环境变量时会跳过集成项，不能把跳过当作通过。上面的 `OfficialCore` 命令验证官方核心；归档完整性测试另需设置 `SING_BOX_ARCHIVE` 并匹配 `OfficialArchive`，Mihomo 解析测试需要 `MIHOMO_BIN`。

协议适配集中在 `internal/node/protocol_*.go` 和注册表；UI 文本集中到 `internal/ui/catalog.go`。后续增加协议仍需注册、参数创建/菜单入口和测试，无需修改配置事务、备份或服务模型。TUIC、完整英文翻译、在线订阅、链式出站和 ACME 缓存迁移留待后续。

开发文档：[架构说明](docs/ARCHITECTURE.md) · [审计与改造计划](docs/AUDIT_STAGE2.md) · [测试报告](docs/TEST_REPORT.md) · [版本说明](docs/RELEASE_NOTES.md)。

## 反馈与许可

发现问题可提交 [GitHub Issue](https://github.com/124aAA/openai/issues)，附上系统版本、CPU 架构、QingNode / sing-box 版本、操作步骤、脱敏错误摘要与诊断结果。提交日志或截图前，检查是否含密码、私钥、完整分享链接或二维码。

QingNode 自有代码采用 [MIT License](LICENSE)，第三方依赖及许可证见 [THIRD_PARTY.md](THIRD_PARTY.md) 与 vendor。感谢 [sing-box](https://github.com/SagerNet/sing-box) 及本项目使用的开源依赖；sing-box 独立下载并遵循其自身许可。
