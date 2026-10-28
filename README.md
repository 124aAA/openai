# QingNode 青节点

QingNode 用 Bash 引导、静态 Go 命令行和官方 sing-box 管理个人代理节点，由实际可用的 systemd/OpenRC 托管；不必安装面板、Docker或数据库。

**本源码版本为 v0.3.0，整合前11批实现。** 正式发行状态、完整源提交和资产摘要以 [Release](https://github.com/124aAA/openai/releases) 和对应 `RELEASE.json` 为准。默认在线入口先选择已经公开的正式发行，再固定版本下载；main 更新而新资产尚未公开时不会请求不存在的新包。本地完整包与显式 `--version` 保持指定版本，不自动换版。

整合起点与各层验收来源见[验证报告](docs/TEST_REPORT.md)。前11批实际结果保持各自提交和环境边界；配置解析、真实流量、服务生命周期、手机GUI与公网分别记录，不把交叉编译当成原生ARM验证。

[![CI](https://github.com/124aAA/openai/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/124aAA/openai/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.3.0-blue)](https://github.com/124aAA/openai/releases/tag/v0.3.0)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

| 想完成的事 | 从这里开始 |
| --- | --- |
| 快速建节点，按已知条件选择 | `qingnode wizard`，协议选择中输入 `h` 帮我选；条件建议不是速度排名 |
| 管理节点和设备凭据 | `qingnode` → 节点与用户；脚本查询用 `list --json` / `info --json` |
| 导出和订阅 | 菜单“导出与订阅”；[完整配置、设备及下载令牌](docs/SUBSCRIPTIONS.md) |
| 测速与排障 | `qingnode probe local` / `status --json`；[固定目标的受限测试](docs/NETWORK_TESTS.md) |
| 证书、备份、迁移和恢复 | [证书资源](docs/CERTIFICATES.md) · [配置备份与完整迁移](docs/MIGRATION.md) |
| NAT、中转和链式出口 | [连接地址与双栈](docs/ENDPOINTS.md) · [拓扑与落地](docs/TOPOLOGY.md) |
| 服务、监控和安装维护 | [实际平台边界](docs/PLATFORMS.md) · [监控与人工停止](docs/MONITORING.md) |

[七条短流程](docs/GETTING_STARTED.md) · [任务与机器接口](docs/WORKFLOWS.md) · [故障FAQ](docs/FAQ.md) · [支持及验证矩阵](docs/CAPABILITIES.md) · [架构](docs/ARCHITECTURE.md)

当前源码有七协议适配器，具体条件见[协议选择](docs/PROTOCOLS.md)。服务端/客户端版本、构建标签、解析、实际流量、GUI及公网分别记录。默认核心仍为1.14.0；1.14.3为显式候选，不跨兼容线自动升级。State为9，旧1–8只在内存兼容，写入保留原件；恢复旧快照不等于允许旧二进制直接读新State。

普通创建、状态和安装摘要默认隐藏认证与完整链接；需要连接配置时使用显式 `export --out`，文件仍须私密保存。URI表达不了的高级设置改用完整配置，不通过删字段假装等价。元数据维护复用真实影响分类，不宣称所有更新无中断。

脚本可在命令前加 `--result-dir 新私有目录` 保存版本1执行回执；命令本身的数据使用 `help --json` 列出的查询格式或显式私有导出。回执不抓取输出、不记录参数或凭据；取消、超时、缺少最终文件都不是完成。写命令报错仍可能已经提交配置，重试前先查状态与恢复材料。详见[机器接口与回执](docs/WORKFLOWS.md)。新增接口的实际测试范围以第11批记录为准。

前批实现历史及准确证据保持独立：[01](docs/BATCH_01.md) · [02](docs/BATCH_02.md) · [03](docs/BATCH_03.md) · [04](docs/BATCH04.md) · [05](docs/BATCH05.md) · [06](docs/BATCH06.md) · [07](docs/BATCH07.md) · [08](docs/BATCH08.md) · [09](docs/BATCH09.md) · [10](docs/BATCH10.md)。第10批Ubuntu24.04.5、Rocky9.8、Alpine3.24.2 amd64 VM的完整流程与三平台核心自启已有各自提交的实测；它们不自动替代本批新交互验收，也不代表原生ARM或公网通过。

## 快速安装

以 **root** 登录 VPS 的 SSH 终端，复制这一整行执行。入口会先完整下载，下载失败不执行，结束后清理临时文件：

```bash
bash -c 'set -e; f=$(mktemp); trap "rm -f \"$f\"" EXIT; curl -fsSL --retry 3 https://raw.githubusercontent.com/124aAA/openai/main/install.sh -o "$f"; bash "$f"'
```

首次运行先显示以下选择，输入编号后才继续安装；输入 `0` 或结束输入可在安装前退出：

```text
1. VLESS REALITY / Vision
2. Shadowsocks 2022
3. Hysteria2
4. AnyTLS
5. Trojan
6. 传统 SS AEAD
7. TUIC v5
0. 退出
```

选择 `1`、`2` 或 `6` 可使用自动地址/端口流程；REALITY另筛选握手目标。`3`、`4`、`5`、`7`先填写连接地址、TLS名称及证书条件，校验后再安装。摘要默认隐藏认证，显示节点信息及显式导出命令。自动出站地址发现不能证明公网入站可用。

只有 wget 的系统可将上面 `curl -fsSL --retry 3 URL -o "$f"` 换成 `wget -O "$f" URL`。也保留常见短入口：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/124aAA/openai/main/install.sh)
```

需要完全无人值守时，明确添加 `--auto`：

```bash
bash -c 'set -e; f=$(mktemp); trap "rm -f \"$f\"" EXIT; curl -fsSL --retry 3 https://raw.githubusercontent.com/124aAA/openai/main/install.sh -o "$f"; bash "$f" --auto'
```

自动搭建会下载并校验发行包和官方核心，优先探测公网 IPv4，失败再试 IPv6；REALITY 对通过 TLS 1.3 / HTTP2 与目标排除检查的站点测速，选择三次握手中位数最低的目标，优先使用 443，冲突时选择避开监听及 SSH 的随机端口，生成并保存凭据，启动服务并显示该节点的导出命令。v0.3.0默认隐藏认证和分享链接，需要时显式导出。没有可用地址或目标时会给出具体重试参数并停止。

显式提供的 `--server`、`--sni`、`--target`、`--port` 不会被自动替换；显式端口冲突会报错。可用 `--auto --protocol ss2022` 自动创建 SS2022。Hysteria2 仍需明确提供域名及证书/ACME 参数。自动模式不修改 SSH 或全机防火墙，云安全组/NAT 端口映射仍需满足安装条件。

再次运行带 `--auto` 的入口会更新管理器并保留现有节点、凭据及运行/自启状态；不重新探测已有节点地址，也不轮换身份。已有安装无参数运行入口会进入管理菜单。无交互终端时，裸入口提示使用 `--auto` 或完整参数并退出，不会代选协议。以后直接运行 `qingnode` 管理节点：

```bash
qingnode
```

普通 sudo 用户可先运行 `sudo -i` 进入 root 终端，再执行安装命令。下面的系统管理命令也需要 root 或 sudo。

### 自动选择伪装目标

`--auto` 对有限候选池并行探测：每站新建三次连接，证书、TLS 1.3、HTTP/2 全部通过后，按 DNS+TCP+TLS 总耗时的中位数排序，展示前三名并选第一名。任一采样失败即排除。手动查看排名不会修改节点：

```bash
qingnode reality-targets
qingnode reality-targets --top 6
```

可以把结果中的域名用于 `--sni`。新增或修改 REALITY 目标会拒绝已知 Cloudflare 域名、代理服务后缀和字面 IP；在线探测还检查目标 CNAME、全部 A/AAAA，并只连接已检查的 IP。Cloudflare 代理网段内置官方 2026-09-09 的 15 个 IPv4、7 个 IPv6 网段；不依赖安装时下载第三方名单。其它共享 CDN、DNS 后续变化及一般回落带宽消耗仍有风险，不能理解为杜绝偷跑。离线生成只做无需 DNS 的检查，部署前应运行在线诊断。

测的是 VPS 到目标站的建连耗时，**不是用户到节点的延迟或下载速度**。已有节点升级和重复安装时保留原 SNI；如果手动修改 SNI，需要同步更新客户端。单个 REALITY 节点使用一个目标，前三名供选择，不会后台轮换。

风险依据：[XTLS REALITY 回落说明](https://xtls.github.io/config/transports/reality.html)、[Cloudflare IPv4](https://www.cloudflare.com/ips-v4)、[IPv6](https://www.cloudflare.com/ips-v6)。筛选降低已知风险；当前 sing-box 不支持直接套用 Xray 的 `limitFallbackUpload/Download` 配置。

### 安装条件

| 项目 | 要求 |
| --- | --- |
| 当前源码安装目标 | Debian 12、13；Ubuntu 22.04、24.04、26.04；Rocky 9；Alpine 3.24；实际验收版本另列 |
| 服务管理 | Debian/Ubuntu/Rocky 为实际 systemd；Alpine 为实际 OpenRC 与 supervise-daemon；普通容器内仅有命令不算 |
| CPU | x86_64 / amd64 或 aarch64 / arm64 |
| 网络 | 能访问 GitHub 与对应 apt/dnf/apk 软件源；也可用已校验本地包；客户端入站另行验证 |
| 下载工具 | 首次下载入口需要 wget 或 curl；其他基础依赖由安装器检测并补装 |
| 节点端口 | 未被其他服务占用，主机防火墙与云安全组允许所需 TCP / UDP 流量 |

只有 IPv4 的 VPS 可以使用。NAT VPS 需要自行确认外部端口映射，脚本不负责配置上游 NAT。系统识别分支通过测试不代表这些系统均已完成真实 VPS 验收。

### 添加节点与 Hysteria2 向导怎么填

v0.3.0 在主菜单选择 `1 快速建节点`，即可选择协议，或输入 `h` 按已知条件查看建议，再填写参数。尚未升级的 v0.2.8 入口为 `6 搭建新节点`。REALITY 的 SNI 默认 `auto`，可直接回车自动筛选，或手动填写目标域名；端口默认 `auto`，可回车自动选端口，也可填写固定端口。

| 参数 | 填写说明 |
| --- | --- |
| 节点名称 | 自己容易辨认的名称，例如 `JP-Reality-01` |
| 协议 | `1` REALITY、`2` SS2022、`3` Hysteria2，以及 AnyTLS、Trojan、传统 SS AEAD、TUIC，条件见协议指南 |
| 服务器地址 | 客户端实际连接的 VPS 公网 IP 或指向 VPS 的域名 |
| 端口 | `auto` 自动选择可用端口，或填写未占用的固定端口 |
| REALITY SNI | `auto` 自动筛选测速，或填写满足握手与目标排除要求的域名 |
| HY2 证书 | 提供对应域名的证书，或满足 ACME 自动签发条件 |
| UUID、密码和密钥 | 首次创建时自动生成并保存，无需手工编造 |

候选安装完成后显示节点 ID/名称、协议、客户端连接地址与端口及配置导出命令；Hysteria2 还显示 TLS 域名与证书方式。使用显式 `export --out` 获取私有配置，或用 `qingnode info --id 节点ID --show-secrets` 查看含认证的信息，再导入客户端并测试连接。公开 v0.2.8 摘要直接显示分享 URI。服务显示“运行中”不等于云安全组和公网链路已经可用。

### 手动下载与非交互安装

安装脚本固定从本仓库的 [GitHub Releases](https://github.com/124aAA/openai/releases) 下载指定版本，不在 VPS 上编译。发布流程通过测试后才上传发行包；若显示 HTTP 404，先检查该版本是否已发布，其他下载失败可查看安装日志。不会自动切换第三方镜像。

也可以下载对应架构的发行包，上传 VPS，解压并进入目录后运行 `sudo bash install.sh`：

| CPU | 安装包 |
| --- | --- |
| Intel / AMD / x86_64 | [qingnode-0.2.8-linux-amd64.tar.gz](https://github.com/124aAA/openai/releases/download/v0.2.8/qingnode-0.2.8-linux-amd64.tar.gz) |
| ARM / Ampere / aarch64 | [qingnode-0.2.8-linux-arm64.tar.gz](https://github.com/124aAA/openai/releases/download/v0.2.8/qingnode-0.2.8-linux-arm64.tar.gz) |

压缩包外层校验清单：[SHA256SUMS](https://github.com/124aAA/openai/releases/download/v0.2.8/SHA256SUMS)。包内另有文件级清单，安装器会验证完整性。

上方公开下载仍为 v0.2.8，不含本批新平台。当前源码按平台矩阵选择 apt、dnf 或 apk，只补实际缺少的必要依赖，不执行系统升级；识别目标不等于已经完成实机验收。正常输出分八个阶段，错误日志保存在 `/var/log/qingnode-install-XXXXXXXX.log`，权限 600。

安装完成自动显示节点信息；候选需显式导出才能取得完整分享链接，公开 v0.2.8 仍直接显示。再次运行 `sudo qingnode` 或无参数的已安装 `install.sh` 进入管理菜单。完整发行包中的 `sudo ./qingnode` 也可调用同目录的已校验安装器。

非交互安装示例，地址和域名必须替换成自己的实际参数：

```bash
sudo bash install.sh --server 203.0.113.10 --sni example.com --port 443
sudo bash install.sh --protocol ss2022 --name SS-01 --server 203.0.113.10 --random-port
```

`--server` 是客户端连接地址；REALITY 的 `--sni` 是你选择的 TLS 握手目标。交互向导可查询公网 IPv4/IPv6，失败后允许手动输入。默认端口被占用时，交互安装可选择新端口；CLI 返回错误与查看进程的建议。随机端口避开已有节点、实际监听和已识别的 SSH 端口。

管理器运行无需 Go、Python 或 qrencode。二维码在静态 Go 程序内生成，不调用外部网站。

## 下载和重复安装

### 旧版本安装失败时的恢复

v0.2.1 读取 `/etc/os-release` 时会被系统的 `VERSION` 覆盖发行版本，导致第 3 步失败；v0.2.2 已修复该问题。真实 VPS 后续又暴露出第 7 步 `core-version: permission denied`：安装器的 `umask 077` 使配置代目录成为 0700，专用服务账户无法进入。v0.2.3 显式设置受管目录权限为 0750，并保留 State 0600、核心配置 0640 与专用服务账户。

以 root 使用最新固定版本入口恢复；`--reinstall` 更新辅助脚本并保留已有节点参数，`--auto` 使尚未完成初始化的机器也可继续自动安装：

```bash
bash -c 'set -e; f=$(mktemp); trap "rm -f \"$f\"" EXIT; curl -fsSL --retry 3 https://raw.githubusercontent.com/124aAA/openai/v0.2.8/install.sh -o "$f"; bash "$f" --reinstall --auto'
```

旧版的在线 self-update 可能调用旧辅助脚本，因此从旧版或临时修复版恢复时优先使用上面的新入口。系统提示需要重启不是这两项安装错误的根因；不要为此删除节点数据库或更换凭据。

默认核心锁定官方 sing-box 1.14.0，验证官方归档 SHA-256 后才执行。GitHub 不通时不会切换未知镜像，可上传本架构官方归档并使用：

```bash
sudo bash install.sh --core-archive /root/sing-box-1.14.0-linux-amd64.tar.gz
```

已有其他 sing-box 不会被接管。重新安装管理器保留已有节点、核心版本、UUID、密码、REALITY 密钥、short ID、端口和服务的运行/停止状态。无参数进入菜单；强制重新安装使用 `--reinstall`。

默认发行仓库为 `124aAA/openai`。需要指定仓库或版本时，使用 `install.sh --repo 124aAA/openai --version v0.2.8`。本地完整发行包优先使用相邻文件；本地包损坏或缺少部分文件时会报错，不会悄悄改为在线下载。

## 功能一览

| 能力 | 当前实现 |
| --- | --- |
| 安装与交互 | 系统/依赖检测、八阶段进度、中文分级菜单、CLI |
| 首页总览 | 本机服务/资源/节点状态，备份/证书、自检与公网实测历史，按需联网查询更新 |
| 多节点管理 | 添加、查看、修改、删除、启用、停用，独立节点 ID 与设备凭据 |
| 参数维护 | 修改地址、端口、SNI、fingerprint；显式轮换 REALITY 密钥和 short ID |
| 客户端导出 | 分享 URI、终端二维码、sing-box JSON、Mihomo YAML、provider 片段 |
| 服务管理 | 启动、停止、重启、开机自启、运行状态、进程与监听检查 |
| 配置保护 | 参数持久化、历史配置代、候选配置检查、失败回退、中断恢复 |
| 长期维护 | 加密备份与恢复、核心更新、管理器更新、分级卸载 |
| 系统工具 | 一键诊断、脱敏日志、防火墙检测、受限 UFW 管理、系统 BBR + fq |
| 网络测试（第 02 批源码） | `probe` 有限分路径测试、脱敏报告与条件对比；独立 `qingprobe` 在桌面/Linux 发起，不改节点或性能参数 |

### 当前源码协议支持（未发行）

| 协议参数 | 协议组合 | 服务端监听 | 使用条件 |
| --- | --- | --- | --- |
| `reality` | VLESS + REALITY + XTLS Vision | TCP | 可用的 REALITY 握手目标；无需给 VPS 申请 TLS 证书 |
| `ss2022` | Shadowsocks 2022 / `2022-blake3-aes-256-gcm` | TCP + UDP | 客户端支持该加密方式与多用户密码格式 |
| `hysteria2` | Hysteria2 | UDP | 可验证的 TLS 证书，或满足 ACME 条件 |
| `anytls` | AnyTLS | TCP | TLS证书与独立用户密码；空闲连接设置只进入完整配置 |
| `trojan` | Trojan / 原生TLS | TCP | TLS证书与独立用户密码，不包含额外WebSocket/gRPC传输 |
| `ss-aead` | 传统SS AEAD三方法 | TCP + UDP | 同方法独立多用户密码，不能混入SS2022服务密钥 |
| `tuic` | TUIC / QUIC | UDP | TLS证书、UUID+密码、QUIC构建能力；0-RTT关闭 |

七协议均有完整sing-box/Mihomo配置导出；TUIC无通用URI，AnyTLS显式空闲设置也不能进入URI/二维码/Base64。Trojan URI还需核对Chrome/Ed25519证书限制。实际导入能力取决于客户端与内核版本，准确实测见[第09批记录](docs/BATCH09.md)。远程Egress仍仅支持原有SOCKS5/REALITY/SS2022/HY2/WireGuard，客户端导出能力不代表可把新四协议添加为服务器远程出口。第06批设备导出与只读订阅的格式限制见[协议说明](docs/PROTOCOLS.md)。

## 菜单与 CLI

v0.3.0主菜单按任务分为七组，每层再展开必要选项。普通查看不反复确认；删除、恢复、轮换密钥和卸载保留明确确认。公开 v0.2.8 的菜单编号与此表不同。

| 编号 | 主菜单 | 主要操作 |
| --- | --- | --- |
| 1 | 快速建节点 | 直接选择协议、条件建议、NAT向导 |
| 2 | 节点与用户 | 修改/启停/删除节点，独立用户凭据 |
| 3 | 导出与订阅 | 链接、二维码、设备配置和下载权限 |
| 4 | 测速与诊断 | 本机/代理路径、服务器自检、公网手工记录 |
| 5 | 证书与备份 | 证书资源、备份、完整迁移与恢复 |
| 6 | 进阶网络 | 端点、拓扑、DNS、HY2及宿主网络 |
| 7 | 系统维护 | 服务、监控、更新、回退和卸载 |
| 8 | 刷新总览 | 只读本机，不联网 |
| 9 | 检查更新 | 联网查询管理器和核心版本，保存结果 |
| 0 | 退出 | 结束菜单 |

### 首页状态怎么读

进入菜单或运行 `sudo qingnode overview` 只读取本机状态，不下载、不运行自检、不恢复事务，也不改变节点或服务。首页显示管理器与配置核心版本、节点总数/启用数、服务本次运行时间、自启与自动重启次数，以及 CPU 核数、1 分钟负载、可用内存和数据磁盘余量。CPU 负载不是使用率；systemd 自动重启次数可以重置，不是永久故障统计。配置核心版本也不等于已核验正在运行的二进制版本。

最近备份只记录本版本成功完成的备份（含自定义路径及恢复前备份）；旧版未登记时显示暂无记录，文件存在不代表已验证恢复。导入的 PEM 显示剩余天数及失效原因；ACME 配置不等于已签发证书，实际期限未知时如实显示未知。REALITY/SS2022 无需自有 TLS 证书，显示不适用。

**服务运行中与公网连接验证分开显示。** 没有实测记录就是“待验证”。先在自己的客户端测试 HTTPS 和 UDP，再从 `4 测速与诊断 → 6 公网验证说明/管理员登记` 登记；也可使用下面命令，将节点和来源换成实际值，没测过的网络填写 `untested`，失败填写 `fail`：

```bash
sudo qingnode public-check --id main --tcp pass --udp untested --source 'Windows sing-box'
```

这是管理员提供的历史结果，程序不会自动证实公网连通。节点配置、核心或管理的防火墙模式变化后提示重新验证；自检也会因配置变化失效。超过 24 小时的结果提示复查，历史通过不代表持续在线。自检显示服务器侧错误/警告数量，不能代替客户端测试。

选择 `9` 或运行 `sudo qingnode check-updates` 才联网查询 GitHub 最近 100 项 Release，首页复用结果与时间。管理器查询包含有本机架构发行包的预发布版，升级前仍须核验兼容性；核心分别显示正式版与已适配版，不会自动跨版本升级。查询失败保留上次成功结果并标记失败；配置版本变化后要求重新检查。

### 常用命令速查

**下表中的 `main` 是示例节点名称。** 先运行 `sudo qingnode list`，再换成自己的节点 ID 或名称。`--id` 同时接受两种标识；改名后 ID 保持不变，自动化中宜使用 ID。

| 任务 | 命令 |
| --- | --- |
| 打开菜单 / 查看版本 | 无参数运行 / `version` |
| 本机总览 / 联网检查更新 | `overview` / `check-updates` |
| 登记客户端实测 | `public-check --id main --tcp pass --udp untested --source 客户端名称` |
| 查看总帮助 | `help` |
| 查看协议能力 / 高级选项 | `protocols list` / `protocols options --file 私有JSON --preview`；见[协议选择](docs/PROTOCOLS.md) |
| 初始化 / 添加 | `init` / `add`，或 `install` 安装核心并初始化 |
| 查看节点 / 凭据 | `list` / `info --id main` / `info --id main --show-secrets` |
| 查看 REALITY 私钥 | `info --id main --show-private` |
| 修改 / 启用 / 停用 | `edit --id main ...` / `enable --id main` / `disable --id main` |
| 预览单项 / 批量修改（本批源码） | `edit --id main --name 新名称 --preview` / `batch --file edits.json [--preview]` |
| 删除单个节点 | `delete --id main --yes` |
| 查看服务与监听 | `status` / `ports` |
| 服务运行 | `start` / `stop` / `restart` |
| 开机自启 | `service enable` / `service disable` |
| 诊断 / 日志 | `diagnose`（等同 `doctor`）/ `logs` |
| 分路径测试 / 桌面测试资料（本批源码） | `probe local` / `probe run --path ... --target ...` / `probe profile --id main --out 私有资料.json`，详见[网络测试](docs/NETWORK_TESTS.md) |
| 端口中转 / 远程出口（第 05 批源码） | `forward list` / `egress list` / `route set --id main --egress 出口ID --preview`，详见[拓扑与落地](docs/TOPOLOGY.md) |
| 拓扑统一应用 / WireGuard 材料 | `topology apply --file 私有拓扑.json --preview` / `wireguard pair --help`；不自动部署远端 |
| 出口链测试 / 显式主备 | `egress health --id 出口或策略ID --target https://自有目标`；仅 `--apply` 累计与切换，重复须显式 `--watch` |
| 配置检查 / 回退 | `check` / `rollback` / `recover` |
| 备份 / 恢复 | `backup` / `restore --file 文件 --yes` |
| 核心版本 / 更新 | `core versions` / `update` |
| 管理器更新 | `self-update --version v0.3.0` 或 `self-update --bundle 新版解压目录` |
| 网络 / 防火墙 | `network status` / `network bbr` / `firewall status` |

以上命令前加 `sudo qingnode`；多数带参数的命令可附 `--help` 查看参数，不接受参数的命令（如 `recover`）请查看 `qingnode help`。`--debug` 是全局参数，应放在命令前，例如 `sudo qingnode --debug diagnose`。非交互执行使用 CLI，不会等待菜单输入。环境变量 `NO_COLOR` 或不支持颜色的终端会禁用颜色。

`restart` 不改变开机自启设置。临时 `stop` 不改变节点 Enabled 字段。此批源码的展示/客户端编辑在运行输入不变时保持停止；端口、凭据、核心等运行变更沿原有应用规则，有启用节点时可以重新启动服务；持久停用使用 `disable`。

批量修改先用 `--preview` 查看哪些节点、客户端配置、服务端和宿主效果受影响。示例文件及字段限制见[本批接口](docs/BATCH_01.md#可运行的批量接口)。所有项按原 State 匹配目标，整体验证后统一应用；一项无效则整批不生效。预览不保存、不恢复事务、不联网检查目标，也不能代替实际应用时的候选核心校验。

## 节点和协议

公开 v0.2.8 支持 REALITY（VLESS + XTLS Vision / TCP）、Shadowsocks 2022 和 Hysteria2。v0.3.0源码另支持 AnyTLS、Trojan、传统 SS AEAD 和 TUIC；新增协议的客户端版本及导出限制见[协议选择](docs/PROTOCOLS.md)。

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

IPv6 字面地址默认监听 `::`；域名默认监听 IPv4。`--listen ::` 采用核心自动双栈套接字策略，不能保证双栈或严格 IPv6-only；须对同一实际监听分别验证 IPv4、IPv6。官方 1.14 没有入站 v6only JSON 开关，本项目不修改全机 IPv6。坏 AAAA 后回落 IPv4 成功不证明 IPv6 可达；纯 IPv4 节点不因没有 IPv6 判失败。

NAT 或中转入口可使用 `--listen 0.0.0.0 --port 443 --connect-port 30000`，表示本地 443、客户端连外部 30000；`--server`、SNI 和 REALITY 目标独立。`wizard --nat` 收集映射，`endpoint material` 列出待验证事项，不改变云厂商配置。TCP、UDP 映射各自核验，SS2022 同一入口必须映射同一个外部 TCP/UDP 端口。`capabilities` 分开报告本机绑定/小包收发、权限与未知项，不当作公网通过。详见 [ENDPOINTS.md](docs/ENDPOINTS.md)。

第 05 批的 `forward` 是固定目标的纯端口转发，使用官方 sing-box direct 入站；新增默认只监听 `127.0.0.1`，必须明确选择 TCP、UDP 或两者。它没有代理用户认证，公开监听前需自行限制可访问来源。`egress` 的 SOCKS5、REALITY、SS2022、HY2 或用户态 WireGuard 是独立远程出口，按稳定 ID 绑定节点；出口失效不会悄悄回到 direct。统一拓扑批量严格接受已定义对象，无效项整批拒绝，普通编辑保留凭据。用户态 WireGuard 不创建系统 wg0、不改宿主默认路由或 DNS，也不增加整个代理的永久权限。

主备只在显式 `egress health --apply` 时累计经过对应出口的应用层结果；失败阈值、恢复阈值和冷却期须保存到策略。普通查询/探测不切换，`--watch` 有轮数、时间与流量预算，不安装常驻监控。共享核心运行配置变化仍可能打断所有已有连接；新出口选择不能迁移已建立 TCP 会话，也不把多出口说成一条连接叠加带宽。客户端 Profile v2 的服务端路径摘要只是导出时声明，不能证明另一台服务器现在仍用该配置；不同路径报告拒绝直接比较。

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

默认导出 `default` 主连接端点；已有额外入口可加 `--endpoint 端点ID`，`probe profile/run` 也支持选择同一入口。公开地址/端口变化使新客户端配置摘要变化，旧测试记录需重验；不会改变 TLS 名称或轮换凭据。本地 `--port` 与已保存 `--connect-port` 独立，要同时更改需明确写出两者。

链接、二维码和客户端文件包含连接凭据；不会导出 REALITY 服务端私钥。官方 Mihomo 1.19.30 与 sing-box 1.14.0 已验证配置解析，Android 应用导入和真实连接未验证。客户端仅提供本机 mixed 入口与单节点转发，不附加 TUN、复杂分流或系统 DNS 接管。

## 事务、诊断和日志

统一数据库位于 `/var/lib/qingnode/current/state.json`，权限 600。核心运行配置为 root:qingnode 640，供专用服务账户读取。修改前保留旧配置代；候选配置先执行官方 `sing-box check`，再切换、启动、检查实际进程拥有的监听。校验失败不切换，启动失败恢复原配置和运行状态；`recover` 处理已记录的中断事务。

重复初始化不会改变时间戳与身份；若保存的身份完整而派生配置被破坏，`init` 或有效快照恢复会重新生成派生文件，保持密钥。不要手工修改 state.json 或服务器 JSON。数据库本身严重损坏、未知 schema 或恢复所需的旧核心缺失时，会停止并报告，需先找回有效历史数据或核心，不会猜测新凭据。

诊断检查核心及摘要、配置、凭据、证书、systemd、PID 所属监听、端口冲突、IPv4/IPv6、DNS、时间同步及 REALITY 目标 TLS1.3/HTTP2，并给出正常/警告/错误和处理建议。状态和诊断不会自动恢复事务或重启服务；完成的诊断会另存首页历史记录。故障或 debug 时输出最近 40 行脱敏日志。公网 IP 查询失败与 IPv6 不可用会单独提示，不把仅 IPv4 VPS 当成安装失败。

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

`backup` 默认按时间保存到状态目录的 backups。v2快照包括State、实际服务器配置、本机服务定义来源材料、管理器版本、节点/防火墙模式，以及导入的PEM。AES-256-GCM + PBKDF2-SHA256 600,000轮，至少12字节口令，不回显。非交互用权限600的 `--password-file`；v1加密备份仍可恢复。

恢复前再次加密备份当前配置，口令与此次恢复所用口令相同。恢复仅从类型校验后的State生成配置，按目标systemd/OpenRC重新渲染服务，不执行快照中的任意服务脚本；验证或启动失败回滚。跨机器需先安装匹配版本的核心，并调整地址和防火墙，可用 `--manual-firewall` 恢复为手动模式。

**默认配置备份不包含ACME账户/证书缓存、核心二进制、全机防火墙和BBR系统设置。** ACME恢复可能重新签发并受CA限制。v0.3.0 另有 `backup --full` 加密迁移与显式备份保留策略，范围、缺项、短停和目标环境预检见[迁移与恢复](docs/MIGRATION.md)；它也不是整机备份。历史配置代和旧核心仍保留。

上面的 `/root/backup.qnbak` 是示例路径，恢复时应换成实际备份文件。建议设置至少 12 位的强口令，将重要加密备份复制到 VPS 之外；忘记口令无法通过管理器找回。

## 卸载

v0.3.0 菜单入口：**7 系统维护 → 2 备份、更新、回退与卸载 → 7 卸载**。CLI 的 `--yes` 表示已确认操作，请按需要选择一种方式：

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

## 更新与旧版迁移

`core versions` 显示当前及官方最新稳定版；`update` 获取官方 Release，校验归档并保留旧核心，通过配置检查和服务就绪后提交。只接受已适配的 1.14.x 正式版，不会自动跨版本。也可显式指定 `core update --version ... --sha256 ... --archive ...`；降级需 `--allow-downgrade`。

管理器使用 `self-update --bundle /绝对路径/新版解压包`，或 `self-update --version v0.3.0` 从 `124aAA/openai` 下载指定版本，不覆盖节点、凭据和备份。可加 `--repo owner/repo` 显式指定其他发行仓库。旧版用户先用原管理器做配置备份，再按[旧正式版升级步骤](docs/MIGRATION.md#从-v028-升级到-v030)运行已核验新包的 `install.sh --reinstall`；旧版没有 `backup --full`，完整迁移预览应使用新包中的程序。旧 State 只读在内存兼容，写入会保留原件并使用 State9；v1/v2 备份仍可读。旧管理器不能直接读取 State9，降级须同时恢复匹配的旧程序、旧 State、核心及受管资源。

核心与管理器是两个独立更新：

| 想更新什么 | 命令 |
| --- | --- |
| 查看 sing-box 当前及官方最新稳定版 | `sudo qingnode core versions` |
| 更新已适配的 sing-box 稳定核心 | `sudo qingnode update` |
| 安装或重新安装管理器 v0.3.0 | `sudo qingnode self-update --version v0.3.0` |
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
| 第 3 步提示仓库名或正式版本号无效 | v0.2.1 安装器存在系统字段冲突；按“下载和重复安装”中的命令使用本版修复入口 |
| wget 或 curl 找不到 | 改用另一条入口命令；两者都没有时，先通过 apt 安装其中一种 |
| 下载报 HTTP 404 | 检查指定版本与发行资产是否存在，确认使用本仓库的安装地址 |
| 下载超时 / DNS 错误 | 核对 VPS DNS、GitHub 连通性和软件源；也可使用完整本地包与官方核心归档 |
| 端口被占用 | 运行 `sudo qingnode ports` 查看进程，选择新端口或随机端口 |
| 找不到 main 节点 | 运行 `sudo qingnode list`，把示例名称换成实际节点 ID 或名称 |
| 服务运行但客户端连不上 | 核对服务器地址、端口、协议、链接是否更新，以及主机防火墙和云安全组 |
| 第 7 步 core-version 权限被拒绝 | v0.2.2 的目录 umask 问题；使用本版新入口加 --reinstall --auto，保留原数据 |
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
| `/etc/init.d/qingnode` | OpenRC平台的本项目服务；按实际平台生成 |
| `/var/lib/qingnode/current/state.json` | 当前节点数据库，权限 600 |
| `/var/lib/qingnode/current/server.json` | sing-box 运行配置，root:qingnode 640 |
| `/var/lib/qingnode/generations` | 历史配置代 |
| `/var/lib/qingnode/cores` | 按版本保存的核心 |
| `/var/lib/qingnode/backups` | 手动备份与恢复前备份 |
| `/var/lib/qingnode/observations.json` | 首页观测历史，权限 600；不属于节点数据库或配置快照 |
| `/var/backups/qingnode` | 卸载快照与保留账户归属记录 |

链接、二维码、私钥和备份都应按凭据保管。不要手动清空状态目录来“重置”安装，也不要公开未加密快照。

## 验证范围

第 01 批源码的测试与未验证范围见 [BATCH_01.md](docs/BATCH_01.md)，第 02 批网络测试证据见 [BATCH_02.md](docs/BATCH_02.md)，核心/协议/客户端/平台分层见 [CAPABILITIES.md](docs/CAPABILITIES.md)。下方发行与 VPS 结果均为对应版本的历史证据，不能当作本批真实 systemd MainPID、持续 TCP、客户端测速或公网验收。

v0.2.8 的发布门槛包括Go/race/vet、安装器故障注入、官方sing-box三协议回环TCP/UDP、固定Mihomo解析、双架构发行包，以及一次性Ubuntu runner真实systemd生命周期。实际结果见[测试报告](docs/TEST_REPORT.md)与[Actions](https://github.com/124aAA/openai/actions)，各自绑定具体提交。以下保留旧版本历史记录。

v0.2.5 的验证重点是首屏协议选择、取消/EOF 前无安装副作用、无终端拒绝代选、显式自动模式兼容及成功信息展示，执行状态见[测试报告](docs/TEST_REPORT.md)。v0.2.4 已增加 REALITY 目标排除、三次探测中位数排序、异常 TLS 和只读候选查询的回归；v0.2.3 已验证自动选择、root 降权权限、明文脱敏、端口边界与 systemd 启动限流恢复。Ubuntu 24.04.4 amd64 VPS 有公开入口升级、身份保持和 Windows 官方客户端公网 HTTPS/UDP 实测记录。历史结果不替代新版本验收；其他系统、ARM64、ACME、BBR、复杂防火墙及移动端仍有未验证项。

v0.2.2 针对系统字段冲突补充回归：测试夹具包含带空格的 `VERSION`，覆盖五种系统标识的在线首装/重装、真实宿主 `/etc/os-release`、显式 `--version` 保持，以及无效仓库与版本参数拒绝。完整安装器测试扩展为 19 组；提交前的实测结果见 [测试报告](docs/TEST_REPORT.md)，远端状态见 [Actions](https://github.com/124aAA/openai/actions)。这仍不能代替各系统的真实 VPS 全流程验收。

以下保留 v0.2.1 发布时的验证记录；原夹具缺少 `VERSION` 字段，未覆盖本次发现的冲突：

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
python3 scripts/test-maintenance-harness.py -v
sudo env GO="$(command -v go)" python3 scripts/test-installer.py
python3 scripts/fetch-test-core.py
SING_BOX_BIN="$PWD/artifacts/test-core/sing-box" go test ./internal/node -run OfficialCore -v -count=1
bash scripts/build.sh 0.3.0
bash scripts/build-probe.sh 0.3.0
```

构建需要 Go 1.25+、Python3、GNU tar；现有 CI 固定 Go 1.27.1，本批实际工具/环境见 BATCH_02。vendor 随源码提供。安装器隔离测试使用临时路径、真实 Bash/CLI 与模拟系统命令。`scripts/acceptance-vps.sh` 另在一次性 Ubuntu runner 上验证真实 systemd 安装、重装、启停、备份恢复及卸载，v0.2.3 已完整通过；每次发布仍须重跑。该脚本仅供可清理的空白机器，公网连接和各平台需单独验收。

`build-probe.sh` 独立生成 `artifacts/probe/` 下 Linux amd64/arm64 和 Windows amd64 测试助手包、内外摘要与许可声明。v0.3.0 发布流程将三份探针包与两份管理器包纳入同一 schema2 发行清单；加上 SHA256SUMS 和 RELEASE.json 共七项公开资产。探针不会作为桌面常驻服务安装。构建成功只证明生成目标文件，各平台执行与官方核心流量另验。

CI 与发布流程保留真实核心 TCP/UDP 测试门槛，成功后才上传发行包。普通 Go 测试未设置外部核心环境变量时会跳过集成项，不能把跳过当作通过。上面的 `OfficialCore` 命令验证官方核心；归档完整性测试另需设置 `SING_BOX_ARCHIVE` 并匹配 `OfficialArchive`，Mihomo 解析测试需要 `MIHOMO_BIN`。

协议适配集中在 `internal/node/protocol_*.go` 和注册表；UI 文本集中到 `internal/ui/catalog.go`。服务器拓扑另用独立的类型对象和校验，不把客户端导出列表当作服务器路由。后续增加协议仍需注册、参数创建/菜单入口和测试，并核对事务与版本边界。完整英文翻译仍未完成；在线订阅、ACME资产迁移和七协议已纳入 v0.3.0 源码，实际公开状态以对应 Release 为准，支持范围和未验证项见[能力矩阵](docs/CAPABILITIES.md)。下方历史报告中的“未发行”保留当时含义。

开发文档：[架构说明](docs/ARCHITECTURE.md) · [能力矩阵](docs/CAPABILITIES.md) · [网络测试](docs/NETWORK_TESTS.md) · [拓扑与落地](docs/TOPOLOGY.md) · [第 05 批持续实施记录](docs/BATCH05.md) · [审计与改造计划](docs/AUDIT_STAGE2.md) · [测试报告](docs/TEST_REPORT.md) · [版本说明](docs/RELEASE_NOTES.md)。

## 反馈与许可

发现问题可提交 [GitHub Issue](https://github.com/124aAA/openai/issues)，附上系统版本、CPU 架构、QingNode / sing-box 版本、操作步骤、脱敏错误摘要与诊断结果。提交日志或截图前，检查是否含密码、私钥、完整分享链接或二维码。

QingNode 自有代码采用 [MIT License](LICENSE)，第三方依赖及许可证见 [THIRD_PARTY.md](THIRD_PARTY.md) 与 vendor。感谢 [sing-box](https://github.com/SagerNet/sing-box) 及本项目使用的开源依赖；sing-box 独立下载并遵循其自身许可。
