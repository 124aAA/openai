# QingNode 青节点

QingNode 是运行在 Linux VPS 上的轻量代理节点管理器。用中文菜单完成创建节点、导出连接信息、诊断、更新和备份；底层使用官方 sing-box，由 systemd 或 OpenRC 托管，无需面板、Docker 或数据库。

[![CI](https://github.com/124aAA/openai/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/124aAA/openai/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**本文对应当前源码。** 已安装版本用 `qingnode version` 查看；正式安装包、源码提交和校验摘要以 [Releases](https://github.com/124aAA/openai/releases/latest) 及包对应的 `RELEASE.json` 为准。未发布的源码改动不会自动进入已发布安装包。

## 一键安装

以 root 登录自己的 VPS，在 SSH 终端执行整行命令。入口完整下载成功后才执行，结束后清理临时文件：

```bash
bash -c 'set -e; f=$(mktemp); trap "rm -f \"$f\"" EXIT; curl -fsSL --retry 3 https://raw.githubusercontent.com/124aAA/openai/main/install.sh -o "$f"; bash "$f"'
```

普通 sudo 用户先运行 `sudo -i`。首次运行按提示选择协议，再填写所需地址、端口和证书；输入 `0` 可在安装前退出。安装器选择已公开的正式发行并固定版本下载，校验通过才安装。再次无参数运行已安装入口会进入管理菜单。

| 安装条件 | 要求 |
| --- | --- |
| 系统 | Debian 12/13、Ubuntu 22.04/24.04/26.04、Rocky 9、Alpine 3.24；实际验收范围见[平台说明](docs/PLATFORMS.md) |
| 服务管理 | 实际运行的 systemd 或 OpenRC；普通容器里只有管理命令不够 |
| 架构 | x86_64 / amd64 或 aarch64 / arm64 |
| 下载 | 在线安装需预先具备 Bash、curl、tar、gzip、sha256sum、awk、grep 及可用 HTTPS；只有 wget 不足以完成后续发行包下载 |
| 网络 | 客户端连接地址正确，节点端口空闲，主机防火墙与云安全组放行所需 TCP / UDP |

安装器补装缺少的运行依赖，不升级整个系统，不接管其他 sing-box 安装。NAT VPS 还需自行配置服务商的外部端口映射。只有 IPv4 的 VPS 也可以使用。

无法在线下载时，从 [Releases](https://github.com/124aAA/openai/releases) 选择对应架构的完整包，核对 `SHA256SUMS` 后解压，运行包内 `sudo bash install.sh`。可通过 `--core-archive` 提供已核验的官方核心归档。管理器运行不需要 Go、Python 或 qrencode。

需要无人值守时，为上面的 `bash "$f"` 明确添加 `--auto`，默认自动创建 REALITY；也可用 `--auto --protocol ss2022`。指定的地址和端口不会被自动替换。TLS 类协议仍需提供证书条件，完整参数见 `bash install.sh --help`。

## 创建和管理节点

安装后运行：

```bash
sudo qingnode
```

主菜单按常见任务安排：

| 编号 | 入口 | 用途 |
| --- | --- | --- |
| 1 | 创建节点 | 直接选择协议；`h` 帮我选，`n` 设置 NAT，`?` 查看详细能力 |
| 2 | 节点管理 | 查看、添加、修改地址/端口、启停、删除与凭据管理 |
| 3 | 导出链接、二维码或配置 | 直接选择节点，导出链接、二维码或客户端配置 |
| 4 | 状态与诊断 | 运行状态、监听端口、自检、测速与监控结果 |
| 5 | 备份与更新 | 加密备份、恢复、更新管理器/核心、回退与卸载 |
| 6 | 高级设置 | 端点、中转、出口、DNS、网络、证书、设备与订阅 |
| 7 | 服务管理 | 启动、停止、重启、自启与日志 |
| 8 / 9 | 刷新 / 检查更新 | 8 只读本机；9 联网查询，不自动升级 |
| 0 | 退出 | 结束菜单 |

创建时通常只需填写名称、客户端连接地址和协议必要参数。端口可用默认 `auto`；REALITY 握手目标也可用 `auto` 自动筛选。UUID、密码和密钥由程序生成并保存，普通修改不会重新生成它们。

协议默认只显示简要条件；详细限制按需查看：

| 协议 | 主要条件 |
| --- | --- |
| REALITY / Vision | 无需自己的域名或证书；客户端支持，服务器可访问适用握手目标 |
| Shadowsocks 2022 | 无需证书；客户端支持 SS2022 多用户密码格式 |
| 传统 SS AEAD | 客户端支持相同的现代 AEAD 加密方法 |
| Hysteria2 / TUIC | 可信 TLS 证书、UDP 入口和匹配客户端；TUIC 没有通用分享 URI |
| AnyTLS / Trojan | TLS 证书及匹配客户端；部分高级设置需完整配置 |
| VLESS / VMess + TLS | 可信证书；VLESS 和 VMess 支持 TLS 直连、WebSocket、gRPC，VLESS 另提供高级 HTTPUpgrade |

列表输入 `0` 返回；表单按提示输入 `:cancel` 取消，提交前不会创建半个节点。删除、恢复、轮换密钥和卸载仍需明确确认。协议细节见[协议说明](docs/PROTOCOLS.md)，NAT 与 IPv6 见[连接端点](docs/ENDPOINTS.md)。

## 导出给客户端

**在菜单中创建成功后，选择 `1 立即导出`，即可继续导出刚创建的节点；默认 `0 返回`，不会自动显示凭据。** 以后直接进入主菜单 `3 导出链接、二维码或配置`，无需逐层寻找。静默创建不显示摘要；需要导出时运行 `qingnode info` 查看对应命令。

选择自己的凭据，再选链接、二维码或完整配置；可以保存为新私有文件。二维码在本机生成，不发送到外部网站。终端太窄导致二维码换行时，改用链接或配置文件。

也可直接使用命令，先用 `list` 找到真实节点 ID；示例中的 `NODE_ID`、`USER_ID` 和输出路径都需替换：

```bash
sudo qingnode list
sudo qingnode info --id NODE_ID
sudo qingnode export --id NODE_ID --user USER_ID --format uri --out /root/node-link.txt
sudo qingnode export --id NODE_ID --user USER_ID --format sing-box --client-version 1.14.0 --out /root/node-client.json
sudo qingnode export --id NODE_ID --user USER_ID --format mihomo --client-version 1.19.30 --out /root/node-client.yaml
```

把文件安全传到设备并从客户端的本地配置入口导入。分享链接、二维码和配置都含认证信息，不能公开；已有输出文件会被拒绝覆盖。普通 `info` 默认隐藏凭据，确需查看时显式使用 `--show-secrets`。

URI 无法表达的高级设置请使用完整配置；`provider` 片段不是可独立运行的完整客户端配置。设备多节点配置和在线订阅是可选能力，在 `6 高级设置 → 设备与订阅` 中管理，详见[导出与订阅](docs/SUBSCRIPTIONS.md)。

## 连不上时怎么查

先进入 `4 状态与诊断`，或按需要运行：

```bash
sudo qingnode status          # 核心运行状态
sudo qingnode ports           # 本机 TCP/UDP 监听
sudo qingnode doctor          # 联网自检并给出处理建议
sudo qingnode logs            # 最近日志，默认脱敏
sudo qingnode firewall status # 本机防火墙和所需端口
```

重点核对客户端地址、外部端口、云安全组、NAT 映射及证书名称。**服务运行、配置通过和本机监听都不等于公网客户端已连通**；最后须在实际客户端网络测试 TCP 及所需 UDP。

查询不会自动恢复事务或重启服务。遇到中断事务先保留现场，确认状态后再按提示使用 `recover`。更多现象见[故障 FAQ](docs/FAQ.md)；需要按同条件测量延迟/吞吐时见[网络测试](docs/NETWORK_TESTS.md)。

## 更新、备份与恢复

主菜单 `5 备份与更新` 直接进入维护操作。管理器与 sing-box 核心分别更新：

| 任务 | 命令 |
| --- | --- |
| 检查可用版本，不安装 | `sudo qingnode check-updates` |
| 更新已适配的 sing-box 核心 | `sudo qingnode update` |
| 用已校验的完整包更新管理器 | `sudo qingnode self-update --bundle /root/qingnode-release` |
| 在线更新管理器到明确版本 | `sudo qingnode self-update --version 实际发行标签` |
| 加密备份配置 | `sudo qingnode backup` |
| 预览备份恢复 | `sudo qingnode restore --file /root/config.qnbak --preview` |
| 确认恢复备份 | `sudo qingnode restore --file /root/config.qnbak --yes` |

先在 [Releases](https://github.com/124aAA/openai/releases) 核对目标版本。默认核心为 1.14.0，只在已适配的 1.14.x 范围内更新；不会自动跨兼容线升级。更新管理器保留节点身份和凭据，完成后重新打开菜单。需要重装时，在已校验的完整包中运行 `sudo bash install.sh --reinstall`，保留现有参数和运行/自启选择。

备份口令至少 12 字节，交互输入不回显；自动化使用权限 `0600` 的 `--password-file`，不要把口令写到命令行。恢复前会备份当前配置，验证或启动失败走现有回滚流程。重要备份请复制到 VPS 之外并保管口令。

**普通配置备份不是整机备份**，不包括 ACME 缓存、核心二进制、全机防火墙和系统网络设置。跨机迁移先运行 `backup --full --preview` 查看资产和可能的短暂停服，再按[迁移与恢复](docs/MIGRATION.md)处理。旧版本升级方法也在该文档，不能直接让旧管理器读取新 State。

卸载入口为 `5 备份与更新 → 7 卸载`。默认只移除核心并保留管理器和配置；完全卸载使用 `uninstall --purge --yes`，操作前仍应自行保存加密备份。完整卸载保留的 `/var/backups/qingnode` 明文快照含凭据，须私密保存。重装后可显式恢复该快照，路径换成实际文件：

```bash
sudo qingnode restore --snapshot --file /var/backups/qingnode/before-uninstall-实际文件.json --yes
```

## 文档与数据

| 需要了解 | 文档 |
| --- | --- |
| 安装、NAT、导出和客户端验证 | [上手指南](docs/GETTING_STARTED.md) |
| CLI、JSON 查询与执行结果 | [工作流程与脚本接口](docs/WORKFLOWS.md)；完整帮助用 `qingnode help` |
| 证书、完整迁移、监控 | [证书](docs/CERTIFICATES.md) · [迁移](docs/MIGRATION.md) · [监控](docs/MONITORING.md) |
| 中转、出口和系统调优 | [拓扑](docs/TOPOLOGY.md) · [网络参数](docs/NETWORK_PERFORMANCE.md) |
| 支持范围与验证边界 | [能力矩阵](docs/CAPABILITIES.md) · [平台说明](docs/PLATFORMS.md) |
| 维护和开发 | [架构](docs/ARCHITECTURE.md) · [开发指南](docs/DEVELOPMENT.md) |
| 历史版本、批次和测试记录 | [发布记录](docs/RELEASE_NOTES.md) · [验证报告](docs/TEST_REPORT.md) |

节点保存在 `/var/lib/qingnode`：`current` 指向当前配置代，`generations` 保留历史，`backups` 保存加密备份。State 是管理器的节点数据文件，权限 `0600`；配置修改通过候选检查、原子切换和失败回滚，不要手工删除状态或更改格式版本号。

问题反馈请附系统、QingNode/核心/客户端版本、失败步骤和脱敏错误，不要附密码、私钥、完整链接、二维码或 `state.json`。项目采用 [MIT 许可证](LICENSE)，第三方说明见 [THIRD_PARTY.md](THIRD_PARTY.md)。
