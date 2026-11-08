# 从安装到客户端验收

本文对应当前源码（`0.4.0`）；已安装版本用 `qingnode version` 查看，正式包以 Release 和 `RELEASE.json` 为准。源码中的新菜单与协议组合需要相应版本才会出现。能力与实测范围见[支持矩阵](CAPABILITIES.md)，历史结果见[验证报告](TEST_REPORT.md)。

## 最短使用路径

1. 按 [README 的一键安装](../README.md#一键安装)在自己的 VPS 安装，选择协议并完成表单。
2. 安装后运行 `sudo qingnode`。新增节点从 `1 创建节点` 开始；协议从原来的 7 种扩展到 **9 种底层协议**（`reality`、`ss2022`、`hysteria2`、`anytls`、`trojan`、`ss-aead`、`tuic`、`vless-tls`、`vmess-tls`），其中 `VLESS + TLS`、`VMess + TLS` 各支持直连（`tcp`）、WebSocket（`ws`）、gRPC（`grpc`）、HTTPUpgrade（`httpupgrade`），`Trojan` 新增 `ws`、`grpc`、`httpupgrade` 三种传输，共计 **11 个新协议与传输组合**。
3. 菜单创建成功后选 `1 立即导出`，即可直接获取分享链接、终端二维码或导出完整客户端配置；默认返回，不自动在公共屏幕回显凭据。以后随时从主菜单 `3 导出链接、二维码或配置`（或 `2 节点管理 → 10 导出链接/二维码/配置`）进入。
4. 将链接或完整配置导入自己的客户端，测试实际连接。需要排障进入 `4 状态与诊断`；备份和升级进入 `5 备份与更新`。

普通列表输入 `0` 返回，表单输入 `:cancel` 取消。创建后的导出是可选下一步，取消导出不会删除已保存的节点。设备与订阅、证书和复杂网络设置收在 `6 高级设置`。

示例中的文档地址 `203.0.113.10`、域名 `node.example.net`、大写 ID 和文件路径都要换成自己的实际值。导出文件、测试 Profile、令牌和备份口令含秘密，不要贴到聊天、公共仓库或第三方转换站。

## 1. 先确认条件，再选协议（9 种协议与 11 个新组合）

当前提供 9 种底层协议：
- **原有 7 种**：`VLESS REALITY / Vision`（`reality`）、`Shadowsocks 2022`（`ss2022`）、`Hysteria2`（`hysteria2`）、`AnyTLS`（`anytls`）、`Trojan`（`trojan`）、`传统 SS AEAD`（`ss-aead`）、`TUIC v5`（`tuic`）。
- **新增 2 种底层协议 + 11 个协议传输组合**：
  - `VLESS + TLS`（`vless-tls`）：支持直连 TCP、WebSocket（`vless-ws-tls`）、gRPC（`vless-grpc-tls`）、HTTPUpgrade（`vless-httpupgrade-tls`）共 4 个组合。
  - `VMess + TLS`（`vmess-tls`）：支持直连 TCP、WebSocket（`vmess-ws-tls`）、gRPC（`vmess-grpc-tls`）、HTTPUpgrade（`vmess-httpupgrade-tls`）共 4 个组合。
  - `Trojan`（`trojan`）：在原有直连 TCP 基础上，新增 WebSocket（`trojan-ws-tls`）、gRPC（`trojan-grpc-tls`）、HTTPUpgrade（`trojan-httpupgrade-tls`）共 3 个组合。

| 已知条件 | 可先考虑的路径 | 仍须核对 |
| --- | --- | --- |
| 没有自己的域名，客户端支持 VLESS REALITY/Vision | REALITY（`1`） | VPS 能访问适用握手目标、入口 TCP 可达；握手目标与客户端连接地址独立 |
| 有匹配域名的可信证书，需要标准 TLS 或 CDN/反代兼容传输 | `VLESS + TLS`（`8`）、`VMess + TLS`（`9`）或 `Trojan`（`5`） | 可选直连 `tcp`、`ws`、`grpc`、`httpupgrade`；证书域名须与客户端 SNI 一致 |
| 客户端明确支持 SS2022 多用户格式，不想管理 TLS 证书 | SS2022（`2`） | 使用 `2022-blake3-aes-256-gcm` 及本项目导出密码，TCP/UDP 分别验证 |
| 客户端只支持传统现代 SS AEAD | `ss-aead`（`6`） | 只选已支持的现代 AEAD 方法（默认 `aes-256-gcm`），不把 SS2022 复合密码移过来 |
| 有匹配域名的可信证书，但入口 UDP 不通 | Trojan（`5`）、AnyTLS（`4`）、VLESS+TLS（`8`）、VMess+TLS（`9`） | TCP 隧道内可承载 UDP（XUDP/UO）；AnyTLS 连接池参数会增加资源成本 |
| 有可信证书、UDP 入口可达，客户端支持对应 QUIC 协议 | Hysteria2（`3`）或 TUIC（`7`） | 证书名称、UDP 映射和实际路径；TUIC 默认关闭 0-RTT，不套用 HY2 带宽字段 |
| NAT 或只有 IPv6 | 先按 `n` 声明内外端点，再选满足条件的协议 | 服务商 TCP/UDP 分别映射、客户端地址族、域名 A/AAAA；出口 IP 不是入站证明 |

没有“服务器测几次就选出你手机最快协议”的功能。先以客户端、证书、网络和资源条件筛选，再从实际客户端网络按同条件测量；缺少样本保留未知。九种协议与传输组合细节见[协议说明](PROTOCOLS.md)。

## 2. 从菜单新建节点、填写证书域名和端口、选择连接方式并导出（完整示例）

下面以普通用户在 SSH 终端新建一个 **VLESS + WebSocket + TLS** 节点并立即导出为例，展示一步步怎么填：

### 交互菜单完整操作示例

1. 运行 `sudo qingnode` 打开主菜单，输入 `1`（创建节点）：
   ```text
   选择要做的事
   1 创建节点
   2 节点管理：查看、修改、停用
   3 导出链接、二维码或配置
   ...
   选择: 1
   ```
2. 在协议选择界面，既可以直接选 `8`（`VLESS + TLS`）再选传输方式，也可以输入 `m` 查看 9 个传输组合简写（`w1`–`w9`），直接输入 `w1`（代表 `VLESS + WebSocket + TLS`）：
   ```text
   请选择要搭建的节点
   1. VLESS REALITY / Vision（无需自己的域名）
   ...
   8. VLESS + TLS（标准TLS，支持TCP/WS/gRPC/HTTPUpgrade）
   9. VMess + TLS（AEAD，支持TCP/WS/gRPC/HTTPUpgrade）
   m. 更多传输组合（WS / gRPC / HTTPUpgrade）  h. 帮我选  n. NAT/端口映射  ?. 查看核心和客户端要求
   0. 返回，不创建
   选择协议编号、m、h、n、?，或0: w1
   ```
3. 按向导提示依次填写节点名称、客户端连接地址、端口、证书域名与连接方式（传输参数）：
   - **节点名称**（默认 `main`）：直接回车或输入 `vless-ws-node`
   - **客户端连接 IP/域名**：输入客户端实际连接的域名或公网 IP，例如 `node.example.net`
   - **端口**（默认 `auto` 自动避开占用，也可填固定端口如 `443` 或 `8443`）：输入 `443`
   - **证书域名**（`--sni`，客户端校验的 TLS 域名）：默认与连接域名相同，直接回车确认 `node.example.net`
   - **证书方式**（`acme` 自动申请 / `pem` 本地证书文件 / 已有证书资源 ID）：输入 `pem`，再填入证书链路径 `/root/fullchain.pem` 和私钥路径 `/root/privkey.pem`（或选 `acme` 并输入邮箱 `admin@example.net`）
   - **WebSocket Path**（默认 `/ws`）：直接回车采用 `/ws`（或填自定义路径如 `/vless-ws`）
   - **WebSocket Host 头**（可选，默认使用证书域名）：直接回车留空
4. 向导会自动校验字段、证书有效期与 `sing-box` 候选配置，应用成功后显示节点摘要，并提示是否立即导出：
   ```text
   节点已创建。需要立即导出连接信息吗？
   1 立即导出刚创建的节点
   0 返回菜单（稍后可在主菜单 3 导出）
   选择 [0]: 1
   ```
5. 输入 `1` 进入导出菜单，选择导出格式：
   - 选 `1`：输出标准分享链接（`vless://...`）
   - 选 `2`：在终端直接显示二维码（同时附带分享链接）
   - 选 `3` / `4`：导出完整 `Mihomo 1.19.30` YAML 或 `sing-box 1.14.0` JSON 配置文件（如果节点是 `vmess-tls`，还会提供 `6` 导出 `v2rayN` 通用 `vmess://` Base64 JSON 链接）

### 实际核对过的等效 CLI 命令

如果不走交互菜单，也可以直接用一条已核对的命令完成创建、查看摘要并导出：

```bash
sudo qingnode add --protocol vless-ws-tls --name vless-ws-node \
  --server node.example.net --port 443 --sni node.example.net \
  --cert /root/fullchain.pem --key /root/privkey.pem --path /ws
sudo qingnode export --id vless-ws-node --format uri
sudo qingnode qr --id vless-ws-node
```

本地安装包示例（使用已下载并核验的完整 `0.4.0` 包及匹配架构的官方核心归档）：

```bash
mkdir -m 700 ./qingnode-package
tar -xzf ./qingnode-0.4.0-linux-amd64.tar.gz -C ./qingnode-package
sudo bash ./qingnode-package/install.sh --protocol ss2022 --name main \
  --server 203.0.113.10 --listen 0.0.0.0 --port 443 \
  --core-archive /root/sing-box-1.14.0-linux-amd64.tar.gz
sudo qingnode capabilities --skip-loopback --json
sudo qingnode status
sudo qingnode info --id main
```

## 3. 服务器监听端口与对外连接端口怎么填（直连、NAT 与 IPv6）

QingNode 严格区分**服务器本机监听**与**客户端对外连接**两组参数，避免 NAT 映射或反代场景下导出错误端口：

| 参数 / 菜单项 | 含义 | 普通直连 VPS 怎么填 | NAT VPS / 端口映射怎么填 |
| --- | --- | --- | --- |
| `--listen`（本机监听 IP） | `sing-box` 在服务器网卡绑定的本地地址 | 默认留空（自动选 `0.0.0.0` 或 `::`） | 填本机内网 IP 或 `0.0.0.0` |
| `--port`（服务器监听端口） | `sing-box` 在服务器本机实际监听的端口 | 填想开放的端口（如 `443`）或用 `--random-port` / 菜单 `auto` | 填**服务器内部**实际监听的端口（例如本机监听 `10443`） |
| `--server`（对外连接地址） | 客户端在手机/电脑上连接的目标域名或公网 IP | 填 VPS 公网 IP 或解析到该 VPS 的域名 | 填 NAT 服务商分配的公网入口 IP 或域名 |
| `--connect-port`（对外连接端口） | 客户端在手机/电脑上实际拨号的外部端口 | **无需填写**（默认自动等于 `--port` 监听端口） | 填服务商映射给你的**公网外部端口**（例如外部 `30000` 映射到本机 `10443`，就填 `30000`） |

- **菜单怎么填外部连接端口**：在 `1 创建节点` 选择协议前先输入 `n` 开启 NAT/端口映射模式，向导就会先后询问“监听端口（服务器本机绑定的端口）”和“外部连接端口（客户端实际连接的公网端口）”；已有节点也可在 `2 节点管理 → 9 REALITY/证书/传输 → 9 修改外部连接端口` 中随时修改，只改外部连接端口不会中断现有连接。
- **命令行怎么填外部连接端口**（声明外部 `30000` 映射到本机 `443` 的示例）：

```bash
sudo qingnode add --protocol reality --name nat-main \
  --server 203.0.113.10 --connect-port 30000 \
  --listen 0.0.0.0 --port 443 --sni TARGET_NAME --target TARGET_NAME:443
sudo qingnode info --id nat-main
sudo qingnode endpoint material --id nat-main --out /root/nat-validation.json
```

此例要求 `443` 当前空闲；服务商仍须把公网 `30000/TCP` 映射到本机 `443/TCP`。HY2/TUIC 使用独立的 UDP 映射声明；TCP 映射通过不能代替 UDP。详细材料见[端点与双栈](ENDPOINTS.md)。

IPv6 字面地址写为 `--server 2001:db8::10`，不要自行给 Host 加方括号；导出器会自动处理 URI 中的 `[2001:db8::10]` 方括号格式。

## 4. 获取链接、二维码、VMess v2rayN 导出与客户端配置的适用范围

菜单使用主菜单 `3 导出链接、二维码或配置`，依次选择节点、凭据和格式；刚创建节点时可直接选 `1 立即导出`。使用 CLI 时先从 `info` 查看真实节点/凭据 ID，再按需导出：

```bash
sudo qingnode info --id main
sudo qingnode export --id NODE_ID --user USER_ID --format uri --out /root/node-uri.txt
sudo qingnode qr --id NODE_ID --user USER_ID
sudo qingnode export --id NODE_ID --user USER_ID --format sing-box \
  --client-version 1.14.0 --out /root/main-client.json
sudo qingnode export --id NODE_ID --user USER_ID --format mihomo \
  --client-version 1.19.30 --out /root/main-client.yaml
```

### VMess 的两种分享链接导出（标准 URI 与 v2rayN 导出）

针对 `vmess-tls`（含 `tcp`/`ws`/`grpc`/`httpupgrade`），QingNode 同时支持两种分享格式：
- **标准 RFC 3986 URI（`--format uri`，菜单选项 `1`）**：形如 `vmess://<uuid>@<host>:<port>?security=tls&sni=...&type=ws&path=...#name`，与 `vless://`、`trojan://` 风格统一，适合支持标准 URL 查询参数的客户端。
- **v2rayN Base64 JSON 导出（`--format vmess-v2rayn`，菜单选项 `6`）**：形如 `vmess://eyJ2IjoiMiIsInBzIjoi...`，编码完整的 v2 JSON 字段（`v:"2"`、`add`、`port`、`id`、`aid:"0"`、`scy:"auto"`、`net:"tcp|ws|grpc|httpupgrade"`、`path`、`host`、`tls:"tls"`、`sni`、`alpn`），专为 v2rayN、v2rayNG 等广泛使用传统 Base64 JSON 格式的客户端准备：
  ```bash
  sudo qingnode export --id NODE_ID --user USER_ID --format vmess-v2rayn
  ```

### 二维码、分享链接、订阅与完整客户端配置的适用范围

| 导出方式 | 适用协议与场景 | 限制与不适用情况 |
| --- | --- | --- |
| **标准分享链接（`uri` / `vmess-v2rayn`）** | 适合单节点快速导入：`reality`、`ss2022`、`ss-aead`、`hysteria2`（基础设置）、`trojan`、`vless-tls`、`vmess-tls`（含 `ws`/`grpc`/`httpupgrade`）、`anytls`（默认连接池） | **不适用**：`tuic`（无通用核验 URI 标准）、配置了自定义空闲池的 `anytls`、配置了非默认带宽/端口跳跃的 `hysteria2`、或使用静态 Ed25519 证书的 TLS 节点（因客户端默认 Chrome 指纹不兼容 Ed25519，拒绝生成有损 URI） |
| **终端二维码（`qr`）** | 适用范围与分享链接相同，适合手机扫码直接导入单节点；本机离线生成，不上传外部网站 | 除继承分享链接的限制外，当 SSH 终端窗口过窄导致二维码被强行折行时无法识别，应拉宽终端或改用分享链接/配置文件 |
| **完整客户端配置（`sing-box` JSON / `mihomo` YAML）** | **全部 9 种协议与 11 个新增组合均支持**；完整保留 TLS/ALPN、传输层参数、TUIC 拥塞与心跳、AnyTLS 空闲池、HY2 速率参数及基础分流 | 需要显式匹配客户端版本（`sing-box` 用 `--client-version 1.14.0` 或 `1.14.3`；`mihomo` 用 `--client-version 1.19.30`）；`provider` 仅含节点列表片段，不能单独作为完整配置运行 |
| **设备多节点与在线订阅（`device` / `subscription`）** | 适合一人多机或多节点聚合管理，支持按设备签发带独立 256 位令牌的只读订阅或离线导出 | 在线订阅需自备可信 HTTPS 反代或证书；当设备绑定含 `tuic` 或带高级连接池的 `anytls` 时，应将 `subscription_formats` 设为 `["sing-box","mihomo","provider"]`，排除有损的默认 URI 格式 |

手机或桌面应用显示“导入成功”之后，还要测试真实 TCP 与所需 UDP。设备有多节点需求时，明确绑定每个节点与凭据：

```bash
sudo qingnode device create --name phone --binding NODE_ID:USER_ID --preview
sudo qingnode device create --name phone --binding NODE_ID:USER_ID
sudo qingnode device list
sudo qingnode export --device DEVICE_ID --format sing-box \
  --client-version 1.14.0 --out /root/phone.json
```

## 5. 从实际客户端网络排查延迟

先做服务器只读检查，再到用户真正上网的位置测代理。目标要使用自己控制或明确允许测试的 HTTPS 端点，没有默认公共测速站。

```bash
sudo qingnode doctor
sudo qingnode probe local --out /root/local-diagnostic.json
sudo qingnode probe run --path server-outbound --target https://TEST_HOST/status \
  --samples 8 --timeout 20s --out /root/server-egress.json
sudo qingnode probe profile --id NODE_ID --user USER_ID --out /root/private-test-profile.json
```

最后一个文件含认证，只传给自己的测试机器并在用后处理。独立工具在桌面或另一台 Linux 上运行；先核实其官方核心和二进制摘要：

```bash
qingprobe run --path client-proxy --profile ./private-test-profile.json \
  --core /absolute/path/sing-box --core-sha256 CORE_BINARY_SHA256 \
  --target https://TEST_HOST/status --initiator home-wifi \
  --samples 8 --timeout 20s --out ./client-light.json
qingprobe run --path client-proxy --profile ./private-test-profile.json \
  --core /absolute/path/sing-box --core-sha256 CORE_BINARY_SHA256 \
  --target https://TEST_HOST/download --initiator home-wifi --mode download \
  --bytes 8388608 --concurrency 1 --samples 8 --timeout 30s --out ./client-load.json
```

失败不回落 direct。报告区分空闲和下载期间 RTT、端到端耗时、单连接有效载荷吞吐及可得资源；详见[网络测试](NETWORK_TESTS.md)。

## 6. 中转与修改先看真实影响

端口中转不是重新实现代理协议。先只读预览，再用同一组参数应用：

```bash
sudo qingnode forward add --name local-forward --listen 127.0.0.1 --port 24443 \
  --network tcp --target-host 198.51.100.20 --target-port 443 --preview
sudo qingnode forward add --name local-forward --listen 127.0.0.1 --port 24443 \
  --network tcp --target-host 198.51.100.20 --target-port 443
sudo qingnode edit --id NODE_ID --name renamed-main --preview
sudo qingnode edit --id NODE_ID --name renamed-main
```

普通改名不轮换凭据，是否重启依据真实派生运行配置和宿主效果；链式出口、WireGuard 配对、显式主备与无 direct 回落说明见[拓扑指南](TOPOLOGY.md)。

## 7. 升级、备份与恢复（先备份 → 再升级 → 最后检查旧节点）

升级管理器或核心前，请严格按照**先备份、再升级、最后检查旧节点是否正常**的三步流程操作，确保任何情况下原有节点身份、UUID/密码和证书都不会丢失：

### 第一步：先备份当前配置

以下命令使用 `v0.4.0`（或当前已安装的 `v0.3.x`）。口令至少 12 字节，使用权限 `0600` 的口令文件或交互隐藏输入，不要写进命令行历史：

```bash
sudo qingnode backup --file /root/config-before-upgrade.qnbak --password-file /root/backup-pass.txt
sudo qingnode backup --full --preview
```

（若仍停留在旧版 `v0.2.8`，应先按[旧版升级步骤](MIGRATION.md#从-v028-升级到-v030)用原程序执行普通 `backup`，再用已校验新包程序做 `--full --preview`，不要向旧版 `v0.2.8` 传 `--full`。）

### 第二步：执行升级

可在主菜单 `5 备份与更新` 中选择 `4 更新管理器` 或 `3 更新 sing-box`，或直接在终端执行：

```bash
# 在线升级管理器到指定正式版本（如 v0.4.0）
sudo qingnode self-update --version v0.4.0

# 或使用已下载并核对 SHA256SUMS 的本地发行包升级
sudo qingnode self-update --bundle /root/qingnode-package
# 也可运行包内安装器重装（自动保留现有节点与启停状态）
sudo bash /root/qingnode-package/install.sh --reinstall
```

升级过程会先校验新版本与现有 State 配置的兼容性；若校验或服务重启失败，安装事务会自动回滚到升级前的管理器和服务状态。

### 第三步：升级后检查旧节点是否正常

升级完成后，依次核对版本、服务状态、配置检查、监听端口与旧节点参数，确认原有节点与客户端连接正常：

```bash
sudo qingnode version
sudo qingnode status
sudo qingnode check
sudo qingnode ports
sudo qingnode list
sudo qingnode info --id main
```

- 确认 `qingnode status` 显示服务运行正常、`qingnode check` 通过、`qingnode list` 中所有旧节点的端口与协议完整保留。
- 普通升级不会改变已有节点的 UUID、密码、REALITY 私钥或证书，客户端无需重新导入链接；最后用手机或电脑客户端实际访问一次目标网站确认连通。
- 如遇中断事务，先保留现场查看 `status` 和 `logs`，再按提示运行 `sudo qingnode recover`；如需回退上一代配置可运行 `sudo qingnode rollback`，或用第一步保存的备份执行恢复预览与还原：

```bash
sudo qingnode restore --file /root/config-before-upgrade.qnbak --password-file /root/backup-pass.txt --preview
sudo qingnode restore --file /root/config-before-upgrade.qnbak --password-file /root/backup-pass.txt --yes
```

完整跨机迁移与旧版本恢复边界见[迁移与恢复](MIGRATION.md)。

## 用自己的客户端完成最后一段验收

核对版本与端点 → 导出指定凭据 → 客户端完整导入 → 经过代理访问自己的 HTTPS 目标 → 单独验证需要的 UDP → 保留脱敏报告与测试位置。普通桌面、手机 SSH 窄终端与手机代理 GUI 分别记录。没有对应设备、公网或原生架构时标未验证，不能用本机回环成功替代。
