# 批量导出、设备订阅与客户端选择

一个设备 Profile 是“明确给这台设备哪些节点、哪条认证和哪个连接入口”的清单。订阅令牌只允许下载这份清单；代理 UUID、密码或密钥才决定能否连接代理。撤销下载链接不能追回已经下载的代理凭据。

本批继续使用本地 State、静态 Go 管理器与独立官方核心。默认核心仍为 1.14.0，没有引入面板、数据库、第三方在线转换或外部订阅抓取。实际测试及环境未提供项见 [BATCH06.md](BATCH06.md)。

## 创建与本地导出

先用现有节点/凭据查询找到稳定 ID；以下大写占位须换成实际 ID，不能用猜测的第一个用户代替。每个绑定为 `NODE_ID:USER_ID[:ENDPOINT_ID]`，省略端点等于 `default`。NAT 外端口、IPv6 与额外端点沿 [连接地址模型](ENDPOINTS.md) 导出；内部第 05 批落地凭据不会进入最终客户端文件。

```bash
qingnode device create --name phone --binding NODE_ID:USER_ID --binding OTHER_NODE_ID:OTHER_USER_ID:ipv6 \
  --routing cn-direct --tun --enable-controller --controller-port 9090 \
  --default-subscription-format sing-box --preview
qingnode device create --name phone --binding NODE_ID:USER_ID --binding OTHER_NODE_ID:OTHER_USER_ID:ipv6 \
  --routing cn-direct --tun --enable-controller --controller-port 9090 \
  --default-subscription-format sing-box
qingnode device list
qingnode device show --id DEVICE_ID
qingnode export --device DEVICE_ID --format sing-box --client-version 1.14.0 --out /root/phone.json
qingnode export --device DEVICE_ID --format mihomo --client-version 1.19.30 --out /root/phone.yaml
```

交互菜单用户也可直接进入 `6 高级设置 → 8 设备与订阅 → 2 交互创建多节点设备配置`，逐步选择多个节点凭据、切换策略（`manual` / `auto` / `fallback`）、分流预设、是否开启 `TUN` 与本地 `127.0.0.1` 控制端口，提交前统一通过 `previewMenuMutation` 展示变更影响预览。

本地文件含被选设备的入口认证，必须保密；输出需要明确新文件，默认不打印多设备秘密。`device show` 会自动隐藏本地控制端口密钥（`[API凭据已隐藏]`）。原有单节点 `export --id ... --user ...` 同样支持 `--routing`、`--tun`、`--enable-controller` 与 `--controller-port` 导出完整客户端配置。Profile 也可用 `export --profile-file /root/profile.json` 临时导出；该文件使用下面的 version1 批量 envelope，但 profiles 必须恰好一项。稳定排序按节点/凭据/端点 ID，唯一 tag/名称含这些 ID；即使显示名相同或带特殊字符也不会覆盖另一条节点。

最多 128 个 Profile，每个明确绑定 1–256 项。缺节点、缺凭据、重复绑定、停用节点、未知端点或不支持字段会明确报错。标签筛选为任意一个标签匹配即保留（OR），只过滤已经绑定的节点，不会从其他用户那里自动补凭据：

```bash
qingnode device tags --id NODE_ID --tags home,ipv6 --preview
qingnode device tags --id NODE_ID --tags home,ipv6
```

`device apply --file /root/devices.json --preview` 检查整体，去掉 `--preview` 后统一应用。输入为权限 0600 的普通私有 JSON，版本 1、最多 1MiB/128 个 Profile；一项无效整批拒绝。相同 ID 替换该 Profile，未提及的设备保留。示例中的 ID 必须换成现存对象：

```json
{"version":1,"profiles":[{"id":"aaaaaaaaaaaaaaaa","name":"phone","bindings":[{"node_id":"1111111111111111","user_id":"2222222222222222","endpoint_id":"default"}],"node_tags":["home"],"strategy":"manual","routing":"cn-direct","default_subscription_format":"sing-box","tun":true,"subscription_formats":["sing-box","mihomo","base64"]}]}
```

## 完整配置、分流预设、TUN 模式与客户端兼容线

| 格式 | 内容与使用方式 |
| --- | --- |
| `sing-box` | 完整 JSON，含本地 mixed（及可选 `tun`）入站、节点与选择组、安全 DNS、路由规则及可选 `127.0.0.1` Clash API；兼容 `1.14.x` 正式版本线（已在受控测试核验 `1.14.0` / `1.14.3`） |
| `mihomo` | 完整 YAML，含监听（及可选 `tun`）、节点、策略组、安全 DNS、规则集及可选 `127.0.0.1` `external-controller`；兼容 `>= 1.19.0` 正式版本线（已在受控测试核验 `1.19.30`） |
| `sing-box-outbounds` | 本地导出的节点出站集合，需并入用户自己的完整配置；不作为在线订阅格式 |
| `provider` | 顶层 `proxies` 节点集合，需要用户现有 Mihomo 完整配置引用；不含策略组或监听 |
| `uri` / `base64` | 分享链接集合（其中 `base64` 对 `vmess-tls` 自动输出客户端通用的 v2rayN Base64 JSON `vmess://` 链接，对无客户端心跳的 `tuic` 输出标准 NEP-408 `tuic://` 链接）；不表达完整客户端策略、分流、DNS 或 HY2 全部高级设置 |

默认 `manual` 手动选择，`global` 把目标流量交给所选入口。`auto` 使用自己的 HTTPS 健康目标，默认 300 秒/50ms 容差；间隔可设 60–3600 秒、容差最多 1000ms。Mihomo 的 `fallback` 按明确顺序选择第一个 HTTP 健康节点。**sing-box 1.14 没有等价有序 fallback，导出会拒绝；不会偷偷改成最低延迟组。** 主备成员顺序依照 Profile 明确绑定顺序；普通集合排序稳定。

**Mihomo 1.19.x 的完整 `auto` 默认拒绝。** 受控 HTTPS 实测发现：当前选中第一项时，即使两项差值仍在容差内也会切换；固定版本的 [urltest.go](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outboundgroup/urltest.go#L118-L140) 与该现象一致。建议使用 `manual` 或明确有序的 `fallback`。只有明确接受缺陷时，才在创建 Profile 时加 `--allow-degraded-auto`，或在批量 JSON 的该 Profile 中设 `"allow_degraded_auto":true`；此项仅允许 `auto`。每次导出仍警告“第一项不能保证容差防抖”，真实 `tolerance` 字段不会被伪造为已有效。该限制不阻止 `provider`、`uri`、`base64` 节点集合导出，集合本身也不含自动选择组。

```bash
qingnode device create --name phone-auto --binding NODE_ID:USER_ID --binding OTHER_NODE_ID:OTHER_USER_ID --strategy auto --test-url https://health.example.net/status --interval 300 --tolerance 50 --subscription-formats sing-box
```

`--timeout` 是 Mihomo 探测毫秒数，500–15000；省略采用核验过的 5000ms。sing-box URLTest 使用核心内部 15 秒限制，没有相同 JSON 字段；设独立 timeout 的完整 sing-box 自动配置会拒绝。客户端自动组的 HTTP 成功只证明该 URL 的 TCP/HTTP，不能证明 UDP；UDP 仍需 [网络测试](NETWORK_TESTS.md) 的受控序号回应。切换不保证迁移已建立的 TCP 会话。

### 分流与防污染 DNS 预设（`--routing`）

1. `global`（默认）：全局代理转发，保持既有最简行为。
2. `basic`：完整覆盖回环、RFC1918、CGNAT、链路本地与唯一本地共 9 个私有/保留网段（`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`100.64.0.0/10`、`169.254.0.0/16`、`::1/128`、`fc00::/7`、`fe80::/10`）直连；`sing-box` 同时启用原生 `"ip_is_private": true` 规则。
3. `cn-direct`（国内外分流 + 防 DNS 泄漏）：
   - `sing-box`（严格遵循 `1.14.x` 新式 DNS server / rule action 语法）：配置经 `PROXY` 出站的加密 DoH 远端 DNS（`dns-remote`）与国内直连 DoH（`dns-direct`），启用路由动作 `sniff`、`hijack-dns` 以及经 `PROXY` 下载的远程 `.srs` 规则集（`geosite-cn`、`geoip-cn`），私有地址与国内域名/IP 走 `direct`，其余流量与默认解析走 `PROXY`。
   - `mihomo`（遵循 `1.19.x` 语法）：生成 `dns: { enable: true, enhanced-mode: fake-ip, ... }`，配合加密 DoH `nameserver` / `proxy-server-nameserver` / `geosite:cn` `nameserver-policy` 及远程 `.mrs` `rule-providers`（`geosite-cn`、`geoip-cn`）实现国内外分流。
4. `global-secure-dns`（全局代理 + 加密远端 DNS）：私有地址直连，其余业务流量及加密 DoH 解析统一经代理出站转发，防止本地运营商 DNS 抢答污染。

### 可选客户端 `TUN` 入站与本地控制端口

- `--tun`：保留原有本地 `127.0.0.1` `mixed` 端口的同时，在完整配置中增加客户端 `TUN` 入站（`sing-box` 生成 `type: "tun"`、`address`、`auto_route: true`、`strict_route: true`；`mihomo` 生成 `tun: { enable: true, stack: mixed, auto-route: true, auto-redirect: false, strict-route: true, auto-detect-interface: true, dns-hijack: ["any:53"] }`）。桌面或移动客户端实际启用 TUN 仍需对应系统的网络扩展/管理员权限，导出器仅生成标准配置。
- `--enable-controller [--controller-port 9090]`：生成**仅绑定 `127.0.0.1`** 且带 128 位随机密钥的 `experimental.clash_api`（`sing-box`）或 `external-controller` + `secret`（`mihomo`），便于本地客户端面板切换 `Selector` 节点，绝不监听 `0.0.0.0` 暴露到局域网或公网。

HY2 高级设置或含 `client_heartbeat` 的 TUIC 不能被 URI 等价表达时，默认拒绝有损导出并说明原因。优先选完整 `sing-box` / `mihomo`；只有明确接受差异才用 `--allow-lossy` 并查看警告，不能把降级文件说成等价配置。

## 可选在线订阅与统一自适应链接

不需要在线服务时，到本地导出即可结束。在线服务只读独立的私有发布快照，不读 root State、不启动代理、不取得管理锁，也不抓取任意 URL。管理写操作提交后生成新快照并原子替换，读请求看到完整旧版或新版。

由管理员先准备专用无登录用户/组，例如 `qingnode-sub`；同名已存在时先核对用途，不接管其他账户。发布目录必须独立于 State，root 保持写权，服务组只获得读取和目录穿越权限。不要把 State、备份或整个 `/var/lib/qingnode` 改为组可读。下面 `SUB_GID` 替换成该专用组的数字 ID：

```bash
qingnode subscription init --dir /var/lib/qingnode-subscription --gid SUB_GID --formats sing-box,mihomo,provider,uri,base64
qingnode subscription configure --formats sing-box,mihomo,provider,uri,base64 --sing-box-version 1.14.3 --mihomo-version 1.19.30
qingnode subscription publish
qingnode subscription status
```

初始化使用 `subscription.CreateInitial`，只允许首次原子独占创建空快照：私有候选写完并同步后，用不覆盖目标的硬链接安装，再移除候选并同步目录。已有 `snapshot.json` 无论空/非空、有效/损坏都保留并拒绝初始化，独立 State 或丢失发布配置也不能用 `init` 清空或接管旧注册表。如果崩溃发生在链接成功与候选移除之间，`snapshot.json` 和自有 `.publication-initial-*` 可能指向同一文件，硬链接数 `nlink=2`；读取会拒绝，程序不暗中删材料修复。若仅丢失管理端的 `subscription-publisher.json`，有原私有备份时由管理员恢复原 0600 配置并核对目录与服务 GID，无原配置时使用新的独立目录重新签发。

只发布自己需要且能完整表达的格式；Profile 可设 `subscription_formats`，创建时对应 `--subscription-formats sing-box,mihomo`：只从发布器启用格式中选明确子集，省略则继承发布器。`subscription configure` 只修改明确提供的 formats、语义化兼容范围内的客户端目标版本（`sing-box 1.14.x`、`mihomo >= 1.19.0`）或 `allow-lossy`，目录/服务组保留。

复用用户已有 HTTPS 反向代理时，后端仅监听字面 loopback，公网只转发 `/s/`。不需要接管 80/443，不自动安装反代或创建防火墙规则：

```bash
qingnode subscription serve --dir /var/lib/qingnode-subscription --listen 127.0.0.1:8389 --public-url https://sub.example.net --reverse-proxy
```

请以专用服务用户运行（如 `User/Group=qingnode-sub`、`NoNewPrivileges=true`、`ProtectSystem=strict`、`ProtectHome=true`、`CapabilityBoundingSet=`）；不复用代理服务账户或给它读取 State 的权限。直接 HTTPS 可改用 `--tls-cert` 与 `--tls-key`，不与 `--reverse-proxy` 同用。公开地址发布前执行：

```bash
qingnode subscription check --base-url https://sub.example.net
qingnode subscription issue --device DEVICE_ID --base-url https://sub.example.net --out /root/phone-token.json
qingnode subscription qr --token-file /root/phone-token.json --format auto --out /root/phone-subscription-qr.txt
```

在交互菜单 `6 高级设置 → 8 设备与订阅 → 5 交互签发订阅令牌并可选显示终端二维码` 中，签发（或确认轮换）完成后可直接选择在当前 SSH 终端展示统一订阅链接 `/s/<TOKEN>` 的二维码；程序会先用终端列宽检查二维码宽度，终端过窄时拒绝输出折行损坏的色块并提示改用 `--out` 保存。

HTTPS 检查只发送无令牌 HEAD，默认系统根证书验证、独立超时、拒绝重定向，无 insecure 开关；成功不等于订阅内容或代理已连通。没有可信 HTTPS 时仍可本地导出，`issue` 省略 `--base-url` 仅保存原始令牌，不生成公网链接或可用订阅二维码。

令牌为 256 位随机数，只在一次性 0600 新文件中保存原值（含 `unified_url` 与各显式格式 `links`），发布快照仅保存 SHA-256 摘要；默认到期 30 天，可用 `--expires` 指定 RFC3339，最多 366 天。状态/错误不打印原令牌和完整链接。

### 统一订阅路径、客户端自动协商与响应元数据头

在线订阅同时支持**显式格式路径**与**统一自适应路径**（仅支持 `GET` / `HEAD`）：
1. **显式路径（最高优先级，完全向后兼容）**：`/s/<TOKEN>/<FORMAT>`，或 `/s/<FORMAT>` 搭配 `Authorization: Bearer <TOKEN>`。
2. **统一自适应路径**：`/s/<TOKEN>`，或 `/s` 搭配 `Authorization: Bearer <TOKEN>`。统一路径仅白名单接受查询参数 `?format=<sing-box|mihomo|clash|provider|base64|uri>` 或 `?flag=<sing-box|sfa|mihomo|clash|meta|v2rayn|shadowrocket|...>`（未知查询参数、重复键或空值一律拒绝）：
   - 若指定了 `?format=` 或 `?flag=`，按显式参数选择对应已发布格式；
   - 未指定查询参数时，按 `User-Agent` 自动识别客户端：
     - `SFA` / `SFI` / `SFM` / `sing-box` → `sing-box`
     - `mihomo` / `Clash.Meta` / `FlClash` / `Clash Verge` / `Stash` → `mihomo`
     - `v2rayN` / `v2rayNG` / `Shadowrocket` / `NekoBox` / `Streisand` → `base64`（若仅发布了 `uri` 则回退 `uri`）
   - 浏览器或通用工具（如 `curl`）访问时，依次回退设备 `default_subscription_format` → `base64` → `uri` → `sing-box` → `mihomo` → `provider` 中该设备首个已发布格式。

成功响应（`200 OK`）附带标准客户端订阅元数据头：
- `Vary: Authorization, User-Agent` 与 `Cache-Control: private, no-store`（禁止反代或中间缓存串用不同客户端响应）
- `Profile-Update-Interval: 24`（建议 24 小时更新周期）
- `Profile-Title: base64:<StdEncoding(DeviceName)>`（客户端自动显示设备 Profile 名称）
- `Content-Disposition: attachment; filename="qingnode-<device_id>.<json|yaml|txt>"`
- `Subscription-Userinfo: [upload=<bytes>; download=<bytes>; [total=<bytes>; ]]expire=<unix_timestamp>`：`expire` 取令牌到期时间与该设备绑定凭据最早计划到期时间（`CredentialExpirations`）中的较小值；当设备关联了持久化流量账本（`monitor/traffic-ledger.json`）或流量配额（`TrafficQuotas`）时，同步输出真实累计 `upload`、`download` 及可选硬配额 `total`（详见 [监控与流量配额](MONITORING.md)）；未配置账本且无配额时绝不伪造 `upload=0; download=0; total=...` 等虚假流量字段。

### 快照缓存与原子切换

`qingnode subscription serve` 内置基于已打开文件句柄 `fstat` 元组 `(dev, ino, size, mtime_sec, mtime_nsec)` 的内存 `SnapshotCache` 与 SHA-256 `O(1)` 令牌索引（命中后仍执行常量时间摘要比对）：
- 每次 HTTP 请求依然先校验受控发布目录所有权标记、`O_NOFOLLOW` 无符号链接打开、属主/属组/0640 权限及普通文件单链接（`nlink == 1`）；
- 当快照文件未变化时直接复用内存已校验结构与索引，避免每次下载重复解析整份快照 JSON；
- 当 `subscription publish` / `issue` / `rotate` / `revoke` 或 `Store.Apply` 原子替换 `snapshot.json`（产生新 inode）后，下一次请求立即感知并在持锁校验后无缝加载新快照。

## 轮换、停用和故障恢复

```bash
qingnode subscription rotate --device DEVICE_ID --base-url https://sub.example.net --out /root/phone-token-new.json --yes
qingnode subscription revoke --device DEVICE_ID --yes
qingnode device disable --id DEVICE_ID --preview
qingnode device disable --id DEVICE_ID --yes
```

轮换只换下载令牌，旧令牌的新请求立刻被新快照拒绝；已认证进行中的响应无法追回。撤销或普通设备停用保留已下载的代理认证。要停用实际代理权限，先预览，再明确 `device disable --id DEVICE_ID --disable-credentials --yes`。只处理该设备明确绑定的凭据；仍被任何其他设备绑定的共享凭据都会使整批拒绝，包括已普通停用下载的设备，因为其已下载认证仍可能有效。某节点最后一个用户被停用时，保存原凭据并停用节点；运行影响按已有事务应用，可能重启共享核心。

`Store.BeforeCommit` 在提交前撤销已移除或停用设备的下载权限；设备停用先撤销下载再应用代理变更，代理应用失败也不会自动恢复已撤销令牌。发布配置与令牌注册表独立于 State/节点备份，恢复或 rollback 不应复活下载权限；迁机要单独保管私有发布目录，推荐重新签发令牌。当前 State 为 **schema 10**，对旧 `schema 1..9` 保持只读内存无损迁移（旧设备继续保持原 `global`/`basic` 分流与本地 `mixed` 入站，不擅自改变既有导出行为）；实际写入操作保留旧代原件，旧二进制明确拒绝 schema 10，且旧 schema JSON 中夹带新版本字段会被严格拒绝。

若代理 State 提交成功但发布新快照失败，命令明确报告“State 已提交”；旧完整快照保留，不声称事务整体未改变。检查 `subscription status`、处理错误后运行 `subscription publish`。订阅服务停止不会损坏代理配置；代理停止也不会让订阅读取启动它。恢复、订阅发布失败和实际服务状态应分别核对。
