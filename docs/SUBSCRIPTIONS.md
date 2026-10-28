# 批量导出、设备订阅与客户端选择

一个设备 Profile 是“明确给这台设备哪些节点、哪条认证和哪个连接入口”的清单。订阅令牌只允许下载这份清单；代理 UUID、密码或密钥才决定能否连接代理。撤销下载链接不能追回已经下载的代理凭据。

本批继续使用本地 State、静态 Go 管理器与独立官方核心。默认核心仍为 1.14.0，没有引入面板、数据库、第三方在线转换或外部订阅抓取。实际测试及环境未提供项见 [BATCH06.md](BATCH06.md)。

## 创建与本地导出

先用现有节点/凭据查询找到稳定 ID；以下大写占位须换成实际 ID，不能用猜测的第一个用户代替。每个绑定为 `NODE_ID:USER_ID[:ENDPOINT_ID]`，省略端点等于 `default`。NAT 外端口、IPv6 与额外端点沿 [连接地址模型](ENDPOINTS.md) 导出；内部第 05 批落地凭据不会进入最终客户端文件。

```bash
qingnode device create --name phone --binding NODE_ID:USER_ID --binding OTHER_NODE_ID:OTHER_USER_ID:ipv6 --preview
qingnode device create --name phone --binding NODE_ID:USER_ID --binding OTHER_NODE_ID:OTHER_USER_ID:ipv6
qingnode device list
qingnode device show --id DEVICE_ID
qingnode export --device DEVICE_ID --format sing-box --client-version 1.14.0 --out /root/phone.json
qingnode export --device DEVICE_ID --format mihomo --client-version 1.19.30 --out /root/phone.yaml
```

本地文件含被选设备的入口认证，必须保密；输出需要明确新文件，默认不打印多设备秘密。原有单节点 `export --id ... --user ...` 保留。Profile 也可用 `export --profile-file /root/profile.json` 临时导出；该文件使用下面的 version1 批量 envelope，但 profiles 必须恰好一项。稳定排序按节点/凭据/端点 ID，唯一 tag/名称含这些 ID；即使显示名相同或带特殊字符也不会覆盖另一条节点。

最多 128 个 Profile，每个明确绑定 1–256 项。缺节点、缺凭据、重复绑定、停用节点、未知端点或不支持字段会明确报错。标签筛选为任意一个标签匹配即保留（OR），只过滤已经绑定的节点，不会从其他用户那里自动补凭据：

```bash
qingnode device tags --id NODE_ID --tags home,ipv6 --preview
qingnode device tags --id NODE_ID --tags home,ipv6
```

`device apply --file /root/devices.json --preview` 检查整体，去掉 `--preview` 后统一应用。输入为权限 0600 的普通私有 JSON，版本 1、最多 1MiB/128 个 Profile；一项无效整批拒绝。相同 ID 替换该 Profile，未提及的设备保留。示例中的 ID 必须换成现存对象：

```json
{"version":1,"profiles":[{"id":"aaaaaaaaaaaaaaaa","name":"phone","bindings":[{"node_id":"1111111111111111","user_id":"2222222222222222","endpoint_id":"default"}],"node_tags":["home"],"strategy":"manual","routing":"global","subscription_formats":["sing-box"]}]}
```

## 完整配置、节点集合与客户端策略

| 格式 | 内容与使用方式 |
| --- | --- |
| `sing-box` | 完整 JSON，含 loopback mixed 监听、节点与选择组、DNS 和路由；仅核验 1.14.0/1.14.3 |
| `mihomo` | 完整 YAML，含监听、节点、策略组与规则；仅核验 1.19.30 |
| `sing-box-outbounds` | 本地导出的节点出站集合，需并入用户自己的完整配置；不作为在线订阅格式 |
| `provider` | 顶层 `proxies` 节点集合，需要用户现有 Mihomo 完整配置引用；不含策略组或监听 |
| `uri` / `base64` | 分享链接集合；不表达完整客户端策略、分流、DNS 或 HY2 全部高级设置 |

默认 `manual` 手动选择，`global` 把目标流量交给所选入口。`auto` 使用自己的 HTTPS 健康目标，默认 300 秒/50ms 容差；间隔可设 60–3600 秒、容差最多 1000ms。Mihomo 的 `fallback` 按明确顺序选择第一个 HTTP 健康节点。**sing-box 1.14 没有等价有序 fallback，导出会拒绝；不会偷偷改成最低延迟组。** 主备成员顺序依照 Profile 明确绑定顺序；普通集合排序稳定。

**Mihomo 1.19.30 的完整 `auto` 默认拒绝。** 本批受控 HTTPS 实测发现：当前选中第一项时，即使两项差值仍在容差内也会切换；固定版本的 [urltest.go](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outboundgroup/urltest.go#L118-L140) 与该现象一致。建议使用 `manual` 或明确有序的 `fallback`。只有明确接受缺陷时，才在创建 Profile 时加 `--allow-degraded-auto`，或在批量 JSON 的该 Profile 中设 `"allow_degraded_auto":true`；此项仅允许 `auto`。每次导出仍警告“第一项不能保证容差防抖”，真实 `tolerance` 字段不会被伪造为已有效。该限制不阻止 `provider`、`uri`、`base64` 节点集合导出，集合本身也不含自动选择组。sing-box `auto` 不受此缺陷影响，两版核心的受控容差测试已单独通过；targeted2在准确提交ea9979be复现Mihomo缺陷，并通过默认拒绝、显式降级与真实解析检查，详见本批记录。这不表示Mihomo容差防抖达标。

```bash
qingnode device create --name phone-auto --binding NODE_ID:USER_ID --binding OTHER_NODE_ID:OTHER_USER_ID --strategy auto --test-url https://health.example.net/status --interval 300 --tolerance 50 --subscription-formats sing-box
```

上例把在线发布格式明确限制为sing-box，发布器也须启用此格式。如果auto Profile省略子集而继承的发布格式含mihomo，未接受缺陷会使整体快照生成拒绝，旧快照保留；不会暗中跳过该格式。只需要节点集合时可选择uri/base64/provider。只有确实接受Mihomo缺陷时才加`--allow-degraded-auto`，它不是修复。

`--timeout` 是 Mihomo 探测毫秒数，500–15000；省略采用核验过的 5000ms。sing-box URLTest 使用核心内部 15 秒限制，没有相同 JSON 字段；设独立 timeout 的完整 sing-box 自动配置会拒绝。客户端自动组的 HTTP 成功只证明该 URL 的 TCP/HTTP，不能证明 UDP；UDP 仍需 [网络测试](NETWORK_TESTS.md) 的受控序号回应。切换不保证迁移已建立的 TCP 会话。

可选 `routing: basic` 只把 RFC1918 的 10/8、172.16/12、192.168/16 与 RFC4193 的 fc00::/7 交给 direct，其余仍代理。这是随程序固定的四个网段，不是完整保留地址、地理或广告规则库；状态标记为 embedded-v1，没有在线更新或网络缓存，也没有更新失败后用空规则覆盖旧规则的过程。默认 global 不含这个直连例外。

HY2 高级设置不能被 URI 或其他客户端等价表达时，默认拒绝有损导出并说明原因。优先选完整 sing-box；只有明确接受差异才用 `--allow-lossy` 并查看警告，不能把降级文件说成等价配置。

## 可选在线订阅

不需要在线服务时，到本地导出即可结束。在线服务只读独立的私有发布快照，不读 root State、不启动代理、不取得管理锁，也不抓取任意 URL。管理写操作提交后生成新快照并原子替换，读请求看到完整旧版或新版。

由管理员先准备专用无登录用户/组，例如 `qingnode-sub`；同名已存在时先核对用途，不接管其他账户。发布目录必须独立于 State，root 保持写权，服务组只获得读取和目录穿越权限。不要把 State、备份或整个 `/var/lib/qingnode` 改为组可读。下面 `SUB_GID` 替换成该专用组的数字 ID：

```bash
qingnode subscription init --dir /var/lib/qingnode-subscription --gid SUB_GID --formats sing-box,mihomo
qingnode subscription configure --formats sing-box,mihomo
qingnode subscription publish
qingnode subscription status
```

初始化使用`subscription.CreateInitial`，只允许首次原子独占创建空快照：私有候选写完并同步后，用不覆盖目标的硬链接安装，再移除候选并同步目录。已有`snapshot.json`无论空/非空、有效/损坏都保留并拒绝初始化，独立State或丢失发布配置也不能用`init`清空或接管旧注册表。此修订提交`23dd99f5e0f7783aa66596a7f5ef67b160cb4623`不在历史d2的full8范围；targeted3同一四项CLI测试在旧d2加唯一测试覆盖层全部触发断言失败，在23dd99f的Linux静态包全部通过。准确`c89f7d1f1a8d6422a5e948bef000bcd0141ce9ee`的full9已在静态、普通Go和race执行四项CLI及三项底层回归通过；31门槛30项0、唯一原生Alpine安装器1，原始限制与独立哈希审计见[BATCH06](BATCH06.md)。

如果崩溃发生在链接成功与候选移除之间，`snapshot.json`和自有`.publication-initial-*`可能指向同一文件，硬链接数`nlink=2`；读取会拒绝，程序不暗中删材料修复。先停止自有订阅服务、私有备份整个发布目录，再由管理员核对所有权标记、属主/组/权限和两个名称的设备号/inode确实相同且没有外部链接。只有归属及内容完整性确认后，才可人工移除那个自有候选链接，保留`snapshot.json`原字节并重新核验；不确定时保留两份材料，不删目标快照或反复init。没有自动恢复/接管旧目录的新接口。

若仅丢失管理端的`subscription-publisher.json`，有原私有备份时由管理员恢复原0600配置，核对它指向同一发布目录和同一服务GID，再运行只读`subscription status`检查。`configure`保存的`subscription-publisher-before-*.json`可作为原配置材料，须核验内容后使用；不是把其他State的配置拷来接管目录。无原配置时保留旧目录，先使用新的独立目录和重新签发流程，不用`init`覆写原快照。首次快照已安装但配置保存失败时同样保留材料，不能以空快照为由重新初始化。

只发布自己需要且能完整表达的格式；默认格式集合中包含 URI，有 HY2 高级设置时可能整体拒绝，不会静默丢字段。Profile 可设 `subscription_formats`，创建时对应 `--subscription-formats sing-box`：只从发布器启用格式中选明确子集，省略则继承发布器。这样完整 sing-box 设备与只发布 `mihomo` 的 fallback 设备可以共用服务，不能因格式不同默默降级。子集包含发布器未启用格式会明确拒绝。

`subscription configure` 只修改明确提供的 formats、客户端版本或 allow-lossy，目录/服务组保留。先整体渲染检查，保存旧私有配置恢复材料后再替换；配置已保存而快照发布失败会分别报告，旧完整快照保留。`init/configure` 不安装/启动服务，也不改变代理。发布目录为 0750，快照及所有权标记为受控私有组读文件；服务不能写发布目录。未知版本、重复字段、路径/所有权/软链接不安全、部分 JSON 或尺寸超限均拒绝。

复用用户已有 HTTPS 反向代理时，后端仅监听字面 loopback，公网只转发 `/s/`。不需要接管 80/443，不自动安装反代或创建防火墙规则：

```bash
qingnode subscription serve --dir /var/lib/qingnode-subscription --listen 127.0.0.1:8389 --public-url https://sub.example.net --reverse-proxy
```

请以专用服务用户运行。需要常驻时可由管理员手动建立独立 unit，`User/Group=qingnode-sub`、`NoNewPrivileges=true`、`ProtectSystem=strict`、`ProtectHome=true`、`CapabilityBoundingSet=`，ExecStart 用上面命令；不复用代理服务账户或给它读取 State 的权限。先在自己的机器核对服务用户读快照成功、写快照/读 State 失败，再启动。此处是部署说明，本批不会自动安装该 unit。

直接 HTTPS 可改用 `--tls-cert` 与 `--tls-key`，不与 `--reverse-proxy` 同用。证书链、有效期、域名和标准系统信任须正确；服务不自动签发或替换现有证书。公开地址发布前执行：

```bash
qingnode subscription check --base-url https://sub.example.net
qingnode subscription issue --device DEVICE_ID --base-url https://sub.example.net --out /root/phone-token.json
qingnode subscription qr --token-file /root/phone-token.json --format mihomo --out /root/phone-subscription-qr.txt
```

HTTPS 检查只发送无令牌 HEAD，默认系统根证书验证、独立超时、拒绝重定向，无 insecure 开关；成功不等于订阅内容或代理已连通。没有可信 HTTPS 时仍可本地导出，`issue` 省略 base-url 仅保存原始令牌，不生成公网链接或可用订阅二维码。

令牌为 256 位随机数，只在一次性 0600 新文件中保存原值，发布快照保存 SHA256；默认到期 30 天，可用 `--expires` 指定 RFC3339，最多 366 天。状态/错误不打印原令牌和完整链接。二维码是本设备下载秘密，默认写私有文本文件供受控展示；复制到手机或扫码时只交给该设备，不上传第三方二维码站点或在线转换器。

`qr` 在创建输出文件前检查令牌材料的格式、到期、设备/令牌 ID、唯一格式列表，以及与令牌完全匹配的 HTTPS `/s/TOKEN/FORMAT` 路径；编码别名或不一致材料拒绝。此检查只验证材料自身，不能证明域名当前运行订阅服务，不能识别被手工换成另一个语法合法的 HTTPS 域名，也不替代 `subscription check --base-url` 的公网证书检查。该新增检查的 Linux 复测结果以 [BATCH06.md](BATCH06.md) 为准。

HTTP 仅有 GET/HEAD：`/s/TOKEN/FORMAT`，或 `/s/FORMAT` 加 `Authorization: Bearer TOKEN`。手机多数使用路径链接；反代应关闭该路径的访问日志，或明确只记无路径的状态计数，避免把令牌写进日志。接口没有管理写入端点；未知/过期/撤销/错误令牌统一拒绝。默认最多 4 个并发、可设 1–16；低内存主机可显式 `--concurrency 1`。单内容 2MiB、快照 16MiB、最多 128 令牌记录，并有请求/响应/空闲/关闭超时。所有响应 `private, no-store`，不发 ETag/共享缓存或虚构流量配额头；下载读取每次重核新快照。

## 轮换、停用和故障恢复

```bash
qingnode subscription rotate --device DEVICE_ID --base-url https://sub.example.net --out /root/phone-token-new.json --yes
qingnode subscription revoke --device DEVICE_ID --yes
qingnode device disable --id DEVICE_ID --preview
qingnode device disable --id DEVICE_ID --yes
```

轮换只换下载令牌，旧令牌的新请求立刻被新快照拒绝；已认证进行中的响应无法追回。撤销或普通设备停用保留已下载的代理认证。要停用实际代理权限，先预览，再明确 `device disable --id DEVICE_ID --disable-credentials --yes`。只处理该设备明确绑定的凭据；仍被任何其他设备绑定的共享凭据都会使整批拒绝，包括已普通停用下载的设备，因为其已下载认证仍可能有效。不能通过先停用另一设备下载来绕过共享认证保护；需要先为其他设备分配独立凭据。某节点最后一个用户被停用时，保存原凭据并停用节点；运行影响按已有事务应用，可能重启共享核心。

full2源码发现并确认上述检查曾错误跳过`other.Disabled`，会让“B仅停下载、A再停共享认证”连带影响B；537d6e8去掉此跳过，保护所有仍注册的绑定。准确c89f7d1的full9静态、普通Go和race再次通过节点两路径及CLI四场景回归：保留其他用户或保留最后用户停节点、原服务运行或停止均覆盖；不再把disabled当作代理认证已作废。历史full7独立证据恢复与full8原collector成功仍分开见[BATCH06](BATCH06.md)；full9才是包含随后init重复覆盖修订的新源码完整结果。

删除认证属于服务器运行配置变更，沿原Apply按仍启用的监听启动或重启；它和普通Profile名称、标签等元数据修改不同。普通元数据没有服务器/宿主变化时保持原停止状态，本批不改这条边界。

`Store.BeforeCommit` 在提交前撤销已移除或停用设备的下载权限；设备停用先撤销下载再应用代理变更，代理应用失败也不会自动恢复已撤销令牌。发布配置与令牌注册表独立于 State/节点备份，恢复或 rollback 不应复活下载权限；迁机要单独保管私有发布目录，推荐重新签发令牌。State schema5 可只读兼容 1/2/3/4；实际写入操作保留旧代原件，旧二进制明确拒绝 schema5，不要改 schema 数字或删 devices/tags 伪装降级。

若代理 State 提交成功但发布新快照失败，命令明确报告“State 已提交”；旧完整快照保留，不声称事务整体未改变。检查 `subscription status`、处理错误后运行 `subscription publish`。订阅服务停止不会损坏代理配置；代理停止也不会让订阅读取启动它。恢复、订阅发布失败和实际服务状态应分别核对。
