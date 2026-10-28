# 中转、代理链与 WireGuard 落地

第 05 批继续使用独立官方 sing-box，默认核心 1.14.0，1.14.3 单列验证。没有默认安装 Realm、GOST、系统 WireGuard、Docker 或数据库。实现、实际命令及未验证范围见 [BATCH05.md](BATCH05.md)，版本/构建标签见 [CAPABILITIES.md](CAPABILITIES.md)。

## 三种入口

| 对象 | 用途 | 出口选择 |
| --- | --- | --- |
| 现有代理节点 `Node` | 客户端连接 REALITY、SS2022、HY2 入口，使用原用户/凭据 | 空 `egress_id` 保持原 direct；可显式绑定远程出口或策略 ID |
| `PortForward` | 本地 TCP、UDP 或两者转发到明确的目标地址/端口 | 独立选择 direct、远程出口或策略，不生成代理用户或分享链接 |
| `Egress` / `EgressPolicy` | 远程 SOCKS5、REALITY、SS2022、HY2、用户态 WireGuard；固定出口或显式主备 | `detour` 是连接远程出口自身时使用的上游；没有失败时的隐式 direct 替代 |

对象 ID 为稳定的 16 位小写十六进制字符串；省略新对象 ID 时生成。名称用于显示和已有对象查询，持久引用使用 ID。远程密码/UUID/WireGuard 密钥与本地 `Users` 分开；普通编辑不生成新凭据。最终客户端导出仍只有入口地址及入口用户，不包含内部落地认证材料。

## 端口中转和出口绑定

```bash
qingnode forward add --name web-forward --listen 127.0.0.1 --port 30000 --network tcp --target-host 192.0.2.20 --target-port 443 --egress direct --preview
qingnode forward add --name web-forward --listen 127.0.0.1 --port 30000 --network tcp --target-host 192.0.2.20 --target-port 443 --egress direct
qingnode forward list
qingnode forward edit --id FORWARD_ID --network tcp+udp --preview
qingnode route set --id NODE_ID --egress EGRESS_ID --preview
qingnode route set --id NODE_ID --egress EGRESS_ID
qingnode route set --id NODE_ID --egress direct --preview
```

示例地址须换成自己的目标。纯转发的 direct 入站本身没有用户认证，只转向保存的固定目标；监听范围、云安全组和访问控制需明确。TCP 与 UDP 的监听、目标及检查分别处理；不把 TCP 成功当成 UDP 已通。防火墙仍只管理自有规则，不创建云映射，不清空全机策略。

```bash
qingnode egress add --name my-socks --protocol socks5 --server 192.0.2.20 --port 1080 --username REMOTE_USER --password REMOTE_PASSWORD --udp --preview
qingnode egress add --name my-socks --protocol socks5 --server 192.0.2.20 --port 1080 --username REMOTE_USER --password REMOTE_PASSWORD --udp
qingnode egress list
qingnode egress show --id EGRESS_ID
qingnode egress edit --id FINAL_EGRESS_ID --via UPSTREAM_EGRESS_ID --preview
qingnode egress edit --id FINAL_EGRESS_ID --via UPSTREAM_EGRESS_ID
qingnode egress edit --id FINAL_EGRESS_ID --via direct --preview
```

密码参数也可能保留在终端历史/进程参数中；需要避免这些暴露时，使用权限 0600 的严格拓扑 JSON 文件导入。查询和错误信息会脱敏，私有 State、备份及导入文件仍必须保管。

SOCKS5 默认只声明 TCP，`--udp` 是用户对远端能力的明确声明，不是探测成功。绑定代理节点时要求 UDP 能力，因为 REALITY 的 TCP 入站也可能承载 UDP 载荷。SOCKS UDP 同时需要 TCP 控制连接与 UDP 数据；HY2/WireGuard 自身的链上连接需要 UDP，不能放在只有 TCP 的上游后面。三个已有远程代理协议默认声明 UDP，但实际远端仍需验证。

REALITY 出口参数为 `--uuid --sni --public-key --short-id`，可选 `--fingerprint`；SS2022 只支持 `2022-blake3-aes-256-gcm`，`--password` 使用远端实际组合密钥；HY2 使用 `--password --sni` 和可选 `--ca PEM文件`，不能关闭 TLS 验证。远程 HY2 的出站性能选择用严格 JSON 的 `hysteria2.performance`，复用第 03 批客户端字段，拒绝服务端性能字段。URI 或 Hysteria 原生 YAML 不是任意配置导入口。

`detour` 启用时上游会忽略同层其他 Dial 字段。本批只开放明确的上游引用，不叠加接口绑定、源地址、MPTCP 等参数宣称同时生效；没有链式带宽叠加或会话无损迁移承诺。

## 整批预览和一次应用

```json
{"version":1,"operations":[{"action":"egress-put","egress":{"id":"1111111111111111","name":"remote","protocol":"socks5","server":"192.0.2.20","port":1080,"udp":true,"socks":{"username":"REMOTE_USER","password":"REMOTE_PASSWORD"}}},{"action":"route-set","node_id":"NODE_ID","egress_id":"1111111111111111"}]}
```

```bash
chmod 600 /root/private-topology.json
qingnode topology apply --file /root/private-topology.json --preview
qingnode topology apply --file /root/private-topology.json
```

`topology batch` 是同一入口的别名。操作包括 `egress-put/remove`、`policy-put/remove`、`forward-put/remove`、`route-set`。不接受未知字段、重复/大小写伪装字段、null、额外 JSON、管道或软链接。批末验证完整候选，一项无效整批不保存；可以在同批显式迁移引用并移除旧出口。单独删除被引用对象会拒绝。

出口和规则只为引用它的入站生成，未使用的纯出口修改不改变服务器运行配置。当前仍是一份共享核心配置：实际运行路径改变时一次统一应用可能重启整个核心，影响其它已有连接。节点级影响预览表示配置依赖范围，不表示每节点都有独立进程或热更新。

## 固定出口与显式主备

固定出口直接绑定 Egress，或用 `egress policy add --mode fixed --primary EGRESS_ID`。主备必须明确两条远程路径、自己的 HTTPS 应用目标、失败/恢复阈值、冷却和超时；不允许隐式 direct 备用。承载 UDP 的主备还必须提供受控序号 UDP 目标。

```bash
qingnode egress policy add --name primary-backup --mode failover --primary PRIMARY_ID --backup BACKUP_ID --target https://your-controlled-host.example/check --udp-target 192.0.2.30:40000 --failure-threshold 3 --recovery-threshold 3 --cooldown-seconds 60 --timeout-seconds 5 --preview
qingnode egress policy list
qingnode egress health --id POLICY_ID --out /root/health-new.json
qingnode egress health --id POLICY_ID --apply --watch --rounds 4 --interval 5s --budget 60s --out /root/health-apply-new.json
```

先将自己的域名/目标及 ID 替换正确，预览后去掉 `--preview` 创建，再绑定策略。普通 health/probe 只测试，不累计切换计数、不写 State；`--out` 可写新结果文件，`--json` 输出完整版本化 JSON。`--apply` 才累计并按阈值应用，且必须使用策略保存的目标；`--watch` 还必须显式带 `--apply`。这是有探测和等待预算的前台命令，不安装永久监控器。取消或超时在事务开始前阻止选择变更；已经开始的原子应用必须完成或恢复，可能超过探测预算，另列 `apply_elapsed_ms`。

每轮测试主、备和各自声明的上游路径，单并发、每路径最多 16 KiB 有效载荷，最多 16 轮、64 路径/轮，探测及等待预算最多 120 秒，总有效载荷上限 16 MiB；协议封装流量未知。原始 HTTPS/UDP 样本保留。各段测试仍包含该段自己的上游，不能把重叠路径的时间相减当作独立握手。测试由当前服务器发起，不能推断用户运营商质量；入口端到端继续从真实客户端用 `probe/qingprobe`。

未知、取消、本地核心崩溃或权限失败不计成远端失败；无有效备用就保持失败。主出口连续失败且备用应用测试通过才切换；恢复也需连续成功并等冷却结束。已建立 TCP 会话不会迁移；统一应用可能关闭它们。观察绑定实际图、核心、DNS 和健康条件，测试期间路径变化会拒绝应用过期结果。

`egress-health.json` 是独立私有观测 version 1，不是节点备份或服务配置。恢复配置时缺失/失效的观测重建保守窗口，防止恢复后立刻抖动。未知观测格式/权限异常拒绝覆盖；选择已提交而观测写入失败时，报告分别列出选择是否实际应用；事务返回错误且提交结果不确定时 `selection_applied: null`，先用 `egress policy list` / `doctor` 核对，再按需显式 `recover`，不能把它报成未改变。即使结果文件写入失败，仍在标准输出显示实际选择并返回保存错误；`timeout` 与用户 `canceled` 分开。

## 两台自有主机的 WireGuard

```bash
qingnode wireguard pair --id pair1 --entry-tunnel 10.66.0.1/32 --landing-tunnel 10.66.0.2/32 --landing-server LANDING_HOST --connect-port 30001 --listen-port 51820 --allowed-ips 0.0.0.0/0 --keepalive 25 --out-dir /root/new-private-pair
```

输出独立两端 `entry.json`、`landing.json` 和逐端 README、无凭据 manifest。材料包含密钥，不能作为公开报告。输出父目录须由当前用户或 root 拥有，且不能被其他用户改写；固定目录句柄并拒绝路径替换，失败只清理自有文件。已有目录不覆盖；每端只携带自己的私钥和共享的预共享密钥。配对标签与随机稳定出口 ID 分开，实际命令使用生成材料列出的 ID。

入口主动连接落地外部 UDP 30001，落地监听本地 UDP 51820；声明不创建映射。入口 peer AllowedIPs 是经隧道到达的明确目标范围；落地 peer AllowedIPs 仅接受入口隧道来源主机地址。此向导每次生成同族 IPv4 /32 或 IPv6 /128 的一对地址，AllowedIPs 同族；更复杂双族配置须在严格对象中明确声明各地址/Peer。

先在落地预览/应用 `landing.json`，自行核验 UDP 映射和出站能力；再在入口预览/应用 `entry.json` 并显式绑定入口 Node。每端完成状态单列，跨主机不是本地原子事务。没有远端登录步骤或访问凭据，工具不会自行 SSH。

WireGuard 使用 `endpoints` 和 `system:false`，所选官方核心须实有 `with_wireguard`、`with_gvisor`。不创建设备或宿主 wg0，不接管已有 Peer、DNS、默认路由或其它服务；不把整个代理永久提权。固定 WireGuard 监听实际使用两个独立 UDP4/UDP6 socket，不能套用普通 `::` 单 socket 的推测。1.14.3 在没有默认网络接口时会暂停 WireGuard；本批用只 lo 的失败和独立测试网络的通过分别验证此条件。工具不替用户创建默认路由，监听就绪也不等于隧道可用。

主动 WireGuard 出口不自动授予对端使用本机网络的新连接权限。核心的 `listen_port:0` 仍可在已认证隧道上收到对端主动建立的 TCP/UDP 流；管理器对实际使用且未授权接收的 endpoint 入站标签显式 reject，保留本端已发起连接的正常回复。只有带监听且明确设置 `ReceiveEgressID` 的被动落地才接收新流。接收策略的主/备候选都检查回指，即使当前未选中也不能回到接收 endpoint 自身。两版核心的修前/修后真实数据和独立目标计数见 [BATCH05.md](BATCH05.md)。

MTU 省略/0 保留核心默认 1408；keepalive 0 关闭，需要维持 NAT 映射时明确选择合适间隔，如 25 秒。落地收到隧道流量后显式走指定出口（配对默认 direct），需要普通目标 TCP/UDP 出站能力。握手、隧道地址内本机服务、任意目标转发和目标看到的实际出口是不同证据。WireGuard 没有响应时，仅凭入口超时不能唯一分辨错密钥、UDP 被拦或对端停止；需结合对端日志、受控 UDP 路径与目标计数，报告不猜原因。

验收应保留目标 HTTPS/序号 UDP 日志和源地址，停掉所选落地后新请求必须失败，同时直接控制请求证明目标仍活着。先在入口显式迁回原出口，移除引用后再删除自有出口；落地独立撤回自己的端点。需要 direct 时必须明确选择，不能把失败恢复当作暗中改走 direct 的授权。

## 版本、恢复与循环边界

State 因真实拓扑字段升为 schema 4。旧 1/2/3 只读在内存兼容，旧监听、客户端端口、用户和密钥保留，旧 direct 服务配置语义保持。首次有意义写入保留旧代并写新代；旧二进制拒绝 schema 4，不能删未知字段或改版本号伪装降级。v1/v2 快照继续使用显式迁移入口，recover/rollback 保留事务与失败恢复材料。

快照外层重复字段（含大小写和 Unicode 折叠别名）直接拒绝，避免后一个 `format` / `state` 掩盖前方未知版本或完整拓扑。此检查只扫描外层，不删除保存的 `server_config` 内部未知或重复字段；旧单个兼容键仍可读，备份 envelope v1/v2 不升版。错误材料保留原件，不能删键或改 schema 数字来绕过拒绝。

拒绝缺失/被删引用、链环、回指自身入口/隧道、UDP 能力冲突和 DNS 引导环。`ReceiveEgressID` 引用策略时，自回指检查覆盖所有主/备候选，不只检查当前选择；实际路由仍只渲染选中路径。写入时只对实际由本机解析或拨号的层做有预算解析和本机回指核对。普通代理链后续的环回/内网地址属于上一跳，不能误当成本机；远端 DNS 与远端环路仍需整链验证。公共入口防环按物理 TCP/UDP 分开；VLESS 的 UDP 载荷仍走物理 TCP。WireGuard peer 引导及其目标域名按固定核心的本地 resolver 语义单独校验。所需本地解析失败拒绝应用，不改用户地址。DNS 后续重绑定、外部 NAT 和未声明中转仍需实际链路证据，不能仅凭预检保证永久无环。只读状态查询不修复事务、不启动服务、不偷偷切出口。

新拓扑入口 Profile/自动报告使用独立显式 version 2 记录内部路径摘要，旧 direct 路径 v1 保留；摘要只声明导出时的配置，不证明远端此刻仍相同。最终客户端文件不含内部出口密码/私钥。公开手动历史与自动结果分开，路径改变后的旧报告不能当新拓扑已验收。

固定来源、许可证、真实测试与未提供的 systemd/公网/原生架构范围见 [THIRD_PARTY.md](../THIRD_PARTY.md) 和 [BATCH05.md](BATCH05.md)。
