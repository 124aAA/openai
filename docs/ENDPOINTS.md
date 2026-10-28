# NAT、双栈与客户端连接地址

第 04 批把“核心在本机接收连接的位置”和“客户端实际连接的入口”分开保存。一个节点仍对应一个本地监听，可声明主入口和最多 16 条额外入口；声明不会创建云厂商 NAT、反向代理或中转，也不改变 SSH、全局默认路由、防火墙策略或 IPv6 开关。默认官方核心仍锁定 1.14.0，1.14.3 只作为同兼容线候选单独验证。

实现、实际测试和未提供环境见 [BATCH04.md](BATCH04.md)，版本、协议、客户端及平台分层见 [CAPABILITIES.md](CAPABILITIES.md)。本页说明接口，不把合法配置、临时绑定或历史结果当作本批公网成功。

## 两套地址各自做什么

| 保存字段 / 参数 | 大白话 | 本次用途 |
| --- | --- | --- |
| `Listen` / `--listen` | VPS 本机接收连接的 IP | sing-box 入站、本机绑定预检、PID 监听就绪；只能是本机可用的 IP 字面量 |
| `Port` / `--port` | VPS 本机监听端口 | 入站、端口冲突、就绪及项目防火墙规则 |
| `Host` / `--server` | 主客户端连接地址 | IP 或域名；不要求等于 VPS 出口 IP，也不替代 TLS 名称 |
| `ConnectPort` / `--connect-port` | 主客户端连接端口 | 分享 URI、二维码、sing-box/Mihomo 及私密测试资料 |
| `AdditionalEndpoints` / `endpoint` 命令 | 同一监听的额外明确入口 | 按稳定端点 ID 选择不同 IP、域名或外部端口；复用原用户与认证材料 |
| SNI、证书名称、REALITY 握手目标 | 验证或握手使用的名称/目标 | 与连接地址独立；编辑端点不自动替换它们 |

例如，云厂商把外部 TCP 30000 转发到 VPS 的 TCP 443，保存 `Port=443`、`ConnectPort=30000`。本机放行和检查 TCP 443；客户端连接外部 30000。HY2 是 UDP / QUIC，其外部 UDP 端口和内部 UDP 端口可与 TCP 映射不同。REALITY 的代理 UDP 载荷仍由 TCP 入站承载，不因此增加 VPS UDP 监听。

项目可选的 UFW 规则继续按本地端口和传输层生成，目标范围仍为 `to any`，没有按具体监听 IP 做防火墙隔离。选择具体 Listen 只约束核心监听范围；外部 ConnectPort 不会自动在本机放行，也不代表云安全组或映射已配置。

SS2022 同时使用 TCP 与 UDP，单条客户端入口只能表达一个端口：该入口的 TCP、UDP 必须映射到相同的外部端口，再分别转发到本节点的本地端口。不能把两个外部端口分别填作“TCP 入口”和“UDP 入口”后声称它们是一条等价 SS2022 配置。额外端点仍各自需要完整映射。

## 创建、编辑与 NAT 向导

`init`、`add` 继续接受原协议参数，另支持 `--connect-port`，Bash 安装入口也将它透传给管理器并在宿主安装前拒绝非法端口。新建时省略它，保存为最终选定的本地端口；显式填写后，与本地端口独立。`--server` 是用户声明，公网出口探测不会覆盖已填写的地址。

已有节点可先预览，再应用；下面的 `NODE` 替换为已有节点 ID 或名称：

```bash
qingnode edit --id NODE --listen 0.0.0.0 --port 443 --connect-port 30000 --preview
qingnode edit --id NODE --listen 0.0.0.0 --port 443 --connect-port 30000
qingnode info --id NODE
qingnode endpoint list --id NODE
```

`edit --port` 只改本地监听端口，已保存的客户端端口保持。若希望两者一起变更，明确同时写 `--port` 和 `--connect-port`。改变本地监听属于运行配置变化，仍可能重启核心；只改公开端点且实际运行/宿主输入未变时，复用影响分类免重启，并保持原来的运行、停止及自启状态。损坏派生文件仍会检查与修复。

```bash
qingnode wizard --nat --protocol reality
qingnode wizard --nat --protocol hysteria2
```

NAT 向导逐项收集本地监听和外部连接端口；不把出口地址探测当作入站证明。向导退出或输入错误时不应用候选，不创建云映射。REALITY 目标及 HY2 证书参数仍需按原协议填写。HY2 使用 ACME HTTP-01 时，还需证书域名的外部 TCP 80 到达本机 TCP 80；单独节点 UDP 映射不证明已具备签发条件，不会停止现有网站。

批量 JSON 仍为 `version: 1`，新增 `connect_port` 和 `additional_endpoints` 可选字段；省略保留旧值，`additional_endpoints: []` 明确移除额外入口，`null` 拒绝。一项无效整批不生效。更多通用规则见 [DEVELOPMENT.md](DEVELOPMENT.md)。

```json
{"version":1,"edits":[{"id":"NODE","connect_port":30000,"additional_endpoints":[{"id":"v6","host":"2001:db8::8","port":31000}]}]}
```

## 额外入口与所有导出

`default` 是保留的主入口；额外 ID 为 1–32 位字母、数字、下划线或连字符，首位为字母或数字。ID 区分大小写；同节点不允许重复 ID 或等价的地址/端口。IP 按地址含义判重，域名判重忽略大小写及末尾点，但不改旧 State 的原始拼写。

```bash
qingnode endpoint add --id NODE --endpoint v6 --server '[2001:db8::8]' --connect-port 31000 --preview
qingnode endpoint add --id NODE --endpoint v6 --server '[2001:db8::8]' --connect-port 31000
qingnode endpoint edit --id NODE --endpoint default --connect-port 30000 --preview
qingnode endpoint edit --id NODE --endpoint v6 --connect-port 31001
qingnode endpoint remove --id NODE --endpoint v6 --preview
```

新输入接受有括号的 IPv6 并去掉外层括号；存储 host 不含端口、协议、IPv6 zone 或空白。URI 使用标准方括号连接 IPv6 与端口，客户端 JSON/YAML 中 host 保持不带括号的字面地址。

```bash
qingnode export --id NODE --endpoint v6 --format uri
qingnode export --id NODE --endpoint v6 --format qr
qingnode export --id NODE --endpoint v6 --format sing-box --out /root/client-v6.json
qingnode export --id NODE --endpoint v6 --format mihomo --out /root/client-v6.yaml
qingnode probe profile --id NODE --endpoint v6 --out /root/private-v6.json
```

省略 `--endpoint` 选择 `default`，不是自动挑选最快地址；不存在的端点明确拒绝。多凭据节点仍需 `--user`。HY2 性能设置的客户端版本和有损导出规则保持，按需要加 `--client-version`；URI 无法表达的性能选项不会因为选择端点而静默丢失。

私密 Profile 已固定该次端点与用户，不再接受另一个 `--endpoint`。复制到实际客户端机器后按 [NETWORK_TESTS.md](NETWORK_TESTS.md) 使用 `qingprobe run --path client-proxy --profile ...`，选择自己的受控 HTTPS / UDP 目标。文件含凭据，不放入外部验证材料。客户端配置摘要包含实际地址和端口；端点变化后，旧自动报告不能当成新配置已测。`public-check` 是管理员登记，其原有完整节点摘要变化也会提示重验。

旧版 `public-check` 的完整节点摘要可能因 schema 迁移或新增端点而保守地提示过期，原登记记录仍保留。自动测试按真实所选用户/入口的 outbound 摘要判断；不能把手动登记当作自动测试结果。

## IPv4、IPv6、域名和实际双栈

| 声明 | 可表达的意图 | 仍需单独核验 |
| --- | --- | --- |
| `--listen 0.0.0.0` | 本机 IPv4 通配监听 | 实际本机绑定、云映射、IPv4 入站与协议认证 |
| `--listen 127.0.0.1` 或本机具体 IPv4 | 指定 IPv4 监听范围 | 地址确实属于本机，转发入口确实到达它 |
| `--listen ::1` 或本机具体 IPv6 | 指定 IPv6 目的地址监听范围 | 本机 IPv6 与实际远端路由 |
| `--listen ::` | IPv6 通配地址，由核心采用自动双栈套接字策略 | 对同一个真实监听分别验证 IPv4、IPv6；不能保证双栈或严格 IPv6-only |
| 客户端域名 | 由客户端解析连接入口 | A、AAAA 内容与各自可达性，DNS 失败与 IPv6 不通分别判断 |

官方 sing-box 1.14.0 / 1.14.3 没有入站 `v6only`、`ipv6_only` 或 `dual_stack` JSON 字段。本批不生成这些假字段、不改全机 `bindv6only`、不关闭 IPv6。Linux 全局 `net.ipv6.bindv6only` 只是默认值；Go/核心可为套接字选择不同值，`tcp6`/`udp6` 行也不证明该 socket 只接 IPv6。

域名在坏 AAAA 后回落 IPv4 成功，只证明成功的 IPv4 路径。要验证 IPv6，声明独立 IPv6 字面端点并从有 IPv6 的实际客户端测试；必要时保留正确的独立 SNI。服务器没有 IPv6 不应使纯 IPv4 节点失败。缺少 IPv6 的测试环境记“未验证”，不写成双栈通过。

`probe` / `qingprobe` 的 `--family` 控制被测目标的地址族，不会强制代理入口使用同族；验证代理入口的 IPv6 路径须选择 IPv6 字面端点，域名回落 IPv4 成功不能证明 AAAA 入口已通过。

冲突判断先按传输层、IP 地址和通配范围识别确定冲突：不同地址可用相同端口，TCP 443 和 UDP 443 可独立存在。同族通配监听会覆盖该族具体地址。涉及 `::` 与 IPv4 的宿主差异时，不靠字段猜测；应用校验临时同时绑定候选监听，并核对旧 socket 的进程和 inode。无法确认归属或实际双栈语义时拒绝冒险应用，保留旧状态。临时绑定关闭后仍存在抢占窗口，真实启动失败沿原事务恢复。

## 本机能力报告与外部验证材料

```bash
qingnode capabilities
qingnode capabilities --json
qingnode capabilities --out /root/capabilities-new.json
qingnode capabilities --skip-loopback
qingnode endpoint material --id NODE --endpoint default --out /root/endpoint-material-new.json
```

`capabilities` 可在初始化前运行，不加载节点 State、不恢复事务。报告版本 1，记录架构、PID 1/init、有效可用内存、当前进程 capability、容器证据、固定内核参数、TUN 设备与固定目录访问权限。目录为 State 根目录、`/etc/systemd/system`、`/usr/local/bin`、`/run`；只检查访问权限，不创建或实际写入，因此 `write_exercised=false`。

默认本机临时测试分别尝试 TCP4、UDP4、TCP6、UDP6 的回环绑定与 32 字节请求/响应，结束关闭自有 socket。绑定成功 `available` 与本次实际收发 `exchange_exercised/exchange_succeeded` 分开；`--skip-loopback` 留未知。TUN 不打开、不执行 ioctl、不创建设备或加载模块；设备存在及访问位不证明能创建接口。报告仅代表当前管理器进程可见的权限、cgroup 和命名空间，不证明专用服务账户或远端客户端具备同样能力。缺失值为 `null`，IPv6 不可用不覆盖 IPv4 结果。

`endpoint material` 是配置声明材料，版本 1，不含分享 URI或完整认证材料：列出本地/外部地址、所需 TCP/UDP 映射、客户端/服务器摘要和待办。材料的客户端摘要覆盖所选端点的全部用户对象；私密 Profile 的摘要覆盖单个选定用户的规范化真实 outbound，两者不直接比较。`dns_a`、`dns_aaaa`、`inbound_tcp`、`inbound_udp` 保持 `unknown`，`cloud_nat_changed=false`；生成材料不会联网或修改运行策略。材料中不适用的协议也不能改写成已通过。出口 IP 探测只说明某次出站地址；它不是可入站地址证明。

外部验收依次核对云映射/安全组、A/AAAA，再从真正客户端经过所选代理执行 HTTPS 和受控 UDP；保留发起端、目标日志、端点配置摘要和关闭所选代理后的失败负例。服务器自测、配置解析和本机回环不能代替这一步，也不能推出用户运营商质量。

## 迁移、备份和恢复

本批有实际新增字段，State 明确升为 schema 3。schema 1 / 2 严格解码后仅在内存迁移：每个旧节点 `ConnectPort` 显式等于旧 `Port`，Host、Listen、Port、ID、用户凭据、REALITY 密钥、证书和时间戳不变，主 URI逐字等价。读取/导出不落盘；首次有意义写操作创建 schema 3 新代，原始旧代与快照保留。schema 1/2 偷塞新端点字段（含 `null`）或未知字段、未来 schema 明确拒绝。

schema 3 的省略 `connect_port` 在内部允许沿用本地 Port；新 CLI 创建会显式保存，旧格式迁移也会显式锁定旧值，避免之后修改监听时悄悄换外部端口。旧管理器不理解 schema 3，会拒绝读取，不提供删字段或修改版本号的伪兼容。

节点 `rollback`、加密备份 v1/v2、明文恢复及显式 `recover` 沿已有入口工作；恢复旧快照仍经本批管理器生成 schema 3，不是自动程序降级。应用失败完整恢复旧配置与原运行状态，恢复失败保留事务证据。使用原始旧格式材料离线降级属于单独验证的恢复步骤，不能把 schema 3 数据直接交给旧二进制。

## 固定来源

字段与调用链核对官方 sing-box [v1.14.0 / 0b89958](https://github.com/SagerNet/sing-box/tree/0b8995879f29a9b98ee027bc17b75e101445b238) 和 [v1.14.3 / 7054cac](https://github.com/SagerNet/sing-box/tree/7054cac5124465ffdb145870d7c01885566711b1)：[Listen 选项](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/inbound.go)、[TCP 绑定](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/common/listener/listener_tcp.go)、[UDP 绑定](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/common/listener/listener_udp.go)、[Dial 文档](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/docs/configuration/shared/dial.md)。没有把出站 DNS 的 `ipv6_only` 策略当作入站开关。

自动地址族还核对 sing 固定依赖与 [Go 1.26.8 / c293dd4](https://github.com/golang/go/tree/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e) 的标准库套接字机制；完整 pin、许可证、借鉴机制与不分发边界见 [THIRD_PARTY.md](../THIRD_PARTY.md)。上游 WireGuard endpoint 属于另一种核心顶层端点，本页的客户端连接端点不是 WireGuard、链式拓扑或新增协议实现。
