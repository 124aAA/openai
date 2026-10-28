# 协议选择、能力与完整配置

第09批当前源码提供七协议：REALITY、SS2022、Hysteria2、AnyTLS、Trojan、传统SS AEAD和TUIC。源码尚未发行，最终代码d0fd58a的定向25/25项、独立能力补测和五步构建已通过；完整回归的准确提交与保留失败见 [BATCH09.md](BATCH09.md)。默认官方核心仍为1.14.0，候选1.14.3不会自动替换。

## 先按需要选，再在自己的链路测试

| 协议 | 当前监听 / 可承载业务 | 使用条件与场景 |
| --- | --- | --- |
| REALITY / XTLS Vision | TCP / TCP、UDP | 已有 REALITY 客户端与合适握手目标；身份为 UUID，目标选择不代表公网更快 |
| SS2022 | TCP、UDP / TCP、UDP | 客户端支持2022方法；独立服务密钥和用户密钥，不能当作传统 SS 密码 |
| Hysteria2 | UDP / TCP、UDP | 有可达 UDP 和有效证书；性能策略独立，详见 [NETWORK_PERFORMANCE.md](NETWORK_PERFORMANCE.md) |
| AnyTLS | TCP / TCP、UDP，UDP在TCP连接内传送 | 需要 TLS、独立用户密码与连接复用；客户端须明确支持 AnyTLS |
| Trojan | TCP / TCP、UDP，UDP在TCP连接内传送 | 需要 TLS 与独立用户密码；本批只支持原生 TLS，不添加 WebSocket、gRPC 或额外复用参数 |
| 传统SS AEAD（`ss-aead`） | TCP、UDP / TCP、UDP | 三种明确方法、同方法同监听的独立用户密码；适合已有传统AEAD客户端，不能当SS2022密钥格式 |
| TUIC | UDP / TCP、UDP | QUIC核心构建能力、TLS证书、独立UUID+密码；客户端须支持TUIC，0-RTT保持关闭 |

没有通用速度排名。监听使用的网络与隧道内承载的业务不同；AnyTLS/Trojan 能承载 UDP 不代表需要额外开放公开 UDP 监听，也不证明某条公网 UDP 路径已成功。使用 [NETWORK_TESTS.md](NETWORK_TESTS.md) 的有界测试比较自己的链路，不把 HTTPS 成功当 UDP 成功。

## 查看能力与创建节点

```bash
qingnode protocols list
qingnode add --protocol anytls --name AnyTLS-01 --server 节点地址 --port 443 \
  --sni 证书域名 --cert /私有目录/fullchain.pem --key /私有目录/key.pem
qingnode add --protocol trojan --name Trojan-01 --server 节点地址 --port 8443 \
  --sni 证书域名 --cert /私有目录/fullchain.pem --key /私有目录/key.pem
qingnode add --protocol ss-aead --method aes-256-gcm --name SS-01 --server 节点地址 --port 8388
qingnode add --protocol tuic --name TUIC-01 --server 节点地址 --port 8443 \
  --sni 证书域名 --cert /私有目录/fullchain.pem --key /私有目录/key.pem
```

TLS协议还可使用既有 PEM、用户文件引用、稳定证书资源与核心 ACME 接口，操作和条件见 [CERTIFICATES.md](CERTIFICATES.md)。凭据首次生成后保存，普通改名、端点修改和重新导出不轮换。新密码为16–512字节有效UTF-8，不含控制字符；AnyTLS/Trojan/传统SS不混UUID，TUIC明确同时需要UUID和密码。服务端按稳定 UserID 记录认证名称，显示名不是身份。

能力输出将 `listener_networks`（本机监听）、`business_networks`（承载业务）、服务端/客户端构建标签、证书、凭据、各导出格式和高级字段分开。`core_binary_verified:false` 表示这只是接口登记；不会声称当前磁盘二进制或公网已经通过。新协议客户端字段只核对 sing-box1.14.0/1.14.3、Mihomo1.19.30，其他版本需另验。

新四协议用命令行导出单节点完整配置时，sing-box 显式加 `--client-version 1.14.0` 或 `1.14.3`，Mihomo/provider 加 `--client-version 1.19.30`；目标是客户端版本，不从服务器核心版本推断。交互导出菜单会选用已核验的 sing-box 1.14.0 或 Mihomo 1.19.30 并显示选择，`info` 的 sing-box 命令也包含版本参数。实际二进制构建标签仍需单独核对，版本字符串不能代替构建标签。

`protocols list` 的 `server` 表示可作为Node入站；`client_outbound` 表示可生成sing-box客户端出站，七协议均为true；`server_egress` 表示可保存为服务器远程Egress，仅REALITY、SS2022、Hysteria2为true。原有 `outbound` 字段为了兼容旧读取端仍等于 `client_outbound`，不得据此推断服务器Egress能力。SOCKS5和用户态WireGuard也属于服务器远程Egress，但不属于七种Node协议适配器，单独登记在拓扑模型中。已有入口仍可显式绑定已支持的出口路径，具体限制见[TOPOLOGY.md](TOPOLOGY.md)。

能力登记 `advanced_options` 使用官方核心字段名；私有State及 `protocols options` 使用下表左列。尤其 `min_idle_session` 是核心字段，私有输入应写 `idle_session_min_keep`，不能直接照抄能力列表作为State字段。

## AnyTLS 空闲连接选择

默认不强制保留空闲连接：两个时长留空时采用固定客户端30秒默认，保留数默认为0。显式保留更多空闲连接会增加连接和内存占用，不能当作自动提速。

| State字段 | sing-box字段 | Mihomo字段与单位 |
| --- | --- | --- |
| `idle_session_check_interval` | `idle_session_check_interval` | `idle-session-check-interval`，整数秒 |
| `idle_session_timeout` | `idle_session_timeout` | `idle-session-timeout`，整数秒 |
| `idle_session_min_keep` | `min_idle_session` | `min-idle-session`，连接数 |

时长只作用于客户端，显式值须为6秒至24小时的整秒时长；两种固定客户端都会把不超过5秒的值改回30秒，因此拒绝保存这种误导值。保留数限制0–1024，这是产品资源边界，不是上游硬上限。未设置和显式0分别保存；空对象恢复客户端默认。

把下面内容保存为权限0600的私有JSON，`node_id`替换为稳定节点ID：

```json
{"version":1,"node_id":"1111111111111111","anytls":{"idle_session_check_interval":"30s","idle_session_timeout":"45s","idle_session_min_keep":0}}
```

```bash
qingnode protocols options --file /私有目录/anytls.json --preview
qingnode protocols options --file /私有目录/anytls.json --yes
```

预览整体校验并显示实际影响，应用沿同一State事务一次提交；不另造服务端性能参数。恢复默认使用 `"anytls":{}`，不接受未知字段或null。

## 传统SS AEAD密码与方法

只支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，默认创建方法为 `aes-256-gcm`。同一方法可在同一TCP/UDP监听保存多个独立用户password，服务端只写users，不写顶层服务密码。密码原始UTF-8内容交给该传统方法的密钥派生（KDF，核心把密码变为加密密钥），不预先Base64解码，不拼接SS2022的 `server:user`。`server_key`必须为空，SS2022的32字节Base64双密钥规则仍由独立适配器处理。

本项目输入为16–512字节UTF-8密码；依[官方AEAD规范](https://shadowsocks.org/doc/aead.html)，AES-128-GCM派生16字节主密钥，AES-256-GCM与ChaCha20-IETF-Poly1305派生32字节主密钥。这是核心内部使用的密钥长度，不要求用户把密码截为该长度，也不把用户输入当作Base64原始密钥。

传统SS的SIP002链接用无填充Base64URL编码 `method:password`；特殊字符与IPv6仍保留原连接信息。方法编辑保留已有用户密码，实际运行输入变化经原事务处理，不承诺无损切换；客户端须同步方法。需要确认同端口多个密码的身份与撤销效果，不能用单用户解析代替。

## TUIC服务端和客户端独立设置

TUIC需要 `with_quic`，使用核心ACME还需要相应证书构建能力。UUID大小写不能区分同一个身份，重复UUID即使密码不同也拒绝。两端TLS固定ALPN为 `h3`，不添加HY2性能或Chrome指纹设置。

| State字段 | sing-box方向与字段 | Mihomo客户端映射 |
| --- | --- | --- |
| `server_congestion_control` | 服务端 `congestion_control` | 不写入客户端 |
| `client_congestion_control` | 客户端 `congestion_control` | `congestion-controller` |
| `auth_timeout` | 仅服务端 `auth_timeout`，1–60秒 | 不映射为客户端超时 |
| `server_heartbeat` | 仅服务端 `heartbeat` | 不写入客户端 |
| `client_heartbeat` | 仅客户端 `heartbeat` | `heartbeat-interval`，整数毫秒 |
| `udp_relay_mode` | 仅客户端 `udp_relay_mode`，`native`或`quic` | `udp-relay-mode` |
| `zero_rtt_handshake` | 仅接受未设置或false，两端明确写false | `reduce-rtt:false` |

拥塞控制只接受 `cubic`、`new_reno`、`bbr`，不同客户端的算法实现不保证完全相同。心跳为1秒至2分钟的整毫秒时长，例如1500ms在Mihomo写1500；不用秒值冒充毫秒。省略保留固定客户端默认，0-RTT始终关闭以避免重放风险。高级设置沿 `protocols options` 私有version1对象的 `tuic` 字段预览/应用；服务端与客户端选项不能相互串用。

## 分享链接、订阅与证书限制

AnyTLS基础URI按官方格式保存密码、显式连接端口、SNI和安全TLS选择。显式空闲设置无法由标准链接表达，因此URI、二维码、Base64分享默认拒绝，改用完整sing-box JSON或Mihomo YAML/provider；不静默丢字段，也不返回空链接冒充成功。

Trojan URI使用百分号转义密码、SNI、TCP与证书验证参数。Mihomo1.19.30导入Trojan URI会默认采用Chrome指纹；该固定组合不接受Ed25519证书，因此对此类静态证书拒绝分享格式，建议完整原生TLS配置或ECDSA/RSA证书。原生TCP TLS的完整JSON/YAML不继承Hysteria2 QUIC/Chrome限制；这不等于所有客户端UI都已验证。ACME实际签发、信任链、导入和传输分别检查。

TUIC当前不提供未经核验的通用URI，URI、二维码、Base64集合明确拒绝，使用完整JSON/YAML/provider。设备含TUIC或AnyTLS高级设置时，应明确选择 `"subscription_formats":["sing-box","mihomo","provider"]`，排除默认URI格式；不能为了发布成功而静默丢设置或省掉节点。下载令牌不等于代理凭据，禁用/撤销沿独立授权处理。

所有客户端连接地址统一来自 `Host/ConnectPort`；`Listen/Port`只用于本地监听。IPv6、NAT额外入口沿 [ENDPOINTS.md](ENDPOINTS.md) 处理，不改证书名称。设备导出、订阅下载权限和代理凭据停用仍是独立范围，见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)、[MONITORING.md](MONITORING.md)。

## 版本、恢复与固定来源

State因真实协议语义和AnyTLS设置升为schema8；旧1–7只在内存兼容并保留原件。旧格式不接受新协议/新选项，即使值为null或使用大小写、Unicode别名；合法schema7观测字段仍可读取。恢复旧快照仍写schema8，不能改版本号或删字段伪装降级，详见 [MIGRATION.md](MIGRATION.md)。

字段核对使用官方固定源码，只取接口事实，未复制或链接GPL实现：sing-box [1.14.0 AnyTLS](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/option/anytls.go)、[1.14.3 AnyTLS](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/anytls.go)、[1.14.3 Trojan](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/trojan.go)，Mihomo [1.19.30 AnyTLS](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outbound/anytls.go)、[分享链接转换](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/common/convert/converter.go)，AnyTLS原作者[基础URI规范](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/uri_scheme.md)。上游许可和二进制来源沿 [THIRD_PARTY.md](../THIRD_PARTY.md)；源文件检查不代替真实核心测试。

第二阶段接口核对另见固定sing-box[传统AEAD多用户入站](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/protocol/shadowsocks/inbound_multi.go)、[TUIC字段](https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/option/tuic.go)，Mihomo[TUIC字段和毫秒转换](https://github.com/MetaCubeX/mihomo/blob/ac017cdd246ce8bd547653d927e7bf77d7ee73d5/adapter/outbound/tuic.go)，及官方[SIP002](https://shadowsocks.org/doc/sip002.html)。外层 `work/batch09-upstream-contract-20261023.md` 保存本批固定来源核对；真实QA以[BATCH09.md](BATCH09.md)中的准确提交和日志为准。
