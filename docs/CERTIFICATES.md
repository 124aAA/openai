# 证书资源与续期

这是第 07 批未发行源码的接口。公开 v0.2.8 包不因此更新。默认核心仍为官方 sing-box 1.14.0，1.14.3 单独验证；两版均需要 `with_acme`，HY2 还需要 `with_quic`。本批实测、失败与环境边界见 [BATCH07.md](BATCH07.md)，完整加密搬迁见 [MIGRATION.md](MIGRATION.md)。

证书资源是保存证书材料的独立对象，有稳定 ID；节点通过 `certificate_id` 引用它。PEM 内容、用户自己的文件引用、核心管理的 ACME 是三种互斥模式。共享资源更新会影响所有引用节点，普通节点编辑则为该节点创建独立资源，避免连带修改。节点 UUID、密码、REALITY 密钥与证书资源是不同身份，更新证书不轮换代理认证。

## 导入、绑定与更新

私有输入文件必须是本机普通文件、权限 0600，不接受链接；不要把私钥或 DNS Token 放进命令行。格式为 `version: 1`，未知字段、重复字段、null 和多余 JSON 均拒绝。PEM 示例中的内容须替换为完整证书链与匹配私钥：

```json
{
  "version": 1,
  "resource": {
    "id": "aabbccddeeff0011",
    "name": "入口证书",
    "certificate": {
      "mode": "pem",
      "server_name": "node.example.com",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
      "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
    }
  }
}
```

```bash
qingnode certificate import --file /私有目录/certificate.json --preview
qingnode certificate import --file /私有目录/certificate.json
qingnode certificate bind --id aabbccddeeff0011 --node 节点ID --preview
qingnode certificate bind --id aabbccddeeff0011 --node 节点ID
qingnode certificate status --id aabbccddeeff0011
qingnode certificate update --id aabbccddeeff0011 --file /私有目录/new-certificate.json --preview
qingnode certificate update --id aabbccddeeff0011 --file /私有目录/new-certificate.json --yes
```

导入时省略 ID 会生成新 ID；导入不能覆盖已有资源。更新必须保持 ID，预览列出引用节点与实际配置影响，提交沿用持锁、候选核心校验、原子切换与失败恢复。域名 SAN、证书/私钥配对、链中签名和有效期不合格时不替换旧有效材料。显式导入/更新还会验证完整服务器证书路径：必须连到本机已有信任根，或输入末尾明确附带的有效自签私有根；缺少中间证书或必要私有根时拒绝，不联网下载补链，不修改宿主信任库。受信任根通常可省略，所需中间证书仍须提供；当前单张非自签证书入口仍要求补齐链。

旧 State 与备份读取保留原来的结构/相邻签名校验，不因新机器的信任库不同就丢掉恢复材料；这不证明旧链完整或客户端可以连接。显式重新导入/更新旧资源会执行上述完整路径校验。签名链校验不等于目标客户端信任该 CA，私有 CA 仍须在客户端明确安装信任。

目前资源绑定用于 HY2，优先选择 ECDSA P-256/P-384 或合适的 RSA。通用证书资源、服务端与备份不把客户端限制混进结构校验：旧 Ed25519 证书仍保留。sing-box 的默认 Chrome QUIC 指纹不支持 Ed25519，因此完整客户端配置和节点集合遇到该组合会明确拒绝，`allow_lossy` 也不能绕过；用户已经明确选择 `disable_chrome_parrot: true` 时保留该选择，不自动关闭指纹。Mihomo 没有此 Chrome 路径，能力单独校验。URI 无法表达这种高级选择，继续沿用有损提示并推荐完整配置。正常 X.509 证书可解析，不等于每个客户端均可连接。

解除引用需给运行节点换上另一张证书，不能让 HY2 变成无 TLS：

```bash
qingnode certificate unbind --id 旧证书ID --node 节点ID --replace 新证书ID --preview
qingnode certificate unbind --id 旧证书ID --node 节点ID --replace 新证书ID --yes
qingnode certificate remove --id 旧证书ID --yes
```

仍有节点引用时删除会失败。删除资源不会删除用户自己的文件。资源移除与旧配置代清理分开，历史仍包含恢复所需的旧材料。

## 用户文件引用

`mode: "file"` 使用 `certificate_path`、`key_path` 的规范绝对路径，不填 PEM 或 ACME 字段。所有路径组件不接受符号链接，文件大小有上限；服务账户必须能读文件并遍历目录。私钥不能给其他用户开放读取。systemd 的 ProtectHome/PrivateTmp 等隔离也参与检查：root 能读不代表代理服务能读。项目不移动、删除或改权限来接管原文件。

外部文件属于用户，配置备份只保存引用。完整迁移默认拒绝漏掉它们；显式 `--allow-incomplete` 才能生成列明缺项的受限包。目标机需先准备同样的文件或显式更新引用。运行中由外部工具替换文件对的一致性和无中断更新另验，不能以源码存在文件监视机制宣称通用热重载。本项目受管 PEM 更新仍走候选配置生效，运行配置变化可能重启共享核心。

## ACME 与三种挑战

ACME 是核心向 CA 申请并续期证书的机制，本项目只保存设置、观察证据，不另建签发/续期循环。新资源例：

```json
{
  "version": 1,
  "resource": {
    "id": "aabbccddeeff0022",
    "name": "DNS 验证证书",
    "certificate": {
      "mode": "acme",
      "server_name": "node.example.com",
      "email": "owner@example.com",
      "acme": {
        "challenge": "dns-01",
        "key_type": "p256",
        "dns01": {
          "provider": "cloudflare",
          "api_token": "仅在私有输入文件中填写",
          "propagation_timeout": "3m"
        }
      }
    }
  }
}
```

| 挑战 | 本地设置 | 必须由用户满足的外部条件 |
| --- | --- | --- |
| `http-01` | 默认 TCP 80，可显式 `alternative_http_port` | CA 仍从公网 **80** 访问该域名；高端口需有正确的外部转发，不会改变 CA 规则 |
| `dns-01` | `dns01` 中配置受支持的 DNS 服务商，不占入站 80/443 | Token 最小权限、真实域名控制权及 TXT 传播；委派须事先建立 |
| `tls-alpn-01` | 默认 TCP 443，可显式 `alternative_tls_port` | CA 从公网 **443** 到达该核心；不得被普通 HTTPS 反代吞掉挑战 ALPN；本机冲突与服务权限也要通过 |

本地端口预检只能证明候选绑定条件，不证明公网转发或 CA 可达。不要占用别人的 80/443。`provider` 留空使用核心默认，也接受 `letsencrypt`、`zerossl` 或明确的 HTTPS ACME directory；不要将 CA 账户、EAB 或其它工具插件字段任意注入。

DNS-01 只适配固定核心确实支持的下表字段。共有字段为 `ttl`、`propagation_delay`、`propagation_timeout`（时长字符串）、`resolvers`（最多 4 个 IP:53）及 `override_domain`。委派可填写 `_acme-challenge.delegated.example.com`。不允许以 `-1` 关闭传播检查；延迟必须小于总超时。未填值沿用核心默认。

| `dns01.provider` | 必需字段 | 可选凭据 |
| --- | --- | --- |
| `alidns` | `access_key_id`、`access_key_secret`、`region_id` | `security_token` |
| `cloudflare` | `api_token` | `zone_token` |
| `acmedns` | `username`、`password`、`subdomain`、HTTPS `server_url` | 无 |

三个提供者的字段不能混用。ACME-DNS 需要已注册的专用账户，不是通用 DNS 插件。新资源的存储为 State 根下 `acme/resources/证书ID`，仍在现有服务的受管可写目录内；从旧节点迁移的 ACME 保留原 `acme` 目录及原默认挑战行为，不偷偷重签或搬空账户。

## 状态与证据

`certificate list/status` 是只读查询，不修复事务、不启动核心、不申请证书、不修改 State。输出不含 PEM 私钥或 DNS 凭据。ACME 只观察该资源当前 CA/domain 的固定存储路径，不能把其它资源或旧 CA 下同 SAN 的缓存当成当前可用。证书可用需实际观察到匹配的证书与私钥、元数据、正确 SAN 和有效期；只有配置时报告“已配置”，无文件或证据不足时不能报告“已签发”。临近过期以剩余有效期判断，错误会给出下一步。

配置 `check` 成功只证明配置被接受。证书 NotBefore 是证书有效期起点，不能当作本机最近签发时间。核心可能正常轮换证书私钥；代理认证和 ACME 账户是否保持需分别核对。固定核心的自然续期检查间隔约十分钟，受控测试的“到期后重新启动续期”不能冒充同一 PID 的后台自然续期验收。最近签发/失败与“签发中”只在可对应到该资源的真实运行记录存在时报告，缺少记录时保留未知。

来源：sing-box [v1.14.3 新 ACME provider](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/certificate-provider/acme.md)、[DNS-01](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/dns01_challenge.md)、[HY2 客户端限制](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/outbound/hysteria2.md)。许可及固定依赖见 [THIRD_PARTY.md](../THIRD_PARTY.md)。
