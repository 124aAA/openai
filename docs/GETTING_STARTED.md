# 从安装到客户端验收

本文对应0.3.0整合源码。先核对正式Release、RELEASE.json的完整提交与SHA256，再使用匹配架构的包内安装器；默认在线入口只选择已经公开的正式发行。当前能力与各层实测见[支持矩阵](CAPABILITIES.md)，整合验收来源见[验证报告](TEST_REPORT.md)，第11批历史见[BATCH11.md](BATCH11.md)。

示例中的文档地址`203.0.113.10`、域名`node.example.net`、大写ID和文件路径都要换成自己的实际值。导出文件、测试Profile、令牌和备份口令含秘密，不要贴到聊天、公共仓库或第三方转换站。

## 1. 先确认条件，再选协议

| 已知条件 | 可先考虑的路径 | 仍须核对 |
| --- | --- | --- |
| 没有自己的域名，客户端支持VLESS REALITY/Vision | REALITY | VPS能访问适用握手目标、入口TCP可达；握手目标与客户端连接地址独立 |
| 客户端明确支持SS2022多用户格式，不想管理TLS证书 | SS2022 | 使用`2022-blake3-aes-256-gcm`及本项目导出密码，TCP/UDP分别验证 |
| 客户端只支持传统现代SS AEAD | `ss-aead` | 只选已支持的现代AEAD方法，不把SS2022复合密码移过来 |
| 有匹配域名的可信证书，但入口UDP不通 | Trojan或AnyTLS | 两端协议及完整配置支持；AnyTLS连接池参数会增加资源成本 |
| 有可信证书、UDP入口可达，客户端支持对应QUIC协议 | Hysteria2或TUIC | 证书名称、UDP映射和实际路径；TUIC默认关闭0-RTT，不套用HY2带宽字段 |
| NAT或只有IPv6 | 先声明内外端点，再选满足条件的协议 | 服务商TCP/UDP分别映射、客户端地址族、域名A/AAAA；出口IP不是入站证明 |

没有“服务器测几次就选出你手机最快协议”的功能。先以客户端、证书、网络和资源条件筛选，再从实际客户端网络按同条件测量；缺少样本保留未知。七协议细节见[协议说明](PROTOCOLS.md)。

## 2. 安装一个最小节点

在自己的服务器SSH终端操作。当前保持Bash引导、静态Go管理器、独立官方sing-box和本机服务托管；不安装面板、Docker或数据库。Ubuntu24.04.5、Rocky9.8、Alpine3.24.2的amd64 VM证据见[平台矩阵](PLATFORMS.md)，其他版本和原生ARM不因可编译而算验收。

先下载本轮交付包和按架构匹配的官方核心归档，核对交付清单与官方摘要。下面使用已下载并核验的完整0.3.0包，不直接执行main源码：

```bash
mkdir -m 700 ./qingnode-package
tar -xzf ./qingnode-0.3.0-linux-amd64.tar.gz -C ./qingnode-package
sudo bash ./qingnode-package/install.sh --protocol ss2022 --name main \
  --server 203.0.113.10 --listen 0.0.0.0 --port 443 \
  --core-archive /root/sing-box-1.14.0-linux-amd64.tar.gz
sudo qingnode capabilities --skip-loopback --json
sudo qingnode status
sudo qingnode info --id main
```

SS2022只是本例，不是速度排名。若客户端不支持它，先按上表选择；0.3.0安装器和管理器均提供七协议入口，旧v0.2.8安装器只有原三协议。显示入口不等于满足该协议的证书、核心和网络条件。

系统状态为运行只表示本机进程状态。下一步要核对云安全组、客户端连接地址和实际导入；QingNode不修改SSH，也不会替你改变云厂商NAT。缺TUN不阻挡不需要TUN的普通节点。

交互运行`sudo qingnode`进入任务菜单。创建向导支持`:cancel`，列表中`0`返回，EOF安全结束；提交前取消不会留下半个节点。若外层安装已完成下载、依赖或目录准备，取消节点表单不会反向撤销这些准备。自动化使用CLI完整参数，不把输入菜单编号当成脚本接口。

## 3. NAT、IPv6和TLS名称分别填写

已安装管理器上新增一个声明外部30000到本地443的TCP节点示例：

```bash
sudo qingnode add --protocol reality --name nat-main \
  --server 203.0.113.10 --connect-port 30000 \
  --listen 0.0.0.0 --port 443 --sni TARGET_NAME --target TARGET_NAME:443
sudo qingnode info --id nat-main
sudo qingnode endpoint material --id nat-main --out /root/nat-validation.json
```

此例要求443当前空闲；不要在第2步的现有443节点上原样重复创建。服务商仍须把公网30000/TCP映射到本机443/TCP。HY2/TUIC使用独立的UDP映射声明；TCP映射通过不能代替UDP。`--server`是客户端地址，`--listen/--port`是本机绑定，证书SNI或REALITY目标不会被公网地址自动替换。详细材料见[端点与双栈](ENDPOINTS.md)。

IPv6字面地址写为`--server 2001:db8::10`，不要自行给Host加方括号；导出器处理URI中的方括号。监听`::`是否同时接IPv4取决于宿主实际绑定语义，不能凭文字保证双栈。纯IPv4可用但IPv6缺失应报告该项未验，不应关闭全机IPv6或把节点整体判失败。

## 4. 导出给明确的客户端和凭据

先从`info`取实际节点/用户ID。普通信息默认不显示完整认证；下面的显式导出会写含凭据的新文件，已存在的文件拒绝覆盖。

```bash
sudo qingnode info --id main
sudo qingnode export --id NODE_ID --user USER_ID --format sing-box \
  --client-version 1.14.0 --out /root/main-client.json
sudo qingnode export --id NODE_ID --user USER_ID --format mihomo \
  --client-version 1.19.30 --out /root/main-client.yaml
```

将文件安全传到设备，在客户端选择“本地完整配置导入”。`provider`只有节点集合，不是能单独运行的完整配置；URI/二维码不能表达所有高级设置，TUIC不伪造通用分享URI。二维码在窄SSH终端可能被客户端字体或自动换行影响，优先使用私有文件，不截断后声称链接仍完整。

手机应用显示“导入成功”之后，还要测试真实TCP与所需UDP。sing-box配置检查、Mihomo解析、受控真实连接和手机GUI是四种不同证据；本项目没有把服务器CLI包装成原生Android测速程序。

设备有多节点需求时，明确绑定每个节点与凭据，不私选第一个用户：

```bash
sudo qingnode device create --name phone --binding NODE_ID:USER_ID --preview
sudo qingnode device create --name phone --binding NODE_ID:USER_ID
sudo qingnode device list
sudo qingnode export --device DEVICE_ID --format sing-box \
  --client-version 1.14.0 --out /root/phone.json
```

在线订阅是可选项。已有可信HTTPS反向代理时，按[订阅指南](SUBSCRIPTIONS.md)准备独立账户、快照和服务，再运行`qingnode subscription check --base-url https://SUBSCRIPTION_HOST`（替换为自己的HTTPS地址）；没有HTTPS就先本地导出。撤销下载令牌不会作废已下载的代理凭据，停用设备须明确处理独立绑定，不能连带撤销共享凭据。

## 5. 从实际客户端网络排查延迟

先做服务器只读检查，再到用户真正上网的位置测代理。目标要使用自己控制或明确允许测试的HTTPS端点，没有默认公共测速站。

```bash
sudo qingnode doctor
sudo qingnode probe local --out /root/local-diagnostic.json
sudo qingnode probe run --path server-outbound --target https://TEST_HOST/status \
  --samples 8 --timeout 20s --out /root/server-egress.json
sudo qingnode probe profile --id NODE_ID --user USER_ID --out /root/private-test-profile.json
```

最后一个文件含认证，只传给自己的测试机器并在用后处理。独立工具在桌面或另一台Linux上运行；先核实其官方核心和二进制摘要：

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

失败不回落direct。报告区分空闲和下载期间RTT、端到端耗时、单连接有效载荷吞吐及可得资源；没有可靠拆分的握手时间保持未知。UDP丢包/抖动必须再提供有序号和超时的受控回包端点，只有DNS成功不能算丢包率。比较保持测点、路径、目标、版本和预算一致，样本太少不下高置信结论；详见[网络测试](NETWORK_TESTS.md)。

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

普通改名不轮换凭据，是否重启依据真实派生运行配置和宿主效果；运行配置相同但文件损坏仍要处理，不能只按字段名跳过。端口/认证/核心变化可能重启共享服务并影响已有连接。链式出口、WireGuard配对、显式主备与无direct回落说明见[拓扑指南](TOPOLOGY.md)，跨主机步骤不是本机原子事务。

## 7. 保存、迁移和恢复

以下命令使用 v0.3.0。若尚在 v0.2.8，应先按[旧版升级步骤](MIGRATION.md#从-v028-升级到-v030)使用原程序配置备份及新包程序只读预览，不向旧程序传 `--full`。普通配置备份不暂停服务；完整迁移要先盘点资产和短停范围。口令至少12字节，用权限0600的口令文件或交互隐藏输入，不放进命令行。

```bash
sudo qingnode backup --file /root/config.qnbak --password-file /root/backup-pass.txt
sudo qingnode backup --full --preview
sudo qingnode restore --file /root/config.qnbak --password-file /root/backup-pass.txt --preview
```

QNBK3完整迁移需资产覆盖和一致性停止证明，明确允许短停时才用`--full --quiesce`；外部引用、独立monitor资料或附属部署缺项时不能标完整，`--allow-incomplete`表示接受列出的受限范围。来源unit只是证据，目标机按实际init和账户重新生成，不执行备份内命令；完整流程见[迁移与恢复](MIGRATION.md)。

发现中断事务先保留材料、看状态和日志，再决定是否显式`qingnode recover`；中断的完整迁移使用`qingnode restore --recover-migration --yes`。已完成变更的上一代回退用`qingnode rollback`；以备份替换配置需指定实际文件与口令，例如`qingnode restore --file /root/config.qnbak --password-file /root/backup-pass.txt --yes`。这些操作不等价，`rollback`没有预览参数，会直接应用。旧State只读内存迁移，不能改schema号骗旧管理器读取新格式。查询不会自动恢复、重启或改参数。

## 用自己的客户端完成最后一段验收

核对版本与端点 → 导出指定凭据 → 客户端完整导入 → 经过代理访问自己的HTTPS目标 → 单独验证需要的UDP → 保留脱敏报告与测试位置。普通桌面、手机SSH窄终端与手机代理GUI分别记录。没有对应设备、公网或原生架构时标未验证，不能用本机回环成功替代。
