# 分路径网络测试与结果解释

第 02 批增加有限时间、有限流量的主动测试。测试只写明确指定的报告或客户端测试资料，不修改 State、节点凭据、核心默认值、systemd 服务、防火墙、BBR 或全局路由，也不恢复未完成配置事务。第 01 批维护改进继续沿用；本批代码与执行证据见 [BATCH_02.md](BATCH_02.md)。

独立 `qingprobe` 第 02 批压缩包携带本文件、BATCH_02、许可和摘要；第 03 批另附 NETWORK_PERFORMANCE/BATCH_03。文中引用的架构/能力矩阵/源码来源文件属于源码树，须从配套源码查看，不表示桌面包附带服务器安装器或管理命令。

## 先确定测试从哪里发起

| 路径 | 实际发起点 / 数据路径 | 能说明什么 |
| --- | --- | --- |
| `local` | 当前机器，只读本机信息，不连接网络目标 | 本机可取得的资源和平台信息；不能说明代理或公网可达 |
| `server-outbound` | 运行命令的服务器 → 明确指定的 HTTPS/UDP 目标 | 这台服务器的出站能力；不能推断用户所在运营商到节点的质量 |
| `client-proxy` | 运行命令的桌面或 Linux 主机 → 隔离官方 sing-box 客户端 → 所选节点 → 指定目标 | 发起端经所选代理的真实 TCP/UDP 路径；在 VPS 上执行时，发起端仍是 VPS |
| `controlled-link` | 两台明确受控的机器之间，按命令声明的直连路径 | 两测试点之间的链路；没有路径证据时不能标成“经代理” |

`initiator` 是用户填写的测试点说明，例如“家中 Windows 有线网络”或“东京 VPS”；它不是自动核验的地理位置或运营商。报告同时保留实际路径、平台/工具版本、节点 ID、地址族与配置摘要。节点 ID 用来定位测试对象，不改变节点身份。

`server-outbound` / `controlled-link` 不使用环境 HTTP 代理，使用发起机器已有的系统路由；程序不会鉴定或绕过机器上已存在的 VPN、隧道或透明转发。需要确认物理路径时仍用受控目标日志、网络命名空间或路由证据，不能把“没有设置 HTTP 代理”当成每段线路直连证明。

`reality-targets` 仍测 VPS 到 REALITY 握手目标，`diagnose` 仍是服务器侧诊断。原 `public-check` 仍是管理员手动登记；新报告标为自动测量，不自动写成旧历史中的公网通过，也不修改首页登记。

## 命令与硬上限

Linux 管理器入口为 `qingnode probe`，独立测试助手直接执行 `qingprobe`。两者复用同一参数和输出；`profile --id` 只有管理器能从原 State 导出，桌面助手只读取已有 `--profile` 文件。

```bash
# 本机资源信息，不联网；--out省略时只显示文本。
qingnode probe local --out local.json
# 从这台服务器直连明确目标，不能叫客户端经代理测速。
qingnode probe run --path server-outbound --target https://probe.example.org/object --initiator '东京VPS' --timeout 20s --samples 8 --out server.json
# 在管理器所在机器经选定节点；发起端仍是该机器。
sudo qingnode probe run --path client-proxy --id 节点ID --user 用户ID --target https://probe.example.org/object --mode light --initiator '东京VPS经自有节点' --out proxy-on-vps.json
```

示例域名、节点 ID 和用户 ID 必须换成自己的实际值；目标需允许 HEAD，下载模式还需允许 GET。HTTP 200–399 记录为成功状态，重定向不自动追随；非成功状态保留错误。用户已停止生产服务时，测试不启动它，代理连不上就失败。`--offline` 拒绝 run/udp-echo，不把它当作联网授权；资料导出遇到未完成事务时拒绝，先按需要显式 `recover`。

| 参数 | 默认 / 硬范围 |
| --- | --- |
| `--mode` | `light` 有限 HEAD；`download` 明确选择后才 GET |
| `--timeout` | 默认 20 秒，1 毫秒至 120 秒；包括隔离客户端核验、启动与测量 |
| `--bytes` | light 默认/最多 65,536；download 默认 8,388,608，最多 67,108,864 有效载荷字节；UDP 收发共用本次预算 |
| `--samples` | 默认 8，每组 1–64；不是预先保证能全部完成 |
| `--concurrency` | 默认 1，download 请求 worker 最多 4；HTTP transport 同时最多 4 个连接，负载 HEAD 最多 1 个请求且满额时等空槽；light 只能 1 |
| `--family` | `auto` / `ipv4` / `ipv6`；代理固定族要求目标为字面 IP，域名目标只能 auto；UDP 目标同样按地址族限制 |
| `--udp-timeout` | 默认 1 秒，每样本 1 毫秒至 5 秒，仍受总超时/字节上限约束 |
| `--ca` / `--proxy-ca` | 分别添加受控 HTTPS 目标 CA / TLS 节点 CA；不关闭验证，不加入系统证书库 |
| `--out` | 显式选择新的 JSON 文件；已有文件拒绝，管理器结果/资料必须保存在管理 State 根目录之外 |

`address_family` 记录请求的目标地址族约束，auto 不保证代理内外每段采用同一地址族，无法观察的段不猜测。`server_core_version` 来自测试资料/State 的服务器配置版本声明，不等于已核验远程运行二进制；`client_core_version` 是本次实际核验并启动的本机核心版本。客户端二进制校验绝对路径、SHA-256、1.14.x 正式兼容线、所选协议所需 `with_utls`/`with_quic` 标签，并先运行官方 `check`；资料声明与客户端验证分开。

## 隔离客户端与路径证明

代理测试使用临时目录、临时本机监听端口及独立官方 sing-box 进程。测试配置只含所选节点出站，默认路由固定指向它，不含 direct（绕过节点直接连接目标）出站、自动选择组或失败直连回落。HTTPS 通过明确的本机 HTTP CONNECT 连接 mixed 入站；UDP 使用同一入站的 SOCKS5 UDP ASSOCIATE，不依赖 `HTTP_PROXY` 环境变量推断路径。测试不打开 TUN（接管 IP 流量的虚拟网络接口），不设置系统代理或路由。

HTTP CONNECT / SOCKS5 是测试程序和临时核心之间的本机接口：核心负责 VLESS REALITY、SS2022 或 Hysteria2 的真正节点传输。凭据错误或所选代理不可用时测试失败；本机 mixed 监听出现只证明入口已启动，实际 HTTPS/UDP 成功才证明相应数据路径可用。

本机 mixed 入口每次使用新随机认证，避免其他本机进程无意占用测试路径；这组临时认证不是节点密码，也不保存到 State。随机认证不能证明监听属于哪个进程，因此另核对本次核心 PID：Linux 比较 `/proc/net/tcp` 的监听 inode 与该 PID 的 fd，Windows 用 `GetExtendedTcpTable` 的 OWNER_PID 表检查本机监听。归属无法核验就拒绝进入测量，不把抢到临时端口的无关服务当成核心就绪。

公网验收可用自己控制的目标访问日志核对时间、请求和代理服务器出口地址，并记录所选节点。再停止或屏蔽测试所选代理的受控测试副本，保持目标可用，重跑必须失败。生产节点不应为这一步被停用；使用隔离副本或经过授权的测试节点。隔离回环验收用目标请求计数、核心日志和坏凭据/不可达代理负例证明相同约束。

导出的测试资料含该用户的客户端认证材料，用来在另一台机器启动隔离核心，必须按密钥保护。它不包含 REALITY 服务端私钥，也不是可公开分享的报告。Unix 上文件权限为 0600；Windows 新文件/临时目录实际设置只允许当前用户与 SYSTEM 的访问控制，不只依靠无效的 Unix 权限位。安全传输后删除不再需要的副本。JSON 结果不含完整凭据、配置正文或分享链接；目标只显示 HTTPS 源地址（协议、主机、端口），URL 路径与查询串不进入报告。`target_sha256` 保存完整测试 URL 的摘要，避免不同隐藏路径或查询串被当成同一目标。不要把密钥放在测试点名称或工具版本字段中。

正常结束、取消、超时和核心异常退出会停止并等待本次自有进程，关闭监听并删除本次临时目录。强制结束整个操作系统进程、断电或文件系统失败不能执行退出清理；若出现残留，仅核对并处理自己的测试 PID/临时目录，不使用 `killall sing-box`，也不清理生产配置。

## 报告里的时间和流量怎么读

报告 JSON 使用独立的 `version: 1`，不提高 State schema。未知或不能分开的数值为 `null`/`unknown`，不记为 0。取消和未完成项保留失败/取消状态，不计通过。原始 HTTP 和 UDP 样本保留序号、成功/失败、耗时及错误类别，摘要给有效样本数、中位数、p95 与成功率。p95 按本次有效样本排序后取 95% 位置的已观察值，样本少时接近最大值；少样本仅描述这次观察，没有统计置信保证。

| 指标 | 本次具体含义 / 限制 |
| --- | --- |
| HTTPS 状态 / 首字节 | 正常校验证书的 HTTPS 响应与从请求开始到响应首字节的总时间，含所选路径的建立和服务器处理 |
| 空闲请求时间 | 下载开始前的小 HTTPS 请求总时间，是应用层请求响应时间；不冒充 ICMP RTT 或纯网络延迟 |
| 下载期间请求时间 | 下载活跃时的小 HTTPS 请求总时间。请求开始和结束均有活跃下载才计 `load`；只覆盖部分下载的 `load_partial_overlap` 样本原样保留，排除 `load_request` 摘要 |
| 连接 / TLS 阶段 | 能准确观察的阶段单列；临时 SOCKS 本机连接不等于代理外层握手，代理握手不能拆分时明确未知 |
| DNS | 直连路径可记录本机解析；代理目标域名交给所选路径，无法独立计时时明确未知。节点 server 域名的本机 bootstrap 解析与目标 DNS 分开解释 |
| 下载吞吐 | 该连接实际收到的响应有效载荷除以计时区间，记录实际字节，以 Mbps（每秒百万比特）显示；单连接与并发结果不能混比 |
| UDP RTT / 丢包 | RTT 是发出请求到收到匹配回应的来回时间；受控端点按发送序号和超时统计。无响应只证明这次未收到，不能单凭它断言防火墙的具体原因 |
| UDP 抖动 | 本项目 `jitter_ms` 是相邻成功序号 RTT 的绝对差的平均值；不是 IRTT IPDV，也不是单向抖动。没有相邻有效样本时未知 |
| CPU / RSS / UDP 错误计数 | RSS 是进程驻留在内存中的字节数。平台和权限可取得时记录；Linux 全机 UDP 计数不是某个代理连接的丢包率，进程 CPU 时间不是全机 CPU 使用率 |
| 流量消耗 | 记录程序实际收发的 HTTP/UDP 有效载荷；TLS、QUIC、TCP 重传、SOCKS、DNS 等线路开销未知，`wire_bytes` 不推算 |

只有 UDP DNS 成功时，可以说“该 DNS UDP 请求可用”，不能说已完成有序列的丢包、抖动或大包测试。本批自己的 UDP 端点只回应识别到的版本化测试帧，携带随机本次标识和序号；无关、重复、旧序号或内容错误的数据不会计成功。

`lost` 只计已经等待完整单次超时的未回应序号；取消、总超时或预算结束导致的已发未决请求计 `unfinished`，相应 `loss_percent` 为 null，不把停止测量当作网络丢包。`received`、`lost`、`unfinished` 与实际 `sent` 保留原始口径，未发送的计划样本不计丢包。

直连路径可分别记录可观察的 DNS、连接、TLS、HTTP 状态、地址族不可用、UDP 未回应、总超时与取消。代理 HTTP 连接只能观察整条代理路径结果：错误凭据和某些代理目标不可达都会归入 `proxy_transport_or_auth_unknown`，当前不能自动把认证、代理内目标 DNS、连接或外层握手精确拆开。隔离核心启动/校验失败另记 `client_setup_failed`；UDP 另外保留自己各序号的未回应/取消/预算结果，不从 TCP 成功推断 UDP 成功。

受控负例可以固定正确目标，仅改变节点认证，证明坏凭据必失败且不会 direct 回落；这证明所选代理的认证/路由边界，不能写成生产报告能独立诊断所有认证根因。本批实测是否执行通过以 BATCH_02 为准。没有可靠远程核心错误接口时保留未知，比根据 TCP 关闭猜“密码错误”更可审查。

## 预算与对比

轻量探测与下载分开选择。轻量默认不会长时间下载；下载需要明确选择模式和目标。每次有独立总超时、有效载荷字节上限、样本与并发上限；没有默认公共测速站。不要为了获得更大的“速度”反复向公共站点刷流量。

并发设为 4 时，HTTP 的四个槽可能全部用于下载，负载 HEAD 会等空槽。下载太快或请求未完整覆盖活跃下载时，报告可以没有有效 `load_request`；这表示未取得完整负载期间样本，不补成 0，也不以排队后空闲请求冒充负载时间。

对比要求两份有效报告的发起端、路径、模式、目标、地址族、节点/配置摘要、核心/客户端/工具版本和预算相近。改变目标、节点、网络、地址族或并发意味着不同条件，程序拒绝把它们算成同一条件的性能升降。相同条件也不能自动控制目标负载、运营商拥塞或无线信号，因此对比是观测差异，不是因果证明。缺失数值不参与差值，失败结果与取消结果不能比较为通过。

当前实现要求这些条件完全一致，并且开始时间相差不超过 24 小时；两报告均 `completed`，原始样本和摘要自洽才可比较。输出差值 `after - before` 与有效样本数；没有共同有效指标时拒绝。仅有本机 local 指标的报告没有共同网络指标，也不产生网络速度对比。

```bash
qingprobe compare --before first.json --after second.json
# Linux管理器等价入口：qingnode probe compare --before first.json --after second.json
```

报告顶层 `source` 固定 `qingnode-automatic-probe`，`started_at`/`finished_at` 是带时区的时间；`conditions` 保存路径、目标源地址/摘要、发起端、节点/配置摘要、版本和 limits；`samples` 保存每次原始 HTTP 观察，`statistics` 是从这些样本重算的摘要；`udp` 保存序号与请求回应统计；`metrics_before`/`metrics_after` 是可得的本机资源；`traffic` 明确有效载荷与未知线路开销；`errors`/`limitations` 保存失败与解释边界。消费者应检查版本，拒绝未知字段、重复键或不自洽摘要，不将手动登记文件改名为自动报告。

## 桌面与另一台 Linux 主机

在实际需要测的网络上运行 `qingprobe`，不要只在服务器上运行后把结果称为客户端网络。它是独立的命令行测试助手，不访问 VPS 的 State，不需要安装 systemd 服务；使用本批构建的 Linux/Windows 二进制和同兼容线的官方 sing-box。先核对官方归档摘要、核心版本与协议所需构建标签，不能只看文件名。

先从服务器按稳定节点 ID 和用户 ID 导出私有测试资料，再安全传到测试端。测试资料中的节点地址必须是测试端实际可达的地址；本机 `127.0.0.1` 资料不适合作为远程目标。指定自己控制或明确允许测试的 HTTPS 端点，从轻量模式开始，再执行受限下载，按需要给出受控 UDP 端点。输出文件必须显式选择；已有文件不自动覆盖。

```bash
# 在服务器导出，目录自行选择，保持私有权限；不轮换凭据。
mkdir -m 700 qingnode-test
sudo qingnode probe profile --id 节点ID --user 用户ID --out "$PWD/qingnode-test/client-profile.json"
```

在 Linux 测试端先从可信官方归档核对摘要并解出 sing-box，随后对已核验的本机二进制计算摘要。`--core-sha256` 是二进制摘要，不是压缩包摘要；不能用它替代官方下载校验：

```bash
core_sum=$(sha256sum /绝对路径/sing-box | cut -d ' ' -f 1)
./qingprobe run --path client-proxy --profile ./client-profile.json --core /绝对路径/sing-box --core-sha256 "$core_sum" --target https://probe.example.org/object --mode light --samples 8 --timeout 20s --initiator '家中Linux有线网络' --out first.json
./qingprobe run --path client-proxy --profile ./client-profile.json --core /绝对路径/sing-box --core-sha256 "$core_sum" --target https://probe.example.org/object --mode download --bytes 4194304 --samples 8 --concurrency 1 --timeout 30s --initiator '家中Linux有线网络' --out download.json
```

Windows PowerShell 等价用法，官方核心/资料路径换成自己的已核验文件：

```powershell
$probeCorePath = (Resolve-Path .\sing-box.exe).Path
$probeCoreSHA = (Get-FileHash -LiteralPath $probeCorePath -Algorithm SHA256).Hash.ToLowerInvariant()
.\qingprobe.exe run --path client-proxy --profile .\client-profile.json --core $probeCorePath --core-sha256 $probeCoreSHA --target https://probe.example.org/object --mode light --samples 8 --timeout 20s --initiator '家中Windows有线网络' --out first.json
```

私有资料 JSON 版本为 1，含 `node_id`、`server_core_version`、`config_sha256` 与单个 `outbound`。只接受本项目三协议白名单，不接受任意 sing-box 配置、direct、选择组、脚本、私钥字段或不匹配的摘要。需要私有测试 CA 时单独给 `--ca`/`--proxy-ca`，不要手改未知字段或使用 insecure 绕过验证。

资料保存的是导出当时所选节点/用户的参数。服务器后来改端口、地址、凭据或证书时，旧文件不会自动更新；重新导出到新文件后再测，并保留报告里的配置摘要来区分。改名不更换稳定节点 ID，测速也不会为解决失败自行轮换凭据。

Windows 在 PowerShell 中执行 `qingprobe.exe`，Linux 执行 `./qingprobe`。两者都用独立官方 sing-box 核心；Windows 的实际运行、Linux 实际运行和跨平台构建是不同证据，见本批记录。`qingnode` 的 Linux 服务器管理、安装与服务命令不会因此成为 Windows/Android 原生服务管理能力。

另一台受控机器可直接运行本工具的有限 UDP 回应端点；将示例 IP 换成它明确的测试接口，命令到期停止，只使用管理员已允许的受控测试网络，不自动更改防火墙：

```bash
./qingprobe udp-echo --listen 192.0.2.20:2112 --duration 30s
# 在发起端给原run命令追加：--udp 192.0.2.20:2112 --udp-timeout 1s
# 明确直连的两机器测试使用：run --path controlled-link --target HTTPS目标 ... --udp 192.0.2.20:2112
```

该端点最多运行 120 秒、处理 1,024 个请求、收发共 1 MiB 有效载荷，不常驻后台，不兼容普通 DNS/IRTT/iperf3 数据包。`controlled-link` 当前只声明本工具明确直连；要证明经代理，应使用 `client-proxy`，不能只改路径标签。

## 手机客户端检查

本批没有原生 Android/iOS 测速程序。手机使用支持对应协议的现有客户端导入原导出资料，在真实移动/Wi-Fi 网络中手动选中节点，并用全局代理/TUN 或该客户端可核验的路由方式访问受控 HTTPS 目标。记录客户端名称、版本、核心、手机网络、地址族、节点、时间、目标状态和出口日志；更换节点后同步验证。

手机页面的下载计时可作有限应用层观察，但无法确认是否走代理时不得登记代理成功。UDP 需客户端实际支持 UDP 并有受控请求响应工具或 IRTT/TUN 流程；仅打开网页或完成 DNS 查询不证明其他 UDP 通过。缺少可运行工具时登记 UDP `untested`，可继续用原 `public-check` 手动登记，来源明确写手机客户端与网络。GUI 导入、后台保活、省电策略和公网双栈仍需实际手机验收。

## 可选两台受控机器：iperf3 / IRTT

这两个工具不是本批必装依赖，也不会自动安装或启动。先在两端取得可信固定版本、核对摘要，并保存 `--version`/帮助输出与端点日志。以下用法核到 [iperf3 `3.22`](https://github.com/esnet/iperf/blob/3.22/src/iperf3.1) 和 [IRTT `v0.9.1`](https://github.com/heistp/irtt/blob/v0.9.1/irtt_client.go)。旧版本缺少参数时先按其固定版本帮助调整，不能把 3.22 的参数兼容当成任意 3.x 已验证。

iperf3 原生不读取分享链接，不使用 HTTP/SOCKS 代理环境变量。明确直连时将服务器绑定受控地址；经代理时，由管理员在专用测试网络命名空间/TUN 或固定转发建立实际路径，并用目标日志/路由和代理禁用负例验证。TUN 配置由所用客户端负责，本批不改全局默认路由。iperf3 UDP 同时需要 TCP 控制连接与 UDP 数据通道，两个方向都要验证。

Linux 受控服务端运行一次性服务，外层 20 秒结束它；仅允许测试端的现有防火墙策略由管理员事先安排：

```bash
iperf3 --version
timeout --signal=TERM --kill-after=2s 20s iperf3 -s -1 -B 192.0.2.20 -p 5201 -J > server.json
```

`192.0.2.20` 是文档示例，必须替换成实际受控地址。每次服务结束后重新开启，客户端独立外层 15 秒。`-P 1` 保持单连接；下行反向使用 `-R`；时间与字节参数不混用：

```bash
# 有限时间与显式低速率：3.22 的 -t / -n / -k 互斥。
timeout --signal=TERM --kill-after=2s 15s iperf3 -c 192.0.2.20 -p 5201 -P 1 -t 5 -b 8M -R -J --connect-timeout 2000 > tcp-time.json
# 有限有效载荷；外层总超时保证慢链路不会无限等待。
timeout --signal=TERM --kill-after=2s 15s iperf3 -c 192.0.2.20 -p 5201 -P 1 -n 4194304 -R -J --connect-timeout 2000 > tcp-bytes.json
# UDP 小流量；仍会先连接 TCP 控制端口。
timeout --signal=TERM --kill-after=2s 15s iperf3 -c 192.0.2.20 -p 5201 -u -P 1 -t 5 -b 128K -l 256 -J --connect-timeout 2000 > udp.json
```

字节上限是工具数据载荷，不是线路字节；`-b` 是目标发送速率而非已测吞吐保证，`-P` 增加时按每流生效。`-J` 通常完成后才产生完整结果，取消/总超时可能只留下失败或不完整文件，不能计成功。保存两端 sender/receiver 方向，不把反向结果写成上行。

IRTT 只对自己的 UDP 端点。服务端与客户端都有时长、间隔、包长和独立外层总超时；不使用 README 的公共服务器：

```bash
irtt version
timeout --signal=TERM --kill-after=2s 20s irtt server -b 192.0.2.20:2112 -d 5s -i 200ms -l 128 --timeout=5s
timeout --signal=TERM --kill-after=2s 15s irtt client -d 5s -i 200ms -l 128 --timeouts=1s,1s --wait=1s -o irtt.json 192.0.2.20:2112
```

这些是专用受控地址的测试，IRTT 输出独立保留，不冒充本项目版本化自动报告。记录收发样本、RTT、丢包和 IPDV，单向延迟只有两端时钟同步误差已独立核验时才可解释；未同步时标未知。至少两个返回包才可能给相邻差异，小样本不保证精确 p95 或丢包率。IRTT 与本项目 `jitter_ms` 定义不同，不直接比较。

版本与许可证及未复制源码的边界见 [THIRD_PARTY.md](../THIRD_PARTY.md)。可选工具流程本批是否实际执行，以及公网/受控机器是否可用，以 [BATCH_02.md](BATCH_02.md) 为准。
