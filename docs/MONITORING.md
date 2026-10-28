# 监控、核心流量观测与代理凭据到期

这些功能可按需启用，源码尚未发行，默认核心仍为1.14.0。监控默认只观察；保存计划、运行一次、安装定时任务、允许重启和执行到期停用分别是独立操作。第08批功能与当时执行结果见[BATCH08.md](BATCH08.md)，第10批systemd/OpenRC生命周期与准确平台证据见[BATCH10.md](BATCH10.md)；前批结果不能替代当前源码执行。

## 保存和运行有限监控

先用 `qingnode list`、`qingnode device list` 核对稳定ID。将下列JSON保存到自己创建的私有普通文件，例如 `/root/monitor.json`，权限设为600；替换节点和用户ID，HTTPS目标须使用自己允许探测的地址。不设置目标时只观察本机信号。

```json
{
  "version": 1,
  "enabled": true,
  "interval_seconds": 60,
  "timeout_ms": 10000,
  "concurrency": 1,
  "max_bytes": 4096,
  "history": {"records": 96, "bytes": 1048576, "events": 128},
  "jobs": [{
    "id": "personal-node",
    "node_id": "1111111111111111",
    "user_id": "2222222222222222",
    "enabled": true,
    "signals": ["process", "listener", "disk", "authentication", "tcp"],
    "target_url": "https://your-controlled-target.example/health"
  }],
  "recovery": {"mode": "observe"},
  "notifications": {"enabled": false}
}
```

```bash
qingnode monitor configure --file /root/monitor.json --preview
qingnode monitor configure --file /root/monitor.json --yes
qingnode monitor run
qingnode monitor run --cycles 3
qingnode monitor status
qingnode monitor history
qingnode monitor disable --preview
qingnode monitor disable --yes
```

`run`默认为一轮，最多100轮；轮次之间使用计划间隔，不补跑错过的轮次。任务最多32个，间隔15–86400秒，单轮时间预算最多120000毫秒、并发1–4、有效载荷预算最多65536字节。预算限制应用有效载荷，协议握手、TLS、包头和重传仍有开销，不能当运营商计费硬上限。周期检查不提供下载测速。主动 `probe run` 与周期检查共用互斥测试锁，冲突即退出，不排队叠加流量。

信号分别为进程、所属监听、认证、TCP、受控UDP、目标、证书、磁盘和可选 `core_api`。需UDP证据时明确配置自己的 `udp_address`，HTTP成功不能代替UDP成功。`healthy/degraded/failed/unknown/disabled`分别表示所选信号健康、部分异常、失败、未知和停用；缺测、取消、API未开启与平台不可读均不写成零或通过。指标来自受管服务PID，临时客户端进程指标不能冒充生产核心。服务器发起的检查始终不能证明用户运营商或公网入口可达。

节点和出口任务分开，出口任务仅观察。节点被显式停用、人工停止服务或存在待恢复事务时不自动启动、恢复事务或改用直连。状态/历史查询不运行探测、不修复State。

## 恢复、通知和定时器分别启用

只有私有配置明确保存 `recovery.mode: "restart"` 才允许有限重启。连续失败默认3次，冷却600秒、滚动窗口3600秒内最多2次；可配范围分别为2–100次、60–86400秒、60–604800秒、1–20次。执行前须有运行中的受管进程和至少两组独立本机故障证据；远端目标或TCP/UDP失败本身不授权重启。本机所属监听缺失和明确启用的核心API传输故障可形成独立证据，API鉴权错误或统计不可用仍为未知。

动作前重新核对策略、节点状态、当前派生配置、核心摘要及官方配置检查，并持久记录尝试；一轮最多一个共享服务动作。使用 `try-restart` 尊重并发人工stop，不回滚配置、不轮换身份、不修改参数。重启会断开共享核心的既有连接。动作后零载荷预算只核对本机状态，完整认证/TCP/UDP恢复仍待下一正常轮验证；“命令执行成功”不等于“链路已恢复”。

通知支持受控HTTPS webhook或Telegram，须在600权限文件的 `notifications` 对象中明确填写 `enabled`、`kind`、`endpoint`或`token/chat_id`；秘密不接命令行。发送只针对状态变化，有限超时/重试及去重；普通输出和历史不记录通知目标、原始响应或秘密。未配置时不发送通知。`monitor disable --yes`停止后续恢复与通知，正在运行的有限检查可结束。

```bash
mkdir -m 700 /root/qingnode-monitor-unit
qingnode monitor timer --manager systemd --out /root/qingnode-monitor-unit
# Alpine/OpenRC改用；二选一，生成目录保持私有并先审查内容。
qingnode monitor timer --manager openrc --out /root/qingnode-monitor-unit
```

这只生成材料，不安装或启用任务。systemd输出service/timer，timer约60秒、service每次只做一轮有限检查；审查后显式安装，停止调度用 `systemctl disable --now qingnode-monitor.timer`。OpenRC输出 `qingnode-monitor` 服务脚本，使用独立 `monitor watch` 按保存的计划间隔串行检查，不修改全局cron；审查后以0755安装到 `/etc/init.d/qingnode-monitor`，再显式设置runlevel和启动。停止当前watch用 `rc-service qingnode-monitor stop`，取消已设置的自启项须按实际runlevel移除。两种平台随后均可用 `qingnode monitor disable --yes` 停用计划；只停计划不等于卸下调度。默认生成命令没有 `--apply-expiry`，恢复权限不因此自动启用。

## 核心API和流量含义

核心API是官方核心的本机观测接口。先创建权限600文件，例如 `/root/core-api.json`：

```json
{"version":1,"config":{"enabled":true,"listen":"127.0.0.1","port":19090,"secret":"REPLACE_WITH_AT_LEAST_32_RANDOM_VISIBLE_ASCII_CHARACTERS"}}
```

```bash
qingnode monitor api configure --file /root/core-api.json --preview
qingnode monitor api configure --file /root/core-api.json --yes
qingnode monitor api status
qingnode monitor traffic --samples 3 --interval-ms 1000 --out /root/new-traffic.json
qingnode monitor api disable --preview
qingnode monitor api disable --yes
```

仅接受 `127.0.0.1`或`::1`、1024–65535端口和32–256字节可见ASCII秘密，拒绝空白/控制字符，API不加公网防火墙放行。启停API改变核心运行配置，先预览共享连接影响。官方服务本身包含管理能力，本项目客户端仅公开读方法；回环和密钥仍须保护，不能把接口无认证暴露公网。

客户端独立实现标准库gRPC-Web有限读取，禁环境代理和跳转，限制时间、帧和字节。固定来源为官方 [1.14.0 / 0b8995879f29a9b98ee027bc17b75e101445b238](https://github.com/SagerNet/sing-box/tree/0b8995879f29a9b98ee027bc17b75e101445b238) 与 [1.14.3 / 7054cac5124465ffdb145870d7c01885566711b1](https://github.com/SagerNet/sing-box/tree/7054cac5124465ffdb145870d7c01885566711b1)。核对了 `option/api.go`、`daemon/started_service.proto`、`service/api/web_bridge.go`等公开契约；未复制或链接GPL上游源码/生成文件，详细方法与出处见源码 `internal/coreapi/README.md`。

全局上传/下载是当前核心生命周期累计值；首样本建立基线，重启另开生命周期，重复不叠加、计数倒退和断连明确标缺口。本命令不保存跨进程账本。连接列表为reset快照及有限最近关闭历史，更新事件没有序号，丢失/重复/断连无法精确重建用户流量。只用本机明确映射的入口及用户标签归属，未知标签记 `unknown`。因此没有用户配额、计费或用量封禁承诺，不生成虚假 `subscription-userinfo`流量头；下载令牌到期也不代表代理凭据到期。

可选 `monitor traffic --warn-bytes N`比较当前核心生命周期的全局双向累计字节，N为0至2^60之间的整数。本地JSON结果为 `below/reached/unknown`（未到/已到/未知），没有数据时保持未知。它只作软提醒，不停用凭据、不执行硬配额、不写订阅计量；周期外部通知当前只针对状态变化，不针对这个用量阈值发送消息。

## 代理凭据到期计划

```bash
qingnode expiration list
qingnode expiration set --node NODE_ID --user USER_ID --expires-at 2030-01-02T03:04:05Z --preview
qingnode expiration set --node NODE_ID --user USER_ID --device DEVICE_ID --expires-at 2030-01-02T03:04:05Z --yes
qingnode expiration apply --preview
qingnode expiration apply --yes
qingnode expiration remove --id PLAN_ID --preview
qingnode expiration remove --id PLAN_ID --yes
```

使用实际16位小写十六进制稳定ID，不按显示名称或“第一个用户”猜测。时间必须明确RFC3339 UTC，以 `Z`结束。每条计划只指向一个节点的一条用户凭据；可选设备范围表示该设备的一条指定绑定。一个设备多条绑定可分别设置计划，不自动扩选；同一节点/凭据不能重复计划。保存、查询、导出或普通编辑不执行到期停用，不续期、不轮换凭据。

设备范围遇其他仍注册设备共享该凭据（包括已停下载的设备）会明确阻止整批，原State、令牌和代理均不改。用户凭据范围会预览所有共享引用并精确移除该凭据；设备还有其他绑定时保留其他绑定及下载权限。设备无剩余绑定才停下载并保留历史身份；节点最后一个用户不能直接删空，保留身份并停监听，完成记录阻止普通enable悄悄恢复。须先显式解除计划并确认恢复，删除计划本身不恢复已删凭据或绑定。删除被计划引用的节点/设备，或待执行用户，须先显式移除计划。

实际执行把全部到期项建成一个候选，再用一次事务提交；一项被阻止就不部分提交。运行配置变更沿用共享核心重启，因此现有TCP连接可能全部断开；新认证拒绝与旧会话是否断开是两份测试证据。订阅发布失败和代理已提交分开报告，下载已撤销不能证明代理已停。

`monitor run --apply-expiry`显式允许每轮执行已保存计划；默认 `monitor run`不改State，监控总开关关闭时也不执行。保存的上轮结束时间参与倒退时钟保护，已有停用记录及2020年前/无效时钟同样阻止执行；这不是可信时钟服务，错误地跳到未来仍需管理员核对。裸 `expiration apply`没有独立持久观察时钟，不能承诺检测所有历史时钟回退。定时器若要执行到期计划，须用户另行审查service命令加入该参数。

## 存储、迁移和撤回

第08批新增实际 `observability`与`credential_expirations`字段时将State升为schema7，当时旧1–6仅内存迁移；当前第10批为schema9、兼容旧1–8，首次有意义写入保留原代，旧管理器拒绝新格式。监控计划、秘密、状态和历史仍独立位于受管 `monitor/`，私有目录700、文件600，有限记录/字节并原子保存；它们不是节点配置代。关闭监控不删除历史，不改代理运行/自启。

普通配置备份含State的API设置和到期计划，不含独立监控资产。当前完整迁移尚未打包监控目录；发现目录时列为明确缺项，`backup --full`需显式 `--allow-incomplete`才可生成受限包，不宣称恢复了监控政策、通知秘密或历史。跨机重建监控需独立核对；还原过期计划后不会在查询中自行停用。systemd/OpenRC的实际调度及人工停止保护按BATCH10准确回执记录；公共通知服务、公网/手机、长期运行和ARM原生执行仍另验。

## 可复验入口与宿主门槛

在源码目录准备已核摘要、版本及构建标签的官方程序后，可在隔离Linux运行：

```bash
SING_BOX_BIN=/absolute/official/sing-box go test ./internal/coreapi -run TestOfficialCoreGRPCWebObservation -v -count=1 -timeout=1m
SING_BOX_BIN=/absolute/official/sing-box go test ./internal/node -run TestOfficialCoreRenderedObservationConfig -v -count=1 -timeout=1m
SING_BOX_BIN=/absolute/official/sing-box QINGNODE_EXPIRY_CORE_TEST=1 go test ./internal/node -run TestOfficialCredentialExpiryExistingTCPAndNewAuthentication -v -count=1 -timeout=2m
go test ./internal/monitor -v -count=1
```

逐版执行1.14.0和1.14.3；不设置变量会明确跳过真实程序测试，不能登记为实测。测试只管理自有临时进程、目录和回环端口。它们不安装或启动生产服务。

原生systemd验收须另用用户批准的隔离Linux机器，预先完成项目正常安装和私有计划配置。记录服务 `ActiveState/SubState/MainPID/UnitFileState`、State/current摘要和已有TCP流，再执行一轮观察；以 `qingnode stop`主动停机后重复 `monitor run`，确认PID仍为0、自启和配置不变。重新启动由管理员显式执行。timer材料先审查再安装，记录安装、启动、停止和取消，检查没有积压或自启动代理。故障恢复测试还要保留每次连续故障、独立本机信号、动作额度、恢复复核和未恢复原因。不要在生产机注入故障，也不要仅凭服务命令退出0认定传输已恢复。
