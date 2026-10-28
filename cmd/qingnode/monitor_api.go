package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"syscall"
	"time"

	"qingnode/internal/coreapi"
	"qingnode/internal/node"
	"qingnode/internal/platform"
)

type monitorAPIRequest struct {
	Version int                   `json:"version"`
	Config  *node.CoreObservation `json:"config"`
}

func decodeMonitorAPIRequest(raw []byte) (node.CoreObservation, error) {
	var request monitorAPIRequest
	if len(raw) > 64<<10 || checkTopologyJSON(json.NewDecoder(bytes.NewReader(raw))) != nil {
		return node.CoreObservation{}, errors.New("观测API文件须为最多64KiB的单个JSON，不接受重复、null或异常拼写字段")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Version != 1 || request.Config == nil {
		return node.CoreObservation{}, errors.New("观测API文件须为version:1和config对象，不接受未知字段")
	}
	if err := node.ValidateCoreObservation(request.Config); err != nil {
		return node.CoreObservation{}, err
	}
	client, err := coreapi.New(coreapi.Config{Endpoint: request.Config.Endpoint(), Secret: request.Config.Secret})
	if err != nil {
		return node.CoreObservation{}, errors.New("观测API鉴权须为32–256字节可见ASCII，不能含空白或控制字符")
	}
	client.Close()
	return *request.Config, nil
}

// Input may contain an API secret. Pin a regular, private, caller/root-owned
// inode and open without following a final symlink or blocking on a FIFO.
func readMonitorAPIFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > 64<<10 {
		return nil, errors.New("观测API输入须为权限600且最多64KiB的普通文件，不接受链接、管道或设备")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0 {
		return nil, errors.New("观测API输入须由当前用户或root拥有")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("无法安全打开观测API输入")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > 64<<10 {
		return nil, errors.New("观测API输入在读取期间改变")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("无法读取观测API输入或超过64KiB")
	}
	return raw, nil
}

func (a *app) monitorAPI(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：monitor api configure --file 私有JSON --preview|--yes；或disable --preview|--yes；status只读查看")
	}
	action := args[0]
	flags := fs("monitor api " + action)
	file := flags.String("file", "", "权限600的version:1/config私有JSON；鉴权值不接受命令行参数")
	preview := flags.Bool("preview", false, "只读查看影响，不保存或启停服务")
	yes := flags.Bool("yes", false, "确认经普通事务保存观测API配置")
	if err := parse(flags, args[1:]); err != nil {
		return err
	}
	if action == "status" {
		if err := rejectTopologyFlags(flags); err != nil {
			return err
		}
		return a.store.InspectExisting(func() error {
			if err := rejectMonitorPending(a.store.Root); err != nil {
				return err
			}
			st, err := a.store.Load()
			if err != nil {
				return err
			}
			if err = st.Validate(); err != nil {
				return err
			}
			report := map[string]any{"version": 1, "configured": st.Observability != nil, "enabled": false, "authentication_required": true, "runtime_verified": false}
			if config := st.Observability; config != nil {
				report["enabled"] = config.Enabled
				report["listen"] = config.Listen
				report["port"] = config.Port
			}
			raw, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			return writeOutput("", raw)
		})
	}
	var supplied node.CoreObservation
	switch action {
	case "configure":
		if err := rejectTopologyFlags(flags, "file", "preview", "yes"); err != nil {
			return err
		}
		if *file == "" || !*preview && !*yes {
			return errors.New("配置需要私有--file和--yes；可先--preview查看。鉴权值不能从命令行传入")
		}
		raw, err := readMonitorAPIFile(*file)
		if err != nil {
			return err
		}
		supplied, err = decodeMonitorAPIRequest(raw)
		if err != nil {
			return err
		}
	case "disable":
		if err := rejectTopologyFlags(flags, "preview", "yes"); err != nil {
			return err
		}
		if !*preview && !*yes {
			return errors.New("关闭观测API需要--yes；可先--preview查看共享核心连接影响")
		}
	default:
		return errors.New("未知monitor api操作；支持configure、disable、status")
	}
	return a.changeTopology(*preview, func(st *node.State) error {
		if action == "configure" {
			config := supplied
			st.Observability = &config
		} else if st.Observability != nil {
			config := *st.Observability
			config.Enabled = false
			st.Observability = &config
		}
		fmt.Println("观测API仅监听本机并要求鉴权。启用、关闭、改端口或更换鉴权值属于共享核心运行配置变化，应用时可能重启核心并断开已有连接。")
		return st.Validate()
	})
}

type monitorTrafficConnection struct {
	ID            string `json:"connection_id"`
	NodeID        string `json:"node_id"`
	UserID        string `json:"user_id"`
	Closed        bool   `json:"closed"`
	UplinkTotal   int64  `json:"uplink_total"`
	DownlinkTotal int64  `json:"downlink_total"`
}

type monitorTrafficSample struct {
	ObservedAt           time.Time                  `json:"observed_at"`
	Status               string                     `json:"status"`
	Reason               string                     `json:"reason,omitempty"`
	Epoch                string                     `json:"epoch,omitempty"`
	PID                  int                        `json:"pid,omitempty"`
	StartedAt            int64                      `json:"core_started_at_ms,omitempty"`
	TrafficAvailable     bool                       `json:"traffic_available"`
	Global               *coreapi.Status            `json:"global,omitempty"`
	Delta                *coreapi.CounterDelta      `json:"sample_delta,omitempty"`
	Gap                  bool                       `json:"gap"`
	ConnectionReset      bool                       `json:"connection_reset"`
	ConnectionsAvailable bool                       `json:"connections_available"`
	Connections          []monitorTrafficConnection `json:"connections,omitempty"`
}

type monitorTrafficReport struct {
	Version          int                    `json:"version"`
	Source           string                 `json:"source"`
	Status           string                 `json:"status"`
	StartedAt        time.Time              `json:"started_at"`
	FinishedAt       time.Time              `json:"finished_at"`
	RequestedSamples int                    `json:"requested_samples"`
	Samples          []monitorTrafficSample `json:"samples"`
	BillingSuitable  bool                   `json:"billing_suitable"`
	ThresholdBytes   *int64                 `json:"threshold_bytes,omitempty"`
	ThresholdStatus  string                 `json:"threshold_status"`
	Limitations      []string               `json:"limitations"`
}

func trafficThreshold(samples []monitorTrafficSample, threshold *int64) string {
	if threshold == nil || len(samples) == 0 {
		return "unknown"
	}
	last := samples[len(samples)-1]
	if !last.TrafficAvailable || last.Global == nil || last.Global.UplinkTotal < 0 || last.Global.DownlinkTotal < 0 {
		return "unknown"
	}
	// Two nonnegative int64 counters sum safely in uint64, even when their
	// combined value would overflow int64. Thresholds are bounded below 2^61.
	total := uint64(last.Global.UplinkTotal) + uint64(last.Global.DownlinkTotal)
	if total >= uint64(*threshold) {
		return "reached"
	}
	return "below"
}

var trafficConnectionIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func trafficFailure(err error) (string, string) {
	switch {
	case errors.Is(err, coreapi.ErrUnauthorized):
		return "unauthorized", "核心API拒绝鉴权；未取得可用流量数据"
	case errors.Is(err, context.Canceled):
		return "cancelled", "采样已取消；本次数据不完整"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "采样超时；不能把未取得的数据当作零流量"
	case errors.Is(err, coreapi.ErrLimit):
		return "limit_reached", "核心API数据超过采样上限；本次数据不完整"
	case errors.Is(err, coreapi.ErrProtocol):
		return "invalid_response", "核心API响应无效；未取得可验证流量数据"
	default:
		return "unavailable", "核心API未就绪、不支持观测或统计不可用；未取得的数据不是零流量"
	}
}

func trafficOwners(st node.State) coreapi.Ownership {
	owners := coreapi.Ownership{NodesByInbound: map[string]string{}, UsersByInbound: map[string]map[string]string{}}
	for _, n := range st.Nodes {
		if !n.Enabled {
			continue
		}
		owners.NodesByInbound[n.ID] = n.ID
		owners.UsersByInbound[n.ID] = map[string]string{}
		for _, u := range n.Users {
			owners.UsersByInbound[n.ID][u.ID] = u.ID
		}
	}
	return owners
}

func trafficPID(backend node.Backend) int {
	var runner node.Runner
	var manager platform.Manager
	switch system := backend.(type) {
	case node.SystemBackend:
		runner = system.Execute
		manager = system.ServiceManager()
	case *node.SystemBackend:
		runner = system.Execute
		manager = system.ServiceManager()
	default:
		return 0
	}
	if runner == nil {
		runner = node.Run
	}
	manager.Kind = manager.ResolvedKind()
	manager.Execute = func(_ time.Duration, name string, args ...string) ([]byte, error) {
		return runner(500*time.Millisecond, name, args...)
	}
	pid, err := manager.PID("qingnode")
	if err != nil || pid < 1 {
		return 0
	}
	return pid
}

// A sample brackets status and the reset snapshot with the API start identity.
// A restart in the middle invalidates the whole sample instead of mixing cores.
func trafficSample(ctx context.Context, client *coreapi.Client, owners coreapi.Ownership, counter *coreapi.StatusCounter, pid int) monitorTrafficSample {
	result := monitorTrafficSample{ObservedAt: time.Now().UTC(), Status: "unavailable", Gap: true, PID: pid}
	failed := func(err error) monitorTrafficSample {
		counter.MarkGap()
		result.Status, result.Reason = trafficFailure(err)
		return result
	}
	started, err := client.StartedAt(ctx)
	if err != nil {
		return failed(err)
	}
	status, err := client.Status(ctx)
	if err != nil {
		return failed(err)
	}
	connections, connectionsErr := client.Connections(ctx)
	finished, err := client.StartedAt(ctx)
	if err != nil {
		return failed(err)
	}
	if started != finished {
		counter.MarkGap()
		result.Status = "epoch_changed"
		result.Reason = "采样期间核心重新启动，已丢弃跨生命周期数据"
		return result
	}
	result.Epoch = strconv.Itoa(pid) + "/" + strconv.FormatInt(started, 10)
	result.StartedAt = started
	delta, err := counter.Apply(result.Epoch, status)
	if err != nil {
		result.Status = "counter_regressed"
		result.Reason = "同一核心生命周期的计数回退，保留上次基线，未计算新流量"
		return result
	}
	result.Status, result.TrafficAvailable, result.Global, result.Delta, result.Gap = "available", true, &status, &delta, delta.Gap
	if connectionsErr != nil {
		result.Status = "partial"
		_, result.Reason = trafficFailure(connectionsErr)
		result.Gap = true
		return result
	}
	result.ConnectionsAvailable, result.ConnectionReset = true, connections.Reset
	for _, event := range connections.Events {
		if event.Connection == nil {
			continue
		}
		connection := *event.Connection
		nodeID, userID := owners.Resolve(connection)
		id := connection.ID
		if !trafficConnectionIDRE.MatchString(id) {
			id = coreapi.UnknownOwner
		}
		result.Connections = append(result.Connections, monitorTrafficConnection{ID: id, NodeID: nodeID, UserID: userID, Closed: connection.ClosedAt > 0, UplinkTotal: connection.UplinkTotal, DownlinkTotal: connection.DownlinkTotal})
	}
	sort.Slice(result.Connections, func(i, j int) bool { return result.Connections[i].ID < result.Connections[j].ID })
	return result
}

func (a *app) monitorTraffic(args []string) error {
	flags := fs("monitor traffic")
	out := flags.String("out", "", "将观测JSON写入尚不存在的私有文件")
	samples := flags.Int("samples", 1, "有限采样次数，1–10")
	interval := flags.Int("interval-ms", 1000, "采样间隔，100–5000毫秒")
	timeout := flags.Int("timeout-ms", 2000, "单次API请求上限，100–5000毫秒；整次最多60秒")
	warnBytes := flags.Int64("warn-bytes", 0, "可选本地软提醒，当前核心总量阈值0–1152921504606846976字节；不设配额、不停用、不发外部通知")
	if err := parse(flags, args); err != nil {
		return err
	}
	if err := rejectTopologyFlags(flags, "out", "samples", "interval-ms", "timeout-ms", "warn-bytes"); err != nil {
		return err
	}
	if *samples < 1 || *samples > 10 || *interval < 100 || *interval > 5000 || *timeout < 100 || *timeout > 5000 {
		return errors.New("流量采样次数为1–10，间隔100–5000毫秒，API请求上限100–5000毫秒")
	}
	if *warnBytes < 0 || *warnBytes > 1<<60 {
		return errors.New("软提醒字节阈值必须为0到1152921504606846976")
	}
	var pinned *pinnedOutput
	if *out != "" {
		if err := a.probeOutput(*out); err != nil {
			return err
		}
		var err error
		pinned, err = pinNewOutput(*out)
		if err != nil {
			return err
		}
		defer pinned.root.Close()
	}
	var snapshot node.State
	if err := a.store.InspectExisting(func() error {
		if err := rejectMonitorPending(a.store.Root); err != nil {
			return err
		}
		st, err := a.store.Load()
		if err != nil {
			return err
		}
		if err = st.Validate(); err != nil {
			return err
		}
		snapshot = st.Clone()
		return nil
	}); err != nil {
		return err
	}
	report := monitorTrafficReport{Version: 1, Source: "sing-box-official-grpc-web", Status: "unavailable", StartedAt: time.Now().UTC(), RequestedSamples: *samples, Samples: []monitorTrafficSample{}, BillingSuitable: false, Limitations: []string{
		"全局总量只属于当前核心生命周期，重启后重新开始；本命令不保存持久账本。",
		"连接列表是reset快照，含活跃及有限已关闭历史；两次采样之间的连接可能缺失，事件无序号，不能作为用户计费依据。",
		"节点和用户只按本次配置的稳定ID精确匹配；缺标签、未知标签或转发入口均标为unknown。",
		"下载令牌有效期与代理认证、流量统计相互独立；本命令不修改订阅流量headers、配置、令牌或服务。",
		"核心启动时间来自官方API；可用时附本机服务PID。该身份用于本次有限采样，不作持久跨进程计费凭证。",
	}}
	if a.offline || snapshot.Observability == nil || !snapshot.Observability.Enabled {
		reason := "观测API尚未配置或未启用；未取得的数据不是零流量"
		if a.offline {
			reason = "离线模式未连接核心API，运行流量未知"
		}
		report.Samples = append(report.Samples, monitorTrafficSample{ObservedAt: time.Now().UTC(), Status: "unavailable", Reason: reason, Gap: true})
	} else {
		client, err := coreapi.New(coreapi.Config{Endpoint: snapshot.Observability.Endpoint(), Secret: snapshot.Observability.Secret, Timeout: time.Duration(*timeout) * time.Millisecond})
		if err != nil {
			return errors.New("已保存的观测API配置无法建立安全客户端；请重新核对私有配置")
		}
		defer client.Close()
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, budgetCancel := context.WithTimeout(ctx, time.Minute)
		defer budgetCancel()
		owners := trafficOwners(snapshot)
		var counter coreapi.StatusCounter
		for i := 0; i < *samples; i++ {
			if ctx.Err() != nil {
				break
			}
			pid := trafficPID(a.store.Backend)
			sample := trafficSample(ctx, client, owners, &counter, pid)
			report.Samples = append(report.Samples, sample)
			if i == *samples-1 || ctx.Err() != nil {
				break
			}
			timer := time.NewTimer(time.Duration(*interval) * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	available, complete := 0, 0
	for _, sample := range report.Samples {
		if sample.TrafficAvailable {
			available++
		}
		if sample.Status == "available" {
			complete++
		}
	}
	if complete == *samples {
		report.Status = "available"
	} else if available > 0 {
		report.Status = "partial"
	}
	report.FinishedAt = time.Now().UTC()
	flags.Visit(func(flagValue *flag.Flag) {
		if flagValue.Name == "warn-bytes" {
			value := *warnBytes
			report.ThresholdBytes = &value
		}
	})
	report.ThresholdStatus = trafficThreshold(report.Samples, report.ThresholdBytes)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if pinned != nil {
		return pinned.write(append(raw, '\n'))
	}
	return writeOutput("", raw)
}
