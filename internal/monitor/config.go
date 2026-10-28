package monitor

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"qingnode/internal/probe"
)

const (
	MaxJobs         = 32
	MaxConfigBytes  = 64 << 10
	MaxStatusBytes  = 1 << 20
	MaxHistoryBytes = 8 << 20
)

func DefaultConfig() Config {
	return Config{Version: ConfigVersion, IntervalSeconds: 60, TimeoutMS: 10000,
		Concurrency: 1, MaxBytes: 64 << 10,
		History:       HistoryLimits{Records: 96, Bytes: 1 << 20, Events: 128},
		Recovery:      RecoveryPolicy{Mode: "observe", ConsecutiveFailures: 3, CooldownSeconds: 600, WindowSeconds: 3600, MaxActions: 2},
		Notifications: NotificationConfig{Kind: "webhook", TimeoutMS: 5000, Retries: 1}}
}

func NormalizeConfig(c Config) (Config, error) {
	d := DefaultConfig()
	if c.Version != ConfigVersion {
		return c, errors.New("监控配置版本必须是1，且独立于节点状态版本")
	}
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = d.IntervalSeconds
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = d.TimeoutMS
	}
	if c.Concurrency == 0 {
		c.Concurrency = d.Concurrency
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = d.MaxBytes
	}
	if c.History.Records == 0 {
		c.History.Records = d.History.Records
	}
	if c.History.Bytes == 0 {
		c.History.Bytes = d.History.Bytes
	}
	if c.History.Events == 0 {
		c.History.Events = d.History.Events
	}
	if c.Recovery.Mode == "" {
		c.Recovery.Mode = "observe"
	}
	if c.Recovery.ConsecutiveFailures == 0 {
		c.Recovery.ConsecutiveFailures = d.Recovery.ConsecutiveFailures
	}
	if c.Recovery.CooldownSeconds == 0 {
		c.Recovery.CooldownSeconds = d.Recovery.CooldownSeconds
	}
	if c.Recovery.WindowSeconds == 0 {
		c.Recovery.WindowSeconds = d.Recovery.WindowSeconds
	}
	if c.Recovery.MaxActions == 0 {
		c.Recovery.MaxActions = d.Recovery.MaxActions
	}
	if c.Notifications.Kind == "" {
		c.Notifications.Kind = "webhook"
	}
	if c.Notifications.TimeoutMS == 0 {
		c.Notifications.TimeoutMS = d.Notifications.TimeoutMS
	}
	if c.IntervalSeconds < 15 || c.IntervalSeconds > 86400 {
		return c, errors.New("监控间隔必须为15到86400秒")
	}
	if c.TimeoutMS < 1 || c.TimeoutMS > 120000 {
		return c, errors.New("单次监控时间预算必须为1到120000毫秒")
	}
	if c.Concurrency < 1 || c.Concurrency > 4 {
		return c, errors.New("监控并发数必须为1到4")
	}
	if c.MaxBytes < 1 || c.MaxBytes > 64<<10 {
		return c, errors.New("周期监控最多使用65536字节，不提供下载测速")
	}
	if c.History.Records < 1 || c.History.Records > 512 || c.History.Bytes < 256 || c.History.Bytes > MaxHistoryBytes || c.History.Events < 1 || c.History.Events > 1024 {
		return c, errors.New("历史上限必须为1到512条、256到8388608字节，事件上限为1到1024条")
	}
	if c.Recovery.Mode != "observe" && c.Recovery.Mode != "restart" {
		return c, errors.New("恢复策略必须为observe或restart")
	}
	if c.Recovery.ConsecutiveFailures < 2 || c.Recovery.ConsecutiveFailures > 100 || c.Recovery.CooldownSeconds < 60 || c.Recovery.CooldownSeconds > 86400 || c.Recovery.WindowSeconds < 60 || c.Recovery.WindowSeconds > 604800 || c.Recovery.MaxActions < 1 || c.Recovery.MaxActions > 20 {
		return c, errors.New("恢复策略超出连续失败、冷却或滚动窗口动作数的安全上限")
	}
	if len(c.Jobs) > MaxJobs {
		return c, errors.New("监控任务最多32个")
	}
	seen := map[string]bool{}
	for i, j := range c.Jobs {
		if !validID(j.ID) || seen[j.ID] || (j.NodeID == "" && j.EgressID == "") || (j.NodeID != "" && j.EgressID != "") || (j.NodeID != "" && !validID(j.NodeID)) || (j.EgressID != "" && !validID(j.EgressID)) {
			return c, errors.New("监控任务需要唯一稳定ID，并以稳定节点或出口ID引用")
		}
		seen[j.ID] = true
		if j.Family == "" {
			c.Jobs[i].Family = "auto"
		} else if j.Family != "auto" && j.Family != "ipv4" && j.Family != "ipv6" {
			return c, errors.New("监控地址族必须为auto、ipv4或ipv6")
		}
		if j.UserID != "" && !validID(j.UserID) || j.EndpointID != "" && !validID(j.EndpointID) {
			return c, errors.New("用户与入口引用必须使用稳定ID")
		}
		if j.TargetURL != "" {
			u, e := url.Parse(j.TargetURL)
			if e != nil || len(j.TargetURL) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return c, errors.New("监控目标必须是无用户信息、查询参数和片段的HTTPS地址")
			}
		}
		if j.UDPAddress != "" {
			h, p, e := net.SplitHostPort(j.UDPAddress)
			pn, pe := strconv.Atoi(p)
			if e != nil || pe != nil || pn < 1 || pn > 65535 || h == "" || len(h) > 253 || strings.ContainsAny(h, "/\\?#@ \r\n\x00") {
				return c, errors.New("受控UDP目标必须是有效host:port")
			}
		}
		if len(j.Signals) == 0 || len(j.Signals) > 9 {
			return c, errors.New("每个监控任务需要1到9类独立信号")
		}
		kinds := map[SignalKind]bool{}
		for _, k := range j.Signals {
			if !validKind(k) || kinds[k] {
				return c, errors.New("监控信号类型未知或重复")
			}
			kinds[k] = true
		}
		if len(j.Labels) > 8 {
			return c, errors.New("任务标签最多8项")
		}
		total := 0
		for k, v := range j.Labels {
			if k == "" || len(k) > 32 || len(v) > 128 || strings.ContainsAny(k+v, "\r\n\x00") {
				return c, errors.New("任务标签过长或含控制字符")
			}
			total += len(k) + len(v)
		}
		if total > 1024 {
			return c, errors.New("每个任务的标签总量最多1024字节")
		}
	}
	if c.Notifications.TimeoutMS < 1 || c.Notifications.TimeoutMS > 10000 || c.Notifications.Retries < 0 || c.Notifications.Retries > 2 {
		return c, errors.New("通知最多等待10秒、重试2次")
	}
	if c.Notifications.Kind != "webhook" && c.Notifications.Kind != "telegram" {
		return c, errors.New("通知类型必须为webhook或telegram")
	}
	if c.Notifications.Enabled {
		if _, err := notificationURL(c.Notifications); err != nil {
			return c, err
		}
		if c.Notifications.Token == "" || len(c.Notifications.Token) > 2048 || strings.ContainsAny(c.Notifications.Token, "\r\n\x00") {
			return c, errors.New("启用通知需要私有配置中的有效令牌")
		}
		if c.Notifications.Kind == "telegram" && (c.Notifications.ChatID == "" || len(c.Notifications.ChatID) > 128) {
			return c, errors.New("Telegram通知需要私有配置中的会话ID")
		}
	}
	return c, nil
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 || strings.ContainsRune("/\\?#@:", r) {
			return false
		}
	}
	return true
}

func validKind(k SignalKind) bool {
	switch k {
	case Process, Listener, Authentication, TCP, UDP, Target, Certificate, Disk, CoreAPI:
		return true
	}
	return false
}

func notificationURL(n NotificationConfig) (*url.URL, error) {
	endpoint := n.Endpoint
	if n.Kind == "telegram" && endpoint == "" {
		endpoint = "https://api.telegram.org"
	}
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 4096 || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("通知地址无效；地址与令牌只从私有配置读取")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("通知地址必须使用HTTPS；受控本机测试仅允许回环IP的HTTP地址")
	}
	if n.Kind == "telegram" {
		if u.RawQuery != "" {
			return nil, errors.New("Telegram通知地址不能含查询参数")
		}
		u.Path = strings.TrimRight(u.Path, "/") + "/bot" + n.Token + "/sendMessage"
	}
	return u, nil
}

type privateNotification struct {
	Enabled   bool   `json:"enabled"`
	Kind      string `json:"kind"`
	Endpoint  string `json:"endpoint,omitempty"`
	Token     string `json:"token,omitempty"`
	ChatID    string `json:"chat_id,omitempty"`
	TimeoutMS int    `json:"timeout_ms"`
	Retries   int    `json:"retries"`
}

type privateConfig struct {
	Version         int                 `json:"version"`
	Enabled         bool                `json:"enabled"`
	IntervalSeconds int                 `json:"interval_seconds"`
	TimeoutMS       int                 `json:"timeout_ms"`
	Concurrency     int                 `json:"concurrency"`
	MaxBytes        int64               `json:"max_bytes"`
	History         HistoryLimits       `json:"history"`
	Jobs            []Job               `json:"jobs"`
	Recovery        RecoveryPolicy      `json:"recovery"`
	Notifications   privateNotification `json:"notifications"`
}

func encodeConfig(c Config) ([]byte, error) {
	c, err := NormalizeConfig(c)
	if err != nil {
		return nil, err
	}
	n := c.Notifications
	p := privateConfig{c.Version, c.Enabled, c.IntervalSeconds, c.TimeoutMS, c.Concurrency, c.MaxBytes, c.History, c.Jobs, c.Recovery, privateNotification{n.Enabled, n.Kind, n.Endpoint, n.Token, n.ChatID, n.TimeoutMS, n.Retries}}
	b, err := json.MarshalIndent(p, "", "  ")
	if len(b) > MaxConfigBytes {
		return nil, errors.New("监控私有配置超过64KiB")
	}
	return append(b, '\n'), err
}

func decodeConfig(b []byte) (Config, error) {
	var p privateConfig
	if err := probe.StrictJSON(b, &p); err != nil {
		return Config{}, errors.New("监控配置JSON无效、字段重复或包含未知字段")
	}
	n := p.Notifications
	c := Config{Version: p.Version, Enabled: p.Enabled, IntervalSeconds: p.IntervalSeconds, TimeoutMS: p.TimeoutMS, Concurrency: p.Concurrency, MaxBytes: p.MaxBytes, History: p.History, Jobs: p.Jobs, Recovery: p.Recovery, Notifications: NotificationConfig{n.Enabled, n.Kind, n.Endpoint, n.Token, n.ChatID, n.TimeoutMS, n.Retries}}
	return NormalizeConfig(c)
}

// LoadConfig reads only; it neither creates directories nor repairs permissions.
func (s *Store) LoadConfig() (Config, error) {
	if err := s.checkRoot(false); err != nil {
		return Config{}, err
	}
	b, err := readOwned(filepath.Join(s.Root, "config.json"), MaxConfigBytes, true)
	if err != nil {
		return Config{}, err
	}
	c, err := decodeConfig(b)
	if err == nil {
		c.privateNotifications = true
		c.privateNotificationHash = notificationHash(c.Notifications)
		c.privateConfigPath = filepath.Join(s.Root, "config.json")
	}
	return c, err
}

func (s *Store) SaveConfig(c Config) error {
	b, err := encodeConfig(c)
	if err != nil {
		return err
	}
	if err = s.Initialize(); err != nil {
		return err
	}
	lock, err := s.acquireNamed(".monitor-config.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	return s.writeOwned("config.json", b, MaxConfigBytes)
}

// ReadConfigFile imports an explicitly selected, already-private file. It does
// not claim the source directory or repair its permissions.
func ReadConfigFile(path string) (Config, error) {
	if err := rejectPathLinks(filepath.Dir(path)); err != nil {
		return Config{}, err
	}
	b, err := readOwned(path, MaxConfigBytes, true)
	if err != nil {
		return Config{}, err
	}
	c, err := decodeConfig(b)
	if err == nil {
		c.privateNotifications = true
		c.privateNotificationHash = notificationHash(c.Notifications)
		c.privateConfigPath = path
	}
	return c, err
}

// File helpers preserve the same owned-directory contract as Store methods.
func LoadConfig(path string) (Config, error) {
	if filepath.Base(path) != "config.json" {
		return Config{}, errors.New("私有监控配置文件名必须为config.json")
	}
	return (&Store{Root: filepath.Dir(path)}).LoadConfig()
}

func SaveConfig(path string, c Config) error {
	if filepath.Base(path) != "config.json" {
		return errors.New("私有监控配置文件名必须为config.json")
	}
	return (&Store{Root: filepath.Dir(path)}).SaveConfig(c)
}

func configBudget(c Config) Budget {
	return Budget{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond, MaxBytes: c.MaxBytes, Concurrency: c.Concurrency}
}

func notificationHash(n NotificationConfig) [32]byte {
	b, _ := json.Marshal(privateNotification{n.Enabled, n.Kind, n.Endpoint, n.Token, n.ChatID, n.TimeoutMS, n.Retries})
	return sha256.Sum256(b)
}
