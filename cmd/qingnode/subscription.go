package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/skip2/go-qrcode"
	"qingnode/internal/node"
	"qingnode/internal/subscription"
)

const publisherConfigName = "subscription-publisher.json"

type publisherConfig struct {
	Version        int      `json:"version"`
	Directory      string   `json:"directory"`
	GroupID        int      `json:"group_id"`
	Formats        []string `json:"formats"`
	SingBoxVersion string   `json:"sing_box_version"`
	MihomoVersion  string   `json:"mihomo_version"`
	AllowLossy     bool     `json:"allow_lossy"`
}

func decodePublisherConfig(raw []byte) (publisherConfig, error) {
	var c publisherConfig
	if len(raw) > 32768 {
		return c, errors.New("订阅发布配置超过32KiB")
	}
	if err := checkTopologyJSON(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return c, errors.New("订阅发布配置含重复、未知拼写、null或额外JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, errors.New("订阅发布配置结构无效")
	}
	if c.Version != 1 || !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) == string(os.PathSeparator) || c.GroupID < -1 || len(c.Formats) < 1 || len(c.Formats) > 5 {
		return c, errors.New("订阅发布配置版本、路径、组或格式数量无效")
	}
	seen := map[string]bool{}
	for _, f := range c.Formats {
		if _, ok := subscription.ContentType(f); !ok || seen[f] {
			return c, errors.New("订阅发布格式未知或重复")
		}
		seen[f] = true
	}
	if c.SingBoxVersion != "1.14.0" && c.SingBoxVersion != "1.14.3" {
		return c, errors.New("订阅sing-box版本仅核验1.14.0/1.14.3")
	}
	if c.MihomoVersion != "1.19.30" {
		return c, errors.New("订阅Mihomo版本仅核验1.19.30")
	}
	return c, nil
}

func (a *app) publisherConfig() (publisherConfig, bool, error) {
	p := filepath.Join(a.store.Root, publisherConfigName)
	i, e := os.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		return publisherConfig{}, false, nil
	}
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 {
		return publisherConfig{}, false, errors.New("订阅发布配置须为私有普通文件")
	}
	if stat, ok := i.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return publisherConfig{}, false, errors.New("订阅发布配置所有权无效")
	}
	b, e := readTopologyFile(p)
	if e != nil {
		return publisherConfig{}, false, e
	}
	c, e := decodePublisherConfig(b)
	return c, true, e
}

func publicationForState(st node.State, c publisherConfig, old subscription.Snapshot) (subscription.Snapshot, error) {
	next := old
	next.Records = append([]subscription.Record{}, old.Records...)
	next.GeneratedAt = time.Now().UTC()
	for i := range next.Records {
		r := &next.Records[i]
		// Published identities are exact stable IDs, never human-name selectors.
		var p *node.DeviceProfile
		for i := range st.Devices {
			if st.Devices[i].ID == r.DeviceID {
				p = &st.Devices[i]
				break
			}
		}
		if p == nil || p.Disabled || r.Revoked {
			r.Revoked = true
			r.Outputs = map[string]subscription.Payload{}
			continue
		}
		r.Outputs = map[string]subscription.Payload{}
		formats := c.Formats
		if len(p.SubscriptionFormats) > 0 {
			formats = p.SubscriptionFormats
			for _, format := range formats {
				enabled := false
				for _, configured := range c.Formats {
					enabled = enabled || format == configured
				}
				if !enabled {
					return next, fmt.Errorf("设备%s要求的订阅格式未在发布配置中启用", p.ID)
				}
			}
		}
		for _, format := range formats {
			v := ""
			if format == "sing-box" {
				v = c.SingBoxVersion
			}
			if format == "mihomo" || format == "provider" {
				v = c.MihomoVersion
			}
			out, e := node.ExportDeviceProfile(st, *p, format, v, c.AllowLossy)
			if e != nil {
				return next, fmt.Errorf("设备%s的%s发布失败：%w", p.ID, format, e)
			}
			for _, warning := range out.Warnings {
				fmt.Fprintf(os.Stderr, "[WARN] 设备%s：%s\n", p.ID, warning)
			}
			ct, _ := subscription.ContentType(format)
			r.Outputs[format] = subscription.Payload{ContentType: ct, Content: out.Content}
		}
	}
	return next, subscription.Validate(next)
}

// Called under the existing management lock after a committed proxy Apply.
// Rendering is bounded and local. HTTP requests never acquire this lock.
func (a *app) refreshPublished(st node.State) error {
	c, ok, e := a.publisherConfig()
	if e != nil || !ok {
		return e
	}
	old, e := subscription.Read(c.Directory)
	if e != nil {
		return e
	}
	next, e := publicationForState(st, c, old)
	if e != nil {
		return e
	}
	return subscription.Publish(c.Directory, next, c.GroupID)
}

func (a *app) revokePublishedDevice(id string) error {
	c, ok, e := a.publisherConfig()
	if e != nil || !ok {
		return e
	}
	s, e := subscription.Read(c.Directory)
	if e != nil {
		return e
	}
	changed := false
	for i := range s.Records {
		if s.Records[i].DeviceID == id && !s.Records[i].Revoked {
			s.Records[i].Revoked = true
			s.Records[i].Outputs = map[string]subscription.Payload{}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	s.GeneratedAt = time.Now().UTC()
	return subscription.Publish(c.Directory, s, c.GroupID)
}

// Covers device batch edits, deletion, restore and rollback as well as the
// dedicated disable command. An unrelated publication/render failure must
// never leave a removed or disabled device's old download token authorized.
func (a *app) revokeRemovedPublishedDevices(next node.State) error {
	c, ok, e := a.publisherConfig()
	if e != nil || !ok {
		return e
	}
	s, e := subscription.Read(c.Directory)
	if e != nil {
		return e
	}
	active := map[string]bool{}
	for _, p := range next.Devices {
		active[p.ID] = !p.Disabled
	}
	changed := false
	for i := range s.Records {
		r := &s.Records[i]
		if !r.Revoked && !active[r.DeviceID] {
			r.Revoked = true
			r.Outputs = map[string]subscription.Payload{}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	s.GeneratedAt = time.Now().UTC()
	return subscription.Publish(c.Directory, s, c.GroupID)
}

type subscriptionLink struct {
	Format string `json:"format"`
	URL    string `json:"url"`
}
type tokenMaterial struct {
	Version   int                `json:"version"`
	DeviceID  string             `json:"device_id"`
	TokenID   string             `json:"token_id"`
	Token     string             `json:"token"`
	ExpiresAt time.Time          `json:"expires_at"`
	Links     []subscriptionLink `json:"links"`
}

func parseSubscriptionOrigin(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || !node.ValidHost(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("公开订阅地址须为HTTPS源地址，不含登录信息、路径、查询或片段")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("公开订阅HTTPS端口无效")
		}
	}
	u.Path = ""
	return u, nil
}

func validateTokenMaterial(m tokenMaterial, now time.Time) error {
	hexValue := func(raw string, length int) bool {
		_, err := hex.DecodeString(raw)
		return err == nil && len(raw) == length && strings.ToLower(raw) == raw
	}
	if m.Version != 1 || !hexValue(m.DeviceID, 16) || !hexValue(m.TokenID, 16) || !hexValue(m.Token, 64) || !now.Before(m.ExpiresAt) || m.ExpiresAt.After(now.Add(366*24*time.Hour)) || len(m.Links) > 5 {
		return errors.New("令牌私有材料的身份、秘密或到期时间无效；请检查原签发文件")
	}
	seen := map[string]bool{}
	for _, link := range m.Links {
		if _, ok := subscription.ContentType(link.Format); !ok || seen[link.Format] {
			return errors.New("令牌链接格式未知或重复")
		}
		seen[link.Format] = true
		u, err := url.Parse(link.URL)
		if err != nil || u.RawPath != "" || u.Path != "/s/"+m.Token+"/"+link.Format {
			return errors.New("令牌链接路径与本设备秘密不符")
		}
		origin := *u
		origin.Path = ""
		if _, err = parseSubscriptionOrigin(origin.String()); err != nil {
			return errors.New("令牌链接须为有效HTTPS源地址与精确下载路径")
		}
	}
	return nil
}

// This request sends no token or proxy credentials. Certificate validation is
// deliberately the standard system trust check; there is no insecure switch.
func verifySubscriptionHTTPS(ctx context.Context, raw string) error {
	u, e := parseSubscriptionOrigin(raw)
	if e != nil {
		return e
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, http.MethodHead, u.String()+"/", nil)
	if e != nil {
		return errors.New("无法建立HTTPS校验请求")
	}
	response, e := client.Do(request)
	if e != nil {
		return errors.New("公开订阅HTTPS证书或连接验证失败；未发送任何令牌")
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return errors.New("公开订阅HTTPS未通过系统信任校验")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return errors.New("公开订阅源地址发生重定向，请验证最终HTTPS源地址")
	}
	return nil
}

func (a *app) subscription(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：subscription init/configure/publish/status/issue/rotate/revoke/qr/check；serve是独立只读服务")
	}
	cmd := args[0]
	f := fs("subscription " + cmd)
	machine := f.Bool("json", false, "仅status：版本1下载授权状态；不输出原始令牌或链接")
	id := f.String("device", "", "设备ID或名称")
	dir := f.String("dir", "", "独立发布目录，不能位于State目录内")
	gid := f.Int("gid", -1, "专用订阅组ID；-1为当前组，不扩大State权限")
	formats := f.String("formats", "sing-box,mihomo,provider,uri,base64", "明确发布格式；不兼容则整批失败，不静默丢失")
	singVersion := f.String("sing-box-version", "1.14.0", "设备sing-box目标版本：1.14.0/1.14.3")
	mihomoVersion := f.String("mihomo-version", "1.19.30", "设备Mihomo目标版本：1.19.30")
	lossy := f.Bool("allow-lossy", false, "显式允许有损格式；优先仅发布完整配置")
	out := f.String("out", "", "一次性令牌/二维码新私有文件")
	baseURL := f.String("base-url", "", "公开HTTPS源地址；先验证可信证书，验证时不发送令牌")
	expires := f.String("expires", "", "RFC3339到期时间，最晚366天；默认30天")
	tokenFile := f.String("token-file", "", "一次性令牌私有文件，二维码只选择此设备")
	format := f.String("format", "mihomo", "二维码使用的已发布格式")
	yes := f.Bool("yes", false, "确认撤销或轮换下载权限，已下载代理认证仍有效")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	if flagSet(f, "json") && cmd != "status" {
		return errors.New("--json仅用于subscription status；令牌材料使用--out私有文件")
	}
	switch cmd {
	case "init":
		if e := rejectTopologyFlags(f, "dir", "gid", "formats", "sing-box-version", "mihomo-version", "allow-lossy"); e != nil {
			return e
		}
		if e := a.probeOutput(*dir); e != nil {
			return e
		}
		c := publisherConfig{Version: 1, Directory: filepath.Clean(*dir), GroupID: *gid, Formats: strings.Split(*formats, ","), SingBoxVersion: *singVersion, MihomoVersion: *mihomoVersion, AllowLossy: *lossy}
		b, _ := json.Marshal(c)
		if _, e := decodePublisherConfig(b); e != nil {
			return e
		}
		return a.store.WithLock(func() error {
			if _, exists, e := a.publisherConfig(); e != nil {
				return e
			} else if exists {
				return errors.New("订阅发布已初始化；不自动更换现有目录或组")
			}
			if e := subscription.CreateInitial(c.Directory, c.GroupID); e != nil {
				return fmt.Errorf("拒绝初始化；请保留已有发布材料并使用新的独立目录，不会清空已有快照：%w", e)
			}
			if e := node.AtomicWrite(filepath.Join(a.store.Root, publisherConfigName), b, 0600); e != nil {
				return fmt.Errorf("空发布目录已创建，配置保存失败；保留目录供检查：%w", e)
			}
			fmt.Fprintln(os.Stderr, "已创建独立私有发布目录；未安装或启动订阅服务，未改变代理服务。")
			return nil
		})
	case "publish":
		if e := rejectTopologyFlags(f); e != nil {
			return e
		}
		return a.store.InspectExisting(func() error {
			if e := rejectPending(a.store.Root); e != nil {
				return e
			}
			st, e := a.store.Load()
			if e != nil {
				return e
			}
			if e = st.Validate(); e != nil {
				return e
			}
			if _, ok, e := a.publisherConfig(); e != nil {
				return e
			} else if !ok {
				return errors.New("先运行subscription init")
			}
			return a.refreshPublished(st)
		})
	case "configure":
		if e := rejectTopologyFlags(f, "formats", "sing-box-version", "mihomo-version", "allow-lossy"); e != nil {
			return e
		}
		return a.store.InspectExisting(func() error {
			if e := rejectPending(a.store.Root); e != nil {
				return e
			}
			c, ok, e := a.publisherConfig()
			if e != nil {
				return e
			}
			if !ok {
				return errors.New("先运行subscription init")
			}
			before, _ := json.Marshal(c)
			if flagSet(f, "formats") {
				c.Formats = strings.Split(*formats, ",")
			}
			if flagSet(f, "sing-box-version") {
				c.SingBoxVersion = *singVersion
			}
			if flagSet(f, "mihomo-version") {
				c.MihomoVersion = *mihomoVersion
			}
			if flagSet(f, "allow-lossy") {
				c.AllowLossy = *lossy
			}
			b, _ := json.Marshal(c)
			if _, e = decodePublisherConfig(b); e != nil {
				return e
			}
			st, e := a.store.Load()
			if e != nil {
				return e
			}
			if e = st.Validate(); e != nil {
				return e
			}
			old, e := subscription.Read(c.Directory)
			if e != nil {
				return e
			}
			next, e := publicationForState(st, c, old)
			if e != nil {
				return e
			}
			if !bytes.Equal(before, b) {
				if e = node.AtomicWrite(filepath.Join(a.store.Root, "subscription-publisher-before-"+node.Token(8)+".json"), before, 0600); e != nil {
					return e
				}
				if e = node.AtomicWrite(filepath.Join(a.store.Root, publisherConfigName), b, 0600); e != nil {
					return e
				}
			}
			if e = subscription.Publish(c.Directory, next, c.GroupID); e != nil {
				return fmt.Errorf("订阅发布选项已保存；快照更新未确认，请检查status并publish重试：%w", e)
			}
			fmt.Fprintln(os.Stderr, "订阅发布选项和快照已更新；未修改代理配置、凭据或服务。")
			return nil
		})
	case "status":
		if e := rejectTopologyFlags(f, "json"); e != nil {
			return e
		}
		return a.store.InspectExisting(func() error {
			c, ok, e := a.publisherConfig()
			if e != nil {
				return e
			}
			if !ok {
				if *machine {
					return queryJSON("qingnode-subscription-authorization", publicSubscriptions{false, []publicSubscriptionRecord{}})
				}
				fmt.Println("未启用在线订阅；仍可本地设备导出。")
				return nil
			}
			s, e := subscription.Read(c.Directory)
			if e != nil {
				return e
			}
			if *machine {
				rows := []publicSubscriptionRecord{}
				for _, r := range s.Records {
					rows = append(rows, publicSubscriptionRecord{r.DeviceID, r.TokenID, r.Revoked, r.ExpiresAt.UTC(), len(r.Outputs)})
				}
				return queryJSON("qingnode-subscription-authorization", publicSubscriptions{true, rows})
			}
			for _, r := range s.Records {
				fmt.Printf("设备=%s\t令牌ID=%s\t撤销=%t\t到期=%s\t已发布格式=%d\n", r.DeviceID, r.TokenID, r.Revoked, r.ExpiresAt.UTC().Format(time.RFC3339), len(r.Outputs))
			}
			return nil
		})
	case "issue", "rotate":
		if e := rejectTopologyFlags(f, "device", "out", "base-url", "expires", "yes"); e != nil {
			return e
		}
		if *out == "" {
			return errors.New("令牌只显示一次，请提供--out保存到新私有文件")
		}
		if cmd == "rotate" && !*yes {
			return errors.New("轮换订阅令牌需要--yes；旧下载链接会失效，代理认证不变")
		}
		now := time.Now().UTC()
		expiry := now.Add(30 * 24 * time.Hour)
		if *expires != "" {
			var e error
			expiry, e = time.Parse(time.RFC3339, *expires)
			if e != nil {
				return errors.New("到期时间须为RFC3339")
			}
		}
		if !expiry.After(now) || expiry.Sub(now) > subscription.MaxTokenLifetime {
			return errors.New("令牌到期须晚于现在且不超过366天")
		}
		if *baseURL != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if e := verifySubscriptionHTTPS(ctx, *baseURL); e != nil {
				return e
			}
		}
		if e := a.probeOutput(*out); e != nil {
			return e
		}
		pinned, e := pinNewOutput(*out)
		if e != nil {
			return e
		}
		defer pinned.root.Close()
		return a.store.InspectExisting(func() error {
			if e := rejectPending(a.store.Root); e != nil {
				return e
			}
			st, e := a.store.Load()
			if e != nil {
				return e
			}
			if e = st.Validate(); e != nil {
				return e
			}
			p, e := node.FindDevice(&st, *id)
			if e != nil {
				return e
			}
			if p.Disabled {
				return errors.New("设备已停用")
			}
			c, ok, e := a.publisherConfig()
			if e != nil {
				return e
			}
			if !ok {
				return errors.New("先运行subscription init")
			}
			s, e := subscription.Read(c.Directory)
			if e != nil {
				return e
			}
			next := s
			next.Records = []subscription.Record{}
			for _, r := range s.Records {
				if r.DeviceID == p.ID {
					if cmd == "issue" {
						return errors.New("该设备已有令牌记录；使用rotate --yes明确替换")
					}
					continue
				}
				next.Records = append(next.Records, r)
			}
			raw, hash, e := subscription.NewToken()
			if e != nil {
				return e
			}
			r := subscription.Record{DeviceID: p.ID, TokenID: node.Token(8), TokenSHA256: hash, IssuedAt: now, ExpiresAt: expiry, Outputs: map[string]subscription.Payload{}}
			next.Records = append(next.Records, r)
			next, e = publicationForState(st, c, next)
			if e != nil {
				return e
			}
			material := tokenMaterial{Version: 1, DeviceID: p.ID, TokenID: r.TokenID, Token: raw, ExpiresAt: expiry, Links: []subscriptionLink{}}
			if *baseURL != "" {
				u, _ := parseSubscriptionOrigin(*baseURL)
				for _, format := range c.Formats {
					if _, published := next.Records[len(next.Records)-1].Outputs[format]; !published {
						continue
					}
					material.Links = append(material.Links, subscriptionLink{Format: format, URL: u.String() + "/s/" + raw + "/" + format})
				}
			}
			b, _ := json.MarshalIndent(material, "", "  ")
			if e = pinned.write(append(b, '\n')); e != nil {
				return e
			}
			if e = subscription.Publish(c.Directory, next, c.GroupID); e != nil {
				return fmt.Errorf("令牌私有材料已生成，但发布结果未确认；请查status，旧链接可能仍有效：%w", e)
			}
			fmt.Fprintf(os.Stderr, "已发布设备%s，令牌ID%s；原始令牌仅在指定私有文件中，未改变代理认证。\n", p.ID, r.TokenID)
			return nil
		})
	case "revoke":
		if e := rejectTopologyFlags(f, "device", "yes"); e != nil {
			return e
		}
		if !*yes {
			return errors.New("撤销下载权限需要--yes；已下载代理认证不会自动失效")
		}
		return a.store.InspectExisting(func() error {
			c, enabled, e := a.publisherConfig()
			if e != nil {
				return e
			}
			if !enabled {
				return errors.New("尚未初始化在线订阅，没有可撤销的下载令牌")
			}
			st, e := a.store.Load()
			if e != nil {
				return e
			}
			p, e := node.FindDevice(&st, *id)
			if e != nil {
				return e
			}
			snapshot, e := subscription.Read(c.Directory)
			if e != nil {
				return e
			}
			found := false
			for _, record := range snapshot.Records {
				if record.DeviceID == p.ID {
					found = true
					break
				}
			}
			if !found {
				return errors.New("该设备尚无已发布的下载令牌")
			}
			if e = a.revokePublishedDevice(p.ID); e != nil {
				return e
			}
			fmt.Fprintln(os.Stderr, "下载权限已撤销；已下载的代理凭据仍有效。停用认证请明确使用device disable --disable-credentials --yes。")
			return nil
		})
	case "check":
		if e := rejectTopologyFlags(f, "base-url"); e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if e := verifySubscriptionHTTPS(ctx, *baseURL); e != nil {
			return e
		}
		fmt.Println("HTTPS系统信任与连接验证通过；未发送令牌，尚未证明下载内容或代理连接。")
		return nil
	case "qr":
		if e := rejectTopologyFlags(f, "token-file", "format", "out"); e != nil {
			return e
		}
		if *out == "" {
			return errors.New("订阅二维码含本设备下载秘密，请用--out保存新私有文件")
		}
		b, e := readTopologyFile(*tokenFile)
		if e != nil {
			return e
		}
		if e = checkTopologyJSON(json.NewDecoder(bytes.NewReader(b))); e != nil {
			return errors.New("令牌私有材料无效")
		}
		var m tokenMaterial
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&m) != nil || m.Version != 1 {
			return errors.New("令牌私有材料格式不支持")
		}
		if e = validateTokenMaterial(m, time.Now()); e != nil {
			return e
		}
		for _, link := range m.Links {
			if link.Format != *format {
				continue
			}
			q, e := qrcode.New(link.URL, qrcode.Medium)
			if e != nil {
				return errors.New("订阅链接过长，无法生成二维码")
			}
			if e = a.probeOutput(*out); e != nil {
				return e
			}
			p, e := pinNewOutput(*out)
			if e != nil {
				return e
			}
			defer p.root.Close()
			return p.write([]byte(q.ToSmallString(false)))
		}
		return errors.New("私有材料中没有该格式的HTTPS链接；本地原始令牌不能冒充已部署订阅")
	default:
		return errors.New("未知subscription操作")
	}
}

func subscriptionServe(args []string) error {
	f := fs("subscription serve")
	dir := f.String("dir", "", "仅含只读发布快照的独立目录")
	listen := f.String("listen", "127.0.0.1:8389", "明确监听地址，不自动接管80/443")
	public := f.String("public-url", "", "已验证的公开HTTPS源地址")
	cert := f.String("tls-cert", "", "PEM证书链")
	key := f.String("tls-key", "", "私有PEM密钥")
	reverse := f.Bool("reverse-proxy", false, "明确通过已有HTTPS反代，仅监听本机HTTP")
	concurrency := f.Int("concurrency", 4, "并发上限1–16；默认4，内存较小时显式用1")
	if e := parse(f, args); e != nil {
		return e
	}
	if _, e := parseSubscriptionOrigin(*public); e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return errors.New("订阅监听失败；请检查端口与权限，不会接管其他服务")
	}
	return subscription.Serve(ctx, listener, subscription.ServeOptions{Directory: *dir, PublicURL: *public, TLSCertFile: *cert, TLSKeyFile: *key, ReverseProxy: *reverse, MaxConcurrent: *concurrency})
}
