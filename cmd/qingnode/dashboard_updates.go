package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"qingnode/internal/node"
)

var dashboardTag = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func dashboardHTTPClient() *http.Client {
	return &http.Client{Timeout: 9 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || r.URL.Host != "api.github.com" || len(via) >= 3 {
			return errors.New("拒绝非官方 HTTPS 地址或过多跳转")
		}
		return nil
	}}
}

// The caller supplies a test server only in tests; production uses the fixed GitHub API.
func fetchDashboardUpdates(client *http.Client, base, repo string, manager bool) (updateRecord, error) {
	var record updateRecord
	req, e := http.NewRequest(http.MethodGet, base+"/repos/"+repo+"/releases?per_page=100", nil)
	if e != nil {
		return record, e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "QingNode")
	resp, e := client.Do(req)
	if e != nil {
		return record, errors.New("GitHub 查询失败，请检查 DNS/HTTPS 后重试")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return record, fmt.Errorf("GitHub 返回 HTTP %d", resp.StatusCode)
	}
	limit := 2 << 20
	if !manager {
		// Core releases carry many platform assets; 100 releases exceed 2 MiB.
		limit = 64 << 20
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if e != nil || len(b) > limit {
		return record, fmt.Errorf("Release 响应读取失败或超过 %d MiB", limit>>20)
	}
	var releases []node.Release
	if e = json.Unmarshal(b, &releases); e != nil {
		return record, errors.New("GitHub Release 响应格式无效")
	}
	for _, r := range releases {
		if r.Draft || !dashboardTag.MatchString(r.Tag) || (!manager && r.Prerelease) {
			continue
		}
		v := strings.TrimPrefix(r.Tag, "v")
		if manager {
			archive, checksums := false, false
			for _, asset := range r.Assets {
				archive = archive || asset.Name == "qingnode-"+v+"-linux-"+runtime.GOARCH+".tar.gz"
				checksums = checksums || asset.Name == "SHA256SUMS"
			}
			if !archive || !checksums {
				continue
			}
		}
		if record.Latest == "" || node.CompareVersion(v, record.Latest) > 0 {
			record.Latest = v
		}
		if !manager && node.SupportedVersion(v) && (record.Compatible == "" || node.CompareVersion(v, record.Compatible) > 0) {
			record.Compatible = v
		}
	}
	if record.Latest == "" {
		return record, errors.New("最近 100 项 Release 中未找到符合条件的版本")
	}
	return record, nil
}

func mergeDashboardUpdate(old, result updateRecord, installed string, at time.Time, failed bool) updateRecord {
	if !failed {
		old = result
		old.At, old.Installed = at, installed
	}
	old.CheckedAt, old.Failed = at, failed
	return old
}

func (a *app) checkUpdates() error {
	if a.offline {
		return errors.New("版本查询需要联网，请移除 --offline")
	}
	var core string
	if e := a.store.Inspect(func() error {
		s, e := a.store.Load()
		core = s.CoreVersion
		if e == nil && !node.SupportedVersion(core) {
			return errors.New("配置核心版本无效，请先修复节点状态")
		}
		return e
	}); e != nil {
		return e
	}
	targets := []struct{ key, repo, installed string }{
		{"manager", "124aAA/openai", version}, {"core", "SagerNet/sing-box", core},
	}
	results, failures := make([]updateRecord, 2), make([]error, 2)
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], failures[i] = fetchDashboardUpdates(dashboardHTTPClient(), "https://api.github.com", targets[i].repo, i == 0)
		}(i)
	}
	wg.Wait() // No management lock is held during network requests.
	at := time.Now().UTC()
	saveErr := a.updateHistory(func(h *dashboardHistory) {
		if h.Updates == nil {
			h.Updates = map[string]updateRecord{}
		}
		for i, target := range targets {
			h.Updates[target.key] = mergeDashboardUpdate(h.Updates[target.key], results[i], target.installed, at, failures[i] != nil)
		}
	})
	for i, target := range targets {
		if failures[i] != nil {
			a.message("WARN", target.key+" 查询失败，保留上次成功记录："+failures[i].Error())
		} else if i == 0 {
			fmt.Printf("管理器当前 %s，发布版本 %s（含预发布；升级前仍需核验适配与发行包）。\n", target.installed, results[i].Latest)
		} else {
			compatible := results[i].Compatible
			if compatible == "" {
				compatible = "未找到（不代表不存在）"
			}
			fmt.Printf("核心当前 %s，最新正式版 %s，最近 100 项中最高适配版 %s。\n", target.installed, results[i].Latest, compatible)
		}
	}
	return errors.Join(saveErr, failures[0], failures[1])
}
