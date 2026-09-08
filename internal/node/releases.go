package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Release struct {
	Tag        string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []ReleaseAsset `json:"assets"`
}
type ReleaseAsset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

var repositoryRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func LatestStable(repo string) (Release, error) {
	var release Release
	if !repositoryRE.MatchString(repo) {
		return release, errors.New("仓库须为 owner/repo")
	}
	client := http.Client{Timeout: 12 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("拒绝不安全跳转")
		}
		return nil
	}}
	req, e := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if e != nil {
		return release, e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "QingNode")
	r, e := client.Do(req)
	if e != nil {
		return release, errors.New("GitHub 版本查询失败；请检查 DNS/HTTPS，或显式指定版本与官方摘要")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return release, fmt.Errorf("GitHub 版本查询返回 HTTP %d；可能未发布或已触发 API 限额", r.StatusCode)
	}
	if e = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&release); e != nil {
		return release, e
	}
	if release.Draft || release.Prerelease || !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(release.Tag) {
		return release, errors.New("GitHub 未返回正式版本")
	}
	return release, nil
}
func (r Release) CoreDigest() string {
	v := strings.TrimPrefix(r.Tag, "v")
	name := fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", v, runtime.GOARCH)
	for _, a := range r.Assets {
		if a.Name == name && strings.HasPrefix(a.Digest, "sha256:") {
			return strings.TrimPrefix(a.Digest, "sha256:")
		}
	}
	return ""
}
func CompareVersion(a, b string) int {
	x := strings.Split(strings.TrimPrefix(a, "v"), ".")
	y := strings.Split(strings.TrimPrefix(b, "v"), ".")
	if len(x) != 3 || len(y) != 3 {
		return 0
	}
	for i := range x {
		u, _ := strconv.Atoi(x[i])
		v, _ := strconv.Atoi(y[i])
		if u < v {
			return -1
		}
		if u > v {
			return 1
		}
	}
	return 0
}
