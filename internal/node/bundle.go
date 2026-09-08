package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func VerifyBundle(dir string) error {
	p := filepath.Join(dir, "SHA256SUMS")
	i, e := os.Lstat(p)
	if e != nil || !i.Mode().IsRegular() {
		return errors.New("发行包摘要文件无效")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("摘要清单过大")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return errors.New("摘要清单格式无效")
		}
		sum, name := fields[0], fields[1]
		if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.Contains(name, "..") || seen[name] {
			return errors.New("摘要清单包含非法或重复路径")
		}
		if _, e := hex.DecodeString(sum); e != nil || len(sum) != 64 {
			return errors.New("摘要格式无效")
		}
		path := filepath.Join(dir, name)
		resolved, e := filepath.EvalSymlinks(path)
		if e != nil {
			return e
		}
		if resolved != path {
			return errors.New("发行包包含符号链接")
		}
		i, e := os.Lstat(path)
		if e != nil || !i.Mode().IsRegular() {
			return errors.New("发行包成员不是普通文件")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		if e != nil {
			return e
		}
		if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sum) {
			return fmt.Errorf("发行包文件 %s 的 SHA-256 不匹配", name)
		}
		seen[name] = true
	}
	if !seen["qingnode"] || !seen["install.sh"] {
		return errors.New("清单缺少管理器或安装器摘要")
	}
	return nil
}
