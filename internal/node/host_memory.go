package node

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// AvailableMemory is a read-only upper bound from MemAvailable and every
// visible cgroup memory limit on this process's ancestry. Missing constraint
// evidence is unknown, never silently replaced with the host's larger RAM.
func AvailableMemory(procRoot, sysRoot string) (*uint64, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	b, e := os.ReadFile(filepath.Join(procRoot, "meminfo"))
	if e != nil {
		return nil, errors.New("无法读取 MemAvailable，实际可用内存未知")
	}
	_, host := parseOverviewMemory(string(b))
	if host == nil {
		return nil, errors.New("MemAvailable 缺失或无效，实际可用内存未知")
	}
	available := *host
	b, e = os.ReadFile(filepath.Join(procRoot, "self", "cgroup"))
	if e != nil {
		return nil, errors.New("无法读取当前进程的 cgroup 归属，不能把宿主内存当成容器可用内存")
	}
	group, version := "", 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return nil, errors.New("cgroup 归属格式无效")
		}
		id, e := strconv.Atoi(parts[0])
		if e != nil || id < 0 || strings.TrimSpace(parts[1]) != parts[1] {
			return nil, errors.New("cgroup 层级或控制器格式无效")
		}
		if containsMemory(parts[1]) {
			if version == 1 {
				return nil, errors.New("出现多个 memory cgroup 归属，拒绝猜测")
			}
			group, version = parts[2], 1
		} else if parts[0] == "0" && parts[1] == "" && version != 1 {
			if version == 2 {
				return nil, errors.New("出现多个统一 cgroup 归属")
			}
			group, version = parts[2], 2
		}
	}
	if version == 0 {
		return &available, nil
	}
	if !safeCgroupPath(group) {
		return nil, errors.New("cgroup 归属路径包含越界或不支持的写法")
	}
	b, e = os.ReadFile(filepath.Join(procRoot, "self", "mountinfo"))
	if e != nil {
		return nil, errors.New("无法读取 cgroup 实际挂载位置，实际可用内存未知")
	}
	type mount struct{ root, point string }
	var mounts []mount
	for _, line := range strings.Split(string(b), "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		l, r := strings.Fields(left), strings.Fields(right)
		if len(l) < 6 || len(r) < 3 {
			continue
		}
		if (version == 2 && r[0] != "cgroup2") || (version == 1 && (r[0] != "cgroup" || !containsMemory(r[2]))) {
			continue
		}
		root, point := unescapeMount(l[3]), unescapeMount(l[4])
		if !safeCgroupPath(root) || !safeCgroupPath(point) {
			return nil, errors.New("cgroup 挂载路径无效")
		}
		if group == root || root == "/" || strings.HasPrefix(group, root+"/") || group == "/" {
			mounts = append(mounts, mount{root, point})
		}
	}
	if len(mounts) == 0 {
		return nil, errors.New("进程声明了 memory cgroup，但对应挂载不可见，实际可用内存未知")
	}
	// Prefer the mount exposing the largest ancestor tree, so a tighter parent
	// constraint is not missed merely because a subtree is also bind-mounted.
	chosen := mounts[0]
	for _, m := range mounts[1:] {
		if len(m.root) < len(chosen.root) {
			chosen = m
		}
	}
	mountDir := chosen.point
	if sysRoot != "/sys" {
		if chosen.point != "/sys" && !strings.HasPrefix(chosen.point, "/sys/") {
			return nil, errors.New("隔离 sys 根无法映射该 cgroup 挂载点")
		}
		mountDir = filepath.Join(sysRoot, strings.TrimPrefix(strings.TrimPrefix(chosen.point, "/sys"), "/"))
	}
	rel := ""
	if group != "/" {
		if chosen.root == "/" {
			rel = strings.TrimPrefix(group, "/")
		} else {
			rel = strings.TrimPrefix(strings.TrimPrefix(group, chosen.root), "/")
		}
	}
	current := filepath.Join(mountDir, filepath.FromSlash(rel))
	inside, e := filepath.Rel(mountDir, current)
	if e != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return nil, errors.New("cgroup 路径越过实际挂载根")
	}
	info, e := os.Stat(current)
	if e != nil || !info.IsDir() {
		return nil, errors.New("当前 memory cgroup 目录不可读取")
	}
	memoryDelegated := true
	if version == 2 {
		controllers, e := os.ReadFile(filepath.Join(mountDir, "cgroup.controllers"))
		if e != nil {
			return nil, errors.New("无法确认统一 cgroup 的 memory 控制器，实际可用内存未知")
		}
		// cgroup.controllers describes controllers available to children. It
		// does not cancel an already present memory.max on this cgroup itself.
		memoryDelegated = containsMemory(strings.Join(strings.Fields(string(controllers)), ","))
	}
	for {
		limitName, usageName := "memory.max", "memory.current"
		if version == 1 {
			limitName, usageName = "memory.limit_in_bytes", "memory.usage_in_bytes"
		}
		data, e := os.ReadFile(filepath.Join(current, limitName))
		if e != nil {
			// The actual hierarchy root has no own limit knob. A namespace or
			// subtree root must still provide its control file; missing evidence
			// there must not be treated as an unlimited host.
			if !(version == 2 && os.IsNotExist(e) && ((current == mountDir && chosen.root == "/") || !memoryDelegated)) {
				return nil, errors.New("memory cgroup 限额不可读取，实际可用内存未知")
			}
		} else {
			text := strings.TrimSpace(string(data))
			unlimited := version == 2 && text == "max"
			var limit uint64
			if !unlimited {
				limit, e = strconv.ParseUint(text, 10, 64)
				if e != nil {
					return nil, errors.New("memory cgroup 限额格式无效")
				}
				if version == 1 && limit >= 1<<60 {
					unlimited = true
				}
			}
			if !unlimited {
				data, e = os.ReadFile(filepath.Join(current, usageName))
				if e != nil {
					return nil, errors.New("memory cgroup 使用量不可读取，实际可用内存未知")
				}
				usage, e := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
				if e != nil {
					return nil, errors.New("memory cgroup 使用量格式无效")
				}
				headroom := uint64(0)
				if usage < limit {
					headroom = limit - usage
				}
				if headroom < available {
					available = headroom
				}
			}
		}
		if current == mountDir {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil, errors.New("cgroup 父级路径无效")
		}
		current = parent
	}
	return &available, nil
}

func containsMemory(controllers string) bool {
	for _, c := range strings.Split(controllers, ",") {
		if c == "memory" {
			return true
		}
	}
	return false
}
func safeCgroupPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\r\n\t\\") || path.Clean(p) != p {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." || segment == "." {
			return false
		}
	}
	return true
}
func unescapeMount(p string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(p)
}
