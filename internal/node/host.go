package node

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const BBRFile = "/etc/sysctl.d/90-qingnode-bbr.conf"
const bbrConfig = "# Managed by QingNode\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"

type Host struct {
	Execute    Runner
	SysctlFile string
}

func (h Host) run(name string, args ...string) ([]byte, error) {
	f := h.Execute
	if f == nil {
		f = Run
	}
	return f(10*time.Second, name, args...)
}
func (h Host) value(key string) (string, error) {
	b, e := h.run("sysctl", "-n", key)
	return strings.TrimSpace(string(b)), e
}
func (h Host) BBRStatus() (string, error) {
	cc, e := h.value("net.ipv4.tcp_congestion_control")
	if e != nil {
		return "", e
	}
	q, e := h.value("net.core.default_qdisc")
	if e != nil {
		return "", e
	}
	available, e := h.value("net.ipv4.tcp_available_congestion_control")
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("当前拥塞控制：%s\n默认队列：%s\n可用算法：%s", cc, q, available), nil
}
func (h Host) EnableBBR() (changed bool, err error) {
	cc, e := h.value("net.ipv4.tcp_congestion_control")
	if e != nil {
		return false, e
	}
	q, e := h.value("net.core.default_qdisc")
	if e != nil {
		return false, e
	}
	if cc == "bbr" && q == "fq" {
		return false, nil
	}
	available, e := h.value("net.ipv4.tcp_available_congestion_control")
	if e != nil {
		return false, e
	}
	if !strings.Contains(" "+available+" ", " bbr ") {
		if _, e = h.run("modprobe", "tcp_bbr"); e != nil {
			return false, errors.New("当前内核未提供 BBR；未安装或更换任何内核")
		}
		available, e = h.value("net.ipv4.tcp_available_congestion_control")
		if e != nil || !strings.Contains(" "+available+" ", " bbr ") {
			return false, errors.New("内核未报告支持 BBR")
		}
	}
	p := h.SysctlFile
	if p == "" {
		p = BBRFile
	}
	old, e := os.ReadFile(p)
	existed := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	if existed {
		info, e := os.Lstat(p)
		if e != nil || !info.Mode().IsRegular() || !strings.HasPrefix(string(old), "# Managed by QingNode\n") {
			return false, errors.New("同名 sysctl 文件不属于 QingNode，拒绝覆盖")
		}
	}
	defer func() {
		if err != nil {
			var recovery []error
			if _, e := h.run("sysctl", "-w", "net.core.default_qdisc="+q); e != nil {
				recovery = append(recovery, e)
			}
			if _, e := h.run("sysctl", "-w", "net.ipv4.tcp_congestion_control="+cc); e != nil {
				recovery = append(recovery, e)
			}
			if existed {
				if e := AtomicWrite(p, old, 0644); e != nil {
					recovery = append(recovery, e)
				}
			} else {
				if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
					recovery = append(recovery, e)
				}
			}
			if len(recovery) > 0 {
				err = fmt.Errorf("BBR 设置失败：%v；恢复未完成：%w", err, errors.Join(recovery...))
			}
		}
	}()
	if err = AtomicWrite(p, []byte(bbrConfig), 0644); err != nil {
		return false, err
	}
	if _, err = h.run("sysctl", "-w", "net.core.default_qdisc=fq"); err != nil {
		return false, err
	}
	if _, err = h.run("sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"); err != nil {
		return false, err
	}
	current, e := h.value("net.ipv4.tcp_congestion_control")
	if e != nil || current != "bbr" {
		return false, errors.New("BBR 设置后读回校验失败")
	}
	return true, nil
}
