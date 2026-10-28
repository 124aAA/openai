package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/term"
	"qingnode/internal/node"
)

// collect-install is an internal bootstrap interface. It reuses the ordinary
// form before a core or service account exists, and emits fields, never State,
// credentials or shell source. A failed/canceled form produces no file.
func collectInstall(args []string) error {
	f := fs("collect-install")
	protocol := f.String("protocol", "", "首次安装的TLS协议")
	out := f.String("out", "", "私有目录内的新参数文件；NUL分隔，不可执行")
	if err := parse(f, args); err != nil {
		return err
	}
	if !node.ProtocolRequiresCertificate(*protocol) {
		return errors.New("此收集入口仅用于需要证书的首次安装")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("首次安装表单需要交互终端；无人值守请提供完整参数")
	}
	a := app{in: bufio.NewReader(os.Stdin)}
	a.wizardCollect = func(fields []string) error { return writeInstallFields(*out, fields) }
	return a.installWizardOptions(true, *protocol, true, false)
}

func writeInstallFields(out string, fields []string) error {
	if len(fields) == 0 || len(fields) > 64 {
		return errors.New("安装参数数量无效")
	}
	for _, value := range fields {
		if len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("安装参数包含控制字符或超过长度上限")
		}
		if value == "--certificate-id" {
			return errors.New("首次安装没有已保存的证书资源；请选择PEM或ACME")
		}
	}
	if err := (&app{}).add("validate-install", fields); err != nil {
		return err
	}
	if !filepath.IsAbs(out) || filepath.Base(out) == "." {
		return errors.New("安装参数文件须为私有目录内的绝对路径")
	}
	parent := filepath.Dir(out)
	i, err := os.Lstat(parent)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
		return errors.New("安装参数目录须为权限0700的真实目录")
	}
	data := []byte("qingnode-install-fields-v1\x00" + strings.Join(fields, "\x00") + "\x00")
	if len(data) > 16<<10 {
		return errors.New("安装参数总量超过16KiB")
	}
	dir, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.OpenFile(filepath.Base(out), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		f.Close()
		if !committed {
			_ = dir.Remove(filepath.Base(out))
		}
	}()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (a *app) applyCollectedInstall(path, protocol string) error {
	i, err := os.Lstat(path)
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > 16<<10 {
		return errors.New("安装参数须为权限0600且不超过16KiB的普通文件")
	}
	b, err := readLimited(path, 16<<10)
	if err != nil {
		return err
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) < 3 || parts[0] != "qingnode-install-fields-v1" || parts[len(parts)-1] != "" {
		return errors.New("安装参数文件版本或结尾无效")
	}
	fields := parts[1 : len(parts)-1]
	if len(fields) > 64 {
		return errors.New("安装参数数量无效")
	}
	matched := false
	for index, value := range fields {
		if value == "--protocol" {
			if index+1 >= len(fields) || fields[index+1] != protocol {
				return errors.New("安装参数协议与选择不一致")
			}
			matched = true
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("安装参数包含控制字符")
		}
		if value == "--certificate-id" {
			return errors.New("首次安装不能引用不存在的证书资源")
		}
	}
	if !matched || !node.ProtocolRequiresCertificate(protocol) {
		return errors.New("安装参数缺少所选TLS协议")
	}
	if err := (&app{}).add("validate-install", fields); err != nil {
		return err
	}
	return a.menuCommand(append([]string{"init"}, fields...))
}
