package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// New private material pins its directory before a long probe. An untrusted
// writable parent cannot redirect a privileged result or cleanup into State.
type pinnedOutput struct {
	root         *os.Root
	parent, name string
	info         os.FileInfo
}

func pinNewOutput(path string) (*pinnedOutput, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, name := filepath.Dir(abs), filepath.Base(abs)
	if name == "." || name == ".." || name == string(os.PathSeparator) {
		return nil, errors.New("输出需要明确的新文件或目录名")
	}
	var before os.FileInfo
	for current := parent; ; current = filepath.Dir(current) {
		i, e := os.Lstat(current)
		if e != nil {
			return nil, e
		}
		stat, ok := i.Sys().(*syscall.Stat_t)
		if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) {
			return nil, errors.New("输出父路径须为当前用户或root拥有的真实目录")
		}
		if i.Mode().Perm()&0022 != 0 && (current == parent || i.Mode()&os.ModeSticky == 0 || stat.Uid != 0) {
			return nil, errors.New("输出父目录可被其他用户改写；请改用自己的私有目录")
		}
		if current == parent {
			before = i
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	r, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		r.Close()
		return nil, errors.New("输出父目录在检查期间改变")
	}
	if _, e := r.Lstat(name); !os.IsNotExist(e) {
		r.Close()
		return nil, errors.New("输出必须是尚不存在的新文件或目录")
	}
	return &pinnedOutput{root: r, parent: parent, name: name, info: opened}, nil
}

func (p *pinnedOutput) unchanged() error {
	i, err := os.Lstat(p.parent)
	if err != nil || i.Mode()&os.ModeSymlink != 0 || !os.SameFile(p.info, i) {
		return errors.New("输出父目录已改变；拒绝跟随替换后的路径")
	}
	return nil
}

func (p *pinnedOutput) write(data []byte) error {
	if err := p.unchanged(); err != nil {
		return err
	}
	f, err := p.root.OpenFile(p.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return p.unchanged()
}
