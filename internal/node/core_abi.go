package node

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CoreABI describes the actual downloaded ELF, independently of the static Go
// manager. Executing version/check is still required to verify dynamic libraries
// and build features; a readable interpreter alone is not a working core.
type CoreABI struct {
	Architecture string   `json:"architecture"`
	Interpreter  string   `json:"interpreter,omitempty"`
	Libraries    []string `json:"needed_libraries"`
}

func InspectCoreABI(path, architecture string) (CoreABI, error) {
	result := CoreABI{Libraries: []string{}}
	f, err := elf.Open(path)
	if err != nil {
		return result, fmt.Errorf("核心不是可识别的Linux ELF程序：%w", err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return result, errors.New("核心ELF位数、字节序或类型不适用")
	}
	switch f.Machine {
	case elf.EM_X86_64:
		result.Architecture = "amd64"
	case elf.EM_AARCH64:
		result.Architecture = "arm64"
	default:
		return result, errors.New("核心ELF架构不受支持")
	}
	if result.Architecture != architecture {
		return result, fmt.Errorf("核心实际架构%s与目标%s不匹配", result.Architecture, architecture)
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if result.Interpreter != "" || p.Filesz < 2 || p.Filesz > 4096 {
			return result, errors.New("核心ELF解释器声明异常")
		}
		b, e := io.ReadAll(io.LimitReader(p.Open(), 4097))
		if e != nil || len(b) != int(p.Filesz) || b[len(b)-1] != 0 {
			return result, errors.New("核心ELF解释器声明不完整")
		}
		result.Interpreter = string(b[:len(b)-1])
		if !filepath.IsAbs(result.Interpreter) || filepath.Clean(result.Interpreter) != result.Interpreter || strings.ContainsAny(result.Interpreter, "\x00\r\n") {
			return result, errors.New("核心ELF解释器路径无效")
		}
	}
	libraries, err := f.ImportedLibraries()
	if err != nil && len(f.Sections) > 0 {
		return result, fmt.Errorf("无法读取核心动态库声明：%w", err)
	}
	result.Libraries = append(result.Libraries, libraries...)
	return result, nil
}

func CheckCoreABI(path, architecture string) (CoreABI, error) {
	result, err := InspectCoreABI(path, architecture)
	if err != nil {
		return result, err
	}
	if result.Interpreter != "" {
		i, e := os.Stat(result.Interpreter)
		if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0111 == 0 {
			return result, fmt.Errorf("核心需要动态加载器%s；当前宿主不可用，请按平台依赖说明准备兼容库，旧核心未被替换", result.Interpreter)
		}
	}
	return result, nil
}
