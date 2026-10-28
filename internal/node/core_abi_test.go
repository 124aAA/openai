package node

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func abiFixture(t *testing.T, machine uint16, interpreter string) string {
	t.Helper()
	b := make([]byte, 120)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	if interpreter != "" {
		binary.LittleEndian.PutUint64(b[32:], 64)
		binary.LittleEndian.PutUint16(b[56:], 1)
		binary.LittleEndian.PutUint32(b[64:], 3)
		binary.LittleEndian.PutUint64(b[72:], 120)
		binary.LittleEndian.PutUint64(b[96:], uint64(len(interpreter)+1))
		b = append(b, append([]byte(interpreter), 0)...)
	}
	p := filepath.Join(t.TempDir(), "core")
	if err := os.WriteFile(p, b, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCoreABISeparatesArchitectureAndDynamicLoader(t *testing.T) {
	for _, item := range []struct {
		arch    string
		machine uint16
	}{{"amd64", 62}, {"arm64", 183}} {
		p := abiFixture(t, item.machine, "")
		if result, err := CheckCoreABI(p, item.arch); err != nil || result.Architecture != item.arch || result.Interpreter != "" {
			t.Fatal(result, err)
		}
		if _, err := InspectCoreABI(p, "wrong"); err == nil {
			t.Fatal("wrong architecture accepted")
		}
	}
	missing := filepath.Join(t.TempDir(), "missing-loader")
	p := abiFixture(t, 62, missing)
	if result, err := InspectCoreABI(p, "amd64"); err != nil || result.Interpreter != missing {
		t.Fatal("could not report actual interpreter", result, err)
	}
	if _, err := CheckCoreABI(p, "amd64"); err == nil || !strings.Contains(err.Error(), "动态加载器") {
		t.Fatal("missing ABI dependency accepted", err)
	}
	p = abiFixture(t, 62, "../loader")
	if _, err := InspectCoreABI(p, "amd64"); err == nil {
		t.Fatal("relative interpreter accepted")
	}
}
