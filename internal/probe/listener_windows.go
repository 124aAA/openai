package probe

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getExtendedTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// MIB_TCPTABLE_OWNER_PID has a DWORD count followed by 24-byte IPv4 rows.
// Microsoft defines local ports in network byte order and PID in the last DWORD.
func ownedListener(pid, port int) (bool, error) {
	if err := getExtendedTCPTable.Find(); err != nil {
		return false, err
	}
	size := uint32(0)
	result, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 3, 0) // AF_INET, TCP_TABLE_OWNER_PID_LISTENER
	if result != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return false, errors.New("cannot size Windows listener table")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if size < 4 || size > 1<<20 {
			return false, errors.New("Windows listener table exceeds bound")
		}
		buf := make([]byte, size)
		result, _, _ = getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 3, 0)
		if result == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if result != 0 || size < 4 || int(size) > len(buf) {
			return false, errors.New("cannot read Windows listener table")
		}
		count := binary.LittleEndian.Uint32(buf[:4])
		if uint64(count)*24+4 > uint64(size) {
			return false, errors.New("invalid Windows listener table")
		}
		for i := uint32(0); i < count; i++ {
			row := buf[4+24*i : 4+24*(i+1)]
			if binary.LittleEndian.Uint32(row[:4]) == 2 && binary.LittleEndian.Uint32(row[4:8]) == 0x0100007f && int(binary.BigEndian.Uint16(row[8:10])) == port && int(binary.LittleEndian.Uint32(row[20:24])) == pid {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("Windows listener table kept changing")
}
