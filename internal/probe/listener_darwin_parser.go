package probe

import (
	"errors"
	"strconv"
	"strings"
)

// parseDarwinLsofListener parses `lsof -Pan -p <pid> -iTCP -sTCP:LISTEN -F pfnT`
// machine-readable output and confirms that the exact process `pid` owns a TCP
// LISTEN socket bound to `127.0.0.1:<port>`.
func parseDarwinLsofListener(raw []byte, pid, port int) (bool, error) {
	if pid <= 0 || port <= 0 || port > 65535 {
		return false, nil
	}
	if len(raw) > 256<<10 {
		return false, errors.New("listener table output exceeded safety limit")
	}
	wantPID := strconv.Itoa(pid)
	wantName := "127.0.0.1:" + strconv.Itoa(port)

	currentPID := ""
	inFD := false
	fdListen := false
	fdMatchAddr := false

	flushFD := func() bool {
		return currentPID == wantPID && inFD && fdListen && fdMatchAddr
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			if flushFD() {
				return true, nil
			}
			currentPID = val
			inFD, fdListen, fdMatchAddr = false, false, false
		case 'f':
			if flushFD() {
				return true, nil
			}
			inFD = true
			fdListen = false
			fdMatchAddr = false
		case 'T':
			if val == "ST=LISTEN" {
				fdListen = true
			}
		case 'n':
			if val == wantName {
				fdMatchAddr = true
			}
		}
	}
	if flushFD() {
		return true, nil
	}
	return false, nil
}
