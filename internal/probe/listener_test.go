package probe

import (
	"net"
	"os"
	"runtime"
	"testing"
)

func TestListenerOwnershipRefusesAnUnrelatedPID(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("supported native listener tables are Linux and Windows")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if yes, err := ownedListener(os.Getpid(), port); err != nil || !yes {
		t.Fatalf("own listener was not confirmed: %v", err)
	}
	if yes, err := ownedListener(os.Getpid()+100000, port); err != nil || yes {
		t.Fatalf("unrelated process accepted: %v", err)
	}
}
