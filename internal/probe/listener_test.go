package probe

import (
	"net"
	"os"
	"runtime"
	"testing"
)

func TestListenerOwnershipRefusesAnUnrelatedPID(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("supported native listener tables are Linux, macOS and Windows")
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

func TestDarwinLsofListenerParser(t *testing.T) {
	sample := []byte("p4242\nf3\nTST=ESTABLISHED\nn127.0.0.1:1080->127.0.0.1:55112\nf7\nTST=LISTEN\nn127.0.0.1:1080\n")
	if ok, err := parseDarwinLsofListener(sample, 4242, 1080); err != nil || !ok {
		t.Fatalf("expected matching loopback LISTEN fd to succeed: ok=%v err=%v", ok, err)
	}
	if ok, err := parseDarwinLsofListener(sample, 9999, 1080); err != nil || ok {
		t.Fatalf("expected mismatched PID to be rejected: ok=%v err=%v", ok, err)
	}
	if ok, err := parseDarwinLsofListener(sample, 4242, 2080); err != nil || ok {
		t.Fatalf("expected mismatched port to be rejected: ok=%v err=%v", ok, err)
	}
	wildcardOnly := []byte("p4242\nf7\nTST=LISTEN\nn*:1080\n")
	if ok, err := parseDarwinLsofListener(wildcardOnly, 4242, 1080); err != nil || ok {
		t.Fatalf("expected wildcard *:port to be rejected when requiring 127.0.0.1 loopback: ok=%v err=%v", ok, err)
	}
	notListen := []byte("p4242\nf7\nTST=CLOSED\nn127.0.0.1:1080\n")
	if ok, err := parseDarwinLsofListener(notListen, 4242, 1080); err != nil || ok {
		t.Fatalf("expected non-LISTEN socket to be rejected: ok=%v err=%v", ok, err)
	}
}
