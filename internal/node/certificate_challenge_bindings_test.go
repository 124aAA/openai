//go:build linux

package node

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func certificateChallengeBindingFixture(port int) State {
	return State{Nodes: []Node{{ID: "1111111111111111", Protocol: "hysteria2", Enabled: true, CertificateID: "2222222222222222", Certificate: &Certificate{Mode: "acme", ServerName: "challenge.example.test", Email: "owner@example.test", ACME: &ACMESettings{Challenge: "http-01", AlternativeHTTPPort: port}}}}}
}

func TestCertificateChallengeBindingsRequireActualPreviousSocketOwnership(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "0.0.0.0:0"
			if network == "tcp" {
				address = ":0"
			} else if network == "tcp6" {
				address = "[::]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				if network == "tcp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
					t.Skipf("IPv6实际绑定不可用；IPv6挑战子项未验证：%v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			state := certificateChallengeBindingFixture(listener.Addr().(*net.TCPAddr).Port)
			snapshot, err := ReadSocketSnapshot("/proc", os.Getpid())
			if err != nil || !snapshot.Complete || !snapshot.NamespaceVerified {
				t.Fatal("cannot verify actual challenge socket ownership", err)
			}
			if err = probeCertificateChallengeBindings(context.Background(), state, state, snapshot); err != nil {
				t.Fatal("actual owned wildcard challenge listener was rejected", err)
			}
			for _, scenario := range []string{"stopped core foreign holder", "incomplete", "unverified namespace", "missing inode", "not in old state"} {
				t.Run(scenario, func(t *testing.T) {
					observed := snapshot
					observed.Sockets = append([]Socket{}, snapshot.Sockets...)
					previous := state
					switch scenario {
					case "stopped core foreign holder":
						var readErr error
						observed, readErr = ReadSocketSnapshot("/proc", 0)
						if readErr != nil || !observed.Complete || !observed.NamespaceVerified {
							t.Fatal("cannot inspect foreign listener with no owned core PID", readErr)
						}
					case "incomplete":
						observed.Complete = false
					case "unverified namespace":
						observed.NamespaceVerified = false
					case "missing inode":
						for i := range observed.Sockets {
							observed.Sockets[i].Inode = ""
						}
					case "not in old state":
						previous = State{}
					}
					if err := probeCertificateChallengeBindings(context.Background(), state, previous, observed); !errors.Is(err, syscall.EADDRINUSE) {
						t.Fatal("old configured port exempted an unverified holder", err)
					}
				})
			}
			if err = listener.Close(); err != nil {
				t.Fatal(err)
			}
			if err = probeCertificateChallengeBindings(context.Background(), state, state, SocketSnapshot{Complete: true, NamespaceVerified: true}); err != nil {
				t.Fatal("stopped core's unused challenge port was rejected", err)
			}
		})
	}
}

func TestCertificateChallengeBindingsCannotClaimAnOwnedUnrelatedAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	state := certificateChallengeBindingFixture(listener.Addr().(*net.TCPAddr).Port)
	snapshot, err := ReadSocketSnapshot("/proc", os.Getpid())
	if err != nil || !snapshot.Complete || !snapshot.NamespaceVerified {
		t.Fatal("cannot inspect distinct actual listener address", err)
	}
	if err = probeCertificateChallengeBindings(context.Background(), state, state, snapshot); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("same process's unrelated concrete listener was claimed as an old wildcard challenge", err)
	}
}
