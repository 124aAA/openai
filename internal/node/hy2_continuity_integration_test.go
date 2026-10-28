//go:build linux

package node

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// processBackend's original startup check expects a TCP server. Keep its
// Check/Active/Stop/counters, but verify this HY2 server's own UDP socket.
type hy2ContinuityBackend struct {
	processBackend
	logs []string
}

func (b *hy2ContinuityBackend) Activate(st State) error {
	if err := b.Stop(); err != nil {
		return err
	}
	b.starts++
	if b.failNext {
		b.failNext = false
		return errors.New("injected startup failure after stopping old core")
	}
	path := filepath.Join(b.root, "current", "server.json")
	config, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	log, err := os.CreateTemp(b.root, "hy2-continuity-core-log-")
	if err != nil {
		return err
	}
	defer log.Close()
	b.logs = append(b.logs, log.Name())
	b.cmd = exec.Command(b.bin, "run", "-c", path)
	b.cmd.Stdout, b.cmd.Stderr = log, log
	if err = b.cmd.Start(); err != nil {
		b.cmd = nil
		return err
	}
	b.done = make(chan error, 1)
	exited := make(chan struct{})
	cmd, done := b.cmd, b.done
	go func() {
		done <- cmd.Wait()
		close(exited)
	}()
	return waitCoreListeners(cmd.Process.Pid, config, exited, 5*time.Second)
}

func TestOfficialCoreHY2ClientPerformanceKeepsProcessAndTCPStream(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires verified official core; real systemd MainPID is a separate host gate")
	}
	versionOutput, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	versionFields := strings.Fields(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if len(versionFields) != 3 || versionFields[0] != "sing-box" || !SupportedVersion(versionFields[2]) {
		t.Fatal("actual core is outside the fixed 1.14.x compatibility line")
	}
	state := hyFixture(t)
	state.CoreVersion = versionFields[2]
	state.Nodes[0].Port = freePort(t)
	backend := &hy2ContinuityBackend{processBackend: processBackend{root: t.TempDir(), bin: bin}}
	store := &Store{Root: backend.root, Backend: backend, GID: -1}
	t.Cleanup(func() {
		if e := backend.Stop(); e != nil {
			t.Error("owned HY2 server cleanup", e)
		}
		if t.Failed() {
			for _, path := range backend.logs {
				log, _ := os.ReadFile(path)
				t.Logf("owned HY2 server log: %s", log)
			}
		}
	})
	apply := func(st State) State {
		t.Helper()
		if e := store.WithLock(func() error { return store.Apply(st) }); e != nil {
			t.Fatal(e)
		}
		loaded, e := store.Load()
		if e != nil {
			t.Fatal(e)
		}
		return loaded
	}
	state = apply(state)
	identity := state.Clone()
	serverBytes, err := Server(state, store.Root)
	if err != nil {
		t.Fatal(err)
	}
	pid, starts := backend.cmd.Process.Pid, backend.starts
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	clientPort := freePort(t)
	client := Client(state.Nodes[0], state.Nodes[0].Users[0], clientPort)
	client["outbounds"].([]any)[0].(M)["tls"].(M)["certificate"] = []string{state.Nodes[0].Certificate.CertPEM}
	clientBytes, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, clientBytes)
	// Open exactly once. All maintenance runs below share this authenticated
	// HY2-backed TCP stream; an interruption is never hidden by reconnecting.
	stream := sustainedSOCKS(t, clientPort, echo.Addr().(*net.TCPAddr).Port)
	var frames atomic.Int64
	flowErrors := make(chan error, 1)
	flowStop, flowDone := make(chan struct{}), make(chan struct{})
	var closeOnce sync.Once
	closeFlow := func() {
		closeOnce.Do(func() {
			close(flowStop)
			stream.Close()
			<-flowDone
		})
	}
	defer closeFlow()
	go func() {
		defer close(flowDone)
		for {
			select {
			case <-flowStop:
				return
			default:
			}
			payload := bytes.Repeat([]byte{0x5a}, 8192)
			binary.BigEndian.PutUint64(payload, uint64(frames.Load()))
			err := stream.SetDeadline(time.Now().Add(5 * time.Second))
			if err == nil {
				var n int
				n, err = stream.Write(payload)
				if err == nil && n != len(payload) {
					err = io.ErrShortWrite
				}
			}
			got := make([]byte, len(payload))
			if err == nil {
				_, err = io.ReadFull(stream, got)
			}
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("HY2 persistent TCP frame payload changed")
			}
			if err != nil {
				select {
				case <-flowStop:
					return
				default:
					flowErrors <- err
					return
				}
			}
			frames.Add(1)
			select {
			case <-flowStop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	assertIdentity := func(st State) {
		t.Helper()
		if st.Nodes[0].ID != identity.Nodes[0].ID || st.Nodes[0].Enabled != identity.Nodes[0].Enabled || !reflect.DeepEqual(st.Nodes[0].Users, identity.Nodes[0].Users) || !reflect.DeepEqual(st.Nodes[0].Certificate, identity.Nodes[0].Certificate) {
			t.Fatal("client-only performance maintenance changed identity, credentials, certificate, or enabled selection")
		}
	}
	probe := func(stage string) {
		t.Helper()
		if !backend.Active() || backend.cmd.Process.Pid != pid || backend.starts != starts {
			t.Fatal("client-only HY2 maintenance replaced the live server process", stage)
		}
		before := frames.Load()
		deadline := time.Now().Add(5 * time.Second)
		for frames.Load() < before+3 {
			select {
			case e := <-flowErrors:
				t.Fatal("same HY2 TCP stream interrupted", stage, e)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("same HY2 TCP stream stopped advancing", stage)
			}
			time.Sleep(20 * time.Millisecond)
		}
		loaded, e := store.Load()
		if e != nil {
			t.Fatal(e)
		}
		assertIdentity(loaded)
		actual, e := os.ReadFile(filepath.Join(store.Root, "current", "server.json"))
		if e != nil || !bytes.Equal(serverBytes, actual) {
			t.Fatal("client-only settings changed actual server configuration", stage, e)
		}
		if !backend.Active() || backend.cmd.Process.Pid != pid || backend.starts != starts {
			t.Fatal("server process changed while checking active frames", stage)
		}
		t.Logf("%s: server process PID=%d (not systemd MainPID), starts=%d, same-stream complete frames=%d -> %d", stage, pid, starts, before, frames.Load())
	}
	probe("baseline")
	state.Nodes[0].HY2 = &HY2Performance{ClientMode: "brutal", ClientUpMbps: hyInt(11), ClientDownMbps: hyInt(13), Client: &HY2Transport{BBRProfile: "conservative", BrutalDebug: hyBool(false), DisableChromeParrot: hyBool(true), QUIC: &HY2QUIC{StreamReceiveWindow: hyBytes(1 << 20), ConnectionReceiveWindow: hyBytes(4 << 20), IdleTimeout: "45s", KeepAlivePeriod: "2s", MaxConcurrentStreams: hyInt(64), InitialPacketSize: hyInt(1200), DisablePathMTUDiscovery: hyBool(false)}}}
	if e := store.Inspect(func() error {
		impact, e := store.Preview(state)
		if e == nil && (!impact.ClientExport || impact.NeedsRestart || impact.ServerRuntime || impact.HostEffects) {
			return fmt.Errorf("client-only HY2 impact misclassified: %+v", impact)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	state = apply(state)
	probe("client bandwidth, BBR, native QUIC and export choices applied")
	generation, err := store.current()
	if err != nil {
		t.Fatal(err)
	}
	state = apply(state)
	repeatedGeneration, err := store.current()
	if err != nil || repeatedGeneration != generation {
		t.Fatal("identical client-only repeat created a generation", err)
	}
	probe("identical repeated apply")
	if err = store.WithLock(store.Rollback); err != nil {
		t.Fatal(err)
	}
	state, err = store.Load()
	if err != nil || state.Nodes[0].HY2 != nil {
		t.Fatal("client-only rollback did not restore core defaults", err)
	}
	probe("client-only rollback")
	state.Nodes[0].HY2 = &HY2Performance{ClientMode: "bbr", Client: &HY2Transport{BBRProfile: "standard", DisableChromeParrot: hyBool(false)}}
	state = apply(state)
	probe("client automatic BBR and explicit default Chrome choice")
	brokenGeneration, err := store.current()
	if err != nil {
		t.Fatal(err)
	}
	brokenPath := filepath.Join(store.Root, brokenGeneration, "server.json")
	brokenBytes := []byte("damaged HY2 derived-file recovery evidence")
	if err = os.WriteFile(brokenPath, brokenBytes, 0640); err != nil {
		t.Fatal(err)
	}
	state = apply(state)
	repairedGeneration, err := store.current()
	if err != nil || repairedGeneration == brokenGeneration {
		t.Fatal("corrupt derived file was not repaired in a new generation", err)
	}
	original, err := os.ReadFile(brokenPath)
	if err != nil || !bytes.Equal(original, brokenBytes) {
		t.Fatal("repair overwrote the original recovery material", err)
	}
	probe("corrupt derived file repaired")
	closeFlow()
	if err = backend.Stop(); err != nil {
		t.Fatal(err)
	}
	state.Nodes[0].HY2 = &HY2Performance{ClientMode: "brutal", ClientUpMbps: hyInt(17), ClientDownMbps: hyInt(19)}
	state = apply(state)
	assertIdentity(state)
	if backend.Active() || backend.starts != starts {
		t.Fatal("client-only performance edit started an originally stopped HY2 core")
	}
	t.Logf("official %s: server process PID=%d preserved across %d complete 8192-byte frames on one HY2-backed TCP connection; stopped-state edit stayed stopped. The existing test client's configuration stayed fixed; this proves server maintenance continuity, not live client reconfiguration or real systemd MainPID.", state.CoreVersion, pid, frames.Load())
}
