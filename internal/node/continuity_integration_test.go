package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/subscription"
)

// This backend runs the actual official core, independently of systemd. It
// proves process/connection continuity; acceptance-vps.sh separately observes
// real systemd MainPID, unit permissions and service enable/disable behavior.
type processBackend struct {
	root     string
	bin      string
	cmd      *exec.Cmd
	done     chan error
	starts   int
	failNext bool
}

func (b *processBackend) Check(st State, path string) error {
	out, err := exec.Command(b.bin, "check", "-c", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("official check: %w (%s)", err, out)
	}
	return nil
}
func (b *processBackend) Active() bool {
	if b.cmd == nil {
		return false
	}
	select {
	case <-b.done:
		b.cmd = nil
		return false
	default:
		return true
	}
}
func (b *processBackend) Stop() error {
	if !b.Active() {
		return nil
	}
	err := b.cmd.Process.Kill()
	<-b.done
	b.cmd = nil
	return err
}
func (b *processBackend) Activate(st State) error {
	if err := b.Stop(); err != nil {
		return err
	}
	b.starts++
	if b.failNext {
		b.failNext = false
		return errors.New("injected startup failure after stopping old core")
	}
	b.cmd = exec.Command(b.bin, "run", "-c", filepath.Join(b.root, "current", "server.json"))
	if err := b.cmd.Start(); err != nil {
		b.cmd = nil
		return err
	}
	b.done = make(chan error, 1)
	cmd, done := b.cmd, b.done
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !b.Active() {
			return errors.New("official core exited during startup")
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(st.Nodes[0].Listen, strconv.Itoa(st.Nodes[0].Port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("official core listener did not start")
}

func sustainedSOCKS(t *testing.T, port, destination int) net.Conn {
	t.Helper()
	// Starting a process is not evidence that its listener is ready. Wait for
	// initial readiness only; after this connection is established the test never
	// reconnects, so any maintenance interruption still fails the payload probe.
	var c net.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("client listener did not become ready", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err = io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, []byte{5, 0}) {
		t.Fatal("SOCKS greeting", err, buf)
	}
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(destination >> 8), byte(destination)}
	if _, err = c.Write(request); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(c, head); err != nil || head[1] != 0 {
		t.Fatal("SOCKS connect", err, head)
	}
	length := 4
	if head[3] == 4 {
		length = 16
	} else if head[3] != 1 {
		t.Fatal("unexpected SOCKS reply", head)
	}
	if _, err = io.ReadFull(c, make([]byte, length+2)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOfficialCoreMetadataKeepsProcessAndTCPStream(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires verified official core; systemd MainPID is a separate host gate")
	}
	backend := &processBackend{root: t.TempDir(), bin: bin}
	store := &Store{Root: backend.root, Backend: backend, GID: -1}
	t.Cleanup(func() { _ = backend.Stop() })
	state := NewState()
	versionOutput, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	versionFields := strings.Fields(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if len(versionFields) != 3 || versionFields[0] != "sing-box" || !SupportedVersion(versionFields[2]) {
		t.Fatal("unverified core version")
	}
	state.CoreVersion = versionFields[2]
	n := ssFixture()
	n.Listen, n.Host, n.Port = "127.0.0.1", "127.0.0.1", freePort(t)
	state.Nodes = []Node{n}
	apply := func(st State) {
		t.Helper()
		if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
			t.Fatal(err)
		}
	}
	apply(state)
	state, _ = store.Load()
	pid := backend.cmd.Process.Pid
	starts := backend.starts
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	clientPort := freePort(t)
	client, _ := json.Marshal(Client(n, n.Users[0], clientPort))
	startCore(t, bin, client)
	stream := sustainedSOCKS(t, clientPort, echo.Addr().(*net.TCPAddr).Port)
	var frames atomic.Int64
	flowErrors := make(chan error, 1)
	flowStop, flowDone := make(chan struct{}), make(chan struct{})
	var closeOnce sync.Once
	closeFlow := func() { closeOnce.Do(func() { close(flowStop); stream.Close(); <-flowDone }) }
	defer closeFlow()
	go func() {
		defer close(flowDone)
		for {
			select {
			case <-flowStop:
				return
			default:
			}
			payload := append([]byte(fmt.Sprintf("continuous-connection-frame-%04d", frames.Load())), bytes.Repeat([]byte{0x5a}, 8192)...)
			stream.SetDeadline(time.Now().Add(5 * time.Second))
			_, err := stream.Write(payload)
			got := make([]byte, len(payload))
			if err == nil {
				_, err = io.ReadFull(stream, got)
			}
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("persistent TCP payload changed")
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
	probe := func() {
		t.Helper()
		if !backend.Active() || backend.cmd.Process.Pid != pid || backend.starts != starts {
			t.Fatal("metadata replaced the live core process")
		}
		before := frames.Load()
		deadline := time.Now().Add(5 * time.Second)
		for frames.Load() < before+3 {
			select {
			case err := <-flowErrors:
				t.Fatal("active TCP stream interrupted", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("active TCP stream stopped advancing")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	probe()
	state.Nodes[0].Name = "renamed while connected"
	apply(state)
	probe()
	state, _ = store.Load()
	state.Nodes[0].Host = "localhost"
	apply(state)
	probe()
	state, _ = store.Load()
	endpointServerBefore, err := Server(state, store.Root)
	if err != nil {
		t.Fatal(err)
	}
	connectPort := freePort(t)
	state.Nodes[0].ConnectPort = &connectPort
	apply(state)
	probe()
	state, _ = store.Load()
	state.Nodes[0].AdditionalEndpoints = []ConnectionEndpoint{{ID: "declared-v6", Host: "::1", Port: freePort(t)}}
	apply(state)
	probe()
	endpointServerAfter, err := Server(state, store.Root)
	if err != nil || !bytes.Equal(endpointServerBefore, endpointServerAfter) {
		t.Fatal("client endpoint metadata changed server configuration", err)
	}
	state, _ = store.Load()
	apply(state)
	probe()
	if err = store.WithLock(store.Rollback); err != nil {
		t.Fatal(err)
	}
	probe()
	state, _ = store.Load()
	oldGeneration, _ := store.current()
	if err = os.WriteFile(filepath.Join(store.Root, oldGeneration, "server.json"), []byte("damaged derived evidence"), 0640); err != nil {
		t.Fatal(err)
	}
	apply(state)
	probe()
	old, _ := os.ReadFile(filepath.Join(store.Root, oldGeneration, "server.json"))
	if string(old) != "damaged derived evidence" {
		t.Fatal("repair overwrote original recovery material")
	}
	// Device metadata and actual publication reads share the live proxy test,
	// rather than inferring continuity from a mock restart count.
	publicationDir := filepath.Join(t.TempDir(), "device-publication")
	if err = subscription.Initialize(publicationDir, -1); err != nil {
		t.Fatal(err)
	}
	rawToken, tokenHash, err := subscription.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	p := DeviceProfile{ID: "dededededededede", Name: "continuous-device", Bindings: []DeviceBinding{{NodeID: state.Nodes[0].ID, UserID: state.Nodes[0].Users[0].ID}}}
	state.Devices = []DeviceProfile{p}
	store.AfterCommit = func(st State) error {
		out, e := ExportDeviceProfile(st, st.Devices[0], "sing-box", st.CoreVersion, false)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		return subscription.Publish(publicationDir, subscription.Snapshot{Version: 1, GeneratedAt: now, Records: []subscription.Record{{DeviceID: p.ID, TokenID: "abababababababab", TokenSHA256: tokenHash, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Outputs: map[string]subscription.Payload{"sing-box": {ContentType: "application/json; charset=utf-8", Content: out.Content}}}}}, -1)
	}
	apply(state)
	handler, err := subscription.NewHandler(func() (subscription.Snapshot, error) { return subscription.Read(publicationDir) }, subscription.HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	download := httptest.NewServer(handler)
	defer download.Close()
	requests := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		for i := 0; i < 30; i++ {
			response, e := client.Get(download.URL + "/s/" + rawToken + "/sing-box")
			if e != nil {
				requests <- errors.New("device snapshot request failed")
				return
			}
			data, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || response.StatusCode != 200 || !json.Valid(data) {
				requests <- errors.New("device snapshot was partial or unauthorized")
				return
			}
		}
		requests <- nil
	}()
	for i := 0; i < 5; i++ {
		state, _ = store.Load()
		state.Devices[0].Name = fmt.Sprintf("device-metadata-%d", i)
		state.Nodes[0].Tags = []string{"personal"}
		apply(state)
		probe()
	}
	if err = <-requests; err != nil {
		t.Fatal(err)
	}
	probe()
	store.AfterCommit = nil
	closeFlow()
	// A runtime change starts a replacement once. Inject a subsequent failure
	// after stopping it and require the prior configuration to start again.
	state, _ = store.Load()
	state.Nodes[0].Port = freePort(t)
	apply(state)
	if backend.starts != starts+1 || backend.cmd.Process.Pid == pid {
		t.Fatal("runtime port change did not restart once")
	}
	committed, _ := store.Load()
	failed := committed.Clone()
	failed.Nodes[0].Port = freePort(t)
	backend.failNext = true
	if err = store.WithLock(func() error { return store.Apply(failed) }); err == nil {
		t.Fatal("startup failure was ignored")
	}
	recovered, err := store.Load()
	if err != nil || recovered.Nodes[0].Port != committed.Nodes[0].Port || !backend.Active() {
		t.Fatal("real process restore failed", err)
	}
	if err = backend.Stop(); err != nil {
		t.Fatal(err)
	}
	recovered.Nodes[0].Name = "edit while stopped"
	apply(recovered)
	if backend.Active() {
		t.Fatal("metadata started a stopped core")
	}
	t.Logf("official %s process PID=%d preserved across %d continuously transferred TCP frames on one connection; runtime restart and injected startup recovery also passed", state.CoreVersion, pid, frames.Load())
}

func TestOfficialCandidateArchiveInstall(t *testing.T) {
	archive := os.Getenv("SING_BOX_CANDIDATE_ARCHIVE")
	if archive == "" {
		t.Skip("requires verified 1.14.3 candidate archive")
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	official := map[string]string{
		"amd64": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
		"arm64": "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
	}[runtime.GOARCH]
	if hex.EncodeToString(sum[:]) != official {
		t.Fatal("candidate archive differs from official release digest")
	}
	store, _ := newStore(t)
	if err = store.WithLock(func() error { return InstallCore(store.Root, "1.14.3", official, archive) }); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCore(store.Root, "1.14.3"); err != nil {
		t.Fatal(err)
	}
}
