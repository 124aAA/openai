package node

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt in separately because this test deliberately closes established local TCP
// sessions by applying an authentication change to the real shared core. It
// starts owned child processes and loopback listeners only, without systemd.
func TestOfficialCredentialExpiryExistingTCPAndNewAuthentication(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if os.Getenv("QINGNODE_EXPIRY_CORE_TEST") != "1" || bin == "" {
		t.Skip("requires QINGNODE_EXPIRY_CORE_TEST=1 and a verified official SING_BOX_BIN; real systemd remains a separate host gate")
	}
	versionOutput, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	versionFields := strings.Fields(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if len(versionFields) != 3 || versionFields[0] != "sing-box" || !SupportedVersion(versionFields[2]) {
		t.Fatal("unsupported official core version")
	}
	for _, scope := range []string{"user", "device-binding"} {
		t.Run(scope, func(t *testing.T) {
			backend := &processBackend{root: t.TempDir(), bin: bin}
			store := &Store{Root: backend.root, Backend: backend, GID: -1}
			t.Cleanup(func() { _ = backend.Stop() })
			s := NewState()
			s.CoreVersion = versionFields[2]
			n := ssFixture()
			n.Listen, n.Host, n.Port = "127.0.0.1", "127.0.0.1", freePort(t)
			s.Nodes = []Node{n}
			device := DeviceProfile{ID: "3000000000000001", Name: "expiry device", Bindings: []DeviceBinding{{NodeID: n.ID, UserID: n.Users[0].ID}, {NodeID: n.ID, UserID: n.Users[1].ID}}}
			s.Devices = []DeviceProfile{device}
			apply := func(st State) {
				t.Helper()
				if err := store.WithLock(func() error { return store.Apply(st) }); err != nil {
					t.Fatal(err)
				}
			}
			apply(s)
			pid, starts := backend.cmd.Process.Pid, backend.starts
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
				}
			}()
			originPayload := "expiry-official-core-authentication-payload"
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, originPayload) }))
			defer origin.Close()
			ports := []int{freePort(t), freePort(t)}
			streams := make([]net.Conn, 2)
			clients := make([]*http.Client, 2)
			for i := range ports {
				config, err := json.Marshal(Client(n, n.Users[i], ports[i]))
				if err != nil {
					t.Fatal(err)
				}
				startCore(t, bin, config)
				streams[i] = sustainedSOCKS(t, ports[i], echo.Addr().(*net.TCPAddr).Port)
				defer streams[i].Close()
				proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(ports[i]))
				transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				clients[i] = &http.Client{Transport: transport, Timeout: 3 * time.Second}
			}
			probeExisting := func(c net.Conn) error {
				payload := bytes.Repeat([]byte("existing-expiry-stream"), 256)
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := c.Write(payload); err != nil {
					return err
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(c, got); err != nil {
					return err
				}
				if !bytes.Equal(got, payload) {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			newAuthentication := func(i int) bool {
				response, err := clients[i].Get(origin.URL)
				if err != nil {
					return false
				}
				defer response.Body.Close()
				data, err := io.ReadAll(response.Body)
				return err == nil && response.StatusCode == http.StatusOK && string(data) == originPayload
			}
			for i, stream := range streams {
				if err := probeExisting(stream); err != nil || !newAuthentication(i) {
					t.Fatal("pre-expiry credential did not establish verified traffic", i, err)
				}
			}
			now := time.Now().UTC()
			e := CredentialExpiration{ID: "4000000000000001", NodeID: n.ID, UserID: n.Users[0].ID, ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano)}
			if scope == "device-binding" {
				e.DeviceID = device.ID
			}
			if err := SetCredentialExpiration(&s, e); err != nil {
				t.Fatal(err)
			}
			apply(s)
			if backend.cmd.Process.Pid != pid || backend.starts != starts {
				t.Fatal("saving a deadline restarted the shared core")
			}
			for i, stream := range streams {
				if err := probeExisting(stream); err != nil {
					t.Fatal("saving/querying a due schedule broke an existing session", i, err)
				}
			}
			candidate, plan, err := ApplyDueExpirations(s, now)
			if err != nil || plan.Ready != 1 {
				t.Fatal(plan, err)
			}
			started := time.Now()
			apply(candidate)
			if backend.cmd.Process.Pid == pid || backend.starts != starts+1 {
				t.Fatal("authentication change did not replace core exactly once")
			}
			for i, stream := range streams {
				err := probeExisting(stream)
				if err == nil {
					t.Fatal("existing TCP stream unexpectedly survived shared-core restart", i)
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("existing TCP probe only timed out; closure was not observed", i, err)
				}
			}
			closedBy := time.Since(started)
			if newAuthentication(0) {
				t.Fatal("new traffic still authenticated with expired credential")
			}
			if !newAuthentication(1) {
				t.Fatal("unrelated credential could not establish new traffic")
			}
			t.Logf("official %s ss2022 %s expiry: expired and unrelated existing TCP sessions both closed within %s of Apply (shared core restart); expired new authentication denied; surviving credential new authentication passed; deadline save preserved PID and established streams", s.CoreVersion, scope, closedBy)
		})
	}
}
