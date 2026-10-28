//go:build linux

package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type anytlsPoolProcess struct {
	pid        int
	startTicks uint64
	done       <-chan struct{}
}

type anytlsPoolResource struct {
	PID        int     `json:"pid"`
	StartTicks uint64  `json:"start_ticks"`
	CPUTicks   *uint64 `json:"cpu_ticks"`
	RSSBytes   *uint64 `json:"rss_bytes"`
}

// CPU is left in actual procfs clock ticks, without assuming CLK_TCK or
// inventing a percentage. Unreadable optional RSS/CPU values remain null.
func anytlsPoolReadResource(pid int) (anytlsPoolResource, error) {
	r := anytlsPoolResource{PID: pid}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	b, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return r, err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return r, errors.New("owned AnyTLS process identity is unreadable")
	}
	f := strings.Fields(string(b[end+1:])) // field 3 (state) onwards
	if len(f) <= 19 || f[0] == "Z" {
		return r, errors.New("owned AnyTLS process exited or has no start identity")
	}
	r.StartTicks, err = strconv.ParseUint(f[19], 10, 64)
	if err != nil || r.StartTicks == 0 {
		return r, errors.New("owned AnyTLS start identity is invalid")
	}
	u, eu := strconv.ParseUint(f[11], 10, 64)
	s, es := strconv.ParseUint(f[12], 10, 64)
	if eu == nil && es == nil && u <= ^uint64(0)-s {
		n := u + s
		r.CPUTicks = &n
	}
	if b, e := os.ReadFile(filepath.Join(root, "statm")); e == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 1 {
			pages, e := strconv.ParseUint(fields[1], 10, 64)
			pageSize := uint64(os.Getpagesize())
			if e == nil && pages <= ^uint64(0)/pageSize {
				n := pages * pageSize
				r.RSSBytes = &n
			}
		}
	}
	return r, nil
}

// Only established TCP sockets whose inodes are held by this exact process
// count. The endpoint port selects the owned AnyTLS server, excluding mixed
// listeners, origin connections, another PID's sockets and TIME_WAIT entries.
func anytlsPoolOwnedSessions(procRoot string, pid, serverPort int, client bool) ([]string, error) {
	root := filepath.Join(procRoot, strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil {
		return nil, err
	}
	owned := map[string]bool{}
	for _, fd := range fds {
		link, e := os.Readlink(filepath.Join(root, "fd", fd.Name()))
		if os.IsNotExist(e) {
			continue // A socket can close between ReadDir and Readlink.
		}
		if e != nil {
			return nil, e
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	inodes := map[string]bool{}
	read := false
	for _, name := range []string{"tcp", "tcp6"} {
		b, e := os.ReadFile(filepath.Join(root, "net", name))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		read = true
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "01" || !owned[f[9]] {
				continue
			}
			endpoint := f[1]
			if client {
				endpoint = f[2]
			}
			colon := strings.LastIndexByte(endpoint, ':')
			if colon < 0 {
				continue
			}
			port, e := strconv.ParseUint(endpoint[colon+1:], 16, 16)
			if e == nil && int(port) == serverPort {
				inodes[f[9]] = true
			}
		}
	}
	if !read {
		return nil, errors.New("owned process has no readable TCP namespace table")
	}
	result := make([]string, 0, len(inodes))
	for inode := range inodes {
		result = append(result, inode)
	}
	sort.Strings(result)
	return result, nil
}

func anytlsPoolStart(t *testing.T, ctx context.Context, bin string, config []byte) anytlsPoolProcess {
	t.Helper()
	config, err := testCoreStartupLogConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "owned-pool.json")
	if err = os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if output, e := exec.CommandContext(startup, bin, "check", "-c", path).CombinedOutput(); e != nil {
		t.Fatalf("official AnyTLS pool configuration rejected: %v %s", e, output)
	}
	log, err := os.CreateTemp(root, "startup-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() {
			_ = cmd.Process.Kill() // Only this fixture's own child.
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("owned AnyTLS pool child did not stop within cleanup budget")
			}
			log.Close()
		})
	})
	if err = waitCoreStartup(startup, cmd.Process.Pid, config, done, log.Name()); err != nil {
		t.Fatal("owned AnyTLS pool startup", err)
	}
	r, err := anytlsPoolReadResource(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return anytlsPoolProcess{cmd.Process.Pid, r.StartTicks, done}
}

type anytlsPoolSample struct {
	Phase        string             `json:"phase"`
	ElapsedMS    int64              `json:"elapsed_ms"`
	Client       anytlsPoolResource `json:"client"`
	Server       anytlsPoolResource `json:"server"`
	ClientInodes []string           `json:"client_established_inodes"`
	ServerInodes []string           `json:"server_established_inodes"`
}

func TestOfficialAnyTLSIdlePoolOwnedSocketsAndResources(t *testing.T) {
	if os.Getenv("QINGNODE_ANYTLS_POOL_TEST") != "1" {
		t.Skip("QINGNODE_ANYTLS_POOL_TEST=1 and verified SING_BOX_BIN required; real AnyTLS pool evidence not collected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	core, version, _ := protocolExpansionInputs(t, false)
	for _, tc := range []struct {
		name    string
		options *AnyTLSOptions
		keep    int
	}{
		{"default-no-prewarm", nil, -1},
		{"six-second-cleanup-min0", &AnyTLSOptions{IdleSessionCheckInterval: "6s", IdleSessionTimeout: "6s", IdleSessionMinKeep: hyInt(0)}, 0},
		{"min2-retains-existing-only", &AnyTLSOptions{IdleSessionCheckInterval: "6s", IdleSessionTimeout: "6s", IdleSessionMinKeep: hyInt(2)}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			s := protocolExpansionTLSState(t, version)
			s.Nodes = s.Nodes[:1] // Only the owned AnyTLS listener.
			n := s.Nodes[0]
			serverConfig, err := Server(s, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			server := anytlsPoolStart(t, ctx, core, serverConfig)
			n.AnyTLS = tc.options // Client pool settings only; production defaults untouched.
			port := freePort(t)
			cfg := Client(n, n.Users[0], port)
			out := cfg["outbounds"].([]any)[0].(M)
			out["tls"].(M)["certificate"] = []string{n.Certificate.CertPEM}
			if tc.options == nil {
				for _, key := range []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"} {
					if _, exists := out[key]; exists {
						t.Fatal("default fixture unexpectedly overrides core pool defaults", key)
					}
				}
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			client := anytlsPoolStart(t, ctx, core, data)
			samples := 0
			var clientPeakRSS, serverPeakRSS *uint64
			sample := func(phase string) anytlsPoolSample {
				t.Helper()
				v := anytlsPoolSample{Phase: phase, ElapsedMS: time.Since(started).Milliseconds()}
				for _, p := range []anytlsPoolProcess{client, server} {
					select {
					case <-p.done:
						t.Fatal("owned pool process exited during observation")
					default:
					}
				}
				v.Client, err = anytlsPoolReadResource(client.pid)
				if err != nil || v.Client.StartTicks != client.startTicks {
					t.Fatal("client process identity changed", err)
				}
				v.Server, err = anytlsPoolReadResource(server.pid)
				if err != nil || v.Server.StartTicks != server.startTicks {
					t.Fatal("server process identity changed", err)
				}
				v.ClientInodes, err = anytlsPoolOwnedSessions("/proc", client.pid, n.Port, true)
				if err != nil {
					t.Fatal("client owned socket observation unavailable", err)
				}
				v.ServerInodes, err = anytlsPoolOwnedSessions("/proc", server.pid, n.Port, false)
				if err != nil {
					t.Fatal("server owned socket observation unavailable", err)
				}
				for _, p := range []anytlsPoolProcess{client, server} {
					select {
					case <-p.done:
						t.Fatal("owned pool process exited while reading sockets")
					default:
					}
				}
				for _, pair := range []struct {
					value *uint64
					peak  **uint64
				}{{v.Client.RSSBytes, &clientPeakRSS}, {v.Server.RSSBytes, &serverPeakRSS}} {
					if pair.value != nil && (*pair.peak == nil || *pair.value > **pair.peak) {
						n := *pair.value
						*pair.peak = &n
					}
				}
				samples++
				b, _ := json.Marshal(v)
				t.Logf("anytls_pool_sample %s", b)
				return v
			}
			defer func() {
				b, _ := json.Marshal(M{"version": version, "samples": samples, "wall_ms": time.Since(started).Milliseconds(), "client_peak_observed_rss_bytes": clientPeakRSS, "server_peak_observed_rss_bytes": serverPeakRSS})
				t.Logf("anytls_pool_summary %s; three concurrent streams only; CPU ticks have no assumed frequency; RSS includes the whole core and is not per-session allocation or a throughput benchmark", b)
			}()
			waitState := func(phase string, want int, budget time.Duration) anytlsPoolSample {
				t.Helper()
				wait, stop := context.WithTimeout(ctx, budget)
				defer stop()
				for {
					v := sample(phase)
					if len(v.ClientInodes) == want && len(v.ServerInodes) == want {
						return v
					}
					select {
					case <-wait.Done():
						t.Fatalf("owned AnyTLS sessions did not reach %d within %s: client=%d server=%d", want, budget, len(v.ClientInodes), len(v.ServerInodes))
					case <-time.After(250 * time.Millisecond):
					}
				}
			}
			stable := func(phase string, want int, duration time.Duration, retained *anytlsPoolSample) {
				t.Helper()
				until := time.Now().Add(duration)
				for {
					v := sample(phase)
					if len(v.ClientInodes) != want || len(v.ServerInodes) != want || retained != nil && (!reflect.DeepEqual(v.ClientInodes, retained.ClientInodes) || !reflect.DeepEqual(v.ServerInodes, retained.ServerInodes)) {
						t.Fatal("idle pool count or retained socket identity changed without a new request")
					}
					if !time.Now().Before(until) {
						return
					}
					select {
					case <-ctx.Done():
						t.Fatal("AnyTLS pool observation exceeded its 110s parent deadline")
					case <-time.After(250 * time.Millisecond):
					}
				}
			}
			noPrewarm := 1500 * time.Millisecond
			if tc.keep == 2 {
				noPrewarm = 7 * time.Second // Cross the configured six-second cleanup tick.
			}
			stable("before-any-request", 0, noPrewarm, nil)
			if tc.keep < 0 {
				return
			}

			gate, entered := make(chan struct{}), make(chan struct{}, 3)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate) }) }
			var targetHits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				entered <- struct{}{}
				select {
				case <-gate:
					w.Header().Set("Connection", "close")
					_, _ = io.WriteString(w, "owned-anytls-pool-payload")
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(origin.Close)
			t.Cleanup(release)
			httpClient := deviceHTTPClient(port)
			httpClient.Timeout = 10 * time.Second
			t.Cleanup(httpClient.CloseIdleConnections)
			requestCtx, requestCancel := context.WithTimeout(ctx, 10*time.Second)
			defer requestCancel()
			results := make(chan error, 3)
			for i := 0; i < 3; i++ {
				go func() {
					req, e := http.NewRequestWithContext(requestCtx, http.MethodGet, origin.URL, nil)
					if e != nil {
						results <- e
						return
					}
					resp, e := httpClient.Do(req)
					if e != nil {
						results <- e
						return
					}
					body, e := io.ReadAll(io.LimitReader(resp.Body, 256))
					resp.Body.Close()
					if e == nil && (resp.StatusCode != http.StatusOK || string(body) != "owned-anytls-pool-payload") {
						e = errors.New("controlled AnyTLS pool payload did not match")
					}
					results <- e
				}()
			}
			for i := 0; i < 3; i++ {
				select {
				case <-entered:
				case <-requestCtx.Done():
					t.Fatal("three real proxy streams did not reach the held controlled target")
				}
			}
			active := waitState("three-active-streams", 3, 3*time.Second)
			release()
			for i := 0; i < 3; i++ {
				select {
				case e := <-results:
					if e != nil {
						t.Fatal("actual pooled AnyTLS TCP transfer failed", e)
					}
				case <-requestCtx.Done():
					t.Fatal("held AnyTLS TCP transfers did not finish")
				}
			}
			if targetHits.Load() != 3 {
				t.Fatal("controlled target did not receive exactly three requests")
			}
			retained := waitState("after-streams-idle-cleanup", tc.keep, 15*time.Second)
			for _, pair := range []struct{ before, after []string }{{active.ClientInodes, retained.ClientInodes}, {active.ServerInodes, retained.ServerInodes}} {
				for _, inode := range pair.after {
					if !sort.StringsAreSorted(pair.before) || sort.SearchStrings(pair.before, inode) >= len(pair.before) || pair.before[sort.SearchStrings(pair.before, inode)] != inode {
						t.Fatal("retained idle pool contains a newly created socket")
					}
				}
			}
			hold := time.Second
			if tc.keep == 2 {
				hold = 7 * time.Second
			}
			stable("retained-idle-without-new-requests", tc.keep, hold, &retained)
		})
	}
}

func TestAnyTLSPoolSocketObservationRequiresExactOwnershipAndEstablishedState(t *testing.T) {
	root := t.TempDir()
	pid := 42
	path := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(path, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	for fd, inode := range map[string]string{"3": "111", "4": "333", "5": "444", "6": "555"} {
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(path, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	line := func(local, remote, state, inode string) string {
		return fmt.Sprintf("0: %s %s %s 0:0 00:0 0 0 0 %s\n", local, remote, state, inode)
	}
	table := "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n" +
		line("0100007F:AAAA", "0100007F:5F7B", "01", "111") + // Owned established to port 24443.
		line("0100007F:AAAB", "0100007F:5F7B", "01", "222") + // Foreign PID.
		line("0100007F:5F7B", "00000000:0000", "0A", "333") + // Listener, not a session.
		line("0100007F:AAAC", "0100007F:5F7B", "06", "444") + // TIME_WAIT.
		line("0100007F:AAAD", "0100007F:5F7C", "01", "555") // Wrong server port.
	if err := os.WriteFile(filepath.Join(path, "net", "tcp"), []byte(table), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := anytlsPoolOwnedSessions(root, pid, 24443, true)
	if err != nil || !reflect.DeepEqual(got, []string{"111"}) {
		t.Fatalf("foreign/listener/closed socket counted: %v %v", got, err)
	}
	got, err = anytlsPoolOwnedSessions(root, pid, 0xAAAA, false)
	if err != nil || !reflect.DeepEqual(got, []string{"111"}) {
		t.Fatalf("server-side ownership observation wrong: %v %v", got, err)
	}
	if _, err = anytlsPoolOwnedSessions(root, pid+1, 24443, true); err == nil {
		t.Fatal("unreadable process became a zero-session observation")
	}
}
