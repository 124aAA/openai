package coreapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in test starts only an isolated loopback core process. It never
// touches the host service, system routing, firewall, credentials, or a VM.
// SING_BOX_BIN must name a separately verified official 1.14.0/1.14.3 binary;
// a version string alone is not proof of binary provenance.
func TestOfficialCoreGRPCWebObservation(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("SING_BOX_BIN unset; real official API/auth/traffic observation was not run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	firstLine := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	if err != nil || firstLine != "sing-box version 1.14.0" && firstLine != "sing-box version 1.14.3" {
		t.Fatalf("requires separately verified official core 1.14.0/1.14.3: %v %s", err, firstLine)
	}
	port := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	apiPort, mixedPort := port(), port()
	for mixedPort == apiPort {
		mixedPort = port()
	}
	secret := "qingnode-loopback-integration-secret-08"
	config := map[string]any{
		"log":       map[string]any{"disabled": true},
		"services":  []any{map[string]any{"type": "api", "tag": "qingnode-test-api", "listen": "127.0.0.1", "listen_port": apiPort, "secret": secret}},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "managed-inbound", "listen": "127.0.0.1", "listen_port": mixedPort, "users": []any{map[string]string{"username": "managed-user", "password": "loopback-fixture-password"}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "core-api.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if out, checkErr := exec.CommandContext(ctx, bin, "check", "-c", path).CombinedOutput(); checkErr != nil {
		t.Fatalf("official core did not accept api service: %v %s", checkErr, out)
	}
	command := exec.CommandContext(ctx, bin, "run", "-c", path)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func(running *exec.Cmd, completed chan<- error) { completed <- running.Wait() }(command, done)
	running := true
	defer func() {
		if !running {
			return
		}
		command.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("isolated core did not exit")
		}
	}()
	client, err := New(Config{Endpoint: fmt.Sprintf("http://127.0.0.1:%d", apiPort), Secret: secret, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var before Status
	deadline := time.Now().Add(8 * time.Second)
	for {
		before, err = client.Status(ctx)
		if err == nil {
			break
		}
		select {
		case processErr := <-done:
			running = false
			t.Fatalf("isolated core exited before API became available: %v", processErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("official gRPC-Web status unavailable: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !before.TrafficAvailable {
		t.Fatal("official API did not expose trafficAvailable")
	}
	started, err := client.StartedAt(ctx)
	if err != nil || started <= 0 {
		t.Fatalf("official StartedAt=%d error=%v", started, err)
	}
	// Exercise native server rejection with both absent and incorrect metadata.
	for _, authorization := range []string{"", "Bearer wrong-fixture-secret"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint+servicePath+"GetStartedAt", bytes.NewReader([]byte{0, 0, 0, 0, 0}))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/grpc-web+proto")
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, err := client.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.Header.Get("Grpc-Status") != "16" && !bytes.Contains(body, []byte("grpc-status: 16")) {
			t.Fatalf("official API did not reject unauthorized local request: HTTP %d", response.StatusCode)
		}
	}
	payload := bytes.Repeat([]byte("qingnode-local-api-observation\n"), 2048)
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Connection", "close"); w.Write(payload) }))
	defer fixture.Close()
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	proxyURL.User = url.UserPassword("managed-user", "loopback-fixture-password")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	trafficClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := trafficClient.Get(fixture.URL)
	if err != nil {
		t.Fatal("real core loopback proxy transfer", err)
	}
	received, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("real transfer mismatch: %v bytes=%d", err, len(received))
	}
	var after Status
	var snapshot ConnectionBatch
	deadline = time.Now().Add(5 * time.Second)
	for {
		after, err = client.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err = client.Connections(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if after.UplinkTotal > before.UplinkTotal && after.DownlinkTotal >= before.DownlinkTotal+int64(len(payload)) && len(snapshot.Events) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("real transfer not reflected in API: before=%+v after=%+v events=%d", before, after, len(snapshot.Events))
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !snapshot.Reset {
		t.Fatal("official connection initial frame was not reset")
	}
	matched := false
	for _, event := range snapshot.Events {
		if event.Connection != nil && event.Connection.Inbound == "managed-inbound" {
			matched = true
			if event.Connection.User != "managed-user" {
				t.Fatalf("official user label missing/incorrect: %q", event.Connection.User)
			}
			if event.Connection.DownlinkTotal < int64(len(payload)) {
				t.Fatalf("connection transfer missing bytes: %d", event.Connection.DownlinkTotal)
			}
		}
	}
	if !matched {
		t.Fatal("official connection snapshot lacked managed inbound label")
	}
	// Reconnect creates a new reset snapshot; it must not become another delta.
	reconnected, err := client.Connections(ctx)
	if err != nil || !reconnected.Reset {
		t.Fatalf("reconnected snapshot: %v reset=%v", err, reconnected.Reset)
	}
	var counter StatusCounter
	if _, err = counter.Apply(fmt.Sprintf("%d/%d", command.Process.Pid, started), before); err != nil {
		t.Fatal(err)
	}
	delta, err := counter.Apply(fmt.Sprintf("%d/%d", command.Process.Pid, started), after)
	if err != nil || delta.Downlink < int64(len(payload)) {
		t.Fatalf("real global difference=%+v error=%v", delta, err)
	}
	if repeated, err := counter.Apply(counter.Epoch, after); err != nil || repeated.Uplink != 0 || repeated.Downlink != 0 {
		t.Fatalf("replay duplicate counted: %+v %v", repeated, err)
	}
	oldPID, oldEpoch := command.Process.Pid, counter.Epoch
	oldConnectionIDs := make(map[string]bool)
	for _, event := range snapshot.Events {
		oldConnectionIDs[event.ID] = true
	}
	// Stop and reap this test's own official core. A dead API is unavailable,
	// never a successful zero measurement, even when the same client is reused.
	if err = command.Process.Kill(); err != nil {
		t.Fatal("kill isolated first-epoch core", err)
	}
	select {
	case <-done:
		running = false
	case <-ctx.Done():
		t.Fatal("first-epoch core did not exit within test budget", ctx.Err())
	}
	stoppedStatus, stoppedErr := client.Status(ctx)
	if !errors.Is(stoppedErr, ErrTransport) || !errors.Is(stoppedErr, ErrUnavailable) || stoppedStatus.TrafficAvailable {
		t.Fatalf("stopped API must fail instead of returning usable zero traffic: status=%+v error=%v", stoppedStatus, stoppedErr)
	}
	counter.MarkGap()
	// Reuse the exact file, API port and proxy port: no endpoint change can
	// explain the new epoch or hide an old connection-history replay.
	command = exec.CommandContext(ctx, bin, "run", "-c", path)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err = command.Start(); err != nil {
		t.Fatal("restart isolated core using unchanged configuration", err)
	}
	running = true
	done = make(chan error, 1)
	go func(restarted *exec.Cmd, completed chan<- error) { completed <- restarted.Wait() }(command, done)
	var newBefore Status
	deadline = time.Now().Add(5 * time.Second)
	for {
		newBefore, err = client.Status(ctx)
		if err == nil {
			break
		}
		select {
		case processErr := <-done:
			running = false
			t.Fatalf("restarted isolated core exited before API readiness: %v", processErr)
		default:
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			t.Fatalf("restarted official API unavailable: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	newStarted, err := client.StartedAt(ctx)
	if err != nil || command.Process.Pid == oldPID || newStarted <= started {
		t.Fatalf("real restart did not change process/start identity: PID %d -> %d, StartedAt %d -> %d, error=%v", oldPID, command.Process.Pid, started, newStarted, err)
	}
	newEpoch := fmt.Sprintf("%d/%d", command.Process.Pid, newStarted)
	if newEpoch == oldEpoch || !newBefore.TrafficAvailable || newBefore.UplinkTotal >= after.UplinkTotal || newBefore.DownlinkTotal >= after.DownlinkTotal {
		t.Fatalf("new core must expose its own lower counters: old=%+v new=%+v epoch=%s -> %s", after, newBefore, oldEpoch, newEpoch)
	}
	resetDelta, err := counter.Apply(newEpoch, newBefore)
	if err != nil || !resetDelta.Baseline || !resetDelta.Reset || !resetDelta.Gap || resetDelta.Uplink != 0 || resetDelta.Downlink != 0 {
		t.Fatalf("new epoch did not establish a gap/reset baseline with zero counted bytes: delta=%+v error=%v", resetDelta, err)
	}
	newSnapshot, err := client.Connections(ctx)
	if err != nil || !newSnapshot.Reset {
		t.Fatalf("new epoch did not send reset snapshot: reset=%v error=%v", newSnapshot.Reset, err)
	}
	for _, event := range newSnapshot.Events {
		if oldConnectionIDs[event.ID] {
			t.Fatalf("new core replayed an old-epoch connection ID: %s", event.ID)
		}
	}
	if len(newSnapshot.Events) != 0 {
		t.Fatalf("new untouched core retained connection history: events=%d", len(newSnapshot.Events))
	}
	response, err = trafficClient.Get(fixture.URL)
	if err != nil {
		t.Fatal("real proxy transfer after restart", err)
	}
	received, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("new-epoch transfer mismatch: error=%v bytes=%d", err, len(received))
	}
	var newAfter Status
	deadline = time.Now().Add(4 * time.Second)
	for {
		newAfter, err = client.Status(ctx)
		if err != nil {
			t.Fatal("new-epoch status after real transfer", err)
		}
		if newAfter.UplinkTotal > newBefore.UplinkTotal && newAfter.DownlinkTotal >= newBefore.DownlinkTotal+int64(len(payload)) {
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			t.Fatalf("new-epoch transfer absent from counters: before=%+v after=%+v", newBefore, newAfter)
		}
		time.Sleep(30 * time.Millisecond)
	}
	newDelta, err := counter.Apply(newEpoch, newAfter)
	if err != nil || newDelta.Baseline || newDelta.Reset || newDelta.Gap || newDelta.Uplink <= 0 || newDelta.Downlink < int64(len(payload)) {
		t.Fatalf("new-epoch traffic difference invalid: delta=%+v error=%v", newDelta, err)
	}
	if counter.ObservedUplink != delta.Uplink+newDelta.Uplink || counter.ObservedDownlink != delta.Downlink+newDelta.Downlink {
		t.Fatalf("cross-epoch observations repeated old traffic: observed=%d/%d old=%+v new=%+v", counter.ObservedUplink, counter.ObservedDownlink, delta, newDelta)
	}
	if repeated, err := counter.Apply(newEpoch, newAfter); err != nil || repeated.Uplink != 0 || repeated.Downlink != 0 {
		t.Fatalf("new-epoch duplicate counted: delta=%+v error=%v", repeated, err)
	}
	newSnapshot, err = client.Connections(ctx)
	if err != nil || !newSnapshot.Reset || len(newSnapshot.Events) == 0 {
		t.Fatalf("new-epoch transfer connection snapshot absent: reset=%v events=%d error=%v", newSnapshot.Reset, len(newSnapshot.Events), err)
	}
	for _, event := range newSnapshot.Events {
		if oldConnectionIDs[event.ID] {
			t.Fatalf("old connection history reappeared after new transfer: %s", event.ID)
		}
	}
	t.Logf("official %s: local unauthorized requests rejected; trafficAvailable=true; transfer downlink delta=%d; connection reset/user labels observed", firstLine, delta.Downlink)
	t.Logf("real kill/wait/restart on identical ports: PID %d -> %d; StartedAt %d -> %d; dead API rejected; lower counters established baseline/reset/gap with zero delta; old connection history absent; new-epoch download delta=%d without duplicate bytes", oldPID, command.Process.Pid, started, newStarted, newDelta.Downlink)
}
