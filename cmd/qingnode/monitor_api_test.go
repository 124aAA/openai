package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"qingnode/internal/coreapi"
	"qingnode/internal/node"
)

func monitorAPIInput(t *testing.T, config node.CoreObservation) string {
	t.Helper()
	raw, err := json.Marshal(monitorAPIRequest{Version: 1, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-api.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMonitorAPIPrivateStrictInput(t *testing.T) {
	secret := strings.Repeat("x", 32)
	valid := `{"version":1,"config":{"enabled":true,"listen":"127.0.0.1","port":18888,"secret":"` + secret + `"}}`
	if _, err := decodeMonitorAPIRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"secret":`, `"Secret":`, 1),
		strings.Replace(valid, `"secret":`, `"ſecret":`, 1),
		strings.Replace(valid, `"config":{`, `"config":null,"other":{`, 1),
		strings.Replace(valid, `"enabled":true`, `"enabled":true,"arbitrary":"injected"`, 1),
		strings.Replace(valid, `127.0.0.1`, `0.0.0.0`, 1),
		strings.Replace(valid, secret, `short`, 1),
		strings.Replace(valid, secret, `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u007f`, 1),
		valid + ` {}`,
	} {
		if _, err := decodeMonitorAPIRequest([]byte(raw)); err == nil {
			t.Fatal("accepted ambiguous or unsafe private API configuration")
		} else if strings.Contains(err.Error(), secret) {
			t.Fatal("echoed API secret")
		}
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMonitorAPIFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMonitorAPIFile(path); err == nil {
		t.Fatal("read public secret input")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readMonitorAPIFile(link); err == nil {
		t.Fatal("followed API input symlink")
	}
}

func TestMonitorAPIConfigurePreviewCommitAndDisable(t *testing.T) {
	a, original := batchFixture(t)
	backend := &batchBackend{active: true}
	a.store.Backend = backend
	config := node.CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: 18888, Secret: "private-observation-secret-123456789"}
	path := monitorAPIInput(t, config)
	generation, before := savedBatchState(t, a)
	output, err := wizardOutput(t, func() error { return a.monitorAPI([]string{"configure", "--file", path, "--preview"}) })
	if err != nil || strings.Contains(output, config.Secret) {
		t.Fatal("preview error or leaked secret", err)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("preview modified state/service")
	}
	if err = a.monitorAPI([]string{"configure", "--file", path}); err == nil {
		t.Fatal("configuration did not require explicit apply")
	}
	if err = a.monitorAPI([]string{"configure", "--file", path, "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Observability == nil || *loaded.Observability != config || len(loaded.Nodes) != len(original.Nodes) || loaded.Nodes[0].Users[0] != original.Nodes[0].Users[0] || backend.starts != 1 {
		t.Fatal("API config changed credentials/topology or skipped runtime activation")
	}
	status, err := wizardOutput(t, func() error { return a.monitorAPI([]string{"status"}) })
	if err != nil || strings.Contains(status, config.Secret) || !strings.Contains(status, `"runtime_verified": false`) {
		t.Fatal("status leaked secret or claimed runtime proof", err)
	}
	if err = a.monitorAPI([]string{"disable", "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = a.store.Load()
	if err != nil || loaded.Observability == nil || loaded.Observability.Enabled || loaded.Observability.Secret != config.Secret {
		t.Fatal("disable lost private config or failed", err)
	}
	if err = a.monitorAPI([]string{"configure", "--file", path, "--secret", config.Secret, "--yes"}); err == nil {
		t.Fatal("accepted CLI secret")
	}
}

func monitorWireVarint(field int, value uint64) []byte {
	raw := binary.AppendUvarint(nil, uint64(field<<3))
	return binary.AppendUvarint(raw, value)
}
func monitorWireBytes(field int, value []byte) []byte {
	raw := binary.AppendUvarint(nil, uint64(field<<3|2))
	raw = binary.AppendUvarint(raw, uint64(len(value)))
	return append(raw, value...)
}
func monitorWireFrame(flag byte, payload []byte) []byte {
	raw := make([]byte, 5, 5+len(payload))
	raw[0] = flag
	binary.BigEndian.PutUint32(raw[1:], uint32(len(payload)))
	return append(raw, payload...)
}
func monitorWireConnection(id, inbound, user string) []byte {
	connection := monitorWireBytes(1, []byte(id))
	connection = append(connection, monitorWireBytes(2, []byte(inbound))...)
	connection = append(connection, monitorWireBytes(10, []byte(user))...)
	connection = append(connection, monitorWireVarint(16, 40)...)
	connection = append(connection, monitorWireVarint(17, 80)...)
	event := monitorWireBytes(2, []byte(id))
	event = append(event, monitorWireBytes(3, connection)...)
	return monitorWireBytes(1, event)
}

func monitorFixtureAPI(t *testing.T, a *app, handler http.HandlerFunc) node.State {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	st, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	st.Observability = &node.CoreObservation{Enabled: true, Listen: host, Port: port, Secret: "fixture-api-auth-secret-123456789"}
	if err = a.store.WithLock(func() error { return a.store.Apply(st) }); err != nil {
		t.Fatal(err)
	}
	a.offline = false
	return st
}

func TestMonitorTrafficUnavailableAndOfflineNeverFabricateZero(t *testing.T) {
	a, _ := batchFixture(t)
	a.offline = false
	for _, offline := range []bool{false, true} {
		a.offline = offline
		beforeGeneration, before := savedBatchState(t, a)
		output, err := wizardOutput(t, func() error { return a.monitorTraffic(nil) })
		if err != nil {
			t.Fatal(err)
		}
		var report monitorTrafficReport
		if err = json.Unmarshal([]byte(output), &report); err != nil {
			t.Fatal(err)
		}
		if report.Status != "unavailable" || len(report.Samples) != 1 || report.Samples[0].Global != nil || report.Samples[0].TrafficAvailable || report.BillingSuitable {
			t.Fatalf("invented unavailable totals %+v", report)
		}
		if current, raw := savedBatchState(t, a); current != beforeGeneration || !bytes.Equal(raw, before) {
			t.Fatal("traffic query changed State")
		}
	}
}

func TestMonitorTrafficOfficialWireMappingGapsAndNoBilling(t *testing.T) {
	a, st := batchFixture(t)
	backend := &batchBackend{}
	a.store.Backend = backend
	var statusCalls atomic.Int64
	st = monitorFixtureAPI(t, a, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		if r.Header.Get("Authorization") != "Bearer fixture-api-auth-secret-123456789" {
			t.Error("API secret missing from authenticated metadata")
		}
		switch r.URL.Path {
		case "/daemon.StartedService/GetStartedAt":
			w.Write(monitorWireFrame(0, monitorWireVarint(1, 1700000000000)))
			w.Write(monitorWireFrame(0x80, []byte("grpc-status: 0\r\n")))
		case "/daemon.StartedService/SubscribeStatus":
			call := statusCalls.Add(1)
			if call == 2 {
				w.Write(monitorWireFrame(0x80, []byte("grpc-status: 14\r\n")))
				return
			}
			raw := monitorWireVarint(5, 1)
			raw = append(raw, monitorWireVarint(8, uint64(call*10))...)
			raw = append(raw, monitorWireVarint(9, uint64(call*20))...)
			w.Write(monitorWireFrame(0, raw))
		case "/daemon.StartedService/SubscribeConnections":
			raw := monitorWireVarint(2, 1)
			raw = append(raw, monitorWireConnection("11111111-1111-4111-8111-111111111111", st.Nodes[0].ID, st.Nodes[0].Users[0].ID)...)
			raw = append(raw, monitorWireConnection("22222222-2222-4222-8222-222222222222", st.Nodes[1].ID, st.Nodes[1].Users[0].Name)...)
			w.Write(monitorWireFrame(0, raw))
		default:
			t.Error("unexpected API method", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	generation, before := savedBatchState(t, a)
	starts := backend.starts
	output, err := wizardOutput(t, func() error { return a.monitorTraffic([]string{"--samples", "3", "--interval-ms", "100"}) })
	if err != nil {
		t.Fatal(err)
	}
	var report monitorTrafficReport
	if err = json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "partial" || report.BillingSuitable || len(report.Samples) != 3 || report.Samples[1].Global != nil || !report.Samples[2].Gap || report.Samples[2].Delta.Uplink != 20 {
		t.Fatalf("gap/total report %+v", report)
	}
	if len(report.Samples[0].Connections) != 2 || report.Samples[0].Connections[0].NodeID != st.Nodes[0].ID || report.Samples[0].Connections[0].UserID != st.Nodes[0].Users[0].ID || report.Samples[0].Connections[1].UserID != "unknown" {
		t.Fatal("invented user ownership", report.Samples[0].Connections)
	}
	if strings.Contains(output, st.Observability.Secret) {
		t.Fatal("traffic leaked API secret")
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) || backend.starts != starts {
		t.Fatal("read query saved/restarted")
	}
}

func TestMonitorTrafficEpochChangeAndAuthenticationFailureAreUnavailable(t *testing.T) {
	for _, authFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "restart", true: "auth"}[authFailure], func(t *testing.T) {
			a, _ := batchFixture(t)
			var startedCalls atomic.Int64
			monitorFixtureAPI(t, a, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/grpc-web+proto")
				if authFailure {
					w.Header().Set("Grpc-Status", "16")
					return
				}
				var raw []byte
				switch r.URL.Path {
				case "/daemon.StartedService/GetStartedAt":
					raw = monitorWireVarint(1, uint64(1700000000000+startedCalls.Add(1)))
				case "/daemon.StartedService/SubscribeStatus":
					raw = monitorWireVarint(5, 1)
				case "/daemon.StartedService/SubscribeConnections":
					raw = monitorWireVarint(2, 1)
				}
				w.Write(monitorWireFrame(0, raw))
				w.Write(monitorWireFrame(0x80, []byte("grpc-status: 0\r\n")))
			})
			output, err := wizardOutput(t, func() error { return a.monitorTraffic(nil) })
			if err != nil {
				t.Fatal(err)
			}
			var report monitorTrafficReport
			if err = json.Unmarshal([]byte(output), &report); err != nil {
				t.Fatal(err)
			}
			if report.Status != "unavailable" || report.Samples[0].Global != nil || !report.Samples[0].Gap {
				t.Fatalf("accepted cross-epoch/auth sample %+v", report)
			}
		})
	}
}

func TestMonitorTrafficSoftThresholdIsLocalEpochObservation(t *testing.T) {
	threshold := int64(100)
	known := func(up, down int64) []monitorTrafficSample {
		return []monitorTrafficSample{{TrafficAvailable: true, Global: &coreapi.Status{TrafficAvailable: true, UplinkTotal: up, DownlinkTotal: down}}}
	}
	if got := trafficThreshold(known(20, 79), &threshold); got != "below" {
		t.Fatal(got)
	}
	if got := trafficThreshold(known(20, 80), &threshold); got != "reached" {
		t.Fatal(got)
	}
	if got := trafficThreshold(known(math.MaxInt64, math.MaxInt64), &threshold); got != "reached" {
		t.Fatal("sum overflowed", got)
	}
	if got := trafficThreshold(append(known(1, 2), monitorTrafficSample{Gap: true}), &threshold); got != "unknown" {
		t.Fatal("used stale measurement", got)
	}
	if got := trafficThreshold(known(1, 2), nil); got != "unknown" {
		t.Fatal("invented a threshold", got)
	}
	a, _ := batchFixture(t)
	generation, before := savedBatchState(t, a)
	output, err := wizardOutput(t, func() error { return a.monitorTraffic([]string{"--warn-bytes", "100"}) })
	if err != nil {
		t.Fatal(err)
	}
	var report monitorTrafficReport
	if err = json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatal(err)
	}
	if report.ThresholdBytes == nil || *report.ThresholdBytes != 100 || report.ThresholdStatus != "unknown" {
		t.Fatalf("missing data treated below threshold %+v", report)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) {
		t.Fatal("soft threshold changed authentication/configuration")
	}
	for _, value := range []string{"-1", "1152921504606846977"} {
		if err = a.monitorTraffic([]string{"--warn-bytes", value}); err == nil {
			t.Fatal("accepted invalid warning threshold", value)
		}
	}
}

func TestMonitorTrafficRefusesManagedOutputAndPendingMigration(t *testing.T) {
	a, _ := batchFixture(t)
	if err := a.monitorTraffic([]string{"--out", filepath.Join(a.store.Root, "new-observation.json")}); err == nil {
		t.Fatal("traffic wrote new file into production State root")
	}
	if err := os.WriteFile(filepath.Join(a.store.Root, node.MigrationJournalName), []byte("pending fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.monitorTraffic(nil); err == nil {
		t.Fatal("traffic observed during pending migration")
	}
	if err := a.monitorAPI([]string{"status"}); err == nil {
		t.Fatal("API status observed during pending migration")
	}
}
