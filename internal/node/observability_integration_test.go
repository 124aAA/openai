package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"qingnode/internal/coreapi"
)

// This opt-in test covers production Server/Client rendering and real proxy
// transfer through an owned loopback core, separate from the raw-wire fixture.
// Binary provenance must be verified outside this test before SING_BOX_BIN is set.
func TestOfficialCoreRenderedObservationConfig(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("SING_BOX_BIN unset; production-rendered real API/traffic integration was not run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	versionOutput, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	versionFields := strings.Fields(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if len(versionFields) != 3 || versionFields[0] != "sing-box" || versionFields[1] != "version" || !SupportedVersion(versionFields[2]) {
		t.Fatal("requires separately verified official sing-box 1.14.0/1.14.3")
	}
	st := NewState()
	st.CoreVersion = versionFields[2]
	n := ssFixture()
	n.ID = "1111111111111111"
	n.Users[0].ID = "2222222222222222"
	n.Users[1].ID = "3333333333333333"
	n.Host, n.Listen, n.Port = "127.0.0.1", "127.0.0.1", freePort(t)
	st.Nodes = []Node{n}
	st.Observability = &CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: freePort(t), Secret: "production-rendered-loopback-api-secret-08"}
	for st.Observability.Port == n.Port {
		st.Observability.Port = freePort(t)
	}
	serverConfig, err := Server(st, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err = json.Unmarshal(serverConfig, &shape); err != nil {
		t.Fatal(err)
	}
	if _, exists := shape["experimental"]; exists {
		t.Fatal("production API unexpectedly enabled an experimental control API")
	}
	startCore(t, bin, serverConfig)
	api, err := coreapi.New(coreapi.Config{Endpoint: st.Observability.Endpoint(), Secret: st.Observability.Secret, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	before, err := api.Status(ctx)
	if err != nil {
		t.Fatalf("production-rendered API did not expose statistics: %v", err)
	}
	started, err := api.StartedAt(ctx)
	if err != nil || started <= 0 {
		t.Fatalf("official start identity=%d error=%v", started, err)
	}
	wrong, err := coreapi.New(coreapi.Config{Endpoint: st.Observability.Endpoint(), Secret: "wrong-production-fixture-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err = wrong.Status(ctx); err != coreapi.ErrUnauthorized {
		t.Fatalf("production-rendered API failed to enforce secret: %v", err)
	}
	clientPort := freePort(t)
	for clientPort == n.Port || clientPort == st.Observability.Port {
		clientPort = freePort(t)
	}
	clientConfig, err := json.Marshal(Client(n, n.Users[0], clientPort))
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, clientConfig)
	payload := bytes.Repeat([]byte("production-rendered-observation\n"), 2048)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Connection", "close"); w.Write(payload) }))
	defer origin.Close()
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(clientPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal("production-rendered actual proxy transfer", err)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("actual transfer mismatch: %v bytes=%d", err, len(got))
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		after, err := api.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections, err := api.Connections(ctx)
		if err != nil {
			t.Fatal(err)
		}
		matched := false
		for _, event := range connections.Events {
			if connection := event.Connection; connection != nil && connection.Inbound == n.ID && connection.User == n.Users[0].ID && connection.DownlinkTotal >= int64(len(payload)) {
				matched = true
			}
		}
		if after.TrafficAvailable && after.DownlinkTotal >= before.DownlinkTotal+int64(len(payload)) && connections.Reset && matched {
			t.Logf("official %s production Server() API config: authentication enforced; start identity=%d; transferred=%d; global downlink difference=%d; exact node/user ID labels and reset observed", st.CoreVersion, started, len(payload), after.DownlinkTotal-before.DownlinkTotal)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("production labels/traffic/reset evidence missing: available=%t reset=%t matched=%t", after.TrafficAvailable, connections.Reset, matched)
		}
		time.Sleep(30 * time.Millisecond)
	}
}
