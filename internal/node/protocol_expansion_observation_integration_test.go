//go:build linux

package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/coreapi"
)

// Observe actual core labels. A protocol name, a parser success, or a successful
// direct request cannot supply a node/user label missing from the API. These
// bounded process observations are deliberately not a billing ledger.
func TestOfficialCoreProtocolExpansionObservationLabels(t *testing.T) {
	core, version, _ := protocolExpansionInputs(t, false)
	type observationCase struct {
		name  string
		state State
	}
	var cases []observationCase
	for _, protocol := range []string{"anytls", "trojan"} {
		s := protocolExpansionTLSState(t, version)
		index := 0
		if protocol == "trojan" {
			index = 1
		}
		s.Nodes = []Node{s.Nodes[index]}
		cases = append(cases, observationCase{protocol, s})
	}
	for _, c := range protocolExpansionPhase2Cases() {
		s := protocolExpansionPhase2State(t, version, c)
		cases = append(cases, observationCase{protocolExpansionObservationCaseName(s.Nodes[0]), s})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			s := tc.state
			n := s.Nodes[0]
			apiPort := freePort(t)
			for apiPort == n.Port {
				apiPort = freePort(t)
			}
			s.Observability = &CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: apiPort, Secret: "owned-expansion-observation-" + Token(16)}
			backend := &protocolExpansionBackend{processBackend: processBackend{root: t.TempDir(), bin: core}}
			store := &Store{Root: backend.root, Backend: backend, GID: -1}
			t.Cleanup(func() {
				if err := backend.Stop(); err != nil {
					t.Error(err)
				}
			})
			if err := store.WithLock(func() error { return store.Apply(s) }); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			n = loaded.Nodes[0]
			api, err := coreapi.New(coreapi.Config{Endpoint: s.Observability.Endpoint(), Secret: s.Observability.Secret, Timeout: 2 * time.Second, MaxFrameBytes: 256 << 10, MaxStreamBytes: 512 << 10, MaxFrames: 8})
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			wrong, err := coreapi.New(coreapi.Config{Endpoint: s.Observability.Endpoint(), Secret: "wrong-private-observation-secret", Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			_, wrongErr := wrong.Status(ctx)
			wrong.Close()
			if !errors.Is(wrongErr, coreapi.ErrUnauthorized) {
				t.Fatal("real protocol API did not enforce its private secret")
			}
			started, err := api.StartedAt(ctx)
			if err != nil || started <= 0 {
				t.Fatal("actual protocol API start identity unavailable", err)
			}
			epoch := strconv.Itoa(backend.cmd.Process.Pid) + "/" + strconv.FormatInt(started, 10)
			owners := coreapi.Ownership{NodesByInbound: map[string]string{n.ID: n.ID}, UsersByInbound: map[string]map[string]string{n.ID: {}}}
			for _, u := range n.Users {
				owners.UsersByInbound[n.ID][u.ID] = u.ID
			}
			payload := bytes.Repeat([]byte("actual-stable-protocol-label\n"), 2048)
			var hits atomic.Int32
			holds := make(chan chan struct{}, 1)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				release := <-holds
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1))
				_, _ = w.Write(payload)
				w.(http.Flusher).Flush()
				select {
				case <-release:
					_, _ = w.Write([]byte("!"))
				case <-r.Context().Done():
				}
			}))
			defer origin.Close()
			seenUsers := map[string]bool{}
			for _, u := range n.Users {
				before, err := api.Status(ctx)
				if err != nil || !before.TrafficAvailable {
					t.Fatal("actual protocol traffic availability unknown", err)
				}
				var counter coreapi.StatusCounter
				baseline, err := counter.Apply(epoch, before)
				if err != nil || !baseline.Baseline || baseline.Downlink != 0 {
					t.Fatal("protocol observation did not establish unknown-before baseline", err)
				}
				var client *http.Client
				var stop func()
				if n.Protocol == "anytls" || n.Protocol == "trojan" {
					_, client, stop = protocolExpansionClient(t, core, "", version, "sing-box", n, u, n.Certificate.CertPEM, "")
				} else {
					_, client, stop = protocolExpansionPhase2Client(t, core, "", version, "sing-box", n, u, "")
				}
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseRequest := func() { releaseOnce.Do(func() { close(release) }) }
				defer releaseRequest()
				holds <- release
				response, err := client.Get(origin.URL)
				if err != nil {
					stop()
					t.Fatal("actual labeled protocol transfer failed", err)
				}
				body := make([]byte, len(payload))
				_, readErr := io.ReadFull(response.Body, body)
				if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
					releaseRequest()
					response.Body.Close()
					stop()
					t.Fatal("actual labeled protocol payload mismatch", readErr)
				}
				deadline := time.Now().Add(4 * time.Second)
				matched := false
				var actual coreapi.Connection
				var after coreapi.Status
				var observedLabels []string
				for {
					after, err = api.Status(ctx)
					if err != nil || !after.TrafficAvailable {
						stop()
						t.Fatal("actual protocol API unavailable after transfer", err)
					}
					batch, batchErr := api.Connections(ctx)
					if batchErr != nil || !batch.Reset {
						stop()
						t.Fatal("actual protocol connection reset snapshot unavailable", batchErr)
					}
					for _, event := range batch.Events {
						if c := event.Connection; c != nil && len(observedLabels) < 8 {
							observedLabels = append(observedLabels, "inbound="+c.Inbound+" user="+c.User+" bytes="+strconv.FormatInt(c.DownlinkTotal, 10))
						}
						if c := event.Connection; c != nil && c.Inbound == n.ID && c.User == u.ID && c.DownlinkTotal >= int64(len(payload)) {
							actual = *c
							matched = true
						}
					}
					if matched && after.DownlinkTotal >= before.DownlinkTotal+int64(len(payload)) {
						break
					}
					if ctx.Err() != nil || time.Now().After(deadline) {
						releaseRequest()
						response.Body.Close()
						stop()
						t.Fatalf("actual stable labels/positive bytes unavailable: protocol=%s matched=%t available=%t downlink_delta=%d labels=%v; missing labels remain unknown", tc.name, matched, after.TrafficAvailable, after.DownlinkTotal-before.DownlinkTotal, observedLabels)
					}
					time.Sleep(30 * time.Millisecond)
				}
				releaseRequest()
				last, lastErr := io.ReadAll(io.LimitReader(response.Body, 2))
				response.Body.Close()
				if lastErr != nil || string(last) != "!" {
					stop()
					t.Fatal("observed active connection did not complete the exact target response", lastErr)
				}
				stop()
				nodeID, userID := owners.Resolve(actual)
				if nodeID != n.ID || userID != u.ID {
					t.Fatal("actual protocol labels did not resolve by exact stable IDs")
				}
				seenUsers[userID] = true
				// Exercise the existing ownership boundary using the real record as
				// the base. Unknown/missing labels cannot be attributed by type or
				// changed into a successful zero-byte per-user observation.
				unknown := actual
				unknown.User = "not-a-managed-stable-id"
				if node, user := owners.Resolve(unknown); node != n.ID || user != coreapi.UnknownOwner {
					t.Fatal("unknown user label was guessed from protocol/inbound")
				}
				unknown.User = ""
				if _, user := owners.Resolve(unknown); user != coreapi.UnknownOwner {
					t.Fatal("missing user label became a known owner")
				}
				unknown.Inbound = "not-a-managed-inbound"
				unknown.User = u.ID
				if node, user := owners.Resolve(unknown); node != coreapi.UnknownOwner || user != coreapi.UnknownOwner {
					t.Fatal("unowned inbound inherited a user label")
				}
				delta, err := counter.Apply(epoch, after)
				if err != nil || delta.Baseline || delta.Gap || delta.Downlink < int64(len(payload)) {
					t.Fatal("real protocol global observation delta unavailable", err)
				}
				if replay, err := counter.Apply(epoch, after); err != nil || replay.Uplink != 0 || replay.Downlink != 0 {
					t.Fatal("replayed API sample counted duplicate protocol bytes", err)
				}
				t.Logf("official %s %s actual API: node_id=%s user_id=%s payload=%d connection_downlink=%d global_downlink_delta=%d; exact stable labels resolved, unknown labels stayed unknown, replay delta zero; observation only, not billing", version, tc.name, nodeID, userID, len(payload), actual.DownlinkTotal, delta.Downlink)
			}
			if hits.Load() != 2 || len(seenUsers) != 2 {
				t.Fatalf("actual two-user labeled transfers incomplete: requests=%d owners=%d", hits.Load(), len(seenUsers))
			}
		})
	}
}
