package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"qingnode/internal/monitor"
	"qingnode/internal/node"
	"qingnode/internal/platform"
	"qingnode/internal/probe"
)

// Sequential PATH scoping invokes a fixed local fake, never the host service.
func monitorFakeSystemctl(t *testing.T, properties string) string {
	t.Helper()
	oldInit := monitorInitKind
	monitorInitKind = func() platform.InitKind { return platform.InitSystemd }
	t.Cleanup(func() { monitorInitKind = oldInit })
	directory := t.TempDir()
	log := filepath.Join(directory, "commands.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$QINGNODE_TEST_MONITOR_LOG\"\nif [ \"$1\" != show ]; then exit 73; fi\nprintf '%s\\n' \"$QINGNODE_TEST_MONITOR_PROPERTIES\"\n"
	if err := os.WriteFile(filepath.Join(directory, "systemctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QINGNODE_TEST_MONITOR_LOG", log)
	t.Setenv("QINGNODE_TEST_MONITOR_PROPERTIES", properties)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func monitorSignal(t *testing.T, observation monitor.Observation, kind monitor.SignalKind) monitor.Signal {
	t.Helper()
	for _, signal := range observation.Signals {
		if signal.Kind == kind {
			return signal
		}
	}
	t.Fatal("missing signal", kind)
	return monitor.Signal{}
}

func TestMonitorAdapterControlledServiceAndIndependentSignals(t *testing.T) {
	a, st := batchFixture(t)
	log := monitorFakeSystemctl(t, "ActiveState=active\nSubState=running\nMainPID=999999999")
	adapter := monitorAdapter{app: a, state: st}
	job := monitorCLIConfig(st).Jobs[0]
	job.Signals = []monitor.SignalKind{monitor.Process, monitor.Listener, monitor.Certificate, monitor.Authentication, monitor.TCP, monitor.UDP, monitor.Target, monitor.CoreAPI}
	generation, before := savedBatchState(t, a)
	observation, err := adapter.Collect(context.Background(), job, monitor.Budget{Timeout: time.Second, MaxBytes: 1024, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if monitorSignal(t, observation, monitor.Process).Status != monitor.Healthy || monitorSignal(t, observation, monitor.Listener).Status != monitor.Unknown || monitorSignal(t, observation, monitor.Authentication).Status != monitor.Unknown || observation.PublicReachability != monitor.Unknown || observation.ManualStopped || observation.Inactive {
		t.Fatalf("signal inference crossed boundaries %+v", observation)
	}
	commands, err := os.ReadFile(log)
	if err != nil || strings.Contains(string(commands), "restart") || strings.Contains(string(commands), "start ") {
		t.Fatal("collector modified host service", err)
	}
	if current, raw := savedBatchState(t, a); current != generation || !bytes.Equal(raw, before) {
		t.Fatal("Collect mutated configuration")
	}
	t.Setenv("QINGNODE_TEST_MONITOR_PROPERTIES", "ActiveState=inactive\nSubState=dead\nMainPID=0")
	observation, err = adapter.Collect(context.Background(), job, monitor.Budget{Timeout: time.Second, MaxBytes: 1024})
	if err != nil || !observation.ManualStopped || monitorSignal(t, observation, monitor.Process).Status != monitor.Failed {
		t.Fatal("manual stop not preserved", err)
	}
	if err = os.WriteFile(filepath.Join(a.store.Root, "transaction.json"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	prior, _ := os.ReadFile(log)
	observation, err = adapter.Collect(context.Background(), job, monitor.Budget{})
	after, _ := os.ReadFile(log)
	if err != nil || !observation.Maintenance || !bytes.Equal(prior, after) {
		t.Fatal("pending maintenance ran collectors", err)
	}
	for _, signal := range observation.Signals {
		if signal.Status != monitor.Unknown {
			t.Fatal("maintenance created positive or failed signal")
		}
	}
}

func TestMonitorAdapterAPITransportAuthAndCapabilityClassification(t *testing.T) {
	for _, kind := range []string{"healthy", "unauthorized", "capability", "invalid", "refused", "timeout", "parent-cancel"} {
		t.Run(kind, func(t *testing.T) {
			a, st := batchFixture(t)
			monitorFakeSystemctl(t, "ActiveState=active\nSubState=running\nMainPID=999999999")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Drain the POST frame so net/http can detect the client's close
				// while this handler deliberately waits for timeout/cancellation.
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/grpc-web+proto")
				switch kind {
				case "healthy":
					w.Write(monitorWireFrame(0, monitorWireVarint(5, 1)))
				case "unauthorized":
					w.Header().Set("Grpc-Status", "16")
				case "capability":
					w.Write(monitorWireFrame(0, nil))
				case "invalid":
					w.Write(monitorWireFrame(1, nil))
				case "timeout", "parent-cancel":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			_, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			port, _ := strconv.Atoi(portText)
			st.Observability = &node.CoreObservation{Enabled: true, Listen: "127.0.0.1", Port: port, Secret: "fixture-api-auth-secret-123456789"}
			if kind == "refused" {
				server.Close()
			}
			adapter := monitorAdapter{app: a, state: st}
			job := monitorCLIConfig(st).Jobs[0]
			job.Signals = []monitor.SignalKind{monitor.CoreAPI}
			ctx := context.Background()
			if kind == "parent-cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			observation, err := adapter.Collect(ctx, job, monitor.Budget{Timeout: time.Second})
			if kind != "parent-cancel" && err != nil {
				t.Fatal(err)
			}
			want := monitor.Unknown
			if kind == "healthy" {
				want = monitor.Healthy
			}
			if kind == "refused" || kind == "timeout" {
				want = monitor.Failed
			}
			if signal := monitorSignal(t, observation, monitor.CoreAPI); signal.Status != want {
				t.Fatalf("%s API=%+v want=%s", kind, signal, want)
			}
		})
	}
}

func TestApplyMonitorProbeSeparatesTCPUDPAuthenticationAndAmbiguity(t *testing.T) {
	code200, code500 := 200, 500
	for _, test := range []struct {
		name           string
		report         probe.Report
		err, cancel    error
		tcp, udp, auth monitor.Status
	}{
		{"tcp-pass-udp-loss", probe.Report{Status: "completed", Samples: []probe.Sample{{Status: "success", HTTPStatus: &code200}}, UDP: &probe.UDPResult{Sent: 1, Lost: 1}}, nil, nil, monitor.Healthy, monitor.Failed, monitor.Healthy},
		{"tcp-fail-udp-pass", probe.Report{Status: "completed", Samples: []probe.Sample{{Status: "failed"}}, UDP: &probe.UDPResult{Sent: 1, Received: 1}}, nil, nil, monitor.Failed, monitor.Healthy, monitor.Healthy},
		{"HTTP500-authenticated", probe.Report{Status: "completed", Samples: []probe.Sample{{Status: "failed", HTTPStatus: &code500}}}, nil, nil, monitor.Healthy, monitor.Unknown, monitor.Healthy},
		{"path-target-auth-ambiguous", probe.Report{Status: "completed", Samples: []probe.Sample{{Status: "failed"}}}, nil, nil, monitor.Failed, monitor.Unknown, monitor.Unknown},
		{"UDP-incomplete", probe.Report{Status: "completed", Samples: []probe.Sample{{Status: "failed"}}, UDP: &probe.UDPResult{Sent: 1, Unfinished: 1}}, nil, nil, monitor.Failed, monitor.Unknown, monitor.Unknown},
		{"cancel", probe.Report{Status: "canceled", Samples: []probe.Sample{{Status: "success", HTTPStatus: &code200}}}, nil, context.Canceled, monitor.Unknown, monitor.Unknown, monitor.Unknown},
		{"error", probe.Report{}, errors.New("fixture"), nil, monitor.Unknown, monitor.Unknown, monitor.Unknown},
		{"no-measurement", probe.Report{}, nil, nil, monitor.Unknown, monitor.Unknown, monitor.Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			signals := map[monitor.SignalKind]monitor.Status{monitor.TCP: monitor.Unknown, monitor.UDP: monitor.Unknown, monitor.Authentication: monitor.Unknown}
			applyMonitorProbe(test.report, test.err, test.cancel, func(kind monitor.SignalKind, status monitor.Status, location, cause string) { signals[kind] = status })
			if signals[monitor.TCP] != test.tcp || signals[monitor.UDP] != test.udp || signals[monitor.Authentication] != test.auth {
				t.Fatalf("got %+v want TCP=%s UDP=%s auth=%s", signals, test.tcp, test.udp, test.auth)
			}
		})
	}
}

func TestMonitorCoreDigestBoundsCancellationAndDiskUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	raw := []byte("owned test executable bytes")
	if err := os.WriteFile(path, raw, 0700); err != nil {
		t.Fatal(err)
	}
	digest, err := monitorCoreDigest(context.Background(), path)
	want := sha256.Sum256(raw)
	if err != nil || digest != hex.EncodeToString(want[:]) {
		t.Fatal(digest, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = monitorCoreDigest(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err = os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err = monitorCoreDigest(context.Background(), alias); err == nil {
		t.Fatal("hashed executable through symlink")
	}
	if status, _ := monitorDiskStatus(node.ResourceOverview{}); status != monitor.Unknown {
		t.Fatal("missing disk measurement treated as zero")
	}
}

func TestMonitorServiceRejectsDuplicateMissingOrInvalidProperties(t *testing.T) {
	monitorFakeSystemctl(t, "ActiveState=active\nSubState=running\nMainPID=1")
	for _, properties := range []string{
		"ActiveState=active\nSubState=running\nMainPID=1\nMainPID=2",
		"ActiveState=active\nSubState=running",
		"ActiveState=active\nSubState=running\nMainPID=-1",
		"ActiveState=imaginary\nSubState=running\nMainPID=1",
	} {
		t.Setenv("QINGNODE_TEST_MONITOR_PROPERTIES", properties)
		if service := readMonitorService(context.Background()); service != (monitorService{}) {
			t.Fatalf("accepted malformed service properties %+v", service)
		}
	}
}

func TestMonitorUDPPreflightSurvivesSuccessfulTCPResultMerge(t *testing.T) {
	st := node.NewState()
	egress := node.Egress{ID: "aaaaaaaaaaaaaaaa", Name: "tcp-only-socks", Protocol: "socks5", Server: "127.0.0.1", Port: 1080, UDP: false, Socks: &node.RemoteSOCKS{}}
	st.Egresses = []node.Egress{egress}
	graph, err := makeEgressGraph(st, egress.ID)
	if err != nil || !graph.SupportsNetwork("tcp") || graph.SupportsNetwork("udp") {
		t.Fatalf("production TCP-only graph capability wrong: %v", err)
	}
	code := 200
	report := probe.Report{Status: "completed", Samples: []probe.Sample{{Status: "success", HTTPStatus: &code}}}
	for _, test := range []struct {
		cause string
		want  monitor.Status
	}{
		{"egress_does_not_support_udp", monitor.Failed},
		{"udp_payload_budget_too_small", monitor.Unknown},
		{"", monitor.Unknown},
	} {
		signals := map[monitor.SignalKind]monitor.Signal{}
		applyMonitorProbeResult(report, nil, nil, test.cause, func(kind monitor.SignalKind, status monitor.Status, location, cause string) {
			signals[kind] = monitor.Signal{Kind: kind, Status: status, Location: location, Cause: cause}
		})
		if signals[monitor.TCP].Status != monitor.Healthy || signals[monitor.Authentication].Status != monitor.Healthy {
			t.Fatal("UDP restriction erased successful independent TCP evidence")
		}
		wantCause := test.cause
		if wantCause == "" {
			wantCause = "no_controlled_udp_measurement"
		}
		if signal := signals[monitor.UDP]; signal.Status != test.want || signal.Cause != wantCause {
			t.Fatalf("preflight lost: UDP=%+v want=%s/%s", signal, test.want, wantCause)
		}
	}
	st.Egresses[0].UDP = true
	graph, err = makeEgressGraph(st, egress.ID)
	if err != nil || !graph.SupportsNetwork("udp") {
		t.Fatalf("control graph did not support declared UDP: %v", err)
	}
	// With no preflight restriction, actual controlled UDP success remains valid.
	report.UDP = &probe.UDPResult{Sent: 1, Received: 1}
	var udp monitor.Signal
	applyMonitorProbeResult(report, nil, nil, "", func(kind monitor.SignalKind, status monitor.Status, location, cause string) {
		if kind == monitor.UDP {
			udp = monitor.Signal{Status: status, Cause: cause}
		}
	})
	if udp.Status != monitor.Healthy || udp.Cause != "controlled_udp_response" {
		t.Fatal("ordinary measured UDP result changed", udp)
	}
}
