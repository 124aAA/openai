package coreapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testVarint(field int, value uint64) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3))
	return binary.AppendUvarint(b, value)
}
func testBytes(field int, value []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(value)))
	return append(b, value...)
}
func testFrame(flag byte, payload []byte) []byte {
	b := make([]byte, 5, 5+len(payload))
	b[0] = flag
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return append(b, payload...)
}
func testStatus(up, down uint64) []byte {
	b := testVarint(5, 1)
	b = append(b, testVarint(8, up)...)
	return append(b, testVarint(9, down)...)
}
func testClient(t *testing.T, handler http.HandlerFunc, modify func(*Config)) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	config := Config{Endpoint: server.URL, Secret: "fixture-secret", Timeout: time.Second}
	if modify != nil {
		modify(&config)
	}
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}
func webHeader(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/grpc-web+proto") }

func TestConfigRejectsPublicAndUnauthenticatedEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://example.com:80", "http://localhost:8000", "http://192.168.1.2:80", "http://0.0.0.0:80", "http://127.0.0.1", "https://127.0.0.1:80", "http://127.0.0.1:80/path", "http://a:b@127.0.0.1:80", "http://127.0.0.1:80?q=x", "http://127.0.0.1:80#x"} {
		if _, err := New(Config{Endpoint: endpoint, Secret: "valid"}); err == nil {
			t.Error("accepted unsafe endpoint", endpoint)
		}
	}
	for _, secret := range []string{"", "Bearer injected", "line\nsecret", "\r", "\t", "\x00", "\x7f"} {
		if _, err := New(Config{Endpoint: "http://127.0.0.1:8000", Secret: secret}); err == nil {
			t.Error("accepted unsafe secret")
		}
	}
	for _, endpoint := range []string{"http://127.0.0.1:8000", "http://[::1]:8000"} {
		client, err := New(Config{Endpoint: endpoint, Secret: "valid"})
		if err != nil {
			t.Fatal(err)
		}
		client.Close()
	}
}

func TestTransportFailureIsDistinctFromMissingCapability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	listener.Close()
	client, err := New(Config{Endpoint: endpoint, Secret: "fixture-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Status(context.Background())
	if !errors.Is(err, ErrTransport) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("transport not distinguishable: %v", err)
	}
	if strings.Contains(err.Error(), endpoint) || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("transport error disclosed endpoint or credential")
	}
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) { webHeader(w); w.Write(testFrame(0, nil)) }, nil)
	_, err = client.Status(context.Background())
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTransport) {
		t.Fatalf("missing capability mislabeled transport: %v", err)
	}
}

func TestRealGRPCWebRequestAndStatus(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/daemon.StartedService/SubscribeStatus" || r.Header.Get("Content-Type") != "application/grpc-web+proto" || r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Errorf("wrong API request: %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, testFrame(0, testVarint(1, uint64(time.Second)))) {
			t.Error("wrong interval wire request")
		}
		webHeader(w)
		w.Write(testFrame(0, testStatus(123, 456)))
	}, nil)
	status, err := client.Status(context.Background())
	if err != nil || !status.TrafficAvailable || status.UplinkTotal != 123 || status.DownlinkTotal != 456 {
		t.Fatalf("status=%+v error=%v", status, err)
	}
}

func TestUnavailableAndAuthenticationAreNeverZeroMeasurements(t *testing.T) {
	tests := []struct {
		name  string
		write func(http.ResponseWriter)
		want  error
	}{
		{"missing-capability", func(w http.ResponseWriter) { w.Write(testFrame(0, testVarint(2, 7))) }, ErrUnavailable},
		{"unauthenticated-header", func(w http.ResponseWriter) { w.Header().Set("Grpc-Status", "16") }, ErrUnauthorized},
		{"unauthenticated-trailer", func(w http.ResponseWriter) {
			w.Write(testFrame(0x80, []byte("grpc-status: 16\r\ngrpc-message: secret-is-not-forwarded\r\n")))
		}, ErrUnauthorized},
		{"unimplemented", func(w http.ResponseWriter) { w.Write(testFrame(0x80, []byte("grpc-status: 12\r\n"))) }, ErrUnavailable},
		{"HTTP-auth", func(w http.ResponseWriter) { w.WriteHeader(401) }, ErrUnauthorized},
		{"HTTP-missing", func(w http.ResponseWriter) { w.WriteHeader(404) }, ErrUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) { webHeader(w); tt.write(w) }, nil)
			_, err := client.Status(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "secret-is-not-forwarded") {
				t.Fatal("leaked remote error text")
			}
		})
	}
}

func TestFramingRejectsMalformedTruncatedAndUnboundedResponses(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		contentType string
		want        error
		modify      func(*Config)
	}{
		{"compressed", testFrame(1, testStatus(1, 2)), "", ErrProtocol, nil},
		{"reserved-flag", testFrame(2, nil), "", ErrProtocol, nil},
		{"bad-protobuf", testFrame(0, []byte{0}), "", ErrProtocol, nil},
		{"negative-total", testFrame(0, append(testVarint(5, 1), testVarint(8, ^uint64(0))...)), "", ErrProtocol, nil},
		{"truncated", []byte{0, 0, 0, 0, 8, 1}, "", ErrProtocol, nil},
		{"truncated-header", []byte{0, 0}, "", ErrProtocol, nil},
		{"large-declared-frame", []byte{0, 0, 0, 1, 0}, "", ErrLimit, func(c *Config) { c.MaxFrameBytes = 32 }},
		{"total-byte-limit", testFrame(0, testStatus(1, 2)), "", ErrLimit, func(c *Config) { c.MaxStreamBytes = 5 }},
		{"HTML-not-api", []byte("<html>"), "text/html", ErrProtocol, nil},
		{"malformed-status", testFrame(0x80, []byte("grpc-status: oops\r\n")), "", ErrProtocol, nil},
		{"absent-status", testFrame(0x80, []byte("x-custom: 1\r\n")), "", ErrProtocol, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				webHeader(w)
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				w.Write(tt.body)
			}, tt.modify)
			_, err := client.Status(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
		})
	}
}

func TestSubscriptionsRequireTrailersAndRespectLimitsAndCancel(t *testing.T) {
	for _, withTrailers := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "clean"}[withTrailers], func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				webHeader(w)
				w.Write(testFrame(0, testStatus(1, 2)))
				if withTrailers {
					w.Write(testFrame(0x80, []byte("grpc-status: 0\r\n")))
				}
			}, nil)
			count := 0
			err := client.SubscribeStatus(context.Background(), time.Second, func(Status) error { count++; return nil })
			if count != 1 || withTrailers && err != nil || !withTrailers && !errors.Is(err, ErrProtocol) {
				t.Fatalf("received=%d err=%v", count, err)
			}
		})
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		webHeader(w)
		w.Write(testFrame(0, testStatus(1, 2)))
		w.Write(testFrame(0, testStatus(2, 3)))
	}, func(c *Config) { c.MaxFrames = 1 })
	if err := client.SubscribeStatus(context.Background(), time.Second, func(Status) error { return nil }); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		webHeader(w)
		w.Write(testFrame(0, testStatus(1, 2)))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	started := time.Now()
	err := client.SubscribeStatus(context.Background(), time.Second, func(Status) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("timeout err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Status(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRedirectDoesNotForwardSecret(t *testing.T) {
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer target.Close()
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }, nil)
	if _, err := client.Status(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("followed redirect with credential")
	}
}

func TestConnectionsPreserveExactLabelsAndRequireReset(t *testing.T) {
	connection := testBytes(1, []byte("cid"))
	connection = append(connection, testBytes(2, []byte("node-label"))...)
	connection = append(connection, testBytes(10, []byte("user-label"))...)
	connection = append(connection, testVarint(16, 19)...)
	event := testBytes(2, []byte("cid"))
	event = append(event, testBytes(3, connection)...)
	batch := testBytes(1, event)
	batch = append(batch, testVarint(2, 1)...)
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/daemon.StartedService/SubscribeConnections" {
			t.Error(r.URL.Path)
		}
		webHeader(w)
		w.Write(testFrame(0, batch))
	}, nil)
	got, err := client.Connections(context.Background())
	if err != nil || !got.Reset || len(got.Events) != 1 || got.Events[0].Connection.User != "user-label" || got.Events[0].Connection.Inbound != "node-label" || got.Events[0].Connection.UplinkTotal != 19 {
		t.Fatalf("%+v %v", got, err)
	}
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) { webHeader(w); w.Write(testFrame(0, testBytes(1, event))) }, nil)
	if _, err = client.Connections(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
}

func TestStartedAtWaitsForSuccessfulTrailers(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/daemon.StartedService/GetStartedAt" {
			t.Error(r.URL.Path)
		}
		webHeader(w)
		w.Write(testFrame(0, testVarint(1, 12345)))
		w.Write(testFrame(0x80, []byte("grpc-status: 0\r\n")))
	}, nil)
	got, err := client.StartedAt(context.Background())
	if err != nil || got != 12345 {
		t.Fatalf("got %d %v", got, err)
	}
}
