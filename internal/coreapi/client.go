// Package coreapi reads the public sing-box 1.14 gRPC-Web observation API.
// The wire codec is independently implemented and has no sing-box dependency.
package coreapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnavailable = errors.New("core observation unavailable")
	// ErrTransport distinguishes an unreachable local endpoint from an API
	// without traffic capability. Transport errors also match ErrUnavailable.
	ErrTransport    = errors.New("core API transport failed")
	ErrUnauthorized = errors.New("core API authentication rejected")
	ErrProtocol     = errors.New("invalid core API response")
	ErrLimit        = errors.New("core API observation limit exceeded")
)

const servicePath = "/daemon.StartedService/"

// Config requires an explicit loopback IP and a nonempty bearer secret. Timeout
// bounds the entire call, including streams; callers reconnect after expiration.
type Config struct {
	Endpoint       string
	Secret         string
	Timeout        time.Duration
	MaxFrameBytes  int
	MaxFrames      int
	MaxStreamBytes int64
}

type Client struct {
	config   Config
	endpoint string
	http     *http.Client
}

func New(config Config) (*Client, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, errors.New("core API endpoint must be an HTTP loopback address without credentials or path")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return nil, errors.New("core API endpoint requires a loopback IP and explicit port")
	}
	if config.Secret == "" || len(config.Secret) > 4096 {
		return nil, errors.New("core API requires a nonempty bounded bearer secret")
	}
	for _, character := range config.Secret {
		if character < 0x21 || character > 0x7e {
			return nil, errors.New("core API bearer secret must contain printable ASCII without whitespace")
		}
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.MaxFrameBytes == 0 {
		config.MaxFrameBytes = 1 << 20
	}
	if config.MaxFrames == 0 {
		config.MaxFrames = 1024
	}
	if config.MaxStreamBytes == 0 {
		config.MaxStreamBytes = 16 << 20
	}
	if config.Timeout < time.Millisecond || config.Timeout > time.Minute || config.MaxFrameBytes < 1 || config.MaxFrameBytes > 8<<20 || config.MaxFrames < 1 || config.MaxFrames > 65536 || config.MaxStreamBytes < 5 || config.MaxStreamBytes > 64<<20 {
		return nil, errors.New("core API limits are outside supported bounds")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: config.Timeout}).DialContext, ResponseHeaderTimeout: config.Timeout, MaxIdleConnsPerHost: 2, DisableCompression: true}
	return &Client{config: config, endpoint: strings.TrimSuffix(config.Endpoint, "/"), http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

// Status obtains the first status sample. Missing traffic capability is an
// explicit error; callers must never turn it into a zero-byte measurement.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var result Status
	err := c.read(ctx, "SubscribeStatus", intervalMessage(time.Second), func(data []byte) (bool, error) {
		var err error
		result, err = decodeStatus(data)
		if err == nil && !result.TrafficAvailable {
			err = ErrUnavailable
		}
		return true, err
	})
	return result, err
}

// StartedAt is milliseconds since Unix epoch for the attached API service. A
// caller should combine it with PID/start identity when persisting counters.
func (c *Client) StartedAt(ctx context.Context) (int64, error) {
	var started int64
	received := false
	err := c.read(ctx, "GetStartedAt", nil, func(data []byte) (bool, error) {
		if received {
			return false, ErrProtocol
		}
		received = true
		err := fields(data, func(f wireField) error {
			if f.number == 1 {
				var err error
				started, err = nonnegative(f)
				return err
			}
			return nil
		})
		if err == nil && started <= 0 {
			err = ErrUnavailable
		}
		return false, err
	})
	return started, err
}

// Connections returns the initial reset snapshot, which may include a bounded
// core-maintained history of closed connections. It is not a billing ledger.
func (c *Client) Connections(ctx context.Context) (ConnectionBatch, error) {
	var result ConnectionBatch
	err := c.read(ctx, "SubscribeConnections", intervalMessage(time.Second), func(data []byte) (bool, error) {
		var err error
		result, err = decodeConnectionBatch(data)
		if err == nil && !result.Reset {
			err = ErrProtocol
		}
		return true, err
	})
	return result, err
}

func (c *Client) SubscribeStatus(ctx context.Context, interval time.Duration, receive func(Status) error) error {
	if interval < time.Millisecond || interval > time.Minute || receive == nil {
		return errors.New("invalid status subscription")
	}
	return c.read(ctx, "SubscribeStatus", intervalMessage(interval), func(data []byte) (bool, error) {
		status, err := decodeStatus(data)
		if err != nil {
			return false, err
		}
		if !status.TrafficAvailable {
			return false, ErrUnavailable
		}
		return false, receive(status)
	})
}

func (c *Client) SubscribeConnections(ctx context.Context, interval time.Duration, receive func(ConnectionBatch) error) error {
	if interval < time.Millisecond || interval > time.Minute || receive == nil {
		return errors.New("invalid connection subscription")
	}
	first := true
	return c.read(ctx, "SubscribeConnections", intervalMessage(interval), func(data []byte) (bool, error) {
		batch, err := decodeConnectionBatch(data)
		if err != nil {
			return false, err
		}
		if first && !batch.Reset {
			return false, ErrProtocol
		}
		first = false
		return false, receive(batch)
	})
}

func intervalMessage(interval time.Duration) []byte { return appendVarint([]byte{8}, uint64(interval)) }

func (c *Client) read(ctx context.Context, method string, message []byte, receive func([]byte) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	payload := make([]byte, 5, 5+len(message))
	binary.BigEndian.PutUint32(payload[1:], uint32(len(message)))
	payload = append(payload, message...)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+servicePath+method, bytes.NewReader(payload))
	if err != nil {
		return ErrProtocol
	}
	request.Header.Set("Content-Type", "application/grpc-web+proto")
	request.Header.Set("X-Grpc-Web", "1")
	request.Header.Set("Authorization", "Bearer "+c.config.Secret)
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %w", ErrUnavailable, ErrTransport)
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return ErrUnauthorized
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrUnavailable, response.StatusCode)
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (contentType != "application/grpc-web" && contentType != "application/grpc-web+proto") {
		return ErrProtocol
	}
	if status := response.Header.Get("Grpc-Status"); status != "" {
		if err = grpcStatus(status); err != nil {
			return err
		}
	}
	reader := io.LimitReader(response.Body, c.config.MaxStreamBytes)
	var consumed int64
	dataFrames := 0
	for count := 0; count < c.config.MaxFrames; count++ {
		var header [5]byte
		if _, err = io.ReadFull(reader, header[:]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if consumed >= c.config.MaxStreamBytes {
				return ErrLimit
			}
			if err == io.EOF && dataFrames == 0 && response.Header.Get("Grpc-Status") != "" {
				return ErrUnavailable
			}
			return fmt.Errorf("%w: missing complete frame or trailers", ErrProtocol)
		}
		consumed += 5
		length := int64(binary.BigEndian.Uint32(header[1:]))
		if length > int64(c.config.MaxFrameBytes) || length > c.config.MaxStreamBytes-consumed {
			return ErrLimit
		}
		if header[0] != 0 && header[0] != 0x80 {
			return fmt.Errorf("%w: unsupported frame flags", ErrProtocol)
		}
		data := make([]byte, int(length))
		if _, err = io.ReadFull(reader, data); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w: incomplete frame", ErrProtocol)
		}
		consumed += length
		if header[0] == 0x80 {
			trailers, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(data, '\r', '\n')))).ReadMIMEHeader()
			if err != nil || len(trailers.Values("Grpc-Status")) != 1 {
				return ErrProtocol
			}
			if err = grpcStatus(trailers.Get("Grpc-Status")); err != nil {
				return err
			}
			if dataFrames == 0 {
				return ErrUnavailable
			}
			return nil
		}
		dataFrames++
		stop, err := receive(data)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return ErrLimit
}

func grpcStatus(value string) error {
	code, err := strconv.Atoi(value)
	if err != nil || code < 0 || code > 16 {
		return ErrProtocol
	}
	switch code {
	case 0:
		return nil
	case 7, 16:
		return ErrUnauthorized
	case 12, 14:
		return ErrUnavailable
	default:
		return fmt.Errorf("%w: gRPC status %d", ErrProtocol, code)
	}
}
