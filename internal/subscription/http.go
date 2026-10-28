package subscription

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Reader func() (Snapshot, error)
type HandlerOptions struct {
	Clock         func() time.Time
	MaxConcurrent int
}

// NewHandler reads a complete publication for every request. There is no token
// cache: after an atomic revocation, every new request consults the new registry.
// Already-authenticated in-flight responses cannot be recalled from a client.
func NewHandler(read Reader, opts HandlerOptions) (http.Handler, error) {
	if read == nil {
		return nil, errors.New("publication reader is required")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.MaxConcurrent == 0 {
		opts.MaxConcurrent = 4
	}
	if opts.MaxConcurrent < 1 || opts.MaxConcurrent > 16 {
		return nil, errors.New("subscription concurrency must be 1..16")
	}
	sem := make(chan struct{}, opts.MaxConcurrent)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Vary", "Authorization")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 || r.Body != nil && r.Body != http.NoBody || len(r.URL.RequestURI()) > 256 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "subscription busy", http.StatusServiceUnavailable)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		var raw, format string
		switch {
		case len(parts) == 4 && parts[0] == "" && parts[1] == "s":
			raw, format = parts[2], parts[3]
			if r.Header.Get("Authorization") != "" {
				http.NotFound(w, r)
				return
			}
		case len(parts) == 3 && parts[0] == "" && parts[1] == "s":
			format = parts[2]
			auth := r.Header.Values("Authorization")
			if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
				http.NotFound(w, r)
				return
			}
			raw = strings.TrimPrefix(auth[0], "Bearer ")
		default:
			http.NotFound(w, r)
			return
		}
		if _, ok := ContentType(format); !ok {
			http.NotFound(w, r)
			return
		}
		// Reject malformed secrets before allocating/decoding a publication.
		// All syntactically valid random tokens still use the same hash lookup.
		if !exactHex(raw, 64) {
			http.NotFound(w, r)
			return
		}
		s, err := read()
		if err != nil {
			http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
			return
		}
		if err = Validate(s); err != nil {
			http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
			return
		}
		sum := sha256.Sum256([]byte(raw))
		now := opts.Clock()
		var selected *Record
		validToken := exactHex(raw, 64)
		for i := range s.Records {
			rec := &s.Records[i]
			expected, _ := hex.DecodeString(rec.TokenSHA256)
			match := subtle.ConstantTimeCompare(sum[:], expected) == 1
			if match && validToken && !rec.Revoked && !now.Before(rec.IssuedAt) && now.Before(rec.ExpiresAt) {
				selected = rec
			}
		}
		if selected == nil {
			http.NotFound(w, r)
			return
		}
		p, ok := selected.Outputs[format]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", p.ContentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(p.Content)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(p.Content)
		}
	}), nil
}

type ServeOptions struct {
	Directory       string
	PublicURL       string
	TLSCertFile     string
	TLSKeyFile      string
	ReverseProxy    bool
	MaxConcurrent   int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Serve owns and closes listener. Public TLS validates its key pair, validity and
// public hostname before serving. HTTP is allowed only on a literal loopback
// listener, with explicit HTTPS reverse-proxy deployment. The caller must verify
// that reverse proxy's publicly trusted HTTPS; this function cannot attest it.
func Serve(ctx context.Context, listener net.Listener, opts ServeOptions) error {
	if listener == nil {
		return errors.New("subscription listener is required")
	}
	defer listener.Close()
	if ctx == nil {
		return errors.New("subscription context is required")
	}
	u, err := url.Parse(opts.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("subscription public URL must be an HTTPS origin")
	}
	var tc *tls.Config
	if opts.TLSCertFile != "" || opts.TLSKeyFile != "" {
		if opts.ReverseProxy {
			return errors.New("choose TLS or loopback reverse proxy")
		}
		pair, e := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if e != nil || len(pair.Certificate) == 0 {
			return errors.New("subscription TLS key pair is invalid")
		}
		cert, e := x509.ParseCertificate(pair.Certificate[0])
		now := time.Now()
		if e != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.VerifyHostname(u.Hostname()) != nil {
			return errors.New("subscription TLS certificate is expired or does not cover the public hostname")
		}
		pair.Leaf = cert
		tc = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	} else {
		host, _, e := net.SplitHostPort(listener.Addr().String())
		ip := net.ParseIP(host)
		if e != nil || ip == nil || !ip.IsLoopback() || !opts.ReverseProxy {
			return errors.New("plain HTTP requires an explicit HTTPS reverse proxy and a loopback listener")
		}
	}
	if _, err = Read(opts.Directory); err != nil {
		return errors.New("subscription publication is unavailable")
	}
	h, err := NewHandler(func() (Snapshot, error) { return Read(opts.Directory) }, HandlerOptions{MaxConcurrent: opts.MaxConcurrent})
	if err != nil {
		return err
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 5 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 10 * time.Second
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 15 * time.Second
	}
	if opts.ShutdownTimeout == 0 {
		opts.ShutdownTimeout = 5 * time.Second
	}
	if opts.ReadTimeout < time.Second || opts.ReadTimeout > 30*time.Second || opts.WriteTimeout < time.Second || opts.WriteTimeout > 30*time.Second || opts.IdleTimeout < time.Second || opts.IdleTimeout > 60*time.Second || opts.ShutdownTimeout < time.Millisecond || opts.ShutdownTimeout > 30*time.Second {
		return errors.New("subscription timeouts are outside supported bounds")
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: opts.ReadTimeout, ReadTimeout: opts.ReadTimeout, WriteTimeout: opts.WriteTimeout, IdleTimeout: opts.IdleTimeout, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.Background(), opts.ShutdownTimeout)
			defer cancel()
			if srv.Shutdown(c) != nil {
				_ = srv.Close()
			}
		case <-done:
		}
	}()
	if tc != nil {
		listener = tls.NewListener(listener, tc)
	}
	err = srv.Serve(listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err != nil {
		return errors.New("subscription listener stopped")
	}
	return nil
}
