package subscription

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

func validFlagParam(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func parseUnifiedQuery(rawQuery string) (explicitFormat string, flagHint string, ok bool) {
	if rawQuery == "" {
		return "", "", true
	}
	parts := strings.Split(rawQuery, "&")
	if len(parts) > 2 {
		return "", "", false
	}
	seenFormat, seenFlag := false, false
	for _, part := range parts {
		k, v, found := strings.Cut(part, "=")
		if !found || k == "" || v == "" {
			return "", "", false
		}
		switch k {
		case "format":
			if seenFormat {
				return "", "", false
			}
			if _, valid := ContentType(v); !valid {
				return "", "", false
			}
			seenFormat = true
			explicitFormat = v
		case "flag":
			if seenFlag || !validFlagParam(v) {
				return "", "", false
			}
			seenFlag = true
			flagHint = v
		default:
			return "", "", false
		}
	}
	return explicitFormat, flagHint, true
}

func NegotiateFormat(ua, flagHint, defaultFormat string, outputs map[string]Payload) (string, bool) {
	if len(outputs) == 0 {
		return "", false
	}
	if flagHint != "" {
		var hinted string
		switch strings.ToLower(flagHint) {
		case "sing-box", "sfa", "sfi", "sfm":
			hinted = "sing-box"
		case "mihomo", "clash", "clash.meta", "meta", "flclash", "stash":
			hinted = "mihomo"
		case "base64", "v2ray", "v2rayn", "v2rayng", "shadowrocket", "nekobox", "streisand":
			hinted = "base64"
		case "uri":
			hinted = "uri"
		case "provider":
			hinted = "provider"
		}
		if hinted != "" {
			if _, ok := outputs[hinted]; ok {
				return hinted, true
			}
		}
	}

	lowerUA := strings.ToLower(ua)
	switch {
	case strings.Contains(lowerUA, "sing-box") ||
		strings.Contains(lowerUA, "sfa/") || strings.HasPrefix(lowerUA, "sfa") ||
		strings.Contains(lowerUA, "sfi/") || strings.HasPrefix(lowerUA, "sfi") ||
		strings.Contains(lowerUA, "sfm/") || strings.HasPrefix(lowerUA, "sfm"):
		if _, ok := outputs["sing-box"]; ok {
			return "sing-box", true
		}
	case strings.Contains(lowerUA, "mihomo") ||
		strings.Contains(lowerUA, "clash.meta") ||
		strings.Contains(lowerUA, "flclash") ||
		strings.Contains(lowerUA, "clash verge") ||
		strings.Contains(lowerUA, "clashverge") ||
		strings.Contains(lowerUA, "clash-verge") ||
		strings.Contains(lowerUA, "stash"):
		if _, ok := outputs["mihomo"]; ok {
			return "mihomo", true
		}
	case strings.Contains(lowerUA, "v2rayn") ||
		strings.Contains(lowerUA, "v2rayng") ||
		strings.Contains(lowerUA, "shadowrocket") ||
		strings.Contains(lowerUA, "nekobox") ||
		strings.Contains(lowerUA, "streisand"):
		if _, ok := outputs["base64"]; ok {
			return "base64", true
		}
		if _, ok := outputs["uri"]; ok {
			return "uri", true
		}
	}

	fallbacks := []string{}
	if defaultFormat != "" {
		fallbacks = append(fallbacks, defaultFormat)
	}
	fallbacks = append(fallbacks, "base64", "uri", "sing-box", "mihomo", "provider")
	for _, candidate := range fallbacks {
		if _, ok := outputs[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

func formatExtension(format string) string {
	switch format {
	case "sing-box":
		return "json"
	case "mihomo", "provider":
		return "yaml"
	default:
		return "txt"
	}
}

// NewHandler reads a publication per request and delegates to NewIndexedHandler.
func NewHandler(read Reader, opts HandlerOptions) (http.Handler, error) {
	if read == nil {
		return nil, errors.New("publication reader is required")
	}
	return NewIndexedHandler(func() (IndexedSnapshot, error) {
		s, err := read()
		if err != nil {
			return IndexedSnapshot{}, err
		}
		return BuildIndex(s)
	}, opts)
}

func NewIndexedHandler(read IndexedReader, opts HandlerOptions) (http.Handler, error) {
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
		w.Header().Set("Vary", "Authorization, User-Agent")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 || r.Body != nil && r.Body != http.NoBody || len(r.URL.RequestURI()) > 256 || r.URL.ForceQuery || r.URL.RawPath != "" {
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
		authValues := r.Header.Values("Authorization")
		var raw, explicitFormat, flagHint string
		unified := false

		if len(authValues) > 0 {
			if len(authValues) != 1 || !strings.HasPrefix(authValues[0], "Bearer ") {
				http.NotFound(w, r)
				return
			}
			raw = strings.TrimPrefix(authValues[0], "Bearer ")
			switch {
			case len(parts) == 3 && parts[0] == "" && parts[1] == "s":
				if r.URL.RawQuery != "" {
					http.NotFound(w, r)
					return
				}
				explicitFormat = parts[2]
			case len(parts) == 2 && parts[0] == "" && parts[1] == "s":
				var ok bool
				explicitFormat, flagHint, ok = parseUnifiedQuery(r.URL.RawQuery)
				if !ok {
					http.NotFound(w, r)
					return
				}
				unified = true
			default:
				http.NotFound(w, r)
				return
			}
		} else {
			switch {
			case len(parts) == 4 && parts[0] == "" && parts[1] == "s":
				if r.URL.RawQuery != "" {
					http.NotFound(w, r)
					return
				}
				raw, explicitFormat = parts[2], parts[3]
			case len(parts) == 3 && parts[0] == "" && parts[1] == "s":
				raw = parts[2]
				var ok bool
				explicitFormat, flagHint, ok = parseUnifiedQuery(r.URL.RawQuery)
				if !ok {
					http.NotFound(w, r)
					return
				}
				unified = true
			default:
				http.NotFound(w, r)
				return
			}
		}

		if explicitFormat != "" {
			if _, ok := ContentType(explicitFormat); !ok {
				http.NotFound(w, r)
				return
			}
		}
		// Reject malformed secrets before allocating/decoding a publication.
		if !exactHex(raw, 64) {
			http.NotFound(w, r)
			return
		}
		indexed, err := read()
		if err != nil {
			http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
			return
		}
		sum := sha256.Sum256([]byte(raw))
		now := opts.Clock()
		var selected *Record
		if idx, ok := indexed.tokenIndex[sum]; ok && idx >= 0 && idx < len(indexed.Snapshot.Records) {
			rec := &indexed.Snapshot.Records[idx]
			var expected [32]byte
			_, _ = hex.Decode(expected[:], []byte(rec.TokenSHA256))
			if subtle.ConstantTimeCompare(sum[:], expected[:]) == 1 && !rec.Revoked && !now.Before(rec.IssuedAt) && now.Before(rec.ExpiresAt) {
				selected = rec
			}
		} else {
			var zero [32]byte
			_ = subtle.ConstantTimeCompare(sum[:], zero[:])
		}
		if selected == nil {
			http.NotFound(w, r)
			return
		}

		chosenFormat := explicitFormat
		if chosenFormat == "" && unified {
			var ok bool
			chosenFormat, ok = NegotiateFormat(r.Header.Get("User-Agent"), flagHint, selected.DefaultFormat, selected.Outputs)
			if !ok {
				http.NotFound(w, r)
				return
			}
		}
		p, ok := selected.Outputs[chosenFormat]
		if !ok {
			http.NotFound(w, r)
			return
		}

		title := selected.DeviceName
		if title == "" {
			title = selected.DeviceID
		}
		expireUnix := selected.ExpiresAt.Unix()
		if selected.EffectiveExpireUnix > 0 && selected.EffectiveExpireUnix < expireUnix {
			expireUnix = selected.EffectiveExpireUnix
		}

		userinfo := "expire=" + strconv.FormatInt(expireUnix, 10)
		if selected.UploadBytes != nil && selected.DownloadBytes != nil {
			parts := []string{
				"upload=" + strconv.FormatInt(*selected.UploadBytes, 10),
				"download=" + strconv.FormatInt(*selected.DownloadBytes, 10),
			}
			if selected.TotalBytes != nil && *selected.TotalBytes > 0 {
				parts = append(parts, "total="+strconv.FormatInt(*selected.TotalBytes, 10))
			}
			parts = append(parts, userinfo)
			userinfo = strings.Join(parts, "; ")
		}

		w.Header().Set("Profile-Update-Interval", "24")
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(title)))
		w.Header().Set("Content-Disposition", `attachment; filename="qingnode-`+selected.DeviceID+`.`+formatExtension(chosenFormat)+`"`)
		w.Header().Set("Subscription-Userinfo", userinfo)
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
	cache := NewSnapshotCache(opts.Directory)
	if _, err = cache.Read(); err != nil {
		return errors.New("subscription publication is unavailable")
	}
	h, err := NewIndexedHandler(cache.Read, HandlerOptions{MaxConcurrent: opts.MaxConcurrent})
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
