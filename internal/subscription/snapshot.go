// Package subscription serves private, already-rendered device publications.
// It has no State, proxy management, remote-fetch, or routing dependency. The
// publication contains proxy credentials and token hashes: keep it group-readable
// only for the dedicated subscription service. Never log raw download URLs.
package subscription

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	Version          = 1
	MaxSnapshotBytes = 16 << 20
	MaxPayloadBytes  = 2 << 20
	MaxRecords       = 128
	MaxTokenLifetime = 366 * 24 * time.Hour
	SnapshotName     = "snapshot.json"
	MarkerName       = ".qingnode-subscription-owner"
	OwnerMarker      = "QingNode subscription publication v1\n"
)

type Snapshot struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Records     []Record  `json:"records"`
}

type Record struct {
	DeviceID    string             `json:"device_id"`
	TokenID     string             `json:"token_id"`
	TokenSHA256 string             `json:"token_sha256"`
	IssuedAt    time.Time          `json:"issued_at"`
	ExpiresAt   time.Time          `json:"expires_at"`
	Revoked     bool               `json:"revoked"`
	Outputs     map[string]Payload `json:"outputs"`
}

type Payload struct {
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
}

// NewToken returns 256 random bits, encoded as 64 lower-case hexadecimal bytes,
// and its SHA-256 hash. Only the hash belongs in a publication; deliver the raw
// token once through an explicitly private file.
func NewToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", errors.New("cannot create subscription token")
	}
	raw := hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func exactHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			if r < 'a' || r > 'f' {
				return false
			}
		}
	}
	return true
}

func ContentType(format string) (string, bool) {
	switch format {
	case "uri", "base64":
		return "text/plain; charset=utf-8", true
	case "sing-box":
		return "application/json; charset=utf-8", true
	case "mihomo", "provider":
		return "application/yaml; charset=utf-8", true
	default:
		return "", false
	}
}

func Validate(s Snapshot) error {
	if s.Version != Version {
		return fmt.Errorf("unsupported subscription publication version %d", s.Version)
	}
	if s.GeneratedAt.IsZero() {
		return errors.New("publication time is required")
	}
	if s.Records == nil || len(s.Records) > MaxRecords {
		return errors.New("publication records are missing or exceed the limit")
	}
	tokens, ids, active := map[string]bool{}, map[string]bool{}, map[string]bool{}
	payloadBytes := 0
	for _, r := range s.Records {
		if !exactHex(r.DeviceID, 16) || !exactHex(r.TokenID, 16) || !exactHex(r.TokenSHA256, 64) {
			return errors.New("invalid publication record identity")
		}
		if tokens[r.TokenSHA256] || ids[r.TokenID] {
			return errors.New("duplicate subscription token record")
		}
		tokens[r.TokenSHA256], ids[r.TokenID] = true, true
		if !r.Revoked {
			if active[r.DeviceID] {
				return errors.New("a device has multiple active subscription tokens")
			}
			active[r.DeviceID] = true
		}
		if r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > MaxTokenLifetime {
			return errors.New("subscription token expiry must be within 366 days of issue")
		}
		if r.Outputs == nil || len(r.Outputs) > 5 || (!r.Revoked && len(r.Outputs) == 0) {
			return errors.New("invalid publication output count")
		}
		for format, p := range r.Outputs {
			ct, ok := ContentType(format)
			if !ok || p.ContentType != ct || len(p.Content) == 0 || len(p.Content) > MaxPayloadBytes || !utf8.Valid(p.Content) {
				return errors.New("invalid subscription output")
			}
			payloadBytes += len(p.Content)
			if payloadBytes > MaxSnapshotBytes/4*3-MaxRecords*1024 {
				return errors.New("publication payload total exceeds its limit")
			}
		}
	}
	return nil
}

func Encode(s Snapshot) ([]byte, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, errors.New("cannot encode publication")
	}
	b = append(b, '\n')
	if len(b) > MaxSnapshotBytes {
		return nil, errors.New("publication exceeds 16 MiB")
	}
	return b, nil
}

func Decode(b []byte) (Snapshot, error) {
	var s Snapshot
	if len(b) > MaxSnapshotBytes {
		return s, errors.New("publication exceeds 16 MiB")
	}
	if err := strictJSON(b); err != nil {
		return s, err
	}
	var shape struct {
		Records []map[string]json.RawMessage `json:"records"`
	}
	if json.Unmarshal(b, &shape) != nil {
		return s, errors.New("invalid publication structure")
	}
	for _, r := range shape.Records {
		if _, ok := r["revoked"]; !ok {
			return s, errors.New("publication revocation field is required")
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, errors.New("invalid publication structure")
	}
	if err := Validate(s); err != nil {
		return s, err
	}
	return s, nil
}

// Check before ordinary decoding: encoding/json otherwise accepts duplicate,
// case-folded and Unicode SimpleFold aliases, and null silently becomes zero.
func strictJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("publication nesting exceeds limit")
		}
		t, err := d.Token()
		if err != nil {
			return errors.New("invalid publication JSON")
		}
		if t == nil {
			return errors.New("null is not allowed in a publication")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					t, err = d.Token()
					if err != nil {
						return errors.New("invalid publication JSON")
					}
					key, ok := t.(string)
					if !ok {
						return errors.New("invalid publication object")
					}
					fold := strings.Map(func(r rune) rune {
						c := r
						for n := unicode.SimpleFold(r); n != r; n = unicode.SimpleFold(n) {
							if n < c {
								c = n
							}
						}
						return c
					}, key)
					if seen[fold] {
						return errors.New("duplicate publication field")
					}
					seen[fold] = true
					for _, r := range key {
						if r > 127 || r >= 'A' && r <= 'Z' {
							return errors.New("publication field spelling must be exact")
						}
					}
					if err = value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err = value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("invalid publication JSON")
			}
			if _, err = d.Token(); err != nil {
				return errors.New("invalid publication JSON")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing publication data")
	}
	return nil
}
