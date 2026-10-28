package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func fixture() (Snapshot, string) {
	raw := strings.Repeat("ab", 32)
	hash := sha256.Sum256([]byte(raw))
	now := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	return Snapshot{Version: Version, GeneratedAt: now, Records: []Record{{DeviceID: "0123456789abcdef", TokenID: "fedcba9876543210", TokenSHA256: hex.EncodeToString(hash[:]), IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Outputs: map[string]Payload{"uri": {ContentType: "text/plain; charset=utf-8", Content: []byte("ss://private-device-a\n")}}}}}, raw
}

func TestTokenAndStrictPublication(t *testing.T) {
	a, ha, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, hb, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !exactHex(a, 64) || !exactHex(ha, 64) || a == b || ha == hb {
		t.Fatal("token entropy or shape")
	}
	sum := sha256.Sum256([]byte(a))
	if ha != hex.EncodeToString(sum[:]) {
		t.Fatal("hash does not bind raw token")
	}
	s, _ := fixture()
	encoded, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || !bytes.Equal(decoded.Records[0].Outputs["uri"].Content, s.Records[0].Outputs["uri"].Content) {
		t.Fatal("roundtrip", err)
	}
	for name, mutate := range map[string]func(string) string{
		"duplicate":         func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 1, "version": 1`, 1) },
		"case duplicate":    func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 1, "VERSION": 1`, 1) },
		"Unicode duplicate": func(s string) string { return strings.Replace(s, `"records": [`, `"recordſ": [], "records": [`, 1) },
		"single alias":      func(s string) string { return strings.Replace(s, `"records": [`, `"recordſ": [`, 1) },
		"unknown":           func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 1, "unknown": false`, 1) },
		"null records":      func(s string) string { return strings.Replace(s, `"records": [`, `"records": null, "ignored": [`, 1) },
		"null bool":         func(s string) string { return strings.Replace(s, `"revoked": false`, `"revoked": null`, 1) },
		"future":            func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 2`, 1) },
		"trailing":          func(s string) string { return s + "{}" },
		"deep":              func(s string) string { return strings.Repeat("[", 18) + "1" + strings.Repeat("]", 18) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(mutate(string(encoded)))); err == nil {
				t.Fatal("malformed publication accepted")
			}
		})
	}
	if _, err := Decode(make([]byte, MaxSnapshotBytes+1)); err == nil {
		t.Fatal("oversized publication accepted")
	}
}

func TestPublicationConstraints(t *testing.T) {
	for name, change := range map[string]func(*Snapshot){
		"no expiry":   func(s *Snapshot) { s.Records[0].ExpiresAt = time.Time{} },
		"too long":    func(s *Snapshot) { s.Records[0].ExpiresAt = s.Records[0].IssuedAt.Add(MaxTokenLifetime + time.Second) },
		"plain token": func(s *Snapshot) { s.Records[0].TokenSHA256 = "raw-token" },
		"duplicate device": func(s *Snapshot) {
			r := s.Records[0]
			r.TokenID = "0000000000000000"
			r.TokenSHA256 = strings.Repeat("0", 64)
			s.Records = append(s.Records, r)
		},
		"unknown format": func(s *Snapshot) {
			s.Records[0].Outputs["external-url"] = Payload{ContentType: "text/plain; charset=utf-8", Content: []byte("https://example.invalid")}
		},
		"header injection": func(s *Snapshot) {
			p := s.Records[0].Outputs["uri"]
			p.ContentType += "\r\nSecret: leak"
			s.Records[0].Outputs["uri"] = p
		},
		"empty active": func(s *Snapshot) { s.Records[0].Outputs = map[string]Payload{} },
		"oversized payload": func(s *Snapshot) {
			p := s.Records[0].Outputs["uri"]
			p.Content = bytes.Repeat([]byte("a"), MaxPayloadBytes+1)
			s.Records[0].Outputs["uri"] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := fixture()
			change(&s)
			if err := Validate(s); err == nil {
				t.Fatal("invalid constraints accepted")
			}
		})
	}
	s, _ := fixture()
	s.Records[0].Revoked = true
	s.Records[0].Outputs = map[string]Payload{}
	if err := Validate(s); err != nil {
		t.Fatal("revocation may discard credential payload", err)
	}
}
