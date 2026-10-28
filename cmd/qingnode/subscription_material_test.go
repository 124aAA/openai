package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionQRRejectsDamagedPrivateMaterialBeforeOutput(t *testing.T) {
	now := time.Now()
	base := tokenMaterial{Version: 1, DeviceID: "aaaaaaaaaaaaaaaa", TokenID: "bbbbbbbbbbbbbbbb", Token: strings.Repeat("c", 64), ExpiresAt: now.Add(time.Hour)}
	base.Links = []subscriptionLink{{Format: "mihomo", URL: "https://sub.example.test/s/" + base.Token + "/mihomo"}}
	if err := validateTokenMaterial(base, now); err != nil {
		t.Fatal("valid issued shape rejected", err)
	}
	a, _, _ := deviceCLIFixture(t)
	beforeGeneration, before := savedBatchState(t, a)
	input, output := filepath.Join(t.TempDir(), "token.json"), filepath.Join(t.TempDir(), "qr.txt")
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	stdout, err := wizardOutput(t, func() error {
		return a.subscription([]string{"qr", "--token-file", input, "--format", "mihomo", "--out", output})
	})
	if err != nil || strings.Contains(stdout, base.Token) {
		t.Fatal("private QR failed or exposed its secret", err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 || info.Size() == 0 {
		t.Fatal("QR output must be a populated private file", err)
	}
	afterGeneration, after := savedBatchState(t, a)
	if beforeGeneration != afterGeneration || string(before) != string(after) {
		t.Fatal("QR changed proxy State")
	}
	for name, change := range map[string]func(*tokenMaterial){
		"wrong device":     func(m *tokenMaterial) { m.DeviceID = "not-an-id" },
		"wrong token id":   func(m *tokenMaterial) { m.TokenID = "not-an-id" },
		"short secret":     func(m *tokenMaterial) { m.Token = "c" },
		"expired":          func(m *tokenMaterial) { m.ExpiresAt = now.Add(-time.Second) },
		"unbounded expiry": func(m *tokenMaterial) { m.ExpiresAt = now.Add(367 * 24 * time.Hour) },
		"unknown format":   func(m *tokenMaterial) { m.Links[0].Format = "unknown" },
		"duplicate format": func(m *tokenMaterial) { m.Links = append(m.Links, m.Links[0]) },
		"prefix path":      func(m *tokenMaterial) { m.Links[0].URL = "https://sub.example.test/prefix/s/" + m.Token + "/mihomo" },
		"wrong secret": func(m *tokenMaterial) {
			m.Links[0].URL = "https://sub.example.test/s/" + strings.Repeat("d", 64) + "/mihomo"
		},
		"encoded path": func(m *tokenMaterial) { m.Links[0].URL = "https://sub.example.test/%73/" + m.Token + "/mihomo" },
		"invalid host": func(m *tokenMaterial) { m.Links[0].URL = "https://bad_host/s/" + m.Token + "/mihomo" },
		"invalid port": func(m *tokenMaterial) { m.Links[0].URL = "https://sub.example.test:65536/s/" + m.Token + "/mihomo" },
		"query":        func(m *tokenMaterial) { m.Links[0].URL += "?other=secret" },
		"empty query":  func(m *tokenMaterial) { m.Links[0].URL += "?" },
		"login": func(m *tokenMaterial) {
			m.Links[0].URL = "https://user:password@sub.example.test/s/" + m.Token + "/mihomo"
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			m.Links = append([]subscriptionLink{}, base.Links...)
			change(&m)
			if err := validateTokenMaterial(m, now); err == nil || strings.Contains(err.Error(), base.Token) {
				t.Fatal("damaged material accepted or its secret disclosed", err)
			}
			a, _, _ := deviceCLIFixture(t)
			input, output := filepath.Join(t.TempDir(), "token.json"), filepath.Join(t.TempDir(), "qr.txt")
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.subscription([]string{"qr", "--token-file", input, "--format", "mihomo", "--out", output}); err == nil {
				t.Fatal("QR emitted from invalid private material")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("invalid material created an output", err)
			}
		})
	}
}
