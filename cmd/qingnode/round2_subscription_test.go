package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/subscription"
)

func TestRound2SubscriptionUnifiedURLSemverInitAndEffectiveExpiry(t *testing.T) {
	a, s, _ := deviceCLIFixture(t)
	a.verifyHTTPSFn = func(origin string) error { return nil }

	// Schedule an earlier credential expiration on s.Devices[0]'s first bound user!
	credExp := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	if err := a.store.WithLock(func() error {
		st, err := a.store.Load()
		if err != nil {
			return err
		}
		b := st.Devices[0].Bindings[0]
		st.CredentialExpirations = append(st.CredentialExpirations, node.CredentialExpiration{
			ID:        node.Token(8),
			NodeID:    b.NodeID,
			UserID:    b.UserID,
			ExpiresAt: credExp.Format(time.RFC3339),
		})
		return a.store.Apply(st)
	}); err != nil {
		t.Fatal(err)
	}

	// 1. subscription init accepts semver-compatible sing-box 1.14.9 and Mihomo 1.20.0.
	pubDir := filepath.Join(t.TempDir(), "published-r2")
	if _, err := subscriptionCLIStderr(t, func() error {
		return a.subscription([]string{
			"init",
			"--dir", pubDir,
			"--sing-box-version", "1.14.9",
			"--mihomo-version", "1.20.0",
			"--allow-lossy",
		})
	}); err != nil {
		t.Fatalf("subscription init rejected semver-compatible client versions: %v", err)
	}

	// 2. Issue token with --base-url and verify UnifiedURL + subscription qr --format auto.
	tokenPath := filepath.Join(t.TempDir(), "dev0-token.json")
	if _, err := subscriptionCLIStderr(t, func() error {
		return a.subscription([]string{
			"issue",
			"--device", s.Devices[0].ID,
			"--base-url", "https://sub.example.test",
			"--out", tokenPath,
		})
	}); err != nil {
		t.Fatalf("subscription issue failed: %v", err)
	}

	rawToken, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	var m tokenMaterial
	if err := json.Unmarshal(rawToken, &m); err != nil {
		t.Fatal(err)
	}
	if m.UnifiedURL != "https://sub.example.test/s/"+m.Token {
		t.Fatalf("expected UnifiedURL https://sub.example.test/s/<token>, got %q", m.UnifiedURL)
	}

	qrPath := filepath.Join(t.TempDir(), "dev0-auto.qr.txt")
	if err := a.subscription([]string{"qr", "--token-file", tokenPath, "--format", "auto", "--out", qrPath}); err != nil {
		t.Fatalf("subscription qr --format auto failed: %v", err)
	}
	qrData, err := os.ReadFile(qrPath)
	if err != nil || len(qrData) == 0 {
		t.Fatalf("expected non-empty auto QR file, err=%v", err)
	}

	// 3. Serve unified /s/<TOKEN> through SnapshotCache + NewIndexedHandler and verify UA negotiation + Subscription-Userinfo effective expiry.
	cache := subscription.NewSnapshotCache(pubDir)
	handler, err := subscription.NewIndexedHandler(cache.Read, subscription.HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		ua       string
		wantCT   string
		wantBody string
	}{
		{"SFA/1.14.3", "application/json; charset=utf-8", `"inbounds"`},
		{"Clash.Meta/1.19.30", "application/yaml; charset=utf-8", "proxy-groups:"},
		{"v2rayNG/1.8.38", "text/plain; charset=utf-8", ""},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/s/"+m.Token, nil)
		req.Header.Set("User-Agent", tc.ua)
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("UA %q got status %d", tc.ua, rec.Code)
		}
		if gotCT := rec.Header().Get("Content-Type"); gotCT != tc.wantCT {
			t.Fatalf("UA %q got Content-Type %q, want %q", tc.ua, gotCT, tc.wantCT)
		}
		if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Fatalf("UA %q body missing %q", tc.ua, tc.wantBody)
		}
		wantUserInfo := "expire=" + strconv.FormatInt(credExp.Unix(), 10)
		if gotUI := rec.Header().Get("Subscription-Userinfo"); gotUI != wantUserInfo {
			t.Fatalf("UA %q got Subscription-Userinfo %q, want %q (must reflect earlier credential expiration without fake traffic counters)", tc.ua, gotUI, wantUserInfo)
		}
		if !strings.HasPrefix(rec.Header().Get("Profile-Title"), "base64:") {
			t.Fatalf("missing Profile-Title header: %q", rec.Header().Get("Profile-Title"))
		}
	}
	if cache.Decodes() != 1 {
		t.Fatalf("expected SnapshotCache to decode unchanged snapshot.json exactly once across 3 requests, got %d", cache.Decodes())
	}

	// 4. Verify CLI device create + device show redacts Controller.Secret, and export CLI flags override routing/TUN/controller.
	createOut, err := wizardOutput(t, func() error {
		return a.device([]string{
			"create",
			"--name", "cli-sec-device",
			"--binding", s.Nodes[0].ID + ":" + s.Nodes[0].Users[0].ID,
			"--routing", "cn-direct",
			"--tun",
			"--enable-controller",
			"--controller-port", "19090",
			"--default-subscription-format", "mihomo",
		})
	})
	if err != nil {
		t.Fatalf("device create with round-2 flags failed: %v", err)
	}
	if !strings.Contains(createOut, "设备ID：") {
		t.Fatalf("missing device ID output: %s", createOut)
	}

	stAfter, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var created *node.DeviceProfile
	for i := range stAfter.Devices {
		if stAfter.Devices[i].Name == "cli-sec-device" {
			created = &stAfter.Devices[i]
			break
		}
	}
	if created == nil || created.Controller == nil || created.Controller.Secret == "" {
		t.Fatalf("created device controller secret missing: %+v", created)
	}
	showOut, err := wizardOutput(t, func() error {
		return a.device([]string{"show", "--id", created.ID})
	})
	if err != nil {
		t.Fatalf("device show failed: %v", err)
	}
	if strings.Contains(showOut, created.Controller.Secret) || !strings.Contains(showOut, "[API凭据已隐藏]") {
		t.Fatalf("device show leaked Controller.Secret: %s", showOut)
	}

	exportPath := filepath.Join(t.TempDir(), "override-export.json")
	if err := a.export("export", []string{
		"--id", s.Nodes[0].ID,
		"--user", s.Nodes[0].Users[0].ID,
		"--format", "sing-box",
		"--client-version", "1.14.5",
		"--routing", "global-secure-dns",
		"--tun",
		"--enable-controller",
		"--controller-port", "29090",
		"--out", exportPath,
	}); err != nil {
		t.Fatalf("single-node export with round-2 client options failed: %v", err)
	}
	exportedBytes, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	exportedStr := string(exportedBytes)
	for _, snippet := range []string{`"type": "tun"`, `"127.0.0.1:29090"`, `"type": "https"`} {
		if !strings.Contains(exportedStr, snippet) {
			t.Fatalf("exported config missing %s:\n%s", snippet, exportedStr)
		}
	}
}
