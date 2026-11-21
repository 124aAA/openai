package monitor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"qingnode/internal/coreapi"
)

func TestTrafficLedgerCleanRestartCrashRegressionAndMonthlyReset(t *testing.T) {
	s := testStore(t)
	t1 := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)

	// Read-only LoadTrafficLedger before initialization must not create directories.
	if _, err := s.LoadTrafficLedger(); err == nil {
		t.Fatal("expected missing ledger error")
	}
	if _, err := os.Lstat(s.Root); !os.IsNotExist(err) {
		t.Fatal("read-only ledger load created monitor root")
	}

	// Sample 1 in epoch 100/1000.
	l, err := s.RecordTrafficSample(LedgerSample{
		ObservedAt:           t1,
		Epoch:                "100/1000",
		Status:               coreapi.Status{TrafficAvailable: true, UplinkTotal: 500, DownlinkTotal: 1200},
		ConnectionsAvailable: true,
		Connections: []LedgerConnection{
			{ID: "00000000-0000-0000-0000-000000000001", NodeID: "1111111111111111", UserID: "2222222222222222", Upload: 400, Download: 1000},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if l.GapDetected || l.BillingSuitable || l.GlobalUpload != 500 || l.GlobalDownload != 1200 || l.UnattributedUpload != 100 || l.UnattributedDownload != 200 {
		t.Fatalf("unexpected initial ledger: %+v", l)
	}

	// Pre-stop flush right before controlled core restart.
	l, err = s.RecordTrafficSample(LedgerSample{
		ObservedAt:           t1.Add(time.Minute),
		Epoch:                "100/1000",
		Status:               coreapi.Status{TrafficAvailable: true, UplinkTotal: 700, DownlinkTotal: 1800},
		ConnectionsAvailable: true,
		PreStop:              true,
		Connections: []LedgerConnection{
			{ID: "00000000-0000-0000-0000-000000000001", NodeID: "1111111111111111", UserID: "2222222222222222", Upload: 600, Download: 1600, Closed: true},
		},
	})
	if err != nil || l.CleanShutdownEpoch != "100/1000" || l.GapDetected {
		t.Fatalf("unexpected pre-stop ledger: %+v err=%v", l, err)
	}

	// New epoch 200/2000 after clean restart: counters start near 0, cumulative totals MUST NOT reset and GapDetected stays false!
	t2 := time.Date(2026, 2, 28, 15, 0, 0, 0, time.UTC)
	l, err = s.RecordTrafficSample(LedgerSample{
		ObservedAt:           t2,
		Epoch:                "200/2000",
		Status:               coreapi.Status{TrafficAvailable: true, UplinkTotal: 300, DownlinkTotal: 400},
		ConnectionsAvailable: true,
		Connections: []LedgerConnection{
			{ID: "00000000-0000-0000-0000-000000000002", NodeID: "1111111111111111", UserID: "2222222222222222", Upload: 300, Download: 400},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if l.GapDetected || l.GlobalUpload != 1000 || l.GlobalDownload != 2200 {
		t.Fatalf("clean restart lost cumulative traffic or marked false gap: %+v", l)
	}
	pair, ok := l.UsageFor("1111111111111111", "2222222222222222", 0, t2)
	if !ok || pair.Upload != 900 || pair.Download != 2000 {
		t.Fatalf("unexpected user cumulative usage: %+v ok=%v", pair, ok)
	}

	// Counter regression within epoch 200/2000: must mark GapDetected and preserve high-water mark (300/400).
	l, err = s.RecordTrafficSample(LedgerSample{
		ObservedAt:           t2.Add(time.Minute),
		Epoch:                "200/2000",
		Status:               coreapi.Status{TrafficAvailable: true, UplinkTotal: 150, DownlinkTotal: 200},
		ConnectionsAvailable: true,
	})
	if !errors.Is(err, coreapi.ErrCounterRegression) || !l.GapDetected || l.LastGapReason != "counter_regression" || l.GlobalUpload != 1000 {
		t.Fatalf("counter regression not handled safely: %+v err=%v", l, err)
	}

	// Subsequent sample above high-water mark (350/500) adds only +50/+100 without double counting.
	l, err = s.RecordTrafficSample(LedgerSample{
		ObservedAt:           t2.Add(2 * time.Minute),
		Epoch:                "200/2000",
		Status:               coreapi.Status{TrafficAvailable: true, UplinkTotal: 350, DownlinkTotal: 500},
		ConnectionsAvailable: true,
		Connections: []LedgerConnection{
			{ID: "00000000-0000-0000-0000-000000000002", NodeID: "1111111111111111", UserID: "2222222222222222", Upload: 350, Download: 500},
		},
	})
	if err != nil || l.GlobalUpload != 1050 || l.GlobalDownload != 2300 {
		t.Fatalf("post-regression delta miscalculated: %+v err=%v", l, err)
	}

	// Unclean crash into epoch 300/3000 in March (without PreStop on 200/2000): increments GapCount and rolls monthly window!
	t3 := time.Date(2026, 3, 5, 8, 0, 0, 0, time.UTC)
	l, err = s.RecordTrafficSample(LedgerSample{
		ObservedAt:           t3,
		Epoch:                "300/3000",
		Status:               coreapi.Status{TrafficAvailable: true, UplinkTotal: 120, DownlinkTotal: 240},
		ConnectionsAvailable: true,
		Connections: []LedgerConnection{
			{ID: "00000000-0000-0000-0000-000000000003", NodeID: "1111111111111111", UserID: "2222222222222222", Upload: 120, Download: 240},
		},
	})
	if err != nil || l.GapCount < 2 || l.LastGapReason != "unclean_epoch_change" {
		t.Fatalf("unclean crash gap not recorded: %+v err=%v", l, err)
	}

	// Monthly reset day 1 on March 5 includes only March usage (120/240), while resetDay=0 includes lifetime (1070/2340).
	marchPair, ok := l.UsageFor("1111111111111111", "2222222222222222", 1, t3)
	if !ok || marchPair.Upload != 120 || marchPair.Download != 240 {
		t.Fatalf("monthly reset_day=1 failed: got %+v", marchPair)
	}
	lifePair, ok := l.UsageFor("1111111111111111", "2222222222222222", 0, t3)
	if !ok || lifePair.Upload != 1070 || lifePair.Download != 2340 {
		t.Fatalf("lifetime reset_day=0 failed: got %+v", lifePair)
	}
	// Reset day 31 in non-leap February 2026 clamps to 2026-02-28!
	if got := QuotaPeriodKey(time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC), 31); got != "2026-02-28" {
		t.Fatalf("expected clamped Feb 28 period start, got %q", got)
	}
	// Leap year 2028 clamps to 2028-02-29!
	if got := QuotaPeriodKey(time.Date(2028, 3, 5, 0, 0, 0, 0, time.UTC), 31); got != "2028-02-29" {
		t.Fatalf("expected clamped Feb 29 period start, got %q", got)
	}

	info, err := os.Lstat(filepath.Join(s.Root, "traffic-ledger.json"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("ledger file must be regular 0600, got %v %v", info, err)
	}
}

func TestAllRichNotificationChannelsSigningAndRedaction(t *testing.T) {
	fixedNow := time.Date(2026, 11, 20, 10, 20, 30, 0, time.UTC)
	daysLeft := 7
	secretPassword := "super-secret-proxy-pass-999"
	sampleEvent := Event{
		At:             fixedNow,
		JobID:          "job-tls-1",
		From:           Healthy,
		To:             Degraded,
		Kind:           "cert-expiring",
		Host:           "vps-tokyo-01",
		TargetName:     "Tokyo-HY2 password=" + secretPassword,
		TargetID:       "1111111111111111",
		Signals:        []string{"certificate=degraded(days_left_7)", "tcp=failed(proxy_path_or_target_failed)"},
		Reason:         "证书即将过期，密码 password=" + secretPassword,
		RecoveryResult: "observe_only",
		CertDaysLeft:   &daysLeft,
	}

	t.Run("telegram_topic_thread_and_redact", func(t *testing.T) {
		var gotBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/botbot-secret-token/sendMessage" {
				t.Errorf("unexpected telegram path: %s", r.URL.Path)
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			fmt.Fprint(w, `{"ok":true}`)
		}))
		defer srv.Close()
		s := testStore(t)
		c := testConfig()
		c.Notifications = NotificationConfig{
			Enabled:         true,
			Kind:            "telegram",
			Endpoint:        srv.URL,
			Token:           "bot-secret-token",
			ChatID:          "-100123456",
			MessageThreadID: 88,
			TimeoutMS:       2000,
			Retries:         0,
		}
		if err := s.SaveConfig(c); err != nil {
			t.Fatal(err)
		}
		loaded, err := s.LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		n := &Notifier{Now: func() time.Time { return fixedNow }}
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "delivered" {
			t.Fatalf("telegram send failed: %s", res)
		}
		text, _ := gotBody["text"].(string)
		if gotBody["message_thread_id"] != float64(88) || !strings.Contains(text, "vps-tokyo-01") ||
			!strings.Contains(text, "1111111111111111") || !strings.Contains(text, "7 天") ||
			strings.Contains(text, secretPassword) || strings.Contains(text, "bot-secret-token") {
			t.Fatalf("unexpected telegram payload: %+v", gotBody)
		}
	})

	t.Run("bark_push_and_app_code_check", func(t *testing.T) {
		var gotPath string
		var gotBody map[string]any
		code := 200
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			fmt.Fprintf(w, `{"code":%d}`, code)
		}))
		defer srv.Close()
		s := testStore(t)
		c := testConfig()
		c.Notifications = NotificationConfig{Enabled: true, Kind: "bark", Endpoint: srv.URL, Token: "bark-dev-key", TimeoutMS: 2000}
		if err := s.SaveConfig(c); err != nil {
			t.Fatal(err)
		}
		loaded, _ := s.LoadConfig()
		n := &Notifier{Now: func() time.Time { return fixedNow }}
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "delivered" || gotPath != "/push" {
			t.Fatalf("bark send failed: res=%s path=%s", res, gotPath)
		}
		if gotBody["device_key"] != "bark-dev-key" || gotBody["group"] != "QingNode" || strings.Contains(fmt.Sprint(gotBody["body"]), secretPassword) {
			t.Fatalf("unexpected bark payload: %+v", gotBody)
		}
		code = 400
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "failed" {
			t.Fatalf("bark HTTP 200 with code=400 must fail, got %s", res)
		}
	})

	t.Run("discord_webhook_204", func(t *testing.T) {
		var content string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var v struct {
				Content string `json:"content"`
			}
			_ = json.NewDecoder(r.Body).Decode(&v)
			content = v.Content
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		s := testStore(t)
		c := testConfig()
		c.Notifications = NotificationConfig{Enabled: true, Kind: "discord", Endpoint: srv.URL + "/api/webhooks/1/tok", TimeoutMS: 2000}
		if err := s.SaveConfig(c); err != nil {
			t.Fatal(err)
		}
		loaded, _ := s.LoadConfig()
		if res := (&Notifier{Now: func() time.Time { return fixedNow }}).Send(context.Background(), loaded, sampleEvent); res != "delivered" {
			t.Fatalf("discord send failed: %s", res)
		}
		if !strings.Contains(content, "1111111111111111") || strings.Contains(content, secretPassword) {
			t.Fatalf("unexpected discord content: %s", content)
		}
	})

	t.Run("feishu_hmac_signature_and_error_code", func(t *testing.T) {
		feishuSecret := "feishu-sign-secret-xyz"
		var got map[string]any
		respCode := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &got)
			fmt.Fprintf(w, `{"code":%d,"msg":"ok"}`, respCode)
		}))
		defer srv.Close()
		s := testStore(t)
		c := testConfig()
		c.Notifications = NotificationConfig{Enabled: true, Kind: "feishu", Endpoint: srv.URL + "/open-apis/bot/v2/hook/abc", Secret: feishuSecret, TimeoutMS: 2000}
		if err := s.SaveConfig(c); err != nil {
			t.Fatal(err)
		}
		loaded, _ := s.LoadConfig()
		n := &Notifier{Now: func() time.Time { return fixedNow }}
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "delivered" {
			t.Fatalf("feishu signed send failed: %s", res)
		}
		wantTS := fmt.Sprintf("%d", fixedNow.Unix())
		mac := hmac.New(sha256.New, []byte(wantTS+"\n"+feishuSecret))
		wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if got["timestamp"] != wantTS || got["sign"] != wantSign || got["msg_type"] != "text" {
			t.Fatalf("feishu signature mismatch: got=%+v wantSign=%s", got, wantSign)
		}
		if strings.Contains(fmt.Sprint(got), feishuSecret) || strings.Contains(fmt.Sprint(got), secretPassword) {
			t.Fatalf("feishu payload leaked secret: %+v", got)
		}
		respCode = 19021
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "failed" {
			t.Fatalf("feishu code=19021 must fail, got %s", res)
		}
	})

	t.Run("dingtalk_hmac_query_signature_and_errcode", func(t *testing.T) {
		dingSecret := "SEC-dingtalk-secret-123"
		var gotQueryTS, gotQuerySign, gotToken string
		var gotBody map[string]any
		errCode := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotToken = r.URL.Query().Get("access_token")
			gotQueryTS = r.URL.Query().Get("timestamp")
			gotQuerySign = r.URL.Query().Get("sign")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			fmt.Fprintf(w, `{"errcode":%d,"errmsg":"ok"}`, errCode)
		}))
		defer srv.Close()
		s := testStore(t)
		c := testConfig()
		c.Notifications = NotificationConfig{Enabled: true, Kind: "dingtalk", Endpoint: srv.URL + "/robot/send?access_token=dt-token-1", Secret: dingSecret, TimeoutMS: 2000}
		if err := s.SaveConfig(c); err != nil {
			t.Fatal(err)
		}
		loaded, _ := s.LoadConfig()
		n := &Notifier{Now: func() time.Time { return fixedNow }}
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "delivered" {
			t.Fatalf("dingtalk signed send failed: %s", res)
		}
		wantTS := fmt.Sprintf("%d", fixedNow.UnixMilli())
		mac := hmac.New(sha256.New, []byte(dingSecret))
		_, _ = mac.Write([]byte(wantTS + "\n" + dingSecret))
		wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if gotToken != "dt-token-1" || gotQueryTS != wantTS || gotQuerySign != wantSign {
			t.Fatalf("dingtalk query signature mismatch: token=%s ts=%s sign=%s want=%s", gotToken, gotQueryTS, gotQuerySign, wantSign)
		}
		if strings.Contains(fmt.Sprint(gotBody), dingSecret) || strings.Contains(fmt.Sprint(gotBody), secretPassword) {
			t.Fatalf("dingtalk body leaked secret: %+v", gotBody)
		}
		errCode = 310000
		if res := n.Send(context.Background(), loaded, sampleEvent); res != "failed" {
			t.Fatalf("dingtalk errcode=310000 must fail, got %s", res)
		}
	})
}

func TestEngineExtraEventsDeduplicationAndRetryOnFailure(t *testing.T) {
	var calls atomic.Int32
	failDelivery := atomic.Bool{}
	failDelivery.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failDelivery.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := testStore(t)
	c := testConfig()
	c.Notifications = NotificationConfig{Enabled: true, Kind: "discord", Endpoint: srv.URL + "/api/webhooks/1/tok", TimeoutMS: 1000, Retries: 0}
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	c, err := s.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	days := 9
	e := Engine{
		Store: s,
		ExtraEvents: func(now time.Time, _ Config) []Event {
			return []Event{{
				At:           now,
				JobID:        "cert-1111111111111111",
				From:         Healthy,
				To:           Degraded,
				Kind:         "cert-expiring",
				TargetName:   "MainCert",
				TargetID:     "1111111111111111",
				Reason:       "证书剩余9天",
				CertDaysLeft: &days,
				DedupeKey:    "cert-expiring:1111111111111111:2026-11-29T00:00:00Z",
			}}
		},
	}

	// Round 1: initial healthy status-change + cert-expiring; delivery fails (500), so dedupe key MUST NOT be locked in yet.
	snap1 := run(t, e, c, constantCollector(nil), nil)
	if len(snap1.Events) != 2 || calls.Load() != 2 {
		t.Fatalf("expected 2 events attempted on round 1, got %+v calls=%d", snap1.Events, calls.Load())
	}

	// Round 2: delivery succeeds; cert-expiring is retried and now delivered!
	failDelivery.Store(false)
	snap2 := run(t, e, c, constantCollector(nil), nil)
	if len(snap2.Events) != 1 || snap2.Events[0].Kind != "cert-expiring" || snap2.Events[0].Notification != "delivered" {
		t.Fatalf("expected cert-expiring retry to succeed on round 2, got %+v", snap2.Events)
	}

	// Round 3: cert-expiring with same DedupeKey is suppressed!
	callsBefore := calls.Load()
	snap3 := run(t, e, c, constantCollector(nil), nil)
	if len(snap3.Events) != 0 || calls.Load() != callsBefore {
		t.Fatalf("expected deduplicated round 3 to emit 0 events, got %+v", snap3.Events)
	}
}
