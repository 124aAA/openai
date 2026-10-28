package monitor

import (
	"context"
	"encoding/json"
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
)

func privateNotificationConfig(t *testing.T, s *Store, endpoint, kind string) Config {
	t.Helper()
	c := testConfig()
	c.Notifications = NotificationConfig{Enabled: true, Kind: kind, Endpoint: endpoint, Token: "never-print-this-token", ChatID: "private-chat", TimeoutMS: 1000, Retries: 1}
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	c, err := s.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNotificationRequiresExplicitPrivateConfig(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	n := &Notifier{}
	c := testConfig()
	c.Notifications.Endpoint = server.URL
	c.Notifications.Token = "secret"
	ev := Event{JobID: "job-1", From: Healthy, To: Failed}
	if got := n.Send(context.Background(), c, ev); got != "disabled" {
		t.Fatal(got)
	}
	c.Notifications.Enabled = true
	if got := n.Send(context.Background(), c, ev); got != "private_config_required" {
		t.Fatal(got)
	}
	if calls.Load() != 0 {
		t.Fatal("sent before private opt-in")
	}
	c = privateNotificationConfig(t, testStore(t), server.URL, "webhook")
	c.Notifications.Token = "unsaved-change"
	if got := n.Send(context.Background(), c, ev); got != "private_config_required" {
		t.Fatal("unsaved config trusted")
	}
}

func TestWebhookAuthenticationRetryDedupeAndRecovery(t *testing.T) {
	var calls atomic.Int32
	var events []Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer never-print-this-token" {
			t.Error("missing explicit auth")
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			io.WriteString(w, "never-print-this-token")
			return
		}
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
		}
		events = append(events, event)
		w.WriteHeader(204)
	}))
	defer server.Close()
	s := testStore(t)
	c := privateNotificationConfig(t, s, server.URL, "webhook")
	e := Engine{Store: s}
	first := run(t, e, c, constantCollector(localFailures), nil)
	if calls.Load() != 2 || first.Events[0].Notification != "delivered" {
		t.Fatalf("retry failed %+v", first)
	}
	run(t, e, c, constantCollector(localFailures), nil)
	if calls.Load() != 2 {
		t.Fatal("unchanged state resent")
	}
	recovered := run(t, e, c, constantCollector(nil), nil)
	if calls.Load() != 3 || recovered.Events[0].Kind != "recovery" {
		t.Fatal("recovery not notified")
	}
	run(t, e, c, constantCollector(nil), nil)
	if calls.Load() != 3 || len(events) != 2 {
		t.Fatal("repeated recovery")
	}
	for _, name := range []string{"status.json", "history.json"} {
		b, err := os.ReadFile(filepath.Join(s.Root, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{c.Notifications.Token, c.Notifications.Endpoint, c.Notifications.ChatID} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("%s leaked a secret", name)
			}
		}
	}
}

func TestNotificationRejectsRedirectAndBoundsBody(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	for _, mode := range []string{"redirect", "large_body", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
				case "large_body":
					io.WriteString(w, strings.Repeat("x", 4097))
				case "unauthorized":
					w.WriteHeader(401)
				}
			}))
			defer server.Close()
			c := privateNotificationConfig(t, testStore(t), server.URL, "webhook")
			n := &Notifier{Client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}}
			got := n.Send(context.Background(), c, Event{JobID: "job-1", From: Healthy, To: Failed})
			if got == "delivered" || calls.Load() != 1 {
				t.Fatalf("unsafe retry/result %s %d", got, calls.Load())
			}
		})
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("redirect leaked authorization")
	}
}

func TestNotificationCancellationDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	arrived := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(arrived)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	c := privateNotificationConfig(t, testStore(t), server.URL, "webhook")
	n := &Notifier{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() { done <- n.Send(ctx, c, Event{JobID: "job-1", From: Healthy, To: Failed}) }()
	<-arrived
	cancel()
	select {
	case got := <-done:
		if got != "cancelled" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel ignored")
	}
	if calls.Load() != 1 {
		t.Fatal("cancelled delivery retried")
	}
}

func TestTelegramPrivateDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botnever-print-this-token/sendMessage" {
			t.Errorf("wrong method path")
		}
		var v struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			t.Error(err)
		}
		if v.ChatID != "private-chat" || strings.Contains(v.Text, "never-print-this-token") {
			t.Error("bad telegram body")
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	c := privateNotificationConfig(t, testStore(t), server.URL, "telegram")
	if got := (&Notifier{}).Send(context.Background(), c, Event{JobID: "job-1", From: Failed, To: Healthy}); got != "delivered" {
		t.Fatal(got)
	}
}

func TestNotificationEndpointPolicy(t *testing.T) {
	for _, endpoint := range []string{"http://example.com/secret", "http://localhost/secret", "https://user:secret@example.com/", "https://example.com/#token", "file:///tmp/token"} {
		if _, err := notificationURL(NotificationConfig{Kind: "webhook", Endpoint: endpoint}); err == nil {
			t.Fatalf("accepted insecure endpoint %q", endpoint)
		}
	}
}
