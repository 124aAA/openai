package node

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestManagedRestartRecoversOnlyConfirmedStartLimit(t *testing.T) {
	const restart = "systemctl restart qingnode.service"
	const inspect = "systemctl show qingnode.service --property=Result --value"
	const reset = "systemctl reset-failed qingnode.service"
	firstFailure := errors.New("first restart failure")
	otherFailure := errors.New("later command failure")
	s := fixture(t)
	private := s.Nodes[0].Reality.PrivateKey
	firstOutput := "initial diagnostic " + private + "\npassword: first-secret\n"
	otherOutput := "later diagnostic " + private + "\npassword: later-secret\n"
	type response struct {
		command string
		output  string
		err     error
	}
	cases := []struct {
		name      string
		responses []response
		wantError bool
		wantLater bool
	}{
		{
			name:      "healthy restart does not inspect or reset",
			responses: []response{{restart, "", nil}},
		},
		{
			name: "confirmed limit resets and retries once",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, "start-limit-hit\n", nil},
				{reset, "", nil}, {restart, "", nil},
			},
		},
		{
			name: "ordinary service failure is not retried",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, "exit-code\n", nil},
			},
			wantError: true,
		},
		{
			name: "empty result is not retried",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, "", nil},
			},
			wantError: true,
		},
		{
			name: "ambiguous result is not retried",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, "start-limit-hit\nexit-code\n", nil},
			},
			wantError: true,
		},
		{
			name: "failed result query preserves both diagnostics",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, otherOutput, otherFailure},
			},
			wantError: true, wantLater: true,
		},
		{
			name: "failed reset prevents retry",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, "start-limit-hit\n", nil},
				{reset, otherOutput, otherFailure},
			},
			wantError: true, wantLater: true,
		},
		{
			name: "failed retry cannot reset or retry again",
			responses: []response{
				{restart, firstOutput, firstFailure}, {inspect, "start-limit-hit\n", nil},
				{reset, "", nil}, {restart, otherOutput, otherFailure},
			},
			wantError: true, wantLater: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			b := SystemBackend{Execute: func(_ time.Duration, name string, args ...string) ([]byte, error) {
				command := name + " " + strings.Join(args, " ")
				if calls >= len(tc.responses) {
					t.Fatalf("unexpected command after final response: %s", command)
				}
				r := tc.responses[calls]
				calls++
				if command != r.command {
					t.Fatalf("command %d: got %q, want %q", calls, command, r.command)
				}
				return []byte(r.output), r.err
			}}
			err := b.restartService(s)
			if (err != nil) != tc.wantError || calls != len(tc.responses) {
				t.Fatalf("error=%v, calls=%d; want error=%v, calls=%d", err, calls, tc.wantError, len(tc.responses))
			}
			if err == nil {
				return
			}
			if !errors.Is(err, firstFailure) || !strings.Contains(err.Error(), "initial diagnostic") || !strings.Contains(err.Error(), restart) {
				t.Fatalf("initial command failure lost: %v", err)
			}
			if tc.wantLater && (!errors.Is(err, otherFailure) || !strings.Contains(err.Error(), "later diagnostic")) {
				t.Fatalf("later command failure lost: %v", err)
			}
			for _, secret := range []string{private, "first-secret", "later-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("command diagnostic leaked credentials")
				}
			}
		})
	}
}
