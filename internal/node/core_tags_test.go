package node

import "testing"

func TestCompatibleVersionRequiresExactBuildCapabilities(t *testing.T) {
	for _, tc := range []struct {
		output   string
		accepted bool
	}{
		{"sing-box version 1.14.3\nTags: with_quic,with_utls,with_acme,with_clash_api\n", true},
		{"sing-box version 1.14.3\nTags: with_quic with_utls with_acme\n", true},
		{"sing-box version 1.14.3\n", false},
		{"sing-box version 1.14.3\nTags: with_quic,with_utls\n", false},
		{"sing-box version 1.14.3\nTags: without_quic,with_utls,with_acme\n", false},
		{"sing-box version 1.14.3\nTags: with_quic_extra,with_utls,with_acme\n", false},
		{"sing-box version 1.14.3\nBuild note: with_quic,with_utls,with_acme\n", false},
	} {
		if err := verifyCoreTags(tc.output); (err == nil) != tc.accepted {
			t.Fatalf("capability verification=%v, expected acceptance=%v", err, tc.accepted)
		}
	}
}
