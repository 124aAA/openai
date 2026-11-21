package node

import (
	"strings"
	"testing"
)

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

func TestPinnedCoreArchiveDigestsPreserveDefaultAndIncludeVerified1143(t *testing.T) {
	if DefaultCore != "1.14.0" {
		t.Fatalf("DefaultCore changed unexpectedly: %s", DefaultCore)
	}
	want := map[[2]string]string{
		{"1.14.0", "amd64"}:  "2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63",
		{"1.14.0", "arm64"}:  "04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088",
		{"1.14.3", "amd64"}:  "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
		{"1.14.3", "arm64"}:  "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
		{"v1.14.3", "amd64"}: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
	}
	for k, expected := range want {
		if got := PinnedCoreArchiveSHA256(k[0], k[1]); got != expected {
			t.Fatalf("PinnedCoreArchiveSHA256(%q, %q) = %q, want %q", k[0], k[1], got, expected)
		}
	}
	if got := PinnedCoreArchiveSHA256("1.14.99", "amd64"); got != "" {
		t.Fatalf("unexpected pinned digest for unverified version: %q", got)
	}
	if err := InstallCore(t.TempDir(), "1.14.99", "", "/nonexistent.tar.gz"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("unpinned version did not require explicit SHA-256: %v", err)
	}
	if err := InstallCore(t.TempDir(), "1.14.3", "", "/nonexistent-1.14.3-archive.tar.gz"); err == nil || strings.Contains(err.Error(), "需要显式提供官方归档的 SHA-256") {
		t.Fatalf("pinned 1.14.3 unexpectedly rejected empty sum before archive open: %v", err)
	}
}
