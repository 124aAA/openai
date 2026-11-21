package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSandboxCoreVerificationCacheHitAndInvalidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script fixture requires unix")
	}
	dir := t.TempDir()
	counterFile := filepath.Join(dir, "invocations")
	coreBin := filepath.Join(dir, "fake-sing-box")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"version\" ]; then\n" +
		"  printf '1' >> '" + counterFile + "'\n" +
		"  printf 'sing-box version 1.14.0\\nTags: with_quic,with_utls,with_wireguard,with_gvisor\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(coreBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(coreBin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		ver, err := verifyProbeCoreTypes(ctx, []string{"hysteria2", "wireguard"}, SandboxOptions{CoreBinary: coreBin, SHA256: digest})
		if err != nil || ver != "1.14.0" {
			t.Fatalf("verify call %d failed: ver=%q err=%v", i, ver, err)
		}
	}
	invocations, err := os.ReadFile(counterFile)
	if err != nil || len(invocations) != 1 {
		t.Fatalf("expected cached verification to execute 'version' once across 5 calls, got %d", len(invocations))
	}

	// Modify core binary (new mtime/size/sha256): cache must invalidate and execute 'version' again!
	time.Sleep(10 * time.Millisecond)
	scriptV2 := script + "# updated\n"
	if err := os.WriteFile(coreBin, []byte(scriptV2), 0700); err != nil {
		t.Fatal(err)
	}
	sum2 := sha256.Sum256([]byte(scriptV2))
	digest2 := hex.EncodeToString(sum2[:])
	if _, err := verifyProbeCoreTypes(ctx, []string{"hysteria2"}, SandboxOptions{CoreBinary: coreBin, SHA256: digest2}); err != nil {
		t.Fatal(err)
	}
	invocations2, err := os.ReadFile(counterFile)
	if err != nil || len(invocations2) != 2 {
		t.Fatalf("expected cache invalidation after binary modification, got %d invocations", len(invocations2))
	}

	// Wrong expected SHA256 must never hit cache!
	if _, err := verifyProbeCoreTypes(ctx, nil, SandboxOptions{CoreBinary: coreBin, SHA256: digest}); err == nil {
		t.Fatal("stale digest erroneously accepted")
	}
}

func TestDarwinLsofListenerParserEdgeCases(t *testing.T) {
	raw := "p4321\nf5\nn127.0.0.1:1080\nTST=LISTEN\nf6\nn127.0.0.1:3080->127.0.0.1:55555\nTST=ESTABLISHED\n"
	if ok, err := parseDarwinLsofListener([]byte(raw), 4321, 1080); err != nil || !ok {
		t.Fatalf("expected 127.0.0.1:1080 LISTEN match, got ok=%v err=%v", ok, err)
	}
	if ok, err := parseDarwinLsofListener([]byte(raw), 4321, 3080); err != nil || ok {
		t.Fatalf("ESTABLISHED socket must not be treated as LISTEN, got ok=%v err=%v", ok, err)
	}
	if ok, err := parseDarwinLsofListener([]byte(raw), 9999, 1080); err != nil || ok {
		t.Fatalf("foreign PID must not match, got ok=%v err=%v", ok, err)
	}
	oversized := make([]byte, (256<<10)+1)
	if _, err := parseDarwinLsofListener(oversized, 4321, 1080); err == nil {
		t.Fatal("expected oversized lsof output to be rejected")
	}
}

