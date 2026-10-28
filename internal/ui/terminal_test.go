package ui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeTextCannotExecuteTerminalCommandsOrBidiOverrides(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"名称\x1b[2J被覆盖\x1b[0m", "名称被覆盖"},
		{"a\x1b]52;c;private-clipboard\a安全", "a安全"},
		{"\x1b]8;;https://untrusted.invalid\x1b\\名称\x1b]8;;\x1b\\", "名称"},
		{"left\x1bPpayload\x1b\\right", "leftright"},
		{"\x1b(0abc\x1b(B", "abc"},
		{"a\u009b31mb\u009b0mc", "abc"},
		{"a\u009d52;payload\u009cb", "ab"},
		{"A\u202eB\u202cC\u2066D\u2069E", "A B C D E"},
		{"a\x00\x08\r\x7fb\tend\nnext", "a    b    end\nnext"},
		{"a\u2028b\u2029c", "a\nb\nc"},
		{"text\x1b]unclosed", "text"},
		{"[ERROR] ordinary 127.0.0.1", "[ERROR] ordinary 127.0.0.1"},
		{"👩🏽‍💻 e\u0301 🇨🇳 1️⃣", "👩🏽‍💻 e\u0301 🇨🇳 1️⃣"},
	} {
		if got := SanitizeText(tc.input); got != tc.want {
			t.Errorf("sanitize %q: got %q want %q", tc.input, got, tc.want)
		}
	}
}

func TestDisplayWidthCountsChineseAndCommonEmojiClusters(t *testing.T) {
	for _, tc := range []struct {
		text  string
		width int
	}{
		{"中文abc", 7}, {"ｅｘ", 4}, {"e\u0301", 1}, {"👩🏽‍💻", 2},
		{"👨‍👩‍👧‍👦", 2}, {"🇨🇳", 2}, {"🇨🇳🇺🇸", 4}, {"1️⃣", 2},
		{"⚠️", 2}, {"✅", 2}, {"a\n中文", 4}, {"a\x1b[31mb", 2},
	} {
		if got := DisplayWidth(tc.text); got != tc.width {
			t.Errorf("width %q: got %d want %d", tc.text, got, tc.width)
		}
	}
}

func TestWrappingFitsPhoneAndDesktopWithoutLosingData(t *testing.T) {
	text := "节点：测试👩🏽‍💻🇨🇳e\u0301 完整地址 [2001:db8:1234:5678:9abc:def0:1234:5678]:30000 " +
		strings.Repeat("very-long-domain-label.", 7) + "example.invalid"
	for _, width := range []int{32, 40, 80} {
		out := WrapText(text, width)
		if !utf8.ValidString(out) || strings.ReplaceAll(out, "\n", "") != text {
			t.Fatalf("width %d changed Unicode or truncated text: %q", width, out)
		}
		for _, line := range strings.Split(out, "\n") {
			if got := DisplayWidth(line); got > width {
				t.Fatalf("width %d overflowed at %d: %q", width, got, line)
			}
		}
		for _, emoji := range []string{"👩🏽‍💻", "🇨🇳", "e\u0301"} {
			if !strings.Contains(out, emoji) {
				t.Fatalf("width %d split cluster %q", width, emoji)
			}
		}
	}
	if got := WrapText(text, 0); got != text {
		t.Fatal("redirected text unexpectedly wrapped")
	}
	if got := WrapText("中🙂x\nabc", 3); got != "中\n🙂x\nabc" {
		t.Fatal("explicit newlines or wide cells changed", got)
	}
}

func TestTextWriterHandlesSplitUTF8EscapeStringsAndFinalLine(t *testing.T) {
	input := "12345\x1b]52;c;hidden\ncontinued\x1b\\中文👩🏽‍💻\n末行"
	var out bytes.Buffer
	w := NewTextWriter(&out, 8)
	for _, b := range []byte(input) {
		if n, err := w.Write([]byte{b}); n != 1 || err != nil {
			t.Fatal("fragment write failed", n, err)
		}
	}
	if strings.Contains(out.String(), "末行") {
		t.Fatal("unterminated human line should wait for explicit Flush")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), WrapText(input, 8); got != want {
		t.Fatalf("stream sanitization differs: %q want %q", got, want)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if DisplayWidth(line) > 8 {
			t.Fatal("fragmented hidden control string lost the display column")
		}
	}
}

func TestHumanWriterRedirectedAndEnvironmentStayPlain(t *testing.T) {
	for _, env := range []struct{ term, noColor string }{{"xterm-256color", ""}, {"dumb", ""}, {"xterm", "1"}} {
		t.Setenv("TERM", env.term)
		t.Setenv("NO_COLOR", env.noColor)
		t.Setenv("COLUMNS", "4")
		var out bytes.Buffer
		w := HumanWriter(&out)
		if Width(&out) != 0 {
			t.Fatal("environment spoofed a redirected writer into a TTY")
		}
		if _, err := io.WriteString(w, "中文长域名.example.invalid\x1b[31m\n"); err != nil {
			t.Fatal(err)
		}
		if out.String() != "中文长域名.example.invalid\n" {
			t.Fatal("redirected human output should be plain and unfolded", out.String())
		}
	}
}

type failedTextOutput struct{}

func (failedTextOutput) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestTextWriterBoundAndOutputErrorAreNotReportedAsSuccess(t *testing.T) {
	var out bytes.Buffer
	w := NewTextWriter(&out, 32)
	if _, err := w.Write(bytes.Repeat([]byte{'a'}, maxHumanLine+1)); err == nil || out.Len() != 0 {
		t.Fatal("oversized unterminated line was accepted")
	}
	if err := w.Flush(); err == nil {
		t.Fatal("failed text writer lost its error")
	}
	w = NewTextWriter(failedTextOutput{}, 40)
	if _, err := w.Write([]byte("test\n")); err == nil {
		t.Fatal("failed underlying output was reported as successful")
	}
	if _, err := w.Write([]byte("retry\n")); err == nil {
		t.Fatal("sticky error was ignored")
	}
}

func TestWideRangeTableIsOrderedAndDoesNotOverrideCombiningMarks(t *testing.T) {
	for i, span := range wideRunes {
		if span[0] > span[1] || i > 0 && wideRunes[i-1][1] >= span[0] {
			t.Fatal("generated Unicode range overlap or disorder")
		}
	}
	if runeWidth('\u0301') != 0 || runeWidth('\ufe0f') != 0 || runeWidth('中') != 2 || runeWidth('a') != 1 {
		t.Fatal("menu tailoring broke base width rules")
	}
}
