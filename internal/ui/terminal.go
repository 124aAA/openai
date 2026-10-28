package ui

// Human text has a separate output path from JSON, client configurations, URIs
// and QR codes. This file never changes terminal modes or cursor visibility.
import (
	"bytes"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

const maxHumanLine = 256 << 10

// Width returns the actual terminal's column count. Redirected output is not
// wrapped, and COLUMNS from the environment cannot impersonate a terminal.
func Width(w io.Writer) int {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0
	}
	columns, _, err := term.GetSize(int(f.Fd()))
	if err != nil || columns < 2 || columns > 4096 {
		return 0
	}
	return columns
}

type escapeState uint8

const (
	plain escapeState = iota
	escape
	intermediate
	csi
	controlString
	stringEscape
)

// SanitizeText removes terminal commands (including OSC hyperlinks and clipboard
// commands), Bidi overrides/isolates and other display controls. Tabs become four
// spaces; line boundaries remain explicit. It does not redact secrets: callers
// must still use the project's State-aware redaction before displaying text.
func SanitizeText(text string) string {
	clean, _ := sanitize(text, plain)
	return clean
}

func sanitize(text string, state escapeState) (string, escapeState) {
	var out strings.Builder
	for _, r := range text {
		switch state {
		case escape:
			switch r {
			case '[':
				state = csi
			case ']', 'P', '^', '_', 'X':
				state = controlString
			default:
				state = plain
				if r >= 0x20 && r <= 0x2f {
					state = intermediate
				}
			}
			continue
		case intermediate:
			if r == 0x1b {
				state = escape
			} else if r >= 0x30 && r <= 0x7e {
				state = plain
			}
			continue
		case csi:
			if r == 0x1b {
				state = escape
			} else if r >= 0x40 && r <= 0x7e {
				state = plain
			}
			continue
		case controlString:
			if r == 7 || r == 0x9c {
				state = plain
			} else if r == 0x1b {
				state = stringEscape
			}
			continue
		case stringEscape:
			if r == '\\' || r == 0x9c || r == 7 {
				state = plain
			} else if r != 0x1b {
				state = controlString
			}
			continue
		}
		switch {
		case r == 0x1b:
			state = escape
		case r == 0x9b:
			state = csi
		case r == 0x90 || r == 0x98 || r == 0x9d || r == 0x9e || r == 0x9f:
			state = controlString
		case r == '\n' || r == 0x2028 || r == 0x2029:
			out.WriteByte('\n')
		case r == '\t':
			out.WriteString("    ")
		case unicode.IsControl(r) || bidiControl(r) || r == 0xfeff || r == 0x200b || r == 0x2060:
			out.WriteByte(' ')
		default:
			out.WriteRune(r)
		}
	}
	return out.String(), state
}

func bidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}

type textCluster struct {
	text  string
	width int
}

func combining(r rune) bool {
	return unicode.IsMark(r) || r == 0x200c || r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0100 && r <= 0xe01ef || r >= 0x1f3fb && r <= 0x1f3ff || r >= 0xe0020 && r <= 0xe007f
}

func regional(r rune) bool { return r >= 0x1f1e6 && r <= 0x1f1ff }

// The menu profile keeps combining marks and the common emoji sequences (ZWJ,
// modifiers, flag pairs and keycaps) together. It is not a full UAX #29 text
// editor. Ambiguous-width characters use one cell; terminal/font differences
// remain possible, so machine data must never be recovered from wrapped text.
func clusters(text string) []textCluster {
	var result []textCluster
	var current strings.Builder
	width, regionalCount := 0, 0
	joinNext := false
	flush := func() {
		if current.Len() > 0 {
			result = append(result, textCluster{current.String(), width})
			current.Reset()
		}
		width, regionalCount, joinNext = 0, 0, false
	}
	for _, r := range text {
		if r == '\n' {
			flush()
			result = append(result, textCluster{"\n", 0})
			continue
		}
		attached := current.Len() > 0 && (combining(r) || r == 0x200d || joinNext || regional(r) && regionalCount == 1)
		if !attached {
			flush()
		}
		current.WriteRune(r)
		if r == 0x200d {
			joinNext = true
			continue
		}
		if regional(r) {
			regionalCount++
			width = 2
		} else if !combining(r) {
			regionalCount = 0
		}
		if r == 0xfe0f || r == 0x20e3 {
			width = max(width, 2)
		} else if !combining(r) {
			width = max(width, runeWidth(r))
		}
		if !combining(r) {
			joinNext = false
		}
	}
	flush()
	return result
}

func runeWidth(r rune) int {
	if combining(r) || r == 0x200d {
		return 0
	}
	lo, hi := 0, len(wideRunes)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if r < wideRunes[mid][0] {
			hi = mid
		} else if r > wideRunes[mid][1] {
			lo = mid + 1
		} else {
			return 2
		}
	}
	return 1
}

// DisplayWidth returns the largest line's width under the menu profile. Newline
// controls and terminal commands are sanitized first.
func DisplayWidth(text string) int {
	longest, column := 0, 0
	for _, cluster := range clusters(SanitizeText(text)) {
		if cluster.text == "\n" {
			longest, column = max(longest, column), 0
		} else {
			column += cluster.width
		}
	}
	return max(longest, column)
}

// WrapText folds human text without truncating Unicode or emoji clusters.
// width<=0 disables folding for ordinary redirected text. This is deliberately
// unsuitable for JSON, exported links, QR codes or configuration documents.
func WrapText(text string, width int) string {
	return wrapClean(SanitizeText(text), width)
}

func wrapClean(text string, width int) string {
	wrapped, _ := wrapCleanAt(text, width, 0)
	return wrapped
}

func wrapCleanAt(text string, width, column int) (string, int) {
	if width <= 0 {
		return text, 0
	}
	var out strings.Builder
	for _, cluster := range clusters(text) {
		if cluster.text == "\n" {
			out.WriteByte('\n')
			column = 0
			continue
		}
		if column > 0 && column+cluster.width > width {
			out.WriteByte('\n')
			column = 0
		}
		out.WriteString(cluster.text)
		column += cluster.width
	}
	return out.String(), column
}

// TextWriter buffers one human line so split UTF-8 and terminal commands cannot
// bypass sanitization. Use Flush for a final unterminated line; prompts should
// use WrapText directly. Writes are bounded and are not concurrency-safe.
type TextWriter struct {
	out     io.Writer
	width   int
	pending []byte
	state   escapeState
	column  int
	err     error
}

func HumanWriter(w io.Writer) *TextWriter { return NewTextWriter(w, Width(w)) }

func NewTextWriter(w io.Writer, width int) *TextWriter {
	return &TextWriter{out: w, width: width}
}

func (w *TextWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	for _, part := range bytes.SplitAfter(p, []byte{'\n'}) {
		if len(w.pending)+len(part) > maxHumanLine {
			w.err = errors.New("人类文本单行超过256KiB，停止输出")
			return 0, w.err
		}
		w.pending = append(w.pending, part...)
		if len(part) > 0 && part[len(part)-1] == '\n' {
			if err := w.emit(); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func (w *TextWriter) emit() error {
	clean, state := sanitize(string(w.pending), w.state)
	w.state = state
	w.pending = w.pending[:0]
	if !utf8.ValidString(clean) {
		clean = strings.ToValidUTF8(clean, "�")
	}
	formatted, column := wrapCleanAt(clean, w.width, w.column)
	w.column = column
	_, w.err = io.WriteString(w.out, formatted)
	return w.err
}

func (w *TextWriter) Flush() error {
	if w.err != nil {
		return w.err
	}
	if len(w.pending) > 0 {
		return w.emit()
	}
	return nil
}
