package main

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

// Flag parsing happens before State can be loaded. Do not echo arbitrary input
// values (which may be pasted credentials) in its automatic error output.
func safeCLIError(text string) string {
	if start := strings.Index(text, "invalid value "); start >= 0 {
		if end := strings.Index(text[start:], " for flag -"); end >= 0 {
			text = text[:start] + "invalid value [input hidden]" + text[start+end:]
		}
	}
	return ui.SanitizeText(node.Redact(text))
}

type cliErrorWriter struct{ out io.Writer }

func (w cliErrorWriter) Write(p []byte) (int, error) {
	_, err := io.WriteString(w.out, ui.WrapText(safeCLIError(string(p)), ui.Width(w.out)))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Redact complete source lines before wrapping: a secret split across writes
// or display columns must never evade State-aware redaction. This writer is
// only for human diagnostics, never JSON or exported client configuration.
type stateTextWriter struct {
	out     io.Writer
	human   *ui.TextWriter
	state   node.State
	pending []byte
	err     error
}

func newStateTextWriter(out io.Writer, state node.State) *stateTextWriter {
	return &stateTextWriter{out: out, human: ui.HumanWriter(out), state: state}
}

func (w *stateTextWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	for _, part := range bytes.SplitAfter(p, []byte{'\n'}) {
		if len(w.pending)+len(part) > 256<<10 {
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

func (w *stateTextWriter) emit() error {
	_, w.err = io.WriteString(w.human, node.Redact(string(w.pending), w.state))
	w.pending = w.pending[:0]
	return w.err
}

func (w *stateTextWriter) Flush() error {
	if w.err == nil && len(w.pending) > 0 {
		w.emit()
	}
	if w.err == nil {
		w.err = w.human.Flush()
	}
	return w.err
}

// Explicit private lines (URI, UUID/password and keys) keep their original
// bytes. Flush ordinary text first; all errors remain visible to final Flush.
func (w *stateTextWriter) Raw(text string) error {
	if err := w.Flush(); err != nil {
		return err
	}
	_, w.err = io.WriteString(w.out, text)
	return w.err
}
