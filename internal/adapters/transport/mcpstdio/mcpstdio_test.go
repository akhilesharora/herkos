package mcpstdio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFramerRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		msgs [][]byte
	}{
		{"single", [][]byte{[]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)}},
		{"several", [][]byte{
			[]byte(`{"id":1}`),
			[]byte(`{"id":2,"params":{"x":1}}`),
			[]byte(`{"id":3}`),
		}},
		{"utf8 body", [][]byte{[]byte(`{"text":"héllo-世界"}`)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			f := NewFramer(&buf, &buf)
			for _, m := range c.msgs {
				if err := f.WriteMessage(m); err != nil {
					t.Fatalf("WriteMessage: %v", err)
				}
			}
			for i, want := range c.msgs {
				got, err := f.ReadMessage()
				if err != nil {
					t.Fatalf("ReadMessage[%d]: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("ReadMessage[%d]=%q want %q", i, got, want)
				}
			}
		})
	}
}

// TestFramerBackToBack checks that two messages written without any gap are each
// read back whole, with no bytes from the second leaking into the first.
func TestFramerBackToBack(t *testing.T) {
	first := []byte(`{"id":1,"method":"a"}`)
	second := []byte(`{"id":2,"method":"b"}`)
	f := NewFramer(strings.NewReader(string(first)+"\n"+string(second)+"\n"), io.Discard)

	got1, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage[0]: %v", err)
	}
	if !bytes.Equal(got1, first) {
		t.Fatalf("ReadMessage[0]=%q want %q", got1, first)
	}
	got2, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage[1]: %v", err)
	}
	if !bytes.Equal(got2, second) {
		t.Fatalf("ReadMessage[1]=%q want %q", got2, second)
	}
}

// TestFramerCRLFTerminated verifies a line ending in CRLF is returned without the
// trailing carriage return, since some peers emit \r\n line endings.
func TestFramerCRLFTerminated(t *testing.T) {
	body := []byte(`{"ok":true}`)
	f := NewFramer(strings.NewReader(string(body)+"\r\n"), io.Discard)
	got, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("ReadMessage=%q want %q", got, body)
	}
}

// TestFramerSkipsBlankLines checks that a blank line between two messages is
// skipped rather than returned as an empty message.
func TestFramerSkipsBlankLines(t *testing.T) {
	first := []byte(`{"id":1}`)
	second := []byte(`{"id":2}`)
	// Blank lines around and between the two messages, including a bare CRLF.
	raw := "\n" + string(first) + "\n\n" + "\r\n" + string(second) + "\n"
	f := NewFramer(strings.NewReader(raw), io.Discard)

	got1, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage[0]: %v", err)
	}
	if !bytes.Equal(got1, first) {
		t.Fatalf("ReadMessage[0]=%q want %q", got1, first)
	}
	got2, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage[1]: %v", err)
	}
	if !bytes.Equal(got2, second) {
		t.Fatalf("ReadMessage[1]=%q want %q", got2, second)
	}
}

// neverNewlineReader yields infinitely many non-newline bytes so ReadMessage can
// never find a frame terminator. It lets the cap be exercised without allocating
// a MaxMessageBytes-sized literal in the test.
type neverNewlineReader struct{}

func (neverNewlineReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// TestFramerReadOverCap checks that a line that never terminates is rejected with
// ErrMalformedFrame once it exceeds MaxMessageBytes, instead of allocating without
// bound.
func TestFramerReadOverCap(t *testing.T) {
	f := NewFramer(neverNewlineReader{}, io.Discard)
	_, err := f.ReadMessage()
	if !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("err=%v want ErrMalformedFrame", err)
	}
}

// TestFramerWriteEmbeddedNewline checks that a body carrying an embedded newline
// is refused: the spec forbids it and writing it would inject a frame boundary.
func TestFramerWriteEmbeddedNewline(t *testing.T) {
	var buf bytes.Buffer
	f := NewFramer(strings.NewReader(""), &buf)
	err := f.WriteMessage([]byte("{\"a\":1}\n{\"b\":2}"))
	if !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("err=%v want ErrMalformedFrame", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("rejected write must not emit bytes; buffer has %d", buf.Len())
	}
}

// TestFramerCleanEOF distinguishes a closed stream from a malformed frame: an EOF
// before any byte is read must surface as io.EOF.
func TestFramerCleanEOF(t *testing.T) {
	f := NewFramer(strings.NewReader(""), io.Discard)
	if _, err := f.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("err=%v want io.EOF", err)
	}
}

// TestFramerUnterminatedFinalLine verifies that a non-empty final line with no
// trailing newline is returned, and the following read reports io.EOF.
func TestFramerUnterminatedFinalLine(t *testing.T) {
	body := []byte(`{"id":1}`)
	f := NewFramer(strings.NewReader(string(body)), io.Discard)

	got, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("ReadMessage=%q want %q", got, body)
	}
	if _, err := f.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("err=%v want io.EOF", err)
	}
}

func TestTransportRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	tr := NewTransport(&buf, &buf)
	ctx := context.Background()
	want := []byte(`{"jsonrpc":"2.0","method":"notify"}`)
	if err := tr.Send(ctx, want); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := tr.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Recv=%q want %q", got, want)
	}
}

func TestTransportRespectsCancelledContext(t *testing.T) {
	var buf bytes.Buffer
	tr := NewTransport(&buf, &buf)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tr.Send(ctx, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send err=%v want context.Canceled", err)
	}
	if _, err := tr.Recv(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recv err=%v want context.Canceled", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("cancelled Send must not write; buffer has %d bytes", buf.Len())
	}
}
