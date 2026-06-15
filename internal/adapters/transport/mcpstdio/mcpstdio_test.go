package mcpstdio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		{"empty body", [][]byte{{}}},
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

// TestFramerHeaderCaseInsensitive checks that a lowercase header name and an
// ignored sibling header still parse, since servers vary on capitalization.
func TestFramerHeaderCaseInsensitive(t *testing.T) {
	body := []byte(`{"ok":true}`)
	raw := fmt.Sprintf("content-length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(body), body)
	f := NewFramer(strings.NewReader(raw), io.Discard)
	got, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("ReadMessage=%q want %q", got, body)
	}
}

func TestFramerReadMalformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"missing content-length", "Content-Type: application/json\r\n\r\n{}"},
		{"non-numeric length", "Content-Length: abc\r\n\r\n{}"},
		{"negative length", "Content-Length: -1\r\n\r\n{}"},
		{"header without colon", "Content-Length 5\r\n\r\nhello"},
		{"length over cap", fmt.Sprintf("Content-Length: %d\r\n\r\n", MaxMessageBytes+1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := NewFramer(strings.NewReader(c.raw), io.Discard)
			_, err := f.ReadMessage()
			if !errors.Is(err, ErrMalformedFrame) {
				t.Fatalf("err=%v want ErrMalformedFrame", err)
			}
		})
	}
}

// TestFramerCleanEOF distinguishes a closed stream from a malformed frame: an
// EOF before any header byte must surface as io.EOF, not ErrMalformedFrame.
func TestFramerCleanEOF(t *testing.T) {
	f := NewFramer(strings.NewReader(""), io.Discard)
	if _, err := f.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("err=%v want io.EOF", err)
	}
}

// TestFramerTruncatedBody verifies that a body shorter than the declared length
// fails rather than returning partial bytes.
func TestFramerTruncatedBody(t *testing.T) {
	f := NewFramer(strings.NewReader("Content-Length: 10\r\n\r\nshort"), io.Discard)
	_, err := f.ReadMessage()
	if err == nil {
		t.Fatal("want error on truncated body, got nil")
	}
	if errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("truncated body should not be ErrMalformedFrame, got %v", err)
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
