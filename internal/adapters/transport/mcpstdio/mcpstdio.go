// Package mcpstdio is a stdio transport adapter that carries MCP/JSON-RPC
// messages using LSP-style Content-Length framing.
//
// The wire format is a header block terminated by a blank line followed by an
// exact-length body:
//
//	Content-Length: <N>\r\n
//	\r\n
//	<N bytes of JSON>
//
// Reading is fail-closed: a missing or malformed length, or a length over the
// cap, is an error rather than a best-effort parse. This adapter is pure
// plumbing - it frames and forwards bytes and never inspects or authorizes the
// payload.
package mcpstdio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/akhilesharora/herkos/internal/ports"
)

// MaxMessageBytes caps the body size a single frame may declare. A frame whose
// Content-Length exceeds this is rejected before any body bytes are read, so a
// hostile or corrupt header cannot drive an unbounded allocation.
const MaxMessageBytes = 32 << 20 // 32 MiB

// contentLengthHeader is the only header Framer interprets; matched case-insensitively.
const contentLengthHeader = "content-length"

// ErrMalformedFrame is returned when a frame's header block is missing the
// Content-Length, carries a non-numeric or negative length, or declares a
// length over [MaxMessageBytes].
var ErrMalformedFrame = errors.New("mcpstdio: malformed frame")

// Framer reads and writes Content-Length-framed JSON-RPC messages over an
// io.Reader / io.Writer pair. It is not safe for concurrent use on the same
// direction; serialize calls to WriteMessage and serialize calls to ReadMessage.
type Framer struct {
	r *bufio.Reader
	w io.Writer
}

// NewFramer returns a Framer that reads frames from r and writes frames to w.
func NewFramer(r io.Reader, w io.Writer) *Framer {
	return &Framer{r: bufio.NewReader(r), w: w}
}

// WriteMessage frames b as "Content-Length: N\r\n\r\n" followed by the raw body
// bytes and writes the whole frame to the underlying writer. b is sent verbatim;
// WriteMessage does not validate that it is JSON.
func (f *Framer) WriteMessage(b []byte) error {
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(b))
	if _, err := io.WriteString(f.w, header); err != nil {
		return fmt.Errorf("mcpstdio: write header: %w", err)
	}
	if _, err := f.w.Write(b); err != nil {
		return fmt.Errorf("mcpstdio: write body: %w", err)
	}
	return nil
}

// ReadMessage reads one frame: it parses the header block, validates the
// Content-Length, then reads exactly that many body bytes and returns them. A
// malformed or oversized length returns [ErrMalformedFrame] without consuming a
// body. A truncated body (EOF before N bytes) returns the underlying read error.
func (f *Framer) ReadMessage() ([]byte, error) {
	n, err := f.readContentLength()
	if err != nil {
		return nil, err
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(f.r, body); err != nil {
		return nil, fmt.Errorf("mcpstdio: read body: %w", err)
	}
	return body, nil
}

// readContentLength consumes the header block up to and including the blank
// separator line and returns the validated body length. It fails closed on a
// missing, duplicate-but-conflicting, non-numeric, negative, or oversized length.
func (f *Framer) readContentLength() (int, error) {
	length := -1
	for {
		line, err := f.r.ReadString('\n')
		if err != nil {
			// EOF mid-header (or with no header at all) is a malformed frame,
			// except a clean EOF before any byte, which we surface as io.EOF so
			// callers can distinguish "stream closed" from "bad frame".
			if errors.Is(err, io.EOF) && line == "" && length < 0 {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("mcpstdio: read header: %w", err)
		}
		// A header line ends in CRLF; the separator is a bare CRLF (or LF).
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			// Blank line: end of header block.
			if length < 0 {
				return 0, fmt.Errorf("%w: missing Content-Length", ErrMalformedFrame)
			}
			return length, nil
		}
		name, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return 0, fmt.Errorf("%w: header line without colon: %q", ErrMalformedFrame, trimmed)
		}
		if !strings.EqualFold(strings.TrimSpace(name), contentLengthHeader) {
			continue // ignore unknown headers, e.g. Content-Type
		}
		v, perr := strconv.Atoi(strings.TrimSpace(value))
		if perr != nil {
			return 0, fmt.Errorf("%w: non-numeric Content-Length %q", ErrMalformedFrame, strings.TrimSpace(value))
		}
		if v < 0 {
			return 0, fmt.Errorf("%w: negative Content-Length %d", ErrMalformedFrame, v)
		}
		if v > MaxMessageBytes {
			return 0, fmt.Errorf("%w: Content-Length %d over cap %d", ErrMalformedFrame, v, MaxMessageBytes)
		}
		length = v
	}
}

// Transport adapts a [Framer] to [ports.TransportPort], carrying framed MCP
// messages over a reader/writer pair such as a child process's stdout/stdin.
type Transport struct {
	f *Framer
}

var _ ports.TransportPort = (*Transport)(nil)

// NewTransport returns a Transport that receives frames from r and sends frames
// to w. Typical wiring points r at the upstream server's stdout and w at its
// stdin.
func NewTransport(r io.Reader, w io.Writer) *Transport {
	return &Transport{f: NewFramer(r, w)}
}

// Send frames and writes msg. It checks ctx before the blocking write so a
// cancelled context short-circuits instead of touching the wire.
func (t *Transport) Send(ctx context.Context, msg []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.f.WriteMessage(msg)
}

// Recv reads one frame and returns its body. It checks ctx before the blocking
// read; once a read is in flight it runs to completion, since the underlying
// reader is not itself cancellable.
func (t *Transport) Recv(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t.f.ReadMessage()
}
