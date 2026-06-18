// Package mcpstdio is a stdio transport adapter that carries MCP/JSON-RPC
// messages using the MCP newline-delimited framing.
//
// The wire format is one message per line: the raw JSON body followed by a
// single '\n'. Messages MUST NOT contain an embedded newline, so each line is
// exactly one message:
//
//	<JSON>\n
//	<JSON>\n
//
// Reading is fail-closed: a line that grows past the cap without a terminator,
// or a body carrying an embedded newline on write, is an error rather than a
// best-effort parse. This adapter is pure plumbing - it frames and forwards
// bytes and never inspects or authorizes the payload.
package mcpstdio

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/akhilesharora/herkos/internal/ports"
)

// MaxMessageBytes caps the size a single line may reach before a terminating
// newline is seen. A peer that never sends '\n' is rejected once the accumulated
// line passes this, so a hostile or corrupt stream cannot drive an unbounded
// allocation.
const MaxMessageBytes = 32 << 20 // 32 MiB

// ErrMalformedFrame is returned when a line exceeds [MaxMessageBytes] without a
// terminating newline, or when a message handed to WriteMessage carries an
// embedded newline that would inject a frame boundary.
var ErrMalformedFrame = errors.New("mcpstdio: malformed frame")

// Framer reads and writes newline-delimited JSON-RPC messages over an
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

// WriteMessage writes b followed by a single '\n'. b is sent verbatim;
// WriteMessage does not validate that it is JSON. Because the framing is
// newline-delimited, a b that itself contains a '\n' is rejected with
// [ErrMalformedFrame] and nothing is written, rather than splitting into two
// frames on the wire.
func (f *Framer) WriteMessage(b []byte) error {
	if bytes.IndexByte(b, '\n') >= 0 {
		return fmt.Errorf("%w: message contains an embedded newline", ErrMalformedFrame)
	}
	if _, err := f.w.Write(b); err != nil {
		return fmt.Errorf("mcpstdio: write body: %w", err)
	}
	if _, err := io.WriteString(f.w, "\n"); err != nil {
		return fmt.Errorf("mcpstdio: write terminator: %w", err)
	}
	return nil
}

// ReadMessage reads bytes up to the next '\n' and returns the line as one
// message. A single trailing '\r' is trimmed so '\r\n'-terminated peers parse.
// Blank lines (empty after trimming) are skipped. A line that grows past
// [MaxMessageBytes] without a terminator returns [ErrMalformedFrame]. A clean
// EOF before any byte returns [io.EOF]; an EOF after a non-empty unterminated
// line returns that line, and the next call returns [io.EOF].
func (f *Framer) ReadMessage() ([]byte, error) {
	for {
		line, err := f.readLine()
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			// Blank line: not a message, keep reading.
			continue
		}
		return line, nil
	}
}

// readLine accumulates bytes up to and not including the next '\n', enforcing the
// [MaxMessageBytes] cap, and trims a single trailing '\r'. A clean EOF before any
// byte returns [io.EOF]; an EOF after some bytes returns the bytes read so far
// (so an unterminated final line is delivered before the stream-closed signal).
func (f *Framer) readLine() ([]byte, error) {
	var line []byte
	for {
		c, err := f.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) == 0 {
				return nil, io.EOF
			}
			if errors.Is(err, io.EOF) {
				return trimCR(line), nil
			}
			return nil, fmt.Errorf("mcpstdio: read: %w", err)
		}
		if c == '\n' {
			return trimCR(line), nil
		}
		if len(line) >= MaxMessageBytes {
			return nil, fmt.Errorf("%w: line over cap %d with no newline", ErrMalformedFrame, MaxMessageBytes)
		}
		line = append(line, c)
	}
}

// trimCR drops a single trailing '\r' so a '\r\n'-terminated line yields just the
// body. A bare '\r' with no following '\n' is left in place; only the terminator
// pairing is normalized.
func trimCR(line []byte) []byte {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		return line[:n-1]
	}
	return line
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
