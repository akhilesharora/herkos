package pool

import (
	"bytes"
	"context"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

func TestPoolRoundTrip(t *testing.T) {
	p := New()
	ctx := context.Background()
	canon := []byte("canonical span bytes")
	c, err := p.Put(ctx, core.Span{File: "a.go", StartLine: 1, EndLine: 5}, canon)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, canon) {
		t.Fatalf("round-trip mismatch: %q != %q", got, canon)
	}
}

func TestPoolContentAddressed(t *testing.T) {
	p := New()
	ctx := context.Background()
	c1, _ := p.Put(ctx, core.Span{File: "a.go", StartLine: 1, EndLine: 2}, []byte("same"))
	c2, _ := p.Put(ctx, core.Span{File: "b.go", StartLine: 9, EndLine: 9 + 1}, []byte("same"))
	if c1 != c2 {
		t.Fatal("identical canonical bytes must yield the same cursor")
	}
}

func TestPoolUnknownCursor(t *testing.T) {
	if _, err := New().Open(context.Background(), core.Cursor("deadbeef")); err == nil {
		t.Fatal("opening an unknown cursor must error")
	}
}
