package core

import (
	"errors"
	"testing"
)

func TestSpanValid(t *testing.T) {
	cases := []struct {
		name string
		s    Span
		want bool
	}{
		{"ok", Span{"a.go", 1, 5}, true},
		{"empty file", Span{"", 1, 5}, false},
		{"zero start", Span{"a.go", 0, 5}, false},
		{"end equals start", Span{"a.go", 5, 5}, false},
		{"end before start", Span{"a.go", 6, 5}, false},
	}
	for _, c := range cases {
		if got := c.s.Valid(); got != c.want {
			t.Errorf("%s: Valid()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestSpanContainsLine(t *testing.T) {
	s := Span{File: "a.go", StartLine: 10, EndLine: 20} // [10,20)
	cases := []struct {
		file string
		line int
		want bool
	}{
		{"a.go", 10, true},  // start inclusive
		{"a.go", 19, true},  // end-1 inclusive
		{"a.go", 20, false}, // end exclusive
		{"a.go", 9, false},
		{"b.go", 12, false}, // different file
	}
	for _, c := range cases {
		if got := s.ContainsLine(c.file, c.line); got != c.want {
			t.Errorf("ContainsLine(%q,%d)=%v want %v", c.file, c.line, got, c.want)
		}
	}
}

// TestZeroSpanSetDeniesEverything pins the load-bearing security invariant.
func TestZeroSpanSetDeniesEverything(t *testing.T) {
	var ss SpanSet
	if ss.Len() != 0 {
		t.Fatalf("zero SpanSet Len=%d want 0", ss.Len())
	}
	if ss.AllowsLine("a.go", 1) {
		t.Fatal("zero SpanSet must deny all lines")
	}
}

func TestNewSpanSet(t *testing.T) {
	ss, err := NewSpanSet(Span{"a.go", 1, 3}, Span{"a.go", 10, 12})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ss.Len() != 2 {
		t.Fatalf("Len=%d want 2", ss.Len())
	}
	if !ss.AllowsLine("a.go", 1) || !ss.AllowsLine("a.go", 11) {
		t.Fatal("in-span lines must be allowed")
	}
	if ss.AllowsLine("a.go", 5) {
		t.Fatal("between-span line must be denied")
	}
	if got, want := ss.TotalLines(), 4; got != want {
		t.Fatalf("TotalLines=%d want %d", got, want)
	}
}

func TestNewSpanSetRejectsInvalid(t *testing.T) {
	if _, err := NewSpanSet(Span{"a.go", 1, 3}, Span{"", 0, 0}); !errors.Is(err, ErrInvalidSpan) {
		t.Fatalf("err=%v want ErrInvalidSpan", err)
	}
}

func TestSpanSetImmutable(t *testing.T) {
	ss, _ := NewSpanSet(Span{"a.go", 1, 3})
	got := ss.Spans()
	got[0].File = "mutated.go"
	if ss.AllowsLine("mutated.go", 1) {
		t.Fatal("mutating the returned slice must not affect the set")
	}
	if !ss.AllowsLine("a.go", 1) {
		t.Fatal("original span must be intact")
	}
}
