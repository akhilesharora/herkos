package core

import "testing"

func TestQueryValid(t *testing.T) {
	cases := []struct {
		name string
		q    Query
		want bool
	}{
		{"anchors+budget", Query{Anchors: []string{"Foo"}, LineBudget: 100}, true},
		{"rawtext+budget", Query{RawText: "where is auth", LineBudget: 50}, true},
		{"no budget", Query{Anchors: []string{"Foo"}}, false},
		{"no anchor or text", Query{LineBudget: 50}, false},
		{"zero", Query{}, false},
	}
	for _, c := range cases {
		if got := c.q.Valid(); got != c.want {
			t.Errorf("%s: Valid()=%v want %v", c.name, got, c.want)
		}
	}
}
