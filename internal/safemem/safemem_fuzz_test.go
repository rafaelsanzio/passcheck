package safemem

import (
	"strings"
	"testing"
)

func FuzzConstantTimeContains(f *testing.F) {
	f.Add("hello world", "world")
	f.Add("short", "longerstring")
	f.Add("exact", "exact")
	f.Add("prefixmatch", "prefix")
	f.Add("matchsuffix", "suffix")

	f.Fuzz(func(t *testing.T, s, substr string) {
		expected := strings.Contains(s, substr)
		got := ConstantTimeContains(s, substr)
		if got != expected {
			t.Errorf("ConstantTimeContains(%q, %q) = %v; want %v (strings.Contains)", s, substr, got, expected)
		}
	})
}
