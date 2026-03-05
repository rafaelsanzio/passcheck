package dictionary

import (
	"reflect"
	"sort"
	"testing"
)

func TestMatcher(t *testing.T) {
	words := []string{"his", "hers", "she", "he"}
	m := NewMatcher(words)

	text := "ushers"
	matches := m.FindAll(text)

	sort.Strings(matches)
	expected := []string{"he", "hers", "she"}
	sort.Strings(expected)

	if !reflect.DeepEqual(matches, expected) {
		t.Errorf("expected %v, got %v", expected, matches)
	}
}
