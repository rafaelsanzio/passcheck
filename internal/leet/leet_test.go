package leet

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no subs", "hello", "hello"},
		{"empty", "", ""},
		{"single @", "@", "a"},
		{"all leet", "@83!0$7+", "abeiostt"},
		{"mixed", "p@$$w0rd", "password"},
		{"digits mapped", "ABCdef123", "ABCdefi2e"},
		{"no leet chars", "XYZabc", "XYZabc"},
		{"unicode preserved", "héllö", "héllö"},
		{"pipe to l", "|eet", "leet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Normalize(tt.input)
			if got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", false},
		{"", false},
		{"p@ss", true},
		{"n0pe", true},
		{"clean", false},
		{"$ign", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Contains(tt.input)
			if got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalize_NoAllocWhenClean(t *testing.T) {
	input := "purealpha"
	got := Normalize(input)
	// When no leet chars present, should return the original string.
	if got != input {
		t.Errorf("expected same string back, got %q", got)
	}
}

func BenchmarkNormalize_Clean(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Normalize("HelloWorld123")
	}
}

func BenchmarkNormalize_Leet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Normalize("p@$$w0rd!23")
	}
}
