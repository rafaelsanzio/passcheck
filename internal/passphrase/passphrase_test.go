package passphrase

import "testing"

func TestDetect_Spaces(t *testing.T) {
	info := Detect("correct horse battery staple", 4)
	if !info.IsPassphrase {
		t.Error("expected passphrase detected")
	}
	if info.WordCount != 4 {
		t.Errorf("expected 4 words, got %d", info.WordCount)
	}
	expected := []string{"correct", "horse", "battery", "staple"}
	if len(info.Words) != len(expected) {
		t.Errorf("expected %d words, got %d", len(expected), len(info.Words))
	}
	for i, w := range expected {
		if i >= len(info.Words) || info.Words[i] != w {
			t.Errorf("word %d: expected %q, got %q", i, w, info.Words[i])
		}
	}
}

func TestDetect_Hyphens(t *testing.T) {
	info := Detect("correct-horse-battery-staple", 4)
	if !info.IsPassphrase {
		t.Error("expected passphrase detected")
	}
	if info.WordCount != 4 {
		t.Errorf("expected 4 words, got %d", info.WordCount)
	}
}

func TestDetect_CamelCase(t *testing.T) {
	info := Detect("CorrectHorseBatteryStaple", 4)
	if !info.IsPassphrase {
		t.Error("expected passphrase detected (camelCase)")
	}
	if info.WordCount != 4 {
		t.Errorf("expected 4 words, got %d", info.WordCount)
	}
}

func TestDetect_SnakeCase(t *testing.T) {
	info := Detect("correct_horse_battery_staple", 4)
	if !info.IsPassphrase {
		t.Error("expected passphrase detected (snake_case)")
	}
	if info.WordCount != 4 {
		t.Errorf("expected 4 words, got %d", info.WordCount)
	}
}

func TestDetect_Mixed(t *testing.T) {
	info := Detect("Correct-Horse_battery staple", 4)
	if !info.IsPassphrase {
		t.Error("expected passphrase detected (mixed separators)")
	}
	if info.WordCount != 4 {
		t.Errorf("expected 4 words, got %d", info.WordCount)
	}
}

func TestDetect_TooFewWords(t *testing.T) {
	info := Detect("correct horse battery", 4)
	if info.IsPassphrase {
		t.Error("expected not a passphrase (only 3 words, need 4)")
	}
	if info.WordCount != 3 {
		t.Errorf("expected 3 words, got %d", info.WordCount)
	}
}

func TestDetect_Deduplication(t *testing.T) {
	info := Detect("correct horse correct battery", 4)
	// Should not be a passphrase because we only have 3 unique words (need 4)
	if info.IsPassphrase {
		t.Error("expected not a passphrase (only 3 unique words, need 4)")
	}
	if info.WordCount != 3 {
		t.Errorf("expected 3 unique words (deduplicated), got %d", info.WordCount)
	}
	// With minWords=3, it should be a passphrase
	info2 := Detect("correct horse correct battery", 3)
	if !info2.IsPassphrase {
		t.Error("expected passphrase with minWords=3")
	}
}

func TestDetect_Empty(t *testing.T) {
	info := Detect("", 4)
	if info.IsPassphrase {
		t.Error("empty string should not be a passphrase")
	}
	if info.WordCount != 0 {
		t.Errorf("expected 0 words, got %d", info.WordCount)
	}
}

func TestDetect_MinWords(t *testing.T) {
	info := Detect("correct horse", 2)
	if !info.IsPassphrase {
		t.Error("expected passphrase with minWords=2")
	}
	info = Detect("correct horse", 3)
	if info.IsPassphrase {
		t.Error("expected not a passphrase with minWords=3")
	}
}

func TestExtractWords_Spaces(t *testing.T) {
	words := extractWords("hello world test")
	expected := []string{"hello", "world", "test"}
	if len(words) != len(expected) {
		t.Fatalf("expected %d words, got %d", len(expected), len(words))
	}
	for i, w := range expected {
		if words[i] != w {
			t.Errorf("word %d: expected %q, got %q", i, w, words[i])
		}
	}
}

func TestExtractWords_CamelCase(t *testing.T) {
	words := extractWords("HelloWorldTest")
	expected := []string{"hello", "world", "test"}
	if len(words) != len(expected) {
		t.Fatalf("expected %d words, got %d", len(expected), len(words))
	}
	for i, w := range expected {
		if words[i] != w {
			t.Errorf("word %d: expected %q, got %q", i, w, words[i])
		}
	}
}

func TestExtractWords_SnakeCase(t *testing.T) {
	words := extractWords("hello_world_test")
	expected := []string{"hello", "world", "test"}
	if len(words) != len(expected) {
		t.Fatalf("expected %d words, got %d", len(expected), len(words))
	}
}

func TestExtractWords_MixedCase(t *testing.T) {
	words := extractWords("HelloWorld_test")
	expected := []string{"hello", "world", "test"}
	if len(words) != len(expected) {
		t.Fatalf("expected %d words, got %d", len(expected), len(words))
	}
}

func TestDeduplicate(t *testing.T) {
	input := []string{"hello", "world", "hello", "test", "world"}
	output := deduplicate(input)
	expected := []string{"hello", "world", "test"}
	if len(output) != len(expected) {
		t.Fatalf("expected %d unique words, got %d", len(expected), len(output))
	}
	seen := make(map[string]bool)
	for _, w := range output {
		if seen[w] {
			t.Errorf("duplicate word: %q", w)
		}
		seen[w] = true
	}
}

func TestDeduplicate_FiltersShort(t *testing.T) {
	input := []string{"a", "hello", "b", "world", "test"}
	output := deduplicate(input)
	// "a" and "b" should be filtered out (< 2 chars)
	if len(output) != 3 {
		t.Errorf("expected 3 words (filtered short), got %d", len(output))
	}
}
