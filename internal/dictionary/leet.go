package dictionary

import "github.com/rafaelsanzio/passcheck/internal/leet"

// normalizeLeet delegates to the shared leet package.
func normalizeLeet(s string) string { return leet.Normalize(s) }

// containsLeet delegates to the shared leet package.
func containsLeet(s string) bool { return leet.Contains(s) }
