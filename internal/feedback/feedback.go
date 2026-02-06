// Package feedback refines raw analysis issues into a curated, user-friendly
// list of actionable messages.
//
// It deduplicates semantically overlapping messages (e.g. the same word
// flagged by both the pattern and dictionary phases), sorts them by
// severity, and limits the output to the most important items.
package feedback

import (
	"sort"
	"strings"

	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

// DefaultMaxIssues is the maximum number of issues returned by Refine
// when no explicit limit is given. Zero means no limit.
const DefaultMaxIssues = 5

// Severity levels — higher is more critical.
const (
	severityRule    = 1
	severityPattern = 2
	severityDict    = 3
)

// rankedIssue pairs a message with its severity and original position
// so that the sort is stable within the same severity tier.
type rankedIssue struct {
	message  string
	severity int
	index    int
}

// Refine processes the categorized issue set and returns a deduplicated,
// priority-sorted list of at most maxIssues messages.
//
// If maxIssues is 0 the full deduplicated list is returned.
func Refine(issues scoring.IssueSet, maxIssues int) []string {
	ranked := buildRanked(issues)
	ranked = dedup(ranked)
	sortBySeverity(ranked)

	if maxIssues > 0 && len(ranked) > maxIssues {
		ranked = ranked[:maxIssues]
	}

	out := make([]string, len(ranked))
	for i, r := range ranked {
		out[i] = r.message
	}
	return out
}

// buildRanked converts an IssueSet into a flat slice of rankedIssues,
// tagging each message with its severity and a stable index.
func buildRanked(issues scoring.IssueSet) []rankedIssue {
	var ranked []rankedIssue
	idx := 0

	// Dictionary issues first (highest severity → appear at top after sort).
	for _, msg := range issues.Dictionary {
		ranked = append(ranked, rankedIssue{msg, severityDict, idx})
		idx++
	}
	for _, msg := range issues.Patterns {
		ranked = append(ranked, rankedIssue{msg, severityPattern, idx})
		idx++
	}
	for _, msg := range issues.Rules {
		ranked = append(ranked, rankedIssue{msg, severityRule, idx})
		idx++
	}

	return ranked
}

// dedup removes semantically duplicate messages. Two messages are
// considered duplicates when they reference the same quoted token
// (the text between single quotes). When duplicates are found the
// message with the highest severity is kept.
//
// Messages without a quoted token are always retained.
func dedup(ranked []rankedIssue) []rankedIssue {
	// First pass: for each quoted token, record the highest severity.
	best := make(map[string]int) // token → best severity
	for _, ri := range ranked {
		token := extractQuoted(ri.message)
		if token == "" {
			continue
		}
		if ri.severity > best[token] {
			best[token] = ri.severity
		}
	}

	// Second pass: keep messages that are either unquoted or the
	// highest-severity representative for their token. If two messages
	// share the same token and severity, the first encountered wins.
	seen := make(map[string]bool)
	var result []rankedIssue

	for _, ri := range ranked {
		token := extractQuoted(ri.message)
		if token == "" {
			result = append(result, ri)
			continue
		}
		if ri.severity == best[token] && !seen[token] {
			seen[token] = true
			result = append(result, ri)
		}
	}

	return result
}

// sortBySeverity sorts ranked issues by severity descending; ties are
// broken by original insertion order (stable).
func sortBySeverity(ranked []rankedIssue) {
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].severity != ranked[j].severity {
			return ranked[i].severity > ranked[j].severity
		}
		return ranked[i].index < ranked[j].index
	})
}

// extractQuoted returns the text between the first pair of single
// quotes in s, or "" if no quoted text is found.
func extractQuoted(s string) string {
	start := strings.Index(s, "'")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start+1:], "'")
	if end < 0 {
		return ""
	}
	return s[start+1 : start+1+end]
}
