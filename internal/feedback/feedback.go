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

	"github.com/rafaelsanzio/passcheck/internal/issue"
	"github.com/rafaelsanzio/passcheck/internal/scoring"
)

// DefaultMaxIssues is the maximum number of issues returned by Refine
// when no explicit limit is given. Zero means no limit.
const DefaultMaxIssues = 5

// rankedIssue pairs an Issue with its original position for stable sort.
type rankedIssue struct {
	issue issue.Issue
	index int
}

// Refine processes the categorized issue set and returns a deduplicated,
// priority-sorted list of at most maxIssues structured issues.
//
// If maxIssues is 0 the full deduplicated list is returned.
// Deduplication uses quoted tokens in the message; when the same token
// appears in multiple issues, the highest-severity one is kept.
func Refine(issues scoring.IssueSet, maxIssues int) []issue.Issue {
	ranked := buildRanked(issues)
	ranked = dedup(ranked)
	sortBySeverity(ranked)

	if maxIssues > 0 && len(ranked) > maxIssues {
		ranked = ranked[:maxIssues]
	}

	out := make([]issue.Issue, len(ranked))
	for i, r := range ranked {
		out[i] = r.issue
	}
	return out
}

// buildRanked converts an IssueSet into a flat slice of rankedIssues,
// preserving category order (dictionary first, then patterns, then rules).
func buildRanked(issues scoring.IssueSet) []rankedIssue {
	var ranked []rankedIssue
	idx := 0

	for _, iss := range issues.Dictionary {
		ranked = append(ranked, rankedIssue{iss, idx})
		idx++
	}
	for _, iss := range issues.Patterns {
		ranked = append(ranked, rankedIssue{iss, idx})
		idx++
	}
	for _, iss := range issues.Rules {
		ranked = append(ranked, rankedIssue{iss, idx})
		idx++
	}

	return ranked
}

// dedup removes semantically duplicate messages. Two messages are
// considered duplicates when they reference the same quoted token
// (the text between single quotes). When duplicates are found the
// issue with the highest severity is kept.
//
// Messages without a quoted token are always retained.
func dedup(ranked []rankedIssue) []rankedIssue {
	best := make(map[string]int)
	for _, ri := range ranked {
		token := extractQuoted(ri.issue.Message)
		if token == "" {
			continue
		}
		if ri.issue.Severity > best[token] {
			best[token] = ri.issue.Severity
		}
	}

	seen := make(map[string]bool)
	var result []rankedIssue
	for _, ri := range ranked {
		token := extractQuoted(ri.issue.Message)
		if token == "" {
			result = append(result, ri)
			continue
		}
		if ri.issue.Severity == best[token] && !seen[token] {
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
		if ranked[i].issue.Severity != ranked[j].issue.Severity {
			return ranked[i].issue.Severity > ranked[j].issue.Severity
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
