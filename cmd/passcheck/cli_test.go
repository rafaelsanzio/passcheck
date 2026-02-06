package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rafaelsanzio/passcheck"
)

// ---------------------------------------------------------------------------
// parseArgs
// ---------------------------------------------------------------------------

func TestParseArgs_PasswordOnly(t *testing.T) {
	opts, err := parseArgs([]string{"mypassword"})
	assertNoError(t, err)
	if opts.password != "mypassword" {
		t.Errorf("password = %q, want %q", opts.password, "mypassword")
	}
}

func TestParseArgs_Help(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		opts, err := parseArgs([]string{flag})
		assertNoError(t, err)
		if !opts.help {
			t.Errorf("%s should set help=true", flag)
		}
	}
}

func TestParseArgs_Version(t *testing.T) {
	opts, err := parseArgs([]string{"--version"})
	assertNoError(t, err)
	if !opts.showVer {
		t.Error("--version should set showVer=true")
	}
}

func TestParseArgs_JSON(t *testing.T) {
	opts, err := parseArgs([]string{"pw", "--json"})
	assertNoError(t, err)
	if !opts.json {
		t.Error("--json should set json=true")
	}
	if opts.password != "pw" {
		t.Errorf("password = %q, want %q", opts.password, "pw")
	}
}

func TestParseArgs_Verbose(t *testing.T) {
	for _, flag := range []string{"--verbose", "-v"} {
		opts, err := parseArgs([]string{"pw", flag})
		assertNoError(t, err)
		if !opts.verbose {
			t.Errorf("%s should set verbose=true", flag)
		}
	}
}

func TestParseArgs_NoColor(t *testing.T) {
	opts, err := parseArgs([]string{"pw", "--no-color"})
	assertNoError(t, err)
	if !opts.noColor {
		t.Error("--no-color should set noColor=true")
	}
}

func TestParseArgs_MinLength(t *testing.T) {
	opts, err := parseArgs([]string{"pw", "--min-length=8"})
	assertNoError(t, err)
	if opts.minLength != 8 {
		t.Errorf("minLength = %d, want 8", opts.minLength)
	}
}

func TestParseArgs_MinLength_Invalid(t *testing.T) {
	_, err := parseArgs([]string{"pw", "--min-length=abc"})
	if err == nil {
		t.Error("expected error for non-numeric --min-length")
	}
}

func TestParseArgs_MinLength_Zero(t *testing.T) {
	_, err := parseArgs([]string{"pw", "--min-length=0"})
	if err == nil {
		t.Error("expected error for --min-length=0")
	}
}

func TestParseArgs_UnknownFlag(t *testing.T) {
	_, err := parseArgs([]string{"pw", "--foobar"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("error should mention 'unknown flag', got: %v", err)
	}
}

func TestParseArgs_DuplicatePassword(t *testing.T) {
	_, err := parseArgs([]string{"first", "second"})
	if err == nil {
		t.Error("expected error for duplicate password")
	}
}

func TestParseArgs_DashDashSeparator(t *testing.T) {
	// Password starting with a dash.
	opts, err := parseArgs([]string{"--", "-mypassword"})
	assertNoError(t, err)
	if opts.password != "-mypassword" {
		t.Errorf("password = %q, want %q", opts.password, "-mypassword")
	}
}

func TestParseArgs_FlagsThenDashDash(t *testing.T) {
	opts, err := parseArgs([]string{"--json", "--", "pw"})
	assertNoError(t, err)
	if !opts.json {
		t.Error("json should be set")
	}
	if opts.password != "pw" {
		t.Errorf("password = %q, want %q", opts.password, "pw")
	}
}

func TestParseArgs_AllFlags(t *testing.T) {
	opts, err := parseArgs([]string{
		"--json", "--verbose", "--no-color", "--min-length=6", "pw",
	})
	assertNoError(t, err)
	if !opts.json || !opts.verbose || !opts.noColor {
		t.Error("all flags should be set")
	}
	if opts.minLength != 6 {
		t.Errorf("minLength = %d, want 6", opts.minLength)
	}
	if opts.password != "pw" {
		t.Errorf("password = %q, want %q", opts.password, "pw")
	}
}

func TestParseArgs_Empty(t *testing.T) {
	opts, err := parseArgs([]string{})
	assertNoError(t, err)
	if opts.password != "" {
		t.Errorf("password should be empty, got %q", opts.password)
	}
}

// ---------------------------------------------------------------------------
// run (integration)
// ---------------------------------------------------------------------------

func TestRun_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"--help"}, false)
	if code != 0 {
		t.Errorf("help should exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("help should show usage")
	}
}

func TestRun_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"--version"}, false)
	if code != 0 {
		t.Errorf("version should exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "passcheck") {
		t.Error("version should show program name")
	}
}

func TestRun_NoPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{}, false)
	if code != 1 {
		t.Errorf("no password should exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "password argument required") {
		t.Errorf("should show error, got: %q", stderr.String())
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"--bad"}, false)
	if code != 2 {
		t.Errorf("unknown flag should exit 2, got %d", code)
	}
}

func TestRun_StrongPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"Xk9$mP2!vR7@nL4&wQzB", "--no-color"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "100/100") {
		t.Errorf("expected score 100/100 in output: %s", out)
	}
	if !strings.Contains(out, "Very Strong") {
		t.Errorf("expected 'Very Strong' in output: %s", out)
	}
	if !strings.Contains(out, "Strengths:") {
		t.Errorf("expected strengths section: %s", out)
	}
}

func TestRun_WeakPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"password", "--no-color"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "Very Weak") {
		t.Errorf("expected 'Very Weak': %s", out)
	}
	if !strings.Contains(out, "Issues:") {
		t.Errorf("expected issues section: %s", out)
	}
}

func TestRun_JSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"password", "--json"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}

	// Verify valid JSON.
	var result passcheck.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, stdout.String())
	}
	if result.Verdict != "Very Weak" {
		t.Errorf("verdict = %q, want %q", result.Verdict, "Very Weak")
	}

	// JSON output should not contain ANSI codes.
	if strings.Contains(stdout.String(), "\033[") {
		t.Error("JSON output should not contain ANSI color codes")
	}
}

func TestRun_VerboseOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"qwerty", "--verbose", "--no-color"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	out := stdout.String()
	// Verbose shows issue count.
	if !strings.Contains(out, "Issues (") {
		t.Errorf("verbose should show 'Issues (N)': %s", out)
	}
	// Verbose shows extra entropy decimals.
	if !strings.Contains(out, "bits") {
		t.Errorf("verbose should show entropy: %s", out)
	}
}

func TestRun_NoColor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"password", "--no-color"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if strings.Contains(stdout.String(), "\033[") {
		t.Error("--no-color output should not contain ANSI codes")
	}
}

func TestRun_EnvNoColor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"password"}, true /* envNoColor */)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if strings.Contains(stdout.String(), "\033[") {
		t.Error("NO_COLOR env output should not contain ANSI codes")
	}
}

func TestRun_ColorEnabled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"password"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	// With colors enabled, output should contain ANSI codes.
	if !strings.Contains(stdout.String(), "\033[") {
		t.Error("colored output should contain ANSI codes")
	}
}

func TestRun_CustomMinLength(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// "aB3!xY" (6 chars) — passes with min-length=6.
	code := run(&stdout, &stderr, []string{"aB3!xY", "--min-length=6", "--no-color"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	out := stdout.String()
	if strings.Contains(strings.ToLower(out), "too short") {
		t.Errorf("6-char password should pass with --min-length=6: %s", out)
	}
}

func TestRun_DashPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr, []string{"--", "-secret-"}, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// color helpers
// ---------------------------------------------------------------------------

func TestVerdictColor(t *testing.T) {
	tests := []struct {
		verdict string
		want    string
	}{
		{"Very Weak", ansiRed + ansiBold},
		{"Weak", ansiRed},
		{"Okay", ansiYellow},
		{"Strong", ansiGreen},
		{"Very Strong", ansiGreen + ansiBold},
		{"Unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			if got := verdictColor(tt.verdict); got != tt.want {
				t.Errorf("verdictColor(%q) = %q, want %q", tt.verdict, got, tt.want)
			}
		})
	}
}

func TestScoreColor(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, ansiRed + ansiBold},
		{20, ansiRed + ansiBold},
		{21, ansiRed},
		{40, ansiRed},
		{41, ansiYellow},
		{60, ansiYellow},
		{61, ansiGreen},
		{80, ansiGreen},
		{81, ansiGreen + ansiBold},
		{100, ansiGreen + ansiBold},
	}
	for _, tt := range tests {
		if got := scoreColor(tt.score); got != tt.want {
			t.Errorf("scoreColor(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestScoreMeter_NoColor(t *testing.T) {
	meter := scoreMeter(80, false)
	if !strings.Contains(meter, "80/100") {
		t.Errorf("meter should contain '80/100': %s", meter)
	}
	if !strings.Contains(meter, "████████") {
		t.Errorf("meter should have 8 filled blocks: %s", meter)
	}
	if !strings.Contains(meter, "░░") {
		t.Errorf("meter should have 2 empty blocks: %s", meter)
	}
}

func TestScoreMeter_WithColor(t *testing.T) {
	meter := scoreMeter(80, true)
	if !strings.Contains(meter, "\033[") {
		t.Error("colored meter should contain ANSI codes")
	}
	if !strings.Contains(meter, "80/100") {
		t.Errorf("meter should contain score: %s", meter)
	}
}

func TestScoreMeter_Zero(t *testing.T) {
	meter := scoreMeter(0, false)
	if !strings.Contains(meter, "0/100") {
		t.Errorf("zero meter should show 0/100: %s", meter)
	}
	if !strings.Contains(meter, "░░░░░░░░░░") {
		t.Errorf("zero meter should be all empty: %s", meter)
	}
}

func TestScoreMeter_Full(t *testing.T) {
	meter := scoreMeter(100, false)
	if !strings.Contains(meter, "██████████") {
		t.Errorf("full meter should be all filled: %s", meter)
	}
}

func TestColorize(t *testing.T) {
	result := colorize("hello", ansiRed)
	if result != ansiRed+"hello"+ansiReset {
		t.Errorf("colorize: got %q", result)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
