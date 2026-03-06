package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rafaelsanzio/passcheck"
)

// Exit codes returned by [run].
const (
	exitOK         = 0 // success
	exitError      = 1 // runtime or check error
	exitUsageError = 2 // invalid arguments
)

// options holds the parsed CLI flags and arguments.
type options struct {
	password  string
	json      bool
	verbose   bool
	noColor   bool
	help      bool
	showVer   bool
	minLength int // 0 = use default
}

// errWriter wraps an io.Writer and records the first write error.
// Once an error is recorded all subsequent writes are no-ops, which
// lets callers chain multiple fmt.Fprintf calls and inspect the result
// once at the end rather than checking every call individually.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	ew.err = err
	return n, err
}

// parseArgs parses command-line arguments into options.
//
// Flags (--flag or -f) can appear anywhere; the first non-flag
// argument is treated as the password. Use "--" to stop flag
// parsing (useful for passwords starting with a dash).
func parseArgs(args []string) (options, error) {
	var opts options
	flagsDone := false

	for _, arg := range args {
		// "--" separator: everything after is a positional argument.
		if arg == "--" && !flagsDone {
			flagsDone = true
			continue
		}

		// Parse flags (unless we've seen "--").
		if !flagsDone && strings.HasPrefix(arg, "-") {
			switch {
			case arg == "--json":
				opts.json = true
			case arg == "--verbose" || arg == "-v":
				opts.verbose = true
			case arg == "--no-color":
				opts.noColor = true
			case arg == "--help" || arg == "-h":
				opts.help = true
			case arg == "--version":
				opts.showVer = true
			case strings.HasPrefix(arg, "--min-length="):
				val := strings.TrimPrefix(arg, "--min-length=")
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					return opts, fmt.Errorf("invalid --min-length value: %q (must be a positive integer)", val)
				}
				opts.minLength = n
			default:
				return opts, fmt.Errorf("unknown flag: %s\nRun 'passcheck --help' for usage", arg)
			}
			continue
		}

		// Positional argument (password).
		if opts.password != "" {
			return opts, fmt.Errorf("unexpected argument: %s (password already provided)", arg)
		}
		opts.password = arg
	}

	return opts, nil
}

// run executes the CLI logic and returns the exit code.
//
// stdout and stderr are the output writers; envNoColor reflects
// whether the NO_COLOR environment variable is set.
func run(stdout, stderr io.Writer, args []string, envNoColor bool) int {
	ew := &errWriter{w: stderr}

	opts, parseErr := parseArgs(args)
	if parseErr != nil {
		_, _ = fmt.Fprintf(ew, "Error: %v\n", parseErr)
		if ew.err != nil {
			return exitError
		}
		return exitUsageError
	}

	if opts.help {
		if helpErr := printHelp(stdout); helpErr != nil {
			_, _ = fmt.Fprintf(ew, "Error writing output: %v\n", helpErr)
			return exitError
		}
		return exitOK
	}

	if opts.showVer {
		vew := &errWriter{w: stdout}
		_, _ = fmt.Fprintf(vew, "passcheck %s\n", version)
		if vew.err != nil {
			_, _ = fmt.Fprintf(ew, "Error writing output: %v\n", vew.err)
			return exitError
		}
		return exitOK
	}

	if opts.password == "" {
		_, _ = fmt.Fprintln(ew, "Error: password argument required")
		_, _ = fmt.Fprintln(ew, "Run 'passcheck --help' for usage")
		return exitError
	}

	// Build config from defaults + CLI overrides.
	cfg := passcheck.DefaultConfig()
	if opts.minLength > 0 {
		cfg.MinLength = opts.minLength
	}
	if opts.verbose {
		cfg.MaxIssues = 0 // show all issues
	}

	result, checkErr := passcheck.CheckWithConfig(opts.password, cfg)
	if checkErr != nil {
		_, _ = fmt.Fprintf(ew, "Error: %v\n", checkErr)
		return exitError
	}

	if opts.json {
		return printJSON(stdout, stderr, result)
	}

	useColor := !opts.noColor && !envNoColor
	if printErr := printResult(stdout, result, opts, useColor); printErr != nil {
		_, _ = fmt.Fprintf(ew, "Error writing output: %v\n", printErr)
		return exitError
	}
	return exitOK
}

// printResult writes the formatted human-readable result and returns any
// write error encountered.
func printResult(w io.Writer, r passcheck.Result, opts options, useColor bool) error {
	ew := &errWriter{w: w}

	// Score line with visual meter.
	_, _ = fmt.Fprintf(ew, "Score:   %s\n", scoreMeter(r.Score, useColor))

	// Verdict with color.
	verdict := r.Verdict
	if useColor {
		verdict = colorize(r.Verdict, verdictColor(r.Verdict))
	}
	_, _ = fmt.Fprintf(ew, "Verdict: %s\n", verdict)

	// Entropy (always in verbose, otherwise only when there are no issues).
	if opts.verbose {
		_, _ = fmt.Fprintf(ew, "Entropy: %.2f bits\n", r.Entropy)
	} else {
		_, _ = fmt.Fprintf(ew, "Entropy: %.1f bits\n", r.Entropy)
	}

	// Issues.
	if len(r.Issues) > 0 {
		if opts.verbose {
			_, _ = fmt.Fprintf(ew, "\nIssues (%d):\n", len(r.Issues))
		} else {
			_, _ = fmt.Fprintln(ew, "\nIssues:")
		}
		for _, iss := range r.Issues {
			marker := "  - "
			if useColor {
				marker = "  " + colorize("-", ansiRed) + " "
			}
			_, _ = fmt.Fprintf(ew, "%s%s\n", marker, iss.Message)
		}
	}

	// Strengths / suggestions.
	if len(r.Suggestions) > 0 {
		_, _ = fmt.Fprintln(ew, "\nStrengths:")
		for _, s := range r.Suggestions {
			marker := "  + "
			if useColor {
				marker = "  " + colorize("+", ansiGreen) + " "
			}
			_, _ = fmt.Fprintf(ew, "%s%s\n", marker, s)
		}
	}

	if len(r.Issues) == 0 && len(r.Suggestions) == 0 {
		_, _ = fmt.Fprintln(ew, "\nNo issues found.")
	}

	return ew.err
}

// printJSON encodes the result as indented JSON.
func printJSON(stdout, stderr io.Writer, r passcheck.Result) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		ew := &errWriter{w: stderr}
		_, _ = fmt.Fprintf(ew, "Error encoding JSON: %v\n", err)
		return exitError
	}
	return exitOK
}

// printHelp writes the CLI usage information and returns any write error.
func printHelp(w io.Writer) error {
	_, err := fmt.Fprintf(w, `passcheck %s - Password strength checker

Usage:
  passcheck <password> [flags]

Flags:
  --json              Output result as JSON
  --verbose, -v       Show all issues and extra details
  --no-color          Disable colored output
  --min-length=N      Set minimum password length (default: 12)
  --version           Show version
  --help, -h          Show this help message

Environment:
  NO_COLOR            Set to any value to disable colored output

Examples:
  passcheck "MyP@ssw0rd123!"
  passcheck "qwerty" --json
  passcheck "short" --min-length=8 --verbose
  passcheck -- "-dashpassword"
`, version)
	return err
}
