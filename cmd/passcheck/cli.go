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
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsageError
	}

	if opts.help {
		printHelp(stdout)
		return exitOK
	}

	if opts.showVer {
		fmt.Fprintf(stdout, "passcheck %s\n", version)
		return exitOK
	}

	if opts.password == "" {
		fmt.Fprintln(stderr, "Error: password argument required")
		fmt.Fprintln(stderr, "Run 'passcheck --help' for usage")
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

	result, err := passcheck.CheckWithConfig(opts.password, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if opts.json {
		return printJSON(stdout, stderr, result)
	}

	useColor := !opts.noColor && !envNoColor
	printResult(stdout, result, opts, useColor)
	return exitOK
}

// printResult writes the formatted human-readable result.
func printResult(w io.Writer, r passcheck.Result, opts options, useColor bool) {
	// Score line with visual meter.
	fmt.Fprintf(w, "Score:   %s\n", scoreMeter(r.Score, useColor))

	// Verdict with color.
	verdict := r.Verdict
	if useColor {
		verdict = colorize(r.Verdict, verdictColor(r.Verdict))
	}
	fmt.Fprintf(w, "Verdict: %s\n", verdict)

	// Entropy (always in verbose, otherwise only when there are no issues).
	if opts.verbose {
		fmt.Fprintf(w, "Entropy: %.2f bits\n", r.Entropy)
	} else {
		fmt.Fprintf(w, "Entropy: %.1f bits\n", r.Entropy)
	}

	// Issues.
	if len(r.Issues) > 0 {
		if opts.verbose {
			fmt.Fprintf(w, "\nIssues (%d):\n", len(r.Issues))
		} else {
			fmt.Fprintln(w, "\nIssues:")
		}
		for _, issue := range r.Issues {
			marker := "  - "
			if useColor {
				marker = "  " + colorize("-", ansiRed) + " "
			}
			fmt.Fprintf(w, "%s%s\n", marker, issue)
		}
	}

	// Strengths / suggestions.
	if len(r.Suggestions) > 0 {
		fmt.Fprintln(w, "\nStrengths:")
		for _, s := range r.Suggestions {
			marker := "  + "
			if useColor {
				marker = "  " + colorize("+", ansiGreen) + " "
			}
			fmt.Fprintf(w, "%s%s\n", marker, s)
		}
	}

	if len(r.Issues) == 0 && len(r.Suggestions) == 0 {
		fmt.Fprintln(w, "\nNo issues found.")
	}
}

// printJSON encodes the result as indented JSON.
func printJSON(stdout, stderr io.Writer, r passcheck.Result) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintf(stderr, "Error encoding JSON: %v\n", err)
		return exitError
	}
	return exitOK
}

// printHelp writes the CLI usage information.
func printHelp(w io.Writer) {
	fmt.Fprintf(w, `passcheck %s - Password strength checker

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
}
