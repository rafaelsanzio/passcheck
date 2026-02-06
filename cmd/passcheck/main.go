// Command passcheck is a CLI tool for checking password strength.
//
// Usage:
//
//	passcheck <password> [flags]
//	passcheck "MyP@ssw0rd123!"
//	passcheck "qwerty" --json
//	passcheck "short" --min-length=8 --verbose
package main

import "os"

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	envNoColor := os.Getenv("NO_COLOR") != ""
	os.Exit(run(os.Stdout, os.Stderr, os.Args[1:], envNoColor))
}
