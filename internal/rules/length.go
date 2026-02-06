package rules

import "fmt"

// DefaultMinLength is the minimum number of characters required in a password.
const DefaultMinLength = 12

// checkMinLength verifies the password meets the minimum length requirement.
// It counts Unicode code points (runes), not bytes.
func checkMinLength(password string, opts Options) []string {
	length := len([]rune(password))
	if length < opts.MinLength {
		return []string{
			fmt.Sprintf("Password is too short (%d chars, minimum %d)", length, opts.MinLength),
		}
	}
	return nil
}
