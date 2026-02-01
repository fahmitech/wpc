package utils

import (
	"fmt"
	"regexp"
)

var (
	// Spec #4: Strict sanitization regex
	SanitizeRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
)

// ValidateString ensures the input matches the strict security requirements
func ValidateString(input string) error {
	if !SanitizeRegex.MatchString(input) {
		return fmt.Errorf("invalid character in input '%s': must match %s", input, SanitizeRegex.String())
	}
	return nil
}
