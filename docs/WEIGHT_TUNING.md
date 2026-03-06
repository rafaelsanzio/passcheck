# Weight Tuning Guide

This guide explains how to customize penalty weights and entropy influence in the `passcheck` library to match your organization's security priorities.

## Overview

The `PenaltyWeights` configuration allows you to adjust how different types of issues affect password strength scores. By default, all weights are `1.0`, meaning penalties are applied at their standard rates. You can increase or decrease these multipliers to prioritize certain security concerns.

## Configuration

```go
import "github.com/rafaelsanzio/passcheck"

cfg := passcheck.DefaultConfig()
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    RuleViolation:  1.0,  // Multiplier for rule violations (length, charset, etc.)
    PatternMatch:   1.0,  // Multiplier for pattern detections (keyboard walks, sequences)
    DictionaryMatch: 1.0, // Multiplier for dictionary matches (common passwords, words)
    ContextMatch:   1.0,  // Multiplier for context detections (username, email)
    HIBPBreach:     1.0,  // Multiplier for HIBP breach database matches
    EntropyWeight:  1.0,  // Multiplier for entropy base score
}
```

## Weight Categories

### RuleViolation (Default: 1.0)

Multiplies penalties for basic rule violations:
- Missing character sets (uppercase, lowercase, digits, symbols)
- Insufficient length
- Whitespace issues
- Excessive character repetition

**Example:** To heavily penalize passwords that don't meet basic requirements:
```go
cfg.PenaltyWeights.RuleViolation = 2.0  // Double the penalty
```

### PatternMatch (Default: 1.0)

Multiplies penalties for detected patterns:
- Keyboard walks (e.g., "qwerty", "asdfgh")
- Sequences (e.g., "123456", "abcdef")
- Repeated blocks (e.g., "abcabcabc")
- Character substitutions (e.g., "P@ssw0rd")

**Example:** To reduce penalties for patterns (if your organization allows them):
```go
cfg.PenaltyWeights.PatternMatch = 0.5  // Half the penalty
```

### DictionaryMatch (Default: 1.0)

Multiplies penalties for dictionary matches:
- Common passwords (e.g., "password", "123456")
- Common words found in passwords
- Leetspeak variants (e.g., "p@ssw0rd")

**Example:** To heavily penalize dictionary words:
```go
cfg.PenaltyWeights.DictionaryMatch = 2.5  // 2.5x the penalty
```

**Note:** Dictionary penalties are automatically eliminated for detected passphrases (multi-word passwords), regardless of this weight.

### ContextMatch (Default: 1.0)

Multiplies penalties for context-aware detections:
- Username found in password
- Email address components found in password
- Company name or other context words

**Example:** To strongly discourage personal information in passwords:
```go
cfg.PenaltyWeights.ContextMatch = 3.0  // Triple the penalty
```

### HIBPBreach (Default: 1.0)

Multiplies penalties for passwords found in the Have I Been Pwned breach database.

**Example:** To make breached passwords unacceptable:
```go
cfg.PenaltyWeights.HIBPBreach = 5.0  // 5x the penalty (effectively blocks)
```

### EntropyWeight (Default: 1.0)

Multiplies the base score derived from entropy. This affects how much entropy contributes to the final score.

- `1.0`: Normal entropy influence (default)
- `< 1.0`: Reduce entropy influence (penalties matter more)
- `> 1.0`: Increase entropy influence (entropy matters more)

**Example:** To reduce entropy influence and rely more on issue penalties:
```go
cfg.PenaltyWeights.EntropyWeight = 0.7  // 70% of normal entropy influence
```

## Use Cases

### Strict Enterprise Policy

Require strong passwords with heavy penalties for common issues:

```go
cfg := passcheck.DefaultConfig()
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    RuleViolation:  2.0,   // Strict rule enforcement
    PatternMatch:   1.5,   // Discourage patterns
    DictionaryMatch: 3.0,  // Strongly discourage dictionary words
    ContextMatch:   4.0,   // Very strict on personal info
    HIBPBreach:     10.0,  // Block breached passwords
    EntropyWeight:  1.0,   // Normal entropy influence
}
```

### Passphrase-Friendly Policy

Encourage passphrases by reducing pattern penalties while maintaining security:

```go
cfg := passcheck.DefaultConfig()
cfg.PassphraseMode = true
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    RuleViolation:  1.0,
    PatternMatch:   0.3,   // Light penalty for patterns (passphrases may have sequences)
    DictionaryMatch: 0.0,  // No dictionary penalty (handled by passphrase mode)
    ContextMatch:   2.0,   // Still discourage personal info
    HIBPBreach:     5.0,   // Block breached passwords
    EntropyWeight:  1.2,   // Slightly favor entropy (passphrases have high entropy)
}
```

### Balanced Policy

Moderate penalties with emphasis on entropy:

```go
cfg := passcheck.DefaultConfig()
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    RuleViolation:  1.0,
    PatternMatch:   1.0,
    DictionaryMatch: 1.5,  // Moderate dictionary penalty
    ContextMatch:   1.5,   // Moderate context penalty
    HIBPBreach:     3.0,   // Strong breach penalty
    EntropyWeight:  1.1,   // Slightly favor entropy
}
```

### Zero-Trust Policy

Heavily penalize all issues, prioritize entropy:

```go
cfg := passcheck.DefaultConfig()
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    RuleViolation:  3.0,
    PatternMatch:   2.5,
    DictionaryMatch: 4.0,
    ContextMatch:   5.0,
    HIBPBreach:     10.0,
    EntropyWeight:  1.5,  // Strongly favor high entropy
}
```

## Zero Values

Zero values in `PenaltyWeights` are treated as defaults (`1.0`). This allows you to set only the weights you want to customize:

```go
// Only customize dictionary penalties
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    DictionaryMatch: 2.0,
    // All other weights default to 1.0
}
```

## Validation

Negative weights are not allowed and will cause `Config.Validate()` to return an error:

```go
cfg.PenaltyWeights = &passcheck.PenaltyWeights{
    RuleViolation: -1.0,  // Invalid!
}

if err := cfg.Validate(); err != nil {
    log.Fatal(err)  // "PenaltyWeights.RuleViolation must be >= 0"
}
```

## Backward Compatibility

When `PenaltyWeights` is `nil` (the default), all weights are treated as `1.0`, maintaining backward compatibility with existing code:

```go
cfg := passcheck.DefaultConfig()
// cfg.PenaltyWeights is nil → all weights = 1.0 (default behavior)
```

## Testing Your Weights

After configuring weights, test with various passwords to ensure scores match your expectations:

```go
testCases := []struct {
    password string
    minScore int
}{
    {"password", 0},           // Should fail with high dictionary penalty
    {"Xk9$mP2!vR7@nL4", 80},  // Should pass with high entropy
    {"qwerty123", 20},         // Should have low score due to patterns
}

for _, tc := range testCases {
    result, _ := passcheck.CheckWithConfig(tc.password, cfg)
    if result.Score < tc.minScore {
        t.Errorf("Password %q scored %d, expected >= %d",
            tc.password, result.Score, tc.minScore)
    }
}
```

## Best Practices

1. **Start with defaults**: Begin with all weights at `1.0` and adjust based on your needs.

2. **Test thoroughly**: Test your weight configuration with a variety of passwords to ensure scores align with your security policy.

3. **Document your choices**: Document why you chose specific weights for future maintainers.

4. **Consider passphrase mode**: If using `PassphraseMode`, remember that dictionary penalties are automatically eliminated for passphrases.

5. **Balance entropy and penalties**: Adjust `EntropyWeight` to balance between entropy-based scoring and issue-based penalties.

6. **Monitor false positives**: If legitimate passwords are scoring too low, consider reducing relevant weights.

7. **Review periodically**: Security requirements change; review and adjust weights as needed.

## Examples

See the [examples](../examples/) directory for complete working examples of weight configuration.
