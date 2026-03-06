//go:build js && wasm

// Package main is the WebAssembly entry point for passcheck.
// It exposes the passcheck library to JavaScript via js.Global().Set().
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/rafaelsanzio/passcheck"
)

// jsConfig is the JSON-friendly counterpart to passcheck.Config.
// Field names match the TypeScript PassCheckConfig interface (camelCase).
// Boolean fields use pointer types so that an explicit false can be
// distinguished from an absent field (which should use the preset/default value).
type jsConfig struct {
	Preset           string            `json:"preset,omitempty"`
	MinLength        int               `json:"minLength,omitempty"`
	RequireUpper     *bool             `json:"requireUpper,omitempty"`
	RequireLower     *bool             `json:"requireLower,omitempty"`
	RequireDigit     *bool             `json:"requireDigit,omitempty"`
	RequireSymbol    *bool             `json:"requireSymbol,omitempty"`
	MaxRepeats       int               `json:"maxRepeats,omitempty"`
	PatternMinLength int               `json:"patternMinLength,omitempty"`
	MaxIssues        int               `json:"maxIssues,omitempty"`
	CustomPasswords  []string          `json:"customPasswords,omitempty"`
	CustomWords      []string          `json:"customWords,omitempty"`
	ContextWords     []string          `json:"contextWords,omitempty"`
	DisableLeet      *bool             `json:"disableLeet,omitempty"`
	HIBPResult       *jsHIBPResult     `json:"hibpResult,omitempty"`
	PassphraseMode   *bool             `json:"passphraseMode,omitempty"`
	MinWords         int               `json:"minWords,omitempty"`
	WordDictSize     int               `json:"wordDictSize,omitempty"`
	EntropyMode      string            `json:"entropyMode,omitempty"`
	PenaltyWeights   *jsPenaltyWeights `json:"penaltyWeights,omitempty"`
}

// jsHIBPResult carries a pre-computed HIBP result from the browser worker.
// The browser performs the k-anonymity lookup and passes the result here so
// the Go side can incorporate it without making outbound HTTP calls.
type jsHIBPResult struct {
	Breached bool `json:"breached"`
	Count    int  `json:"count"`
}

type jsPenaltyWeights struct {
	RuleViolation   float64 `json:"ruleViolation,omitempty"`
	PatternMatch    float64 `json:"patternMatch,omitempty"`
	DictionaryMatch float64 `json:"dictionaryMatch,omitempty"`
	ContextMatch    float64 `json:"contextMatch,omitempty"`
	HIBPBreach      float64 `json:"hibpBreach,omitempty"`
	EntropyWeight   float64 `json:"entropyWeight,omitempty"`
}

// incrementalResponse is the JSON envelope returned by the incremental check
// functions. It matches the shape the TypeScript worker expects:
// result.result and result.delta.
type incrementalResponse struct {
	Result passcheck.Result           `json:"result"`
	Delta  passcheck.IncrementalDelta `json:"delta"`
}

// toConfig converts a jsConfig into a passcheck.Config.
// It starts from the named preset (or DefaultConfig when preset is empty),
// then overrides individual fields with any non-zero/non-nil values.
func (jc *jsConfig) toConfig() passcheck.Config {
	var cfg passcheck.Config
	switch jc.Preset {
	case "nist":
		cfg = passcheck.NISTConfig()
	case "pci":
		cfg = passcheck.PCIDSSConfig()
	case "owasp":
		cfg = passcheck.OWASPConfig()
	case "enterprise":
		cfg = passcheck.EnterpriseConfig()
	case "userfriendly":
		cfg = passcheck.UserFriendlyConfig()
	default:
		cfg = passcheck.DefaultConfig()
	}

	if jc.MinLength > 0 {
		cfg.MinLength = jc.MinLength
	}
	if jc.RequireUpper != nil {
		cfg.RequireUpper = *jc.RequireUpper
	}
	if jc.RequireLower != nil {
		cfg.RequireLower = *jc.RequireLower
	}
	if jc.RequireDigit != nil {
		cfg.RequireDigit = *jc.RequireDigit
	}
	if jc.RequireSymbol != nil {
		cfg.RequireSymbol = *jc.RequireSymbol
	}
	if jc.MaxRepeats > 0 {
		cfg.MaxRepeats = jc.MaxRepeats
	}
	if jc.PatternMinLength > 0 {
		cfg.PatternMinLength = jc.PatternMinLength
	}
	if jc.MaxIssues > 0 {
		cfg.MaxIssues = jc.MaxIssues
	}
	cfg.CustomPasswords = jc.CustomPasswords
	cfg.CustomWords = jc.CustomWords
	cfg.ContextWords = jc.ContextWords
	if jc.DisableLeet != nil {
		cfg.DisableLeet = *jc.DisableLeet
	}
	if jc.HIBPResult != nil {
		cfg.HIBPResult = &passcheck.HIBPCheckResult{
			Breached: jc.HIBPResult.Breached,
			Count:    jc.HIBPResult.Count,
		}
	}
	if jc.PassphraseMode != nil {
		cfg.PassphraseMode = *jc.PassphraseMode
	}
	if jc.MinWords > 0 {
		cfg.MinWords = jc.MinWords
	}
	if jc.WordDictSize > 0 {
		cfg.WordDictSize = jc.WordDictSize
	}
	if jc.EntropyMode != "" {
		cfg.EntropyMode = passcheck.EntropyMode(jc.EntropyMode)
	}
	if jc.PenaltyWeights != nil {
		cfg.PenaltyWeights = &passcheck.PenaltyWeights{
			RuleViolation:   jc.PenaltyWeights.RuleViolation,
			PatternMatch:    jc.PenaltyWeights.PatternMatch,
			DictionaryMatch: jc.PenaltyWeights.DictionaryMatch,
			ContextMatch:    jc.PenaltyWeights.ContextMatch,
			HIBPBreach:      jc.PenaltyWeights.HIBPBreach,
			EntropyWeight:   jc.PenaltyWeights.EntropyWeight,
		}
	}
	return cfg
}

// parseConfig decodes a JSON config string sent from JavaScript.
// "null" or "" returns DefaultConfig so callers can pass null safely.
func parseConfig(configJSON string) (passcheck.Config, error) {
	if configJSON == "" || configJSON == "null" {
		return passcheck.DefaultConfig(), nil
	}
	var jc jsConfig
	if err := json.Unmarshal([]byte(configJSON), &jc); err != nil {
		return passcheck.Config{}, err
	}
	return jc.toConfig(), nil
}

// parseResult decodes a previously returned Result JSON.
// "null" or "" returns nil, indicating no prior result.
func parseResult(resultJSON string) *passcheck.Result {
	if resultJSON == "" || resultJSON == "null" {
		return nil
	}
	var r passcheck.Result
	if err := json.Unmarshal([]byte(resultJSON), &r); err != nil {
		return nil
	}
	return &r
}

// errJSON returns a JSON string of the form {"error":"..."}.
func errJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

// marshal serialises v to a JSON string, returning an error envelope on failure.
func marshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return errJSON(err.Error())
	}
	return string(b)
}

func main() {
	done := make(chan struct{})

	// passcheckCheck(password: string) → JSON Result
	js.Global().Set("passcheckCheck", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return errJSON("passcheckCheck: missing password argument")
		}
		return marshal(passcheck.Check(args[0].String()))
	}))

	// passcheckCheckWithConfig(password: string, configJSON: string) → JSON Result
	js.Global().Set("passcheckCheckWithConfig", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 2 {
			return errJSON("passcheckCheckWithConfig: requires (password, configJSON)")
		}
		cfg, err := parseConfig(args[1].String())
		if err != nil {
			return errJSON(err.Error())
		}
		result, err := passcheck.CheckWithConfig(args[0].String(), cfg)
		if err != nil {
			return errJSON(err.Error())
		}
		return marshal(result)
	}))

	// passcheckCheckIncremental(password: string, previousResultJSON: string) → JSON {result, delta}
	js.Global().Set("passcheckCheckIncremental", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 2 {
			return errJSON("passcheckCheckIncremental: requires (password, previousResultJSON)")
		}
		prev := parseResult(args[1].String())
		result, delta, _ := passcheck.CheckIncrementalWithConfig(args[0].String(), prev, passcheck.DefaultConfig())
		return marshal(incrementalResponse{Result: result, Delta: delta})
	}))

	// passcheckCheckIncrementalWithConfig(password: string, previousResultJSON: string, configJSON: string) → JSON {result, delta}
	js.Global().Set("passcheckCheckIncrementalWithConfig", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 3 {
			return errJSON("passcheckCheckIncrementalWithConfig: requires (password, previousResultJSON, configJSON)")
		}
		prev := parseResult(args[1].String())
		cfg, err := parseConfig(args[2].String())
		if err != nil {
			return errJSON(err.Error())
		}
		result, delta, err := passcheck.CheckIncrementalWithConfig(args[0].String(), prev, cfg)
		if err != nil {
			return errJSON(err.Error())
		}
		return marshal(incrementalResponse{Result: result, Delta: delta})
	}))

	<-done
}
