package dictionary

import (
	"sort"

	"github.com/rafaelsanzio/passcheck/internal/safemem"
)

// DefaultMinWordLen is the minimum length of a dictionary word considered
// for substring matching. Shorter words produce too many false positives
// (e.g. "the" matching inside "other").
const DefaultMinWordLen = 4

// commonWords is a list of common English words frequently found in
// passwords. The list is sorted longest-first at init time so that the
// most significant match is reported first and shorter substrings of an
// already-matched word can be skipped.
//
// Only words of DefaultMinWordLen or more characters are included.
//
//go:generate go test -run "TestWordList" -count=1 -v
var commonWords []string

func init() {
	raw := []string{
		// ── Security / credentials ─────────────────────────────────────
		"password", "passwd", "passw", "secret", "private",
		"admin", "login", "access", "secure", "master",
		"credential", "authenticate", "authorize", "permission",

		// ── Technology ─────────────────────────────────────────────────
		"computer", "internet", "system", "server", "network",
		"phone", "mobile", "laptop", "email", "account",
		"software", "hardware", "program", "database", "cloud",
		"digital", "online", "website", "browser", "download",
		"upload", "wireless", "bluetooth", "keyboard", "monitor",
		"printer", "router", "modem", "pixel", "cursor",
		"algorithm", "binary", "compiler", "debug", "encrypt",
		"firewall", "gateway", "hostname", "interface", "kernel",
		"protocol", "socket", "terminal", "virtual", "quantum",

		// ── Money & business ───────────────────────────────────────────
		"money", "dollar", "credit", "bank", "gold",
		"silver", "diamond", "crystal", "magic", "power",
		"bitcoin", "crypto", "wallet", "stock", "market",
		"profit", "business", "company", "corporate", "manager",
		"finance", "invest", "wealth", "fortune", "million",
		"billion", "salary", "bonus", "budget", "payment",

		// ── Nature & elements ──────────────────────────────────────────
		"energy", "fire", "water", "earth", "storm",
		"thunder", "shadow", "light", "dark", "night",
		"star", "moon", "heaven", "angel", "devil",
		"sunrise", "sunset", "ocean", "river", "mountain",
		"forest", "garden", "flower", "island", "beach",
		"desert", "jungle", "valley", "meadow", "canyon",
		"volcano", "glacier", "waterfall", "horizon", "aurora",
		"eclipse", "nebula", "comet", "meteor", "asteroid",
		"tornado", "hurricane", "blizzard", "avalanche",
		"rainbow", "snowflake", "lightning", "breeze", "frost",

		// ── Animals ────────────────────────────────────────────────────
		"dragon", "tiger", "eagle", "falcon", "wolf",
		"panther", "cobra", "viper", "monkey", "horse",
		"chicken", "kitten", "puppy", "bear", "lion",
		"shark", "phoenix", "unicorn", "dolphin", "whale",
		"elephant", "giraffe", "penguin", "parrot", "turtle",
		"butterfly", "spider", "scorpion", "gorilla", "leopard",
		"cheetah", "stallion", "mustang", "hawk", "raven",
		"sparrow", "robin", "owl", "flamingo", "pelican",
		"jaguar", "cougar", "coyote", "buffalo", "moose",

		// ── People & names ─────────────────────────────────────────────
		"michael", "daniel", "robert", "william", "thomas",
		"james", "joseph", "richard", "charles", "david",
		"jennifer", "jessica", "michelle", "nicole", "amanda",
		"samantha", "ashley", "princess", "queen", "king",
		"alexander", "benjamin", "christopher", "elizabeth",
		"victoria", "katherine", "stephanie", "jonathan",

		// ── Sports & games ─────────────────────────────────────────────
		"football", "baseball", "soccer", "hockey", "basketball",
		"tennis", "golf", "rugby", "cricket", "volleyball",
		"player", "winner", "champion", "legend", "warrior",
		"ninja", "pirate", "wizard", "samurai", "spartan",
		"boxing", "wrestling", "karate", "marathon", "sprint",
		"trophy", "medal", "victory", "defeat", "tournament",

		// ── Pop culture ────────────────────────────────────────────────
		"batman", "superman", "spiderman", "ironman", "avengers",
		"starwars", "pokemon", "minecraft", "fortnite", "roblox",
		"marvel", "disney", "hogwarts", "naruto", "gandalf",
		"wolverine", "deadpool", "captain", "shield", "gotham",
		"joker", "thanos", "hulk", "thor", "loki",

		// ── Seasons & time ─────────────────────────────────────────────
		"summer", "winter", "spring", "autumn", "october",
		"november", "december", "january", "february", "forever",
		"today", "tomorrow", "yesterday", "morning", "midnight",
		"evening", "afternoon", "weekend", "holiday", "vacation",
		"monday", "tuesday", "wednesday", "thursday", "friday",
		"saturday", "sunday",

		// ── Feelings & actions ─────────────────────────────────────────
		"love", "trust", "friend", "happy", "lucky",
		"freedom", "peace", "welcome", "hello", "sunshine",
		"smile", "dream", "hope", "faith",
		"courage", "strength", "honor", "glory", "destiny",
		"passion", "desire", "wonder", "inspire", "believe",
		"imagine", "create", "discover", "explore", "adventure",
		"journey", "spirit", "grace", "beauty", "truth",
		"wisdom", "knowledge", "justice", "mercy",

		// ── Colors ─────────────────────────────────────────────────────
		"purple", "orange", "yellow", "green", "blue",
		"black", "white", "golden", "crimson",
		"scarlet", "violet", "indigo", "turquoise", "magenta",

		// ── Food & drink ───────────────────────────────────────────────
		"cookie", "butter", "pepper", "ginger", "cheese",
		"chocolate", "coffee", "apple", "banana", "cherry",
		"lemon", "mango", "pizza", "burger", "candy",
		"vanilla", "caramel", "cinnamon", "nutmeg", "saffron",
		"steak", "sushi", "pasta", "noodle", "bacon",
		"waffle", "pancake", "brownie", "cupcake", "donut",
		"espresso", "latte", "smoothie", "cocktail",

		// ── Places & brands ────────────────────────────────────────────
		"google", "facebook", "twitter", "youtube", "amazon",
		"america", "london", "paris", "tokyo",
		"berlin", "sydney", "toronto", "chicago", "boston",
		"netflix", "spotify", "instagram", "tiktok",

		// ── Music & culture ────────────────────────────────────────────
		"music", "guitar", "piano", "dance", "rock",
		"metal", "jazz", "concert", "rhythm", "melody",
		"harmony", "symphony", "orchestra", "chorus", "lyric",

		// ── Fantasy & mythology ────────────────────────────────────────
		"knight", "paladin", "sorcerer", "warlock", "shaman",
		"vampire", "werewolf", "zombie", "ghost",
		"demon", "goblin", "troll", "fairy", "elf",
		"treasure", "quest", "dungeon", "castle", "tower",
		"throne", "crown", "scepter", "artifact", "relic",
		"enchant", "mystical", "arcane", "divine", "eternal",
		"immortal", "specter", "wraith", "sentinel",

		// ── Military & vehicles ────────────────────────────────────────
		"soldier", "marine", "general", "colonel", "commander",
		"sniper", "rifle", "bullet", "weapon",
		"corvette", "ferrari", "porsche", "lamborghini", "tesla",
		"harley", "yamaha", "kawasaki",

		// ── Miscellaneous common password words ────────────────────────
		"killer", "hunter", "ranger", "charlie", "buster",
		"buddy", "prince", "hacker", "cyber", "matrix",
		"maverick", "rebel", "outlaw", "rogue",
		"stealth", "silent", "venom", "toxic",
		"chaos", "havoc", "fury", "rage", "blaze",
		"inferno", "nitro", "turbo", "rocket", "laser",
		"bolt", "flash", "spark", "flame",
	}

	// Filter to minimum length and sort longest-first.
	commonWords = make([]string, 0, len(raw))
	for _, w := range raw {
		if len(w) >= DefaultMinWordLen {
			commonWords = append(commonWords, w)
		}
	}
	sort.Slice(commonWords, func(i, j int) bool {
		return len(commonWords[i]) > len(commonWords[j])
	})
}

// findCommonWords returns all common dictionary words that appear as
// substrings of password. When constantTime is true, uses constant-time
// substring checks so timing does not leak match position.
//
// password must be lowercase.
func findCommonWords(password string, constantTime bool) []string {
	if constantTime {
		return findCommonWordsInConstantTime(password, commonWords)
	}
	return findCommonWordsIn(password, commonWords)
}

// findCommonWordsIn is the core implementation shared by findCommonWords
// and findCommonWordsWithCustom. It scans the (pre-sorted) wordlist for
// substring matches, skipping regions already covered by longer words.
func findCommonWordsIn(password string, words []string) []string {
	if len(password) < DefaultMinWordLen {
		return nil
	}

	var matches []string
	covered := make([]bool, len(password))

	for _, word := range words {
		if len(word) > len(password) {
			continue
		}

		idx := indexOfSubstring(password, word)
		if idx < 0 {
			continue
		}

		// Skip if this region is already covered by a longer match.
		if isRegionCovered(covered, idx, len(word)) {
			continue
		}

		markRegion(covered, idx, len(word))
		matches = append(matches, word)
	}

	return matches
}

// findCommonWordsWithCustom merges custom words into the default word list,
// sorts the combined list longest-first, and performs substring matching.
func findCommonWordsWithCustom(password string, custom []string, constantTime bool) []string {
	if len(custom) == 0 {
		return findCommonWords(password, constantTime)
	}

	// Merge: default + filtered custom words.
	merged := make([]string, len(commonWords), len(commonWords)+len(custom))
	copy(merged, commonWords)
	for _, w := range custom {
		if len(w) >= DefaultMinWordLen {
			merged = append(merged, w)
		}
	}

	// Re-sort longest-first for correct coverage logic (when not constant-time).
	sort.Slice(merged, func(i, j int) bool {
		return len(merged[i]) > len(merged[j])
	})

	if constantTime {
		return findCommonWordsInConstantTime(password, merged)
	}
	return findCommonWordsIn(password, merged)
}

// findCommonWordsInConstantTime reports every word in words that appears as
// a substring of password, using constant-time contains so timing does not leak.
func findCommonWordsInConstantTime(password string, words []string) []string {
	if len(password) < DefaultMinWordLen {
		return nil
	}
	var matches []string
	for _, word := range words {
		if len(word) > len(password) {
			continue
		}
		if safemem.ConstantTimeContains(password, word) {
			matches = append(matches, word)
		}
	}
	return matches
}

// indexOfSubstring returns the index of the first occurrence of substr
// in s, or -1 if not found.
func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// isRegionCovered reports whether all bytes in s[start:start+length]
// have already been covered by a previous match.
func isRegionCovered(covered []bool, start, length int) bool {
	for i := start; i < start+length; i++ {
		if !covered[i] {
			return false
		}
	}
	return true
}

// markRegion marks bytes in the covered slice for the given range.
func markRegion(covered []bool, start, length int) {
	for i := start; i < start+length; i++ {
		covered[i] = true
	}
}
