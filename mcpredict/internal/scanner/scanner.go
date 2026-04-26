// Package scanner implements DLP secret scanning over arbitrary text/JSON payloads.
//
// ARCHITECTURE.md v1.1 §4 §9. Gitleaks 정규식 11개 + Shannon 엔트로피 보조.
// RE2 (Go stdlib regexp), 1MB cap to bound regex DoS.
package scanner

import (
	"math"
	"regexp"
	"strings"
)

// MaxScanBytes caps the scanned text to bound regex DoS surface.
const MaxScanBytes = 1 << 20 // 1 MiB

// Hit represents one detected secret occurrence.
type Hit struct {
	PatternID string
	Start     int
	End       int
	Excerpt   string // masked: first 4 + "***" + last 4
}

type pattern struct {
	id         string
	re         *regexp.Regexp
	entropyMin float64 // 0 means not enforced
}

var patterns = []pattern{
	{id: "aws-access-key-id", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{id: "aws-secret-access-key", re: regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`), entropyMin: 5.0},
	{id: "github-pat", re: regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`)},
	{id: "github-oauth", re: regexp.MustCompile(`\bgho_[0-9A-Za-z]{36}\b`)},
	{id: "github-app", re: regexp.MustCompile(`\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b`)},
	{id: "slack-bot-token", re: regexp.MustCompile(`\bxoxb-[0-9]+-[0-9]+-[0-9a-zA-Z]+\b`)},
	{id: "private-key-pem", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----`)},
	{id: "openai-api-key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{id: "anthropic-api-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{50,}\b`)},
	{id: "stripe-secret", re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b`)},
	// Filesystem paths with long slash-joined segments can satisfy the 32+ char
	// character class but sit at moderate entropy (~4.0–4.7). True opaque secrets
	// (AWS secret access key, base64 token) are at 5.0+. Threshold tuned to suppress
	// path-shaped false positives while still catching real high-entropy material.
	{id: "generic-high-entropy", re: regexp.MustCompile(`\b[A-Za-z0-9+/=_\-]{32,}\b`), entropyMin: 5.0},
}

// Scan returns all secret hits in the input. Empty slice if none.
func Scan(text string) []Hit {
	if len(text) > MaxScanBytes {
		text = text[:MaxScanBytes]
	}
	var hits []Hit
	for _, p := range patterns {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			match := text[loc[0]:loc[1]]
			if p.entropyMin > 0 && shannonEntropy(match) < p.entropyMin {
				continue
			}
			hits = append(hits, Hit{
				PatternID: p.id,
				Start:     loc[0],
				End:       loc[1],
				Excerpt:   mask(match),
			})
		}
	}
	return hits
}

// Any returns true if any pattern matches.
func Any(text string) bool {
	return len(Scan(text)) > 0
}

func mask(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "***" + s[len(s)-4:]
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// PatternIDs returns the list of pattern identifiers (for help/debug output).
func PatternIDs() []string {
	ids := make([]string, len(patterns))
	for i, p := range patterns {
		ids[i] = p.id
	}
	return ids
}

// stringBytesView is a tiny helper to keep Scan signature flexible if callers pass json.RawMessage.
func stringBytesView(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.Clone(string(b))
}

// ScanBytes is a convenience for callers holding a byte slice.
func ScanBytes(b []byte) []Hit { return Scan(stringBytesView(b)) }
