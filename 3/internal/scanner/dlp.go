package scanner

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Finding is one DLP detection result.
type Finding struct {
	Name    string
	Matched string
	Entropy float64
}

type dlpPattern struct {
	name string
	re   *regexp.Regexp
}

// 10 embedded DLP patterns covering the most common secret types.
var dlpPatterns = []dlpPattern{
	{name: "aws-access-key", re: regexp.MustCompile(`(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`)},
	{name: "aws-secret-key", re: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"]([A-Za-z0-9+/]{40})['"]`)},
	{name: "github-token", re: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`)},
	{name: "private-key-pem", re: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{name: "google-api-key", re: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{name: "slack-token", re: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`)},
	{name: "jwt-token", re: regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`)},
	{name: "password-in-url", re: regexp.MustCompile(`https?://[^:@\s/]+:[^:@\s/]+@`)},
	{name: "env-file-leak", re: regexp.MustCompile(`(?i)(\.env|dotenv).{0,30}(upload|send|post|fetch|curl|wget)`)},
	{name: "generic-api-key", re: regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`)},
}

// shannonEntropy calculates Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var e float64
	l := float64(len(s))
	for _, c := range freq {
		p := c / l
		e -= p * math.Log2(p)
	}
	return e
}

// isHighEntropyToken returns true for long alphanumeric tokens with high entropy.
func isHighEntropyToken(s string) bool {
	if len(s) < 32 {
		return false
	}
	var alnum int
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '=' || r == '-' || r == '_' {
			alnum++
		}
	}
	if float64(alnum)/float64(len(s)) < 0.85 {
		return false
	}
	return shannonEntropy(s) > 4.8
}

var tokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{32,}`)

// Scan checks text for secrets and high-entropy tokens.
func Scan(text string) []Finding {
	var findings []Finding

	for _, p := range dlpPatterns {
		if m := p.re.FindString(text); m != "" {
			findings = append(findings, Finding{
				Name:    p.name,
				Matched: maskSecret(m),
				Entropy: shannonEntropy(m),
			})
		}
	}

	for _, tok := range tokenRe.FindAllString(text, -1) {
		e := shannonEntropy(tok)
		if isHighEntropyToken(tok) {
			findings = append(findings, Finding{
				Name:    "high-entropy-token",
				Matched: tok[:8] + "...",
				Entropy: e,
			})
			break // one high-entropy finding is enough
		}
	}

	return dedupe(findings)
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func dedupe(in []Finding) []Finding {
	seen := make(map[string]bool)
	var out []Finding
	for _, f := range in {
		if !seen[f.Name] {
			seen[f.Name] = true
			out = append(out, f)
		}
	}
	return out
}
