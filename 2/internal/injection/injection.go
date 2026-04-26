// Package injection detects prompt-injection patterns in tool responses.
//
// ARCHITECTURE.md v1.1 §2.2 §4. PostToolUse 입력의 tool_response 텍스트를 스캔.
// 차단 대상은 "오염된 응답이 LLM 컨텍스트에 진입하는 것" — 행위 자체는 이미 발생.
package injection

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

// Hit represents one detected injection signal.
type Hit struct {
	PatternID string
	Excerpt   string
}

type pattern struct {
	id string
	re *regexp.Regexp
}

var patterns = []pattern{
	// Direct override attempts.
	{id: "ignore-previous", re: regexp.MustCompile(`(?i)ignore\s+(all\s+)?(prior|previous)\s+(instructions?|prompts?|messages?)`)},
	{id: "disregard-instructions", re: regexp.MustCompile(`(?i)disregard\s+(all\s+)?(prior|previous|the)?\s*instructions?`)},
	{id: "forget-everything", re: regexp.MustCompile(`(?i)forget\s+(everything|all|prior|previous)`)},
	{id: "now-you-are", re: regexp.MustCompile(`(?i)you\s+are\s+now\s+(an\s+)?(unrestricted|jailbroken|DAN|do anything now)`)},
	{id: "new-instructions", re: regexp.MustCompile(`(?i)\bnew\s+(system\s+)?(instructions?|prompts?|directives?)\s*[:\-]`)},

	// Tag injections.
	{id: "system-tag", re: regexp.MustCompile(`(?i)<\s*/?\s*system\s*>`)},
	{id: "instruction-tag", re: regexp.MustCompile(`(?i)<\s*/?\s*(instructions?|admin)\s*>`)},

	// Common payload requests.
	{id: "exfil-request", re: regexp.MustCompile(`(?i)(send|post|upload|exfil(trate)?)\s+(the\s+)?(api[_\s-]?key|credential|password|secret|token|env)`)},
	{id: "reveal-secrets", re: regexp.MustCompile(`(?i)(reveal|disclose|print|output|leak)\s+(the\s+)?(api[_\s-]?key|credential|password|secret|environment\s+variable)`)},
	{id: "exfil-curl", re: regexp.MustCompile(`(?i)curl\s+[^\s]*\s+(-d|--data|-F)\s+["'\$]`)},

	// Hidden / obfuscated.
	{id: "base64-blob", re: regexp.MustCompile(`\b[A-Za-z0-9+/]{200,}={0,2}\b`)},
}

// Scan returns injection hits. Caller decides verdict (warn/deny).
func Scan(text string) []Hit {
	if text == "" {
		return nil
	}
	var hits []Hit
	for _, p := range patterns {
		if loc := p.re.FindStringIndex(text); loc != nil {
			hits = append(hits, Hit{PatternID: p.id, Excerpt: trim(text[loc[0]:loc[1]])})
		}
	}
	if hasHiddenUnicode(text) {
		hits = append(hits, Hit{PatternID: "hidden-unicode", Excerpt: "(non-printable codepoints detected)"})
	}
	return hits
}

// Any returns true if any injection signal is present.
func Any(text string) bool {
	return len(Scan(text)) > 0
}

func trim(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// hasHiddenUnicode flags zero-width / bidi-control / BOM codepoints.
//
// We rely on unicode.Cf (Format) which covers ZWSP/ZWNJ/ZWJ/LRM/RLM/PDI/BOM etc.
// Embedding literal U+FEFF in source trips the Go lexer's BOM rule, so we avoid
// hand-listing them and instead use the Cf category check.
func hasHiddenUnicode(s string) bool {
	for _, r := range s {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u200E', '\u200F',
			'\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
			'\u2066', '\u2067', '\u2068', '\u2069',
			'\uFEFF':
			return true
		}
		if unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// PatternIDs returns the static pattern IDs (debug/help).
func PatternIDs() []string {
	ids := make([]string, 0, len(patterns)+1)
	for _, p := range patterns {
		ids = append(ids, p.id)
	}
	ids = append(ids, "hidden-unicode")
	return ids
}

// ExtractText pulls plain text out of a tool_response payload that may be either a JSON string or
// an object with common text-bearing keys (result, content, text, body). Falls back to concatenating
// all string values found anywhere in the payload. If the payload is not valid JSON, returns it as-is.
func ExtractText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return extractTextValue(v)
}

func extractTextValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		// Prefer common text-bearing keys.
		for _, key := range []string{"result", "content", "text", "body", "output"} {
			if val, ok := t[key]; ok {
				if s, ok := val.(string); ok && s != "" {
					return s
				}
				if nested := extractTextValue(val); nested != "" {
					return nested
				}
			}
		}
		// Fallback: concatenate all string-valued fields.
		var parts []string
		for _, val := range t {
			if s, ok := val.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	case []any:
		var parts []string
		for _, e := range t {
			if s := extractTextValue(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}
