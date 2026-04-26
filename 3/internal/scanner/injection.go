package scanner

import "regexp"

// InjectionMatch is the name of a matched injection pattern.
type InjectionMatch struct {
	Name string
}

type injectionPattern struct {
	name string
	re   *regexp.Regexp
}

var injectionPatterns = []injectionPattern{
	{
		name: "ignore-previous-instructions",
		re:   regexp.MustCompile(`(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|earlier).{0,30}(instructions?|prompt|context|rules?)`),
	},
	{
		name: "system-prompt-override",
		re:   regexp.MustCompile(`(?i)(new|updated?|revised?|actual|real)\s+(system\s+prompt|instructions?|directives?)`),
	},
	{
		name: "jailbreak-roleplay",
		re:   regexp.MustCompile(`(?i)(you are now|act as|pretend (to be|you are)|from now on you).{0,60}(assistant|ai|bot|model|claude|gpt|llm)`),
	},
	{
		name: "unrestricted-mode",
		re:   regexp.MustCompile(`(?i)(unrestricted\s+mode|jailbreak|DAN\s+mode|developer\s+mode|evil\s+mode|god\s+mode)`),
	},
	{
		name: "tool-call-injection",
		re:   regexp.MustCompile(`(?i)<(tool_use|function_call|invoke|tool)\b`),
	},
	{
		name: "data-exfil-instruction",
		re:   regexp.MustCompile(`(?i)(send|upload|exfiltrate|leak|transmit).{0,40}(to|at)\s+https?://`),
	},
	{
		name: "hidden-instruction-marker",
		re:   regexp.MustCompile(`(?i)(#\s*SYSTEM|<!--\s*INJECT|/\*\s*OVERRIDE|\[\s*HIDDEN\s*\])`),
	},
}

// ScanInjection checks text for prompt injection patterns and returns matched names.
func ScanInjection(text string) []string {
	var matches []string
	for _, p := range injectionPatterns {
		if p.re.MatchString(text) {
			matches = append(matches, p.name)
		}
	}
	return matches
}
