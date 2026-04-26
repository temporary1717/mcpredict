package scanner

import "regexp"

// BypassFinding is a detected evasion technique.
type BypassFinding struct {
	Name string
	Kind string // "exec", "obfuscate", "unicode"
}

type bypassPattern struct {
	name string
	kind string
	re   *regexp.Regexp
}

// bashBypassPatterns covers known shell command evasion techniques.
var bashBypassPatterns = []bypassPattern{
	// ── Interpreter escape ────────────────────────────────────────────────────
	{
		name: "python-shell-escape",
		kind: "exec",
		re:   regexp.MustCompile(`(?i)python[23]?\s+-c\s+['"]{0,1}.{0,60}(import\s+os|exec\s*\(|__import__|subprocess|pty)`),
	},
	{
		name: "perl-shell-escape",
		kind: "exec",
		re:   regexp.MustCompile(`(?i)perl\s+-e\s+['"]{0,1}.{0,60}(system\s*\(|exec\s*\(|open\s*\([^)]+\|)`),
	},
	{
		name: "node-shell-escape",
		kind: "exec",
		re:   regexp.MustCompile(`(?i)node\s+(-e|-p)\s+['"]{0,1}.{0,60}(require\s*\(\s*['"]child_process|exec\s*\(|spawn\s*\()`),
	},
	{
		name: "ruby-shell-escape",
		kind: "exec",
		re:   regexp.MustCompile("(?i)ruby\\s+-e\\s+['\"]?.{0,60}(`|system\\s*\\(|exec\\s*\\(|IO\\.popen)"),
	},
	// ── Base64 / encoding obfuscation ─────────────────────────────────────────
	{
		name: "base64-pipe-exec",
		kind: "obfuscate",
		re:   regexp.MustCompile(`(?i)(echo\s+[A-Za-z0-9+/=]{16,}[^|]*\|[^|]*base64\s*(-d|--decode)|base64\s*(-d|--decode)[^|]*\|)\s*(sh|bash|zsh|fish)`),
	},
	{
		name: "base64-herestring-exec",
		kind: "obfuscate",
		re:   regexp.MustCompile(`(?i)base64\s*(-d|--decode)\s*<<<\s*[A-Za-z0-9+/=]{16,}`),
	},
	{
		name: "xxd-decode-exec",
		kind: "obfuscate",
		re:   regexp.MustCompile(`(?i)xxd\s*(-r|-revert)[^|]*\|\s*(sh|bash|zsh)`),
	},
	// ── Shell metacharacter bypass ─────────────────────────────────────────────
	{
		name: "ifs-bypass",
		kind: "obfuscate",
		re:   regexp.MustCompile(`\$\{?IFS\}?`),
	},
	{
		name: "ansi-c-hex-escape",
		kind: "obfuscate",
		// $'\x62\x61\x73\x68' spells "bash" in hex; allow 1-2 backslashes to handle JSON encoding
		re: regexp.MustCompile(`\$'(\\{1,2}x[0-9a-fA-F]{2}|\\{1,2}[0-7]{1,3}){3,}'`),
	},
	{
		name: "string-concat-bypass",
		kind: "obfuscate",
		// Matches ba''sh, b"a"sh, b$@ash, b${x}ash etc.
		re: regexp.MustCompile(`\bb['"\$]?[a-z'"\$]?['"\$]?s[h'"\$]\b`),
	},
	{
		name: "env-exec-bypass",
		kind: "exec",
		// env sh -c "..." or env -i bash -c "..."
		re: regexp.MustCompile(`(?i)\benv\b(\s+-\w+)*\s+(sh|bash|zsh|python|perl|node|ruby)\b`),
	},
	// ── Download + execute (deferred) ────────────────────────────────────────
	{
		name: "download-then-execute",
		kind: "exec",
		re:   regexp.MustCompile(`(?i)(curl|wget)[^\n;]{0,120}(-o\s+\S+|-O\s+\S+|--output\s+\S+).*[;&\n]\s*(chmod|bash|sh|./)`),
	},
	{
		name: "tmpfile-exec",
		kind: "exec",
		// Write to /tmp then chmod and execute — RE2 has no backrefs so we match the /tmp+chmod combo
		re: regexp.MustCompile(`(?i)/tmp/[a-z0-9_.-]+[^|{]{0,80}[;&\n][^|{]{0,80}chmod|chmod[^|{]{0,80}/tmp/[a-z0-9_.-]+`),
	},
	// ── exec with file descriptors ─────────────────────────────────────────────
	{
		name: "exec-fd-hijack",
		kind: "exec",
		re:   regexp.MustCompile(`\bexec\s+[0-9]+[<>][&]?[0-9]`),
	},
	// ── Path obfuscation ─────────────────────────────────────────────────────
	{
		name: "path-traversal-cmd",
		kind: "obfuscate",
		// /usr/bin/../bin/bash or ///bin/bash
		re: regexp.MustCompile(`/{2,}(bin|sh|bash)|/\w+/\.\./+\w*(sh|bash)`),
	},
}

// ScanBypass checks Bash command text for known evasion techniques.
func ScanBypass(text string) []BypassFinding {
	var findings []BypassFinding
	for _, p := range bashBypassPatterns {
		if p.re.MatchString(text) {
			findings = append(findings, BypassFinding{Name: p.name, Kind: p.kind})
		}
	}
	return findings
}

// ── Unicode / invisible character bypass ──────────────────────────────────────

// unicodeHomoglyphRe detects Cyrillic and other non-ASCII lookalike characters
// that can be used to spell "ignore", "instructions", "system", etc.
// while evading ASCII-based pattern matching.
// Cyrillic lookalikes — U+0406 U+0456 U+0410 U+0430 U+0412 U+0432
//   U+0435 U+043E U+0440 U+0441 U+0443 U+04BB U+0581
var unicodeHomoglyphRe = regexp.MustCompile(
	`[\x{0406}\x{0456}\x{0410}\x{0430}\x{0412}\x{0432}\x{0435}\x{043E}\x{0440}\x{0441}\x{0443}\x{04BB}\x{0581}]`,
)

// zeroWidthRe detects invisible characters injected between words to split
// keywords and evade substring-based detection.
// Covers: U+200B U+200C U+200D U+200E U+200F U+FEFF U+2060 U+2061 U+2062 U+2063
var zeroWidthRe = regexp.MustCompile(
	`[\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}\x{FEFF}\x{2060}\x{2061}\x{2062}\x{2063}]`,
)

// ScanUnicodeBypass returns bypass technique names if the text contains
// Unicode homoglyphs or zero-width characters.
func ScanUnicodeBypass(text string) []string {
	var matches []string
	if unicodeHomoglyphRe.MatchString(text) {
		matches = append(matches, "unicode-homoglyph")
	}
	if zeroWidthRe.MatchString(text) {
		matches = append(matches, "zero-width-chars")
	}
	return matches
}
