package intent

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

// transcriptEntry is one line in the Claude Code transcript JSONL.
type transcriptEntry struct {
	Role    string          `json:"role"`
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
	Message *transcriptEntry `json:"message,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// LastAssistantMessage reads the transcript JSONL and returns the most recent
// assistant turn as a plain string.
func LastAssistantMessage(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e transcriptEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		// Unwrap nested {message:{role:...}} format.
		if e.Message != nil {
			inner := e.Message
			if e.Role == "" {
				e.Role = inner.Role
			}
			if e.Type == "" {
				e.Type = inner.Type
			}
			e.Content = inner.Content
		}
		role := e.Role
		if role == "" {
			role = e.Type
		}
		if role != "assistant" {
			continue
		}
		if text := extractText(e.Content); text != "" {
			last = text
		}
	}
	return last, sc.Err()
}

func extractText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []contentBlock
	if json.Unmarshal(raw, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// Verdict is the result of an intent–action consistency check.
type Verdict struct {
	Consistent bool
	Reason     string
}

type intentGroup struct {
	keywords   []string
	allowTools []string
	denyBashRe *regexp.Regexp
}

// intentGroups maps intent signals to expected tools and banned sub-patterns.
var intentGroups = []intentGroup{
	{
		keywords:   []string{"설치", "install", "add package", "download", "의존성", "dependency", "dependencies"},
		allowTools: []string{"Bash", "Read"},
		denyBashRe: regexp.MustCompile(`(?i)(curl|wget).{0,200}\|\s*(sh|bash|zsh)|eval\s*\$\(`),
	},
	{
		keywords:   []string{"읽", "확인", "검토", "check", "read", "review", "view", "show", "보여", "cat "},
		allowTools: []string{"Read", "Bash"},
		denyBashRe: regexp.MustCompile(`(?i)(>\s*[^>]|tee\s+|rm\s+)`),
	},
	{
		keywords:   []string{"삭제", "제거", "지우", "delete", "remove", "clean"},
		allowTools: []string{"Bash", "Edit"},
		denyBashRe: regexp.MustCompile(`rm\s+(-rf|-fr)\s+(/\s*$|/root|~/|\$HOME)`),
	},
}

// dangerousBashRe catches high-risk Bash patterns regardless of intent context.
// Note: patterns must work against the full JSON-encoded tool_input string, so
// we cannot rely on end-of-string anchors after the command value.
var dangerousBashRe = regexp.MustCompile(
	`(?i)(` +
		`\|\s*(sh|bash|zsh|fish|cmd|powershell)(\s|[;"']|$)` + // pipe to shell
		`|bash\s*<\(` + // process substitution
		`|eval\s*\$\(` + // eval of subshell
		`|wget[^\n"]+\|\s*(sh|bash)` + // wget pipe
		`|curl[^\n"]+\|\s*(sh|bash)` + // curl pipe
		`|rm\s+(-rf|-fr)\s+/(?:["\s;]|$)` + // rm -rf / (followed by quote, space, semicolon or EOL)
		`)`,
)

// CheckConsistency returns whether the tool call is consistent with the
// stated assistant intent. An empty lastAssistant still triggers the
// unconditional dangerous-pattern check.
func CheckConsistency(lastAssistant, toolName, toolInputStr string) Verdict {
	// Always-on: dangerous Bash patterns are blocked regardless of intent.
	if toolName == "Bash" && dangerousBashRe.MatchString(toolInputStr) {
		return Verdict{
			Consistent: false,
			Reason:     "dangerous Bash pattern (pipe-to-shell / eval / recursive root delete)",
		}
	}

	if lastAssistant == "" {
		return Verdict{Consistent: true}
	}

	lower := strings.ToLower(lastAssistant)

	for _, g := range intentGroups {
		matched := false
		for _, kw := range g.keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		allowed := false
		for _, t := range g.allowTools {
			if t == toolName {
				allowed = true
				break
			}
		}
		if !allowed {
			return Verdict{
				Consistent: false,
				Reason: "tool " + toolName + " is inconsistent with stated intent (" +
					g.keywords[0] + ")",
			}
		}

		if toolName == "Bash" && g.denyBashRe != nil && g.denyBashRe.MatchString(toolInputStr) {
			return Verdict{
				Consistent: false,
				Reason: "Bash command contradicts stated intent (" + g.keywords[0] + "): " +
					"operation pattern inconsistent with declared purpose",
			}
		}
	}

	return Verdict{Consistent: true}
}
