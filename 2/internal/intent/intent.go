// Package intent extracts the LLM-stated intent from the transcript JSONL
// and provides a Verifier interface (A9).
//
// ARCHITECTURE.md v1.1 §4.1, §8.3. Decision per V3:
//   - 한 LLM 응답 = 하나의 record (type:"assistant").
//   - .message.content[] 중 .type=="text" 블록만.
//   - JSONL은 chronological. user record 등장 후의 모든 assistant record가
//     "현재 user 요청에 대한 LLM의 표명". 마지막 1 record만 보면 thinking/tool_use만
//     있는 turn에서 직전 brief가 누락됨.
package intent

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// Verifier scores semantic alignment between intent and action. 1.0=fully aligned, 0.0=mismatch.
// Default impl: rule-based (§3 메커니즘 #1). Future: embedding-based via Ollama (§3 #3).
type Verifier interface {
	Score(intent, action string) float64
}

// transcriptRecord captures the subset of fields we read from the JSONL.
type transcriptRecord struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Message   struct {
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"message"`
}

// Result is the extracted intent context.
type Result struct {
	// Text concatenates all assistant text blocks emitted since the last user record
	// (chronological order). Empty string if the transcript has no assistant text yet.
	Text string

	// LastTimestamp is the timestamp of the most recent assistant record contributing to Text.
	LastTimestamp string

	// RecordCount is the number of assistant records merged (debug / observability).
	RecordCount int

	// Empty == true ⇔ Text == "".
	Empty bool

	SourcePath string
}

// Extract scans the transcript JSONL and returns the concatenated assistant text
// emitted since the last user record. Tool_use / thinking blocks are ignored.
//
// Robustness over the previous "last assistant record only" rule:
//   - Captures multiple assistant turns inside the same user request (thinking → text →
//     tool_use → tool_result → text → tool_use ... pattern).
//   - Works even when the very last assistant record contains only thinking or tool_use
//     blocks (no text) — earlier text blocks in the same user turn still surface.
//
// Streaming-friendly: keeps a single text-buffer per "since-last-user" window and resets
// it whenever a new user record appears, so memory is O(window size).
func Extract(transcriptPath string) (*Result, error) {
	if transcriptPath == "" {
		return &Result{Empty: true}, nil
	}
	f, err := os.Open(transcriptPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := &Result{SourcePath: transcriptPath, Empty: true}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<24) // 16MB max line

	var current []string
	var lastTS string
	var recCount int

	flushReset := func() {
		current = current[:0]
		lastTS = ""
		recCount = 0
	}

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec transcriptRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		switch rec.Type {
		case "user":
			// New user request — drop any in-flight buffer; this user message
			// starts a fresh "current intent window".
			flushReset()
		case "assistant":
			if rec.Message.Role != "assistant" {
				continue
			}
			added := false
			for _, b := range rec.Message.Content {
				if b.Type == "text" && b.Text != "" {
					current = append(current, b.Text)
					added = true
				}
			}
			if added {
				lastTS = rec.Timestamp
				recCount++
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return res, err
	}
	if len(current) > 0 {
		res.Text = strings.Join(current, "\n")
		res.LastTimestamp = lastTS
		res.RecordCount = recCount
		res.Empty = false
	}
	return res, nil
}

// ----------------------------------------------------------------------------
// RuleVerifier — keyword-based score implementation (§3 메커니즘 #1).
// ----------------------------------------------------------------------------

// RuleVerifier scores intent/action alignment by keyword presence and simple
// negation awareness. It is intentionally cheap (substring + word-boundary scan)
// so it can run inside the 50 ms rule-matching budget without a regex JIT.
//
// Score semantics:
//
//	1.00  any RequiredKeywords appears in intent (or action) AND no AbsentKeywords appears
//	0.50  no signal in either direction (neutral)
//	0.00  any AbsentKeywords appears in intent (or action), OR RequiredKeywords missing
//	      when CaseRequired is true
//
// CaseInsensitive is on by default. NegationAware tries to suppress matches that
// are negated ("절대 install하지 않겠습니다" -> 'install' shouldn't count as
// install intent). It is a heuristic: looks for a small set of negation tokens
// within ~24 chars before each match.
type RuleVerifier struct {
	RequiredKeywords []string
	AbsentKeywords   []string
	CaseInsensitive  bool
	NegationAware    bool
	CaseRequired     bool // when true, missing required ⇒ score 0.0 instead of 0.5
}

// negation tokens. Korean + English; small list, conservative.
var negationTokens = []string{
	"절대", "안 ", "않겠", "않을", "안할",
	"never ", "won't ", "wont ", "do not ", "don't ", "dont ", "no ",
}

// Score implements Verifier. Combines intent + action haystacks; either is sufficient.
func (rv *RuleVerifier) Score(intent, action string) float64 {
	hay := intent
	if action != "" {
		if hay != "" {
			hay = hay + "\n" + action
		} else {
			hay = action
		}
	}
	if hay == "" {
		return 0.5
	}
	if rv.CaseInsensitive {
		hay = strings.ToLower(hay)
	}
	prep := func(k string) string {
		if rv.CaseInsensitive {
			return strings.ToLower(k)
		}
		return k
	}

	for _, abs := range rv.AbsentKeywords {
		if abs == "" {
			continue
		}
		if rv.contains(hay, prep(abs)) {
			return 0.0
		}
	}

	if len(rv.RequiredKeywords) == 0 {
		return 0.5
	}
	for _, req := range rv.RequiredKeywords {
		if req == "" {
			continue
		}
		if rv.contains(hay, prep(req)) {
			return 1.0
		}
	}
	if rv.CaseRequired {
		return 0.0
	}
	return 0.5
}

// contains: substring match with optional negation suppression.
func (rv *RuleVerifier) contains(hay, needle string) bool {
	if hay == "" || needle == "" {
		return false
	}
	if !rv.NegationAware {
		return strings.Contains(hay, needle)
	}
	// Walk all occurrences; ignore the ones immediately preceded by a negation token.
	idx := 0
	for {
		off := strings.Index(hay[idx:], needle)
		if off < 0 {
			return false
		}
		pos := idx + off
		if !rv.precededByNegation(hay, pos) {
			return true
		}
		idx = pos + len(needle)
		if idx >= len(hay) {
			return false
		}
	}
}

// precededByNegation returns true iff a negation token appears in the 24 chars
// preceding pos. Window is small to avoid spurious suppression across sentence
// boundaries.
func (rv *RuleVerifier) precededByNegation(hay string, pos int) bool {
	start := pos - 24
	if start < 0 {
		start = 0
	}
	prefix := hay[start:pos]
	for _, t := range negationTokens {
		tt := t
		if rv.CaseInsensitive {
			tt = strings.ToLower(t)
		}
		if strings.Contains(prefix, tt) {
			return true
		}
	}
	return false
}

// NewInstallVerifier returns a verifier preconfigured for the canonical
// "install/setup intent" check used by bash-curl-pipe-shell.
//
// Convenience helper so callers don't reinstate the keyword list at every site.
func NewInstallVerifier() *RuleVerifier {
	return &RuleVerifier{
		RequiredKeywords: []string{"install", "설치", "setup", "공식 설치", "package", "패키지"},
		CaseInsensitive:  true,
		NegationAware:    true,
		CaseRequired:     true,
	}
}
