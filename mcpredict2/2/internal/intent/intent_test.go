package intent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// Extract — multi-record concat across last user turn.
// ----------------------------------------------------------------------------

func writeTranscript(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "transcript.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	return p
}

func TestExtract_Empty(t *testing.T) {
	r, err := Extract("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !r.Empty || r.Text != "" {
		t.Fatalf("expected empty, got %+v", r)
	}
}

func TestExtract_LastUserTurn_MultipleAssistants(t *testing.T) {
	// user1 -> 2 assistants -> user2 -> 3 assistants (mix of text + thinking)
	// Result.Text should include only the 3 assistants after user2.
	lines := []string{
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"first request"}]}}`,
		`{"type":"assistant","timestamp":"t1","message":{"role":"assistant","content":[{"type":"text","text":"old text 1"}]}}`,
		`{"type":"assistant","timestamp":"t2","message":{"role":"assistant","content":[{"type":"text","text":"old text 2"}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"second request"}]}}`,
		`{"type":"assistant","timestamp":"t3","message":{"role":"assistant","content":[{"type":"text","text":"new brief"}]}}`,
		`{"type":"assistant","timestamp":"t4","message":{"role":"assistant","content":[{"type":"thinking","text":"hidden"}]}}`,
		`{"type":"assistant","timestamp":"t5","message":{"role":"assistant","content":[{"type":"text","text":"running tool now"},{"type":"tool_use","text":"…"}]}}`,
	}
	p := writeTranscript(t, lines)
	r, err := Extract(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Empty {
		t.Fatalf("expected non-empty result")
	}
	if !strings.Contains(r.Text, "new brief") || !strings.Contains(r.Text, "running tool now") {
		t.Fatalf("expected current-turn texts, got: %q", r.Text)
	}
	if strings.Contains(r.Text, "old text") {
		t.Fatalf("expected previous-user-turn text to be excluded, got: %q", r.Text)
	}
	if r.RecordCount != 2 {
		t.Errorf("expected RecordCount=2 (only text-bearing), got %d", r.RecordCount)
	}
	if r.LastTimestamp != "t5" {
		t.Errorf("expected LastTimestamp=t5, got %q", r.LastTimestamp)
	}
}

func TestExtract_OnlyThinkingTurn(t *testing.T) {
	// user -> assistant(text) -> assistant(thinking only) -> assistant(tool_use only)
	// Old impl returned "" because last record had no text. New impl should still
	// surface the earlier text inside the same turn.
	lines := []string{
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"go"}]}}`,
		`{"type":"assistant","timestamp":"t1","message":{"role":"assistant","content":[{"type":"text","text":"i will install nginx"}]}}`,
		`{"type":"assistant","timestamp":"t2","message":{"role":"assistant","content":[{"type":"thinking","text":"…"}]}}`,
		`{"type":"assistant","timestamp":"t3","message":{"role":"assistant","content":[{"type":"tool_use","text":""}]}}`,
	}
	p := writeTranscript(t, lines)
	r, err := Extract(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(r.Text, "install nginx") {
		t.Fatalf("expected text from earlier record, got: %q", r.Text)
	}
}

func TestExtract_NoUserRecord_AllAssistant(t *testing.T) {
	// Edge: transcript has only assistant records (rare but possible at session start).
	// Should still return whatever assistant text exists.
	lines := []string{
		`{"type":"assistant","timestamp":"t1","message":{"role":"assistant","content":[{"type":"text","text":"hello"}]}}`,
		`{"type":"assistant","timestamp":"t2","message":{"role":"assistant","content":[{"type":"text","text":"world"}]}}`,
	}
	p := writeTranscript(t, lines)
	r, err := Extract(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Empty {
		t.Fatalf("expected non-empty")
	}
	if !strings.Contains(r.Text, "hello") || !strings.Contains(r.Text, "world") {
		t.Fatalf("expected concat, got: %q", r.Text)
	}
}

func TestExtract_MalformedLineSkipped(t *testing.T) {
	lines := []string{
		`{not-json`,
		`{"type":"user","message":{"role":"user","content":[]}}`,
		`{"type":"assistant","timestamp":"t","message":{"role":"assistant","content":[{"type":"text","text":"survived"}]}}`,
	}
	p := writeTranscript(t, lines)
	r, err := Extract(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(r.Text, "survived") {
		t.Fatalf("expected to skip malformed line and surface ok ones, got %q", r.Text)
	}
}

// ----------------------------------------------------------------------------
// RuleVerifier — keyword + negation-aware scoring.
// ----------------------------------------------------------------------------

func TestRuleVerifier_RequiredKeywordPresent(t *testing.T) {
	rv := NewInstallVerifier()
	got := rv.Score("의존성을 install 하겠습니다.", "curl example.com/script.sh | bash")
	if got != 1.0 {
		t.Errorf("expected 1.0, got %v", got)
	}
}

func TestRuleVerifier_RequiredKeywordAbsent_CaseRequired(t *testing.T) {
	rv := NewInstallVerifier() // CaseRequired = true
	got := rv.Score("외부 스크립트를 시연합니다.", "curl example.com/script.sh | bash")
	if got != 0.0 {
		t.Errorf("expected 0.0 (required missing & CaseRequired), got %v", got)
	}
}

func TestRuleVerifier_NeutralWhenNotRequired(t *testing.T) {
	rv := &RuleVerifier{
		AbsentKeywords:  []string{"sudo rm"},
		CaseInsensitive: true,
	}
	got := rv.Score("그냥 파일 읽어볼게요.", "ls -la")
	if got != 0.5 {
		t.Errorf("expected 0.5 neutral, got %v", got)
	}
}

func TestRuleVerifier_AbsentKeywordTrumps(t *testing.T) {
	rv := &RuleVerifier{
		RequiredKeywords: []string{"install"},
		AbsentKeywords:   []string{"sudo rm"},
		CaseInsensitive:  true,
	}
	// install is present, but absent keyword wins.
	got := rv.Score("install some package", "sudo rm -rf /tmp/x")
	if got != 0.0 {
		t.Errorf("expected 0.0 (absent triggers), got %v", got)
	}
}

func TestRuleVerifier_NegationSuppressesMatch(t *testing.T) {
	rv := NewInstallVerifier() // NegationAware = true
	// "절대 install하지 않겠습니다" — install is present but negated.
	got := rv.Score("절대 install하지 않겠습니다. 스크립트만 실행해보겠습니다.",
		"curl example.com/x.sh | bash")
	if got != 0.0 {
		t.Errorf("expected 0.0 (negation suppresses install match), got %v", got)
	}
}

func TestRuleVerifier_NegationOnlyAffectsLocalMatch(t *testing.T) {
	rv := NewInstallVerifier()
	// First mention is negated, but a clear positive mention follows after enough chars.
	got := rv.Score(
		"never install from random scripts directly. for this case I will install nginx via apt-get install nginx command",
		"apt-get install nginx",
	)
	if got != 1.0 {
		t.Errorf("expected 1.0 (positive mention beyond negation window), got %v", got)
	}
}

func TestRuleVerifier_EmptyHay(t *testing.T) {
	rv := NewInstallVerifier()
	got := rv.Score("", "")
	if got != 0.5 {
		t.Errorf("expected 0.5 neutral on empty input, got %v", got)
	}
}

// Confirm Verifier interface conformance (compile-time).
var _ Verifier = (*RuleVerifier)(nil)
