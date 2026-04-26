// Package hookio handles Claude Code hook stdin/stdout JSON.
//
// Spec: https://code.claude.com/docs/en/hooks.md (verified 2026-04-26 via claude-code-guide).
// Schema frozen via ARCHITECTURE.md v1.1 §4.1 (Round 1 합의 + V2/V3 검증).
package hookio

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// HookInput is the stdin JSON contract for Pre/PostToolUse hooks.
// transcript_path is always present per public docs.
// permission_mode discovered via V2 (claude-code-guide spec recheck).
type HookInput struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response,omitempty"`
	CWD            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode,omitempty"`
}

// HookOutput is the stdout JSON contract — A6 합의 (exit code 0 + stdout JSON).
// Pre/Post fields are union-style: only the relevant subset populated per event.
type HookOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
	// PostToolUse-specific top-level fields (per public docs).
	Decision string `json:"decision,omitempty"` // "block" for Post
	Reason   string `json:"reason,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName string `json:"hookEventName"`
	// PreToolUse-only.
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	// PostToolUse-only — text injected into LLM context.
	AdditionalContext string `json:"additionalContext,omitempty"`
}

const (
	DecisionAllow = "allow"
	DecisionAsk   = "ask"
	DecisionDeny  = "deny"

	EventPre  = "PreToolUse"
	EventPost = "PostToolUse"
)

// Read parses stdin into a HookInput. 1 MiB cap to bound regex DoS surface (§9).
func Read(r io.Reader) (*HookInput, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("hookio: read stdin: %w", err)
	}
	var in HookInput
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("hookio: parse: %w", err)
	}
	if in.HookEventName == "" {
		return nil, fmt.Errorf("hookio: hook_event_name missing")
	}
	return &in, nil
}

// Write emits a PreToolUse HookOutput to stdout (permissionDecision form).
func Write(w io.Writer, event, decision, reason string, systemMsg string) error {
	out := HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            event,
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
		SystemMessage: systemMsg,
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// WritePost emits a PostToolUse HookOutput. blocked == true uses top-level
// decision="block" + reason; injects additionalContext into LLM context regardless.
func WritePost(w io.Writer, blocked bool, reason, additionalContext, systemMsg string) error {
	out := HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:     EventPost,
			AdditionalContext: additionalContext,
		},
		SystemMessage: systemMsg,
	}
	if blocked {
		out.Decision = "block"
		out.Reason = reason
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// Allow is a convenience for the success path.
func Allow(event string) error { return Write(os.Stdout, event, DecisionAllow, "", "") }
