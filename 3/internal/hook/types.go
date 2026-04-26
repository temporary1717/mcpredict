package hook

import "encoding/json"

// Input is the JSON payload Claude Code sends to the hook on stdin.
type Input struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   *ToolResponse   `json:"tool_response,omitempty"`
	HookEventName  string          `json:"hook_event_name"`
}

// ToolResponse is the result of the tool execution (PostToolUse only).
type ToolResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Output is written to stdout when the hook wants to block.
type Output struct {
	Decision string `json:"decision"`        // "block"
	Reason   string `json:"reason,omitempty"`
}

const (
	DecisionAllow = "allow"
	DecisionBlock = "block"
	DecisionWarn  = "warn"
)
