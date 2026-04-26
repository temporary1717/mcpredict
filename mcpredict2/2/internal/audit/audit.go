// Package audit writes append-only JSONL audit records.
//
// ARCHITECTURE.md v1.1 §4.4. Hash-only persistence (privacy + dedup). 0600 perms.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Record is the audit.jsonl line shape (§4.4).
type Record struct {
	TS            string   `json:"ts"`
	SessionID     string   `json:"session_id"`
	HookEvent     string   `json:"hook_event"`
	ToolName      string   `json:"tool_name"`
	Verdict       string   `json:"verdict"`
	Source        string   `json:"source,omitempty"`
	RuleIDs       []string `json:"rule_ids,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	IntentHash    string   `json:"intent_hash,omitempty"`
	ToolInputHash string   `json:"tool_input_hash,omitempty"`
	RawInputPath  string   `json:"raw_input_path,omitempty"` // debug mode only
	LatencyMS     int64    `json:"latency_ms,omitempty"`
}

// Logger is goroutine-safe (A10).
type Logger struct {
	path string
	mu   sync.Mutex
}

func NewLogger(path string) *Logger { return &Logger{path: path} }

// Append writes a single record + newline. Failure logs to stderr only (§10).
func (l *Logger) Append(rec Record) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		debugf("audit open: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		debugf("audit encode: %v", err)
	}
}

// Hash returns sha256:<hex> over the input text (intent / tool_input canonical JSON).
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalJSON returns a deterministic JSON encoding (sorted keys, no HTML escape) for
// hashing tool_input regardless of original key order or whitespace (A11).
func CanonicalJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	return canonicalEncode(v)
}

func canonicalEncode(v any) []byte {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, _ := json.Marshal(k)
			out = append(out, kb...)
			out = append(out, ':')
			out = append(out, canonicalEncode(t[k])...)
		}
		return append(out, '}')
	case []any:
		out := []byte{'['}
		for i, e := range t {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, canonicalEncode(e)...)
		}
		return append(out, ']')
	default:
		b, _ := json.Marshal(t)
		return b
	}
}

func debugf(format string, args ...any) {
	if os.Getenv("MCPREDICT_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[mcpredict audit] "+format+"\n", args...)
	}
}
