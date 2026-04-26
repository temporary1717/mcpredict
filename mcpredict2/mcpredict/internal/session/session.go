// Package session persists per-session counters and tool_call history (§4.5).
//
// MVP NOTE: SQLite integration deferred to future work (sequence anomaly detection §3 #2).
// The 9h MVP relies on audit.jsonl as the source of truth; this package keeps an
// in-process counter so other modules don't have to special-case "no DB".
//
// SQLite re-enable path:
//   - import _ "modernc.org/sqlite" (Go 1.20+ recommended for current versions)
//   - replace counters with sql.Open("sqlite", path)
//   - schema lives in this file (kept as a const for forward-compat)
package session

import "sync"

// Schema is the SQLite schema we will use once SQLite is re-enabled.
// Kept here so the contract is visible to readers.
const Schema = `
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,
  cwd TEXT,
  tool_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tool_calls (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  ts INTEGER NOT NULL,
  hook_event TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  verdict TEXT,
  reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_session ON tool_calls(session_id, ts);
`

// Recorder is currently a thin in-memory counter. Same interface as the planned
// SQLite-backed implementation so cmd/mcpredict doesn't need to change.
type Recorder struct {
	mu       sync.Mutex
	sessions map[string]int
}

func Open(_ string) (*Recorder, error) {
	return &Recorder{sessions: make(map[string]int)}, nil
}

func (r *Recorder) Close() error { return nil }

func (r *Recorder) Touch(sessionID, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[sessionID]++
	return nil
}

func (r *Recorder) Record(_ string, _ string, _ string, _ string, _ string) error {
	// No-op in MVP. audit.jsonl carries the durable record.
	return nil
}
