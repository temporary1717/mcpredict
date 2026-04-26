package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Call records one tool invocation outcome.
type Call struct {
	Timestamp string         `json:"timestamp"`
	Tool      string         `json:"tool"`
	Input     map[string]any `json:"input,omitempty"`
	Verdict   string         `json:"verdict"`
}

// State is the accumulated context for a session, persisted as JSON.
type State struct {
	SessionID    string  `json:"session_id"`
	CreatedAt    string  `json:"created_at"`
	Calls        []Call  `json:"calls"`
	BlockCount   int     `json:"block_count"`
	AnomalyScore float64 `json:"anomaly_score"`
}

// Tracker persists one JSON file per session_id under dir.
type Tracker struct {
	mu  sync.Mutex
	dir string
}

func New(dir string) *Tracker {
	_ = os.MkdirAll(dir, 0700)
	return &Tracker{dir: dir}
}

func (t *Tracker) filePath(id string) string {
	return filepath.Join(t.dir, id+".json")
}

func (t *Tracker) load(id string) State {
	data, err := os.ReadFile(t.filePath(id))
	if err != nil {
		return State{SessionID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	var s State
	_ = json.Unmarshal(data, &s)
	return s
}

// Append records a call and writes updated state to disk.
func (t *Tracker) Append(sessionID string, c Call) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	s := t.load(sessionID)
	c.Timestamp = time.Now().UTC().Format(time.RFC3339)
	s.Calls = append(s.Calls, c)

	if c.Verdict == "block" {
		s.BlockCount++
		// Raise anomaly score on repeated blocks — sequence anomaly signal.
		s.AnomalyScore = float64(s.BlockCount) / float64(len(s.Calls))
	}

	// Keep last 100 calls per session.
	if len(s.Calls) > 100 {
		s.Calls = s.Calls[len(s.Calls)-100:]
	}

	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(t.filePath(sessionID), out, 0600)
}

// Load returns the current state for a session.
func (t *Tracker) Load(sessionID string) State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.load(sessionID)
}
