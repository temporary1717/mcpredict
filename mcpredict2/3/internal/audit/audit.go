package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry is a single line in the JSONL audit log.
type Entry struct {
	Timestamp    string         `json:"ts"`
	SessionID    string         `json:"session_id"`
	Event        string         `json:"event"`
	Tool         string         `json:"tool"`
	Verdict      string         `json:"verdict"`
	Reason       string         `json:"reason,omitempty"`
	RulesMatched []string       `json:"rules_matched,omitempty"`
	Input        map[string]any `json:"input,omitempty"`
}

// Logger appends entries to a JSONL file.
type Logger struct {
	mu   sync.Mutex
	path string
}

func New(path string) *Logger { return &Logger{path: path} }

func (l *Logger) Write(e Entry) error {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}
