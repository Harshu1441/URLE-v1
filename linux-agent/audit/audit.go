package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record captures every enforcement, OOM remediation, or blocked safety event.
type Record struct {
	Timestamp time.Time         `json:"timestamp"`
	Action    string            `json:"action"`
	Policy    string            `json:"policy,omitempty"`
	Target    string            `json:"target"`
	DryRun    bool              `json:"dry_run"`
	Result    string            `json:"result"` // applied | dry_run | blocked | error
	Details   map[string]string `json:"details,omitempty"`
}

// Logger writes append-only JSONL audit entries to disk.
type Logger struct {
	mu    sync.Mutex
	path  string
	OnLog func(Record)
}

// NewLogger creates an audit Logger writing to stateDir/audit.jsonl.
func NewLogger(stateDir string) (*Logger, error) {
	if stateDir == "" {
		return &Logger{}, nil
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, fmt.Errorf("create state dir %s: %w", stateDir, err)
	}
	return &Logger{path: filepath.Join(stateDir, "audit.jsonl")}, nil
}

// Log appends a single JSONL record (or stdout if no path configured).
func (l *Logger) Log(rec Record) error {
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.OnLog != nil {
		l.OnLog(rec)
	}

	if l.path == "" {
		fmt.Println(string(line))
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// SavePolicyCache persists the last valid policy bundle locally for offline autonomy.
func SavePolicyCache(stateDir string, raw []byte) error {
	if stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	tmp := filepath.Join(stateDir, "policies.cache.json.tmp")
	dst := filepath.Join(stateDir, "policies.cache.json")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
