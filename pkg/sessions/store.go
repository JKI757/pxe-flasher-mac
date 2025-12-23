package sessions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mu    sync.Mutex
	runID string
	file  *os.File
}

func NewStore(runID, dir string) (*Store, error) {
	if runID == "" {
		return nil, fmt.Errorf("runID required")
	}
	path := filepath.Join(dir, "sessions.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open sessions log: %w", err)
	}
	return &Store{runID: runID, file: file}, nil
}

func (s *Store) Append(event SessionEvent) error {
	if s == nil {
		return fmt.Errorf("store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return fmt.Errorf("store is closed")
	}
	if event.RunID == "" {
		event.RunID = s.runID
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := s.file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
