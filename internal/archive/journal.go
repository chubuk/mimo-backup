package archive

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Journal records every entry written during a restore so a failed restore can
// be diagnosed (and cleaned up) precisely.
type Journal struct {
	f *os.File
	w *bufio.Writer
}

// JournalEntry is one restored path record.
type JournalEntry struct {
	Path string    `json:"path"`
	At   time.Time `json:"at"`
}

// OpenJournal creates (appends to) a restore journal at path.
func OpenJournal(path string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	return &Journal{f: f, w: bufio.NewWriter(f)}, nil
}

// Record appends one entry and fsyncs it.
func (j *Journal) Record(path string) error {
	rec := JournalEntry{Path: path, At: time.Now().UTC()}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := j.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("journal write: %w", err)
	}
	if err := j.w.Flush(); err != nil {
		return fmt.Errorf("journal flush: %w", err)
	}
	return j.f.Sync()
}

// Close flushes and closes the journal.
func (j *Journal) Close() error {
	if err := j.w.Flush(); err != nil {
		return err
	}
	return j.f.Close()
}
