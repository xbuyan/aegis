package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Store persists Evidence records to disk, one JSON file per record, named
// by the record's ContentHash. This exists because Evidence.Hash()
// commits to CapturedAt, which can't be recomputed later from the file
// alone — verifying a file against its original log entry requires the
// exact original Evidence record, not a freshly captured one.
type Store struct {
	Dir string
}

// NewStore returns a Store rooted at dir, creating the directory if it
// doesn't exist.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("evidence: create store dir %q: %w", dir, err)
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) pathFor(contentHash string) string {
	return filepath.Join(s.Dir, contentHash+".json")
}

// Save writes ev to disk, named by its ContentHash. Overwrites any
// existing record for the same content hash (re-capturing identical
// content is expected to be idempotent at the store level; the log is
// what records that it happened again, with a new CapturedAt).
func (s *Store) Save(ev *Evidence) error {
	if ev.ContentHash == "" {
		return fmt.Errorf("evidence: cannot save a record with an empty ContentHash")
	}
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: marshal for store: %w", err)
	}
	if err := os.WriteFile(s.pathFor(ev.ContentHash), b, 0o600); err != nil {
		return fmt.Errorf("evidence: write store file: %w", err)
	}
	return nil
}

// Load reads back the Evidence record for a given content hash.
func (s *Store) Load(contentHash string) (*Evidence, error) {
	b, err := os.ReadFile(s.pathFor(contentHash))
	if err != nil {
		return nil, fmt.Errorf("evidence: load %q: %w", contentHash, err)
	}
	var ev Evidence
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, fmt.Errorf("evidence: unmarshal stored record %q: %w", contentHash, err)
	}
	return &ev, nil
}
