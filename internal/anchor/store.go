package anchor

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PendingAnchor is what Aegis persists after submitting a digest to a
// calendar: enough to re-parse the calendar's response later (RawProof)
// and to ask the same calendar for an upgrade (CalendarURL), without
// needing to keep the digest bytes anywhere except as the file's name.
type PendingAnchor struct {
	Digest      string    `json:"digest"` // hex-encoded, also the store's lookup key
	CalendarURL string    `json:"calendar_url"`
	RawProof    []byte    `json:"raw_proof"` // exact bytes the calendar returned; json.Marshal base64-encodes this automatically
	SubmittedAt time.Time `json:"submitted_at"`
}

// Store persists PendingAnchor records to disk, one JSON file per digest.
type Store struct {
	Dir string
}

// NewStore returns a Store rooted at dir, creating the directory if it
// doesn't exist.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("anchor: create store dir %q: %w", dir, err)
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) pathFor(digestHex string) string {
	return filepath.Join(s.Dir, digestHex+".json")
}

// Save writes pa to disk, named by its Digest.
func (s *Store) Save(pa *PendingAnchor) error {
	if pa.Digest == "" {
		return fmt.Errorf("anchor: cannot save a PendingAnchor with an empty Digest")
	}
	b, err := json.MarshalIndent(pa, "", "  ")
	if err != nil {
		return fmt.Errorf("anchor: marshal PendingAnchor: %w", err)
	}
	if err := os.WriteFile(s.pathFor(pa.Digest), b, 0o600); err != nil {
		return fmt.Errorf("anchor: write PendingAnchor file: %w", err)
	}
	return nil
}

// Load reads back the PendingAnchor for a given hex-encoded digest.
func (s *Store) Load(digestHex string) (*PendingAnchor, error) {
	b, err := os.ReadFile(s.pathFor(digestHex))
	if err != nil {
		return nil, fmt.Errorf("anchor: load PendingAnchor %q: %w", digestHex, err)
	}
	var pa PendingAnchor
	if err := json.Unmarshal(b, &pa); err != nil {
		return nil, fmt.Errorf("anchor: unmarshal PendingAnchor %q: %w", digestHex, err)
	}
	return &pa, nil
}

// ListDigests returns the hex digest of every PendingAnchor currently in
// the store, so a caller (e.g. `aegis upgrade`) can iterate all of them
// without needing to already know which digests exist.
func (s *Store) ListDigests() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("anchor: list store dir %q: %w", s.Dir, err)
	}
	var digests []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		const suffix = ".json"
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			digests = append(digests, name[:len(name)-len(suffix)])
		}
	}
	return digests, nil
}

// NewPendingAnchor builds a PendingAnchor from a fresh Submit result.
func NewPendingAnchor(digest []byte, calendarURL string, rawProof []byte) *PendingAnchor {
	return &PendingAnchor{
		Digest:      hex.EncodeToString(digest),
		CalendarURL: calendarURL,
		RawProof:    rawProof,
		SubmittedAt: time.Now().UTC(),
	}
}
