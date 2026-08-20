// Package evidence defines the atomic unit Aegis operates on: a record
// binding a file's content hash to capture metadata. Evidence records are
// the input to the hash-chained log (internal/log) and, eventually, to
// Bitcoin-anchored timestamping (internal/anchor).
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Evidence is a deterministic record of a file's content and when Aegis
// captured it. Field order is fixed and JSON-tagged explicitly: Go's
// encoding/json marshals struct fields in declaration order (unlike map
// keys), so two Evidence values with identical field values always
// serialize to identical bytes. That determinism is required because
// Hash() is used as an input to the hash-chained log — a record that
// serialized differently on each call would silently break chain
// verification.
//
// CapturedAt is stored as UTC and truncated to whole seconds before being
// set, so that a value survives a JSON marshal/unmarshal round trip
// byte-for-byte (sub-second precision is dropped, not preserved-then-lost).
type Evidence struct {
	ContentHash string    `json:"content_hash"` // hex-encoded SHA-256 of the file's bytes
	Filename    string    `json:"filename"`     // base name of the file, informational only
	SizeBytes   int64     `json:"size_bytes"`
	CapturedAt  time.Time `json:"captured_at"` // UTC, truncated to the second; when Aegis hashed the file — NOT proof of origin
}

// NewEvidence reads the file at path, computes its SHA-256 content hash,
// and returns the resulting Evidence record.
//
// The file is streamed into the hasher via io.Copy rather than read fully
// into memory first, so memory use stays constant regardless of file size
// — this matters for the intended use case (video evidence can run into
// gigabytes).
func NewEvidence(path string) (*Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: open %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("evidence: stat %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("evidence: %q is a directory, not a file", path)
	}

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("evidence: hash %q: %w", path, err)
	}

	return &Evidence{
		ContentHash: hex.EncodeToString(h.Sum(nil)),
		Filename:    filepath.Base(path),
		SizeBytes:   size,
		CapturedAt:  time.Now().UTC().Truncate(time.Second),
	}, nil
}

// Hash returns the deterministic SHA-256 of the Evidence record itself
// (not the file it describes), hex-encoded. This is the value Component 2
// (the hash-chained log) uses as a log entry's content when chaining
// evidence records together.
func (e *Evidence) Hash() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("evidence: marshal for hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
