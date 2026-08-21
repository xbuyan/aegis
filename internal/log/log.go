// Package log implements an append-only, hash-chained log of evidence
// hashes. Each entry commits to its own fields and to the previous
// entry's chain hash, so any tampering with a persisted entry — altering
// a field, deleting an entry, or reordering entries — breaks the chain
// from that point forward and is detectable by Verify.
//
// Verify never trusts an in-memory view of the log: it always re-reads
// the log file from disk and recomputes the chain from those bytes, so
// it verifies what is actually persisted, not what a Log value happens
// to remember.
package log

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

var (
	// ErrEmptyEvidenceHash is returned by Append when given an empty hash string.
	ErrEmptyEvidenceHash = errors.New("log: evidence hash must not be empty")

	// ErrCorruptEntry is returned when a line in the log file cannot be
	// parsed as a valid Entry.
	ErrCorruptEntry = errors.New("log: corrupt entry")

	// ErrChainBroken is returned by Verify when an entry's PrevChainHash
	// does not match the previous entry's ChainHash.
	ErrChainBroken = errors.New("log: chain broken")

	// ErrEntryTampered is returned by Verify when an entry's own fields
	// no longer produce the ChainHash stored for that entry.
	ErrEntryTampered = errors.New("log: entry tampered")

	// ErrIndexOutOfSequence is returned by Verify when entry indices are
	// not exactly 0, 1, 2, ... in order (catches deleted or inserted entries).
	ErrIndexOutOfSequence = errors.New("log: index out of sequence")
)

// Entry is one record in the hash-chained log. ChainHash commits to every
// other field in the entry, so changing any one of them — including
// Index or LoggedAt — invalidates ChainHash.
type Entry struct {
	Index         uint64    `json:"index"`
	EvidenceHash  string    `json:"evidence_hash"`   // from evidence.Evidence.Hash()
	PrevChainHash string    `json:"prev_chain_hash"` // empty string only for Index 0
	LoggedAt      time.Time `json:"logged_at"`       // UTC, truncated to the second
	ChainHash     string    `json:"chain_hash"`
}

// computeChainHash returns the deterministic SHA-256 (hex-encoded) that
// commits to e's fields other than ChainHash itself.
func computeChainHash(e Entry) (string, error) {
	e.ChainHash = "" // never include the field being computed in its own input
	b, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("log: marshal entry for chain hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log is an append-only, hash-chained log backed by a JSON-Lines file on
// disk (one Entry per line). Log holds only the file path — it never
// caches entries in memory, so every Append and Verify call reflects the
// file's actual current contents.
type Log struct {
	path string
}

// Open opens the log at path, creating an empty file if it does not
// already exist. It does not read or validate any existing content —
// call Verify explicitly if you need to confirm an existing log's
// integrity before appending to it.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("log: open %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("log: close %q after create: %w", path, err)
	}
	return &Log{path: path}, nil
}

// readLastEntry scans the log file from disk and returns the last valid
// entry, or (nil, nil) if the file has no entries yet.
func readLastEntry(path string) (*Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("log: open %q: %w", path, err)
	}
	defer f.Close()
	return readLastEntryFromFile(f)
}

// readLastEntryFromFile is the same scan as readLastEntry, but against an
// already-open file handle — used by Append, which needs to read and
// then write through the same locked handle rather than opening the file
// twice.
func readLastEntryFromFile(f *os.File) (*Entry, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("log: seek to start: %w", err)
	}

	var last *Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrCorruptEntry, lineNum, err)
		}
		entryCopy := e
		last = &entryCopy
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("log: scan: %w", err)
	}

	// Append will Write() next, which appends regardless of the current
	// seek position on a file opened with O_APPEND — but seeking back to
	// the end explicitly here avoids relying on that O_APPEND behavior
	// being the only thing keeping the write position correct.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("log: seek to end: %w", err)
	}

	return last, nil
}

// Append computes the next entry from evidenceHash and the log's current
// last entry (read fresh from disk, not cached), writes it to the log
// file, and returns it.
//
// Append holds an exclusive advisory lock on the log file for the
// duration of the read-then-write (see lockFile's doc comment), so two
// concurrent Append calls — from two Aegis processes, or two goroutines —
// cannot race on computing the next Index/PrevChainHash.
func (l *Log) Append(evidenceHash string) (*Entry, error) {
	if evidenceHash == "" {
		return nil, ErrEmptyEvidenceHash
	}

	// Open once and hold it for both the read and the write, with the
	// lock held across both — this is what actually closes the race, not
	// just locking around the write.
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("log: open %q for append: %w", l.path, err)
	}
	defer f.Close()

	if err := lockFile(f); err != nil {
		return nil, err
	}
	defer unlockFile(f)

	last, err := readLastEntryFromFile(f)
	if err != nil {
		return nil, err
	}

	var index uint64
	var prevChainHash string
	if last != nil {
		index = last.Index + 1
		prevChainHash = last.ChainHash
	}

	entry := Entry{
		Index:         index,
		EvidenceHash:  evidenceHash,
		PrevChainHash: prevChainHash,
		LoggedAt:      time.Now().UTC().Truncate(time.Second),
	}
	chainHash, err := computeChainHash(entry)
	if err != nil {
		return nil, err
	}
	entry.ChainHash = chainHash

	line, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("log: marshal entry: %w", err)
	}

	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("log: write entry: %w", err)
	}

	return &entry, nil
}

// Entries reads and returns every entry in the log, in order, straight
// from disk. Unlike Verify, it does not check chain integrity — callers
// that need both should call Verify first.
func (l *Log) Entries() ([]Entry, error) {
	f, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("log: open %q: %w", l.path, err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrCorruptEntry, lineNum, err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("log: scan %q: %w", l.path, err)
	}
	return entries, nil
}

// FindByEvidenceHash returns the first entry whose EvidenceHash matches,
// or nil if none does.
func (l *Log) FindByEvidenceHash(evidenceHash string) (*Entry, error) {
	entries, err := l.Entries()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.EvidenceHash == evidenceHash {
			found := e
			return &found, nil
		}
	}
	return nil, nil
}

// Verify re-reads the entire log file from disk and recomputes the chain
// from scratch. It returns nil if every entry's ChainHash matches its own
// fields and every entry's PrevChainHash matches the preceding entry's
// ChainHash. An empty or nonexistent-but-created log verifies
// successfully (there is nothing to contradict).
//
// On failure, the returned error identifies the first entry index at
// which verification failed and why (io.EOF-style sentinel wrapping via
// errors.Is works with ErrChainBroken, ErrEntryTampered,
// ErrIndexOutOfSequence, and ErrCorruptEntry).
func (l *Log) Verify() error {
	f, err := os.Open(l.path)
	if err != nil {
		return fmt.Errorf("log: open %q: %w", l.path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var prevChainHash string
	var expectedIndex uint64
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("%w: line %d: %v", ErrCorruptEntry, lineNum, err)
		}

		if e.Index != expectedIndex {
			return fmt.Errorf("%w: entry at line %d has index %d, want %d",
				ErrIndexOutOfSequence, lineNum, e.Index, expectedIndex)
		}

		if e.PrevChainHash != prevChainHash {
			return fmt.Errorf("%w: entry index %d: prev_chain_hash does not match preceding entry's chain_hash",
				ErrChainBroken, e.Index)
		}

		recomputed, err := computeChainHash(e)
		if err != nil {
			return err
		}
		if recomputed != e.ChainHash {
			return fmt.Errorf("%w: entry index %d: stored chain_hash does not match its own fields",
				ErrEntryTampered, e.Index)
		}

		prevChainHash = e.ChainHash
		expectedIndex++
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("log: scan %q: %w", l.path, err)
	}

	return nil
}
