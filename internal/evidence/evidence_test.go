package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	return path
}

func TestNewEvidence_KnownContentHash(t *testing.T) {
	dir := t.TempDir()
	content := []byte("this is a test evidence file")
	path := writeTempFile(t, dir, "doc.txt", content)

	ev, err := NewEvidence(path)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	if ev.ContentHash != want {
		t.Errorf("ContentHash = %s, want %s", ev.ContentHash, want)
	}
	if ev.Filename != "doc.txt" {
		t.Errorf("Filename = %s, want doc.txt", ev.Filename)
	}
	if ev.SizeBytes != int64(len(content)) {
		t.Errorf("SizeBytes = %d, want %d", ev.SizeBytes, len(content))
	}
	if ev.CapturedAt.IsZero() {
		t.Error("CapturedAt is zero, want a real timestamp")
	}
	if ev.CapturedAt.Location().String() != "UTC" {
		t.Errorf("CapturedAt location = %s, want UTC", ev.CapturedAt.Location())
	}
}

func TestNewEvidence_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "empty.txt", []byte{})

	ev, err := NewEvidence(path)
	if err != nil {
		t.Fatalf("NewEvidence on empty file should not error: %v", err)
	}

	sum := sha256.Sum256([]byte{})
	want := hex.EncodeToString(sum[:])
	if ev.ContentHash != want {
		t.Errorf("empty file ContentHash = %s, want %s (SHA-256 of empty input)", ev.ContentHash, want)
	}
	if ev.SizeBytes != 0 {
		t.Errorf("SizeBytes = %d, want 0", ev.SizeBytes)
	}
}

func TestNewEvidence_NonexistentFile(t *testing.T) {
	_, err := NewEvidence("/nonexistent/path/does-not-exist.txt")
	if err == nil {
		t.Fatal("NewEvidence on nonexistent file: want error, got nil")
	}
}

func TestNewEvidence_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := NewEvidence(dir)
	if err == nil {
		t.Fatal("NewEvidence on a directory: want error, got nil")
	}
}

func TestNewEvidence_LargerFileStreamsCorrectly(t *testing.T) {
	// Not a true "large file, constant memory" test — that requires
	// profiling, not a unit test — but it does confirm streaming via
	// io.Copy produces the correct hash for content that spans many
	// hasher writes, not just a single small buffer.
	dir := t.TempDir()
	content := make([]byte, 5*1024*1024) // 5MB
	for i := range content {
		content[i] = byte(i % 251) // non-repeating-enough pattern
	}
	path := writeTempFile(t, dir, "large.bin", content)

	ev, err := NewEvidence(path)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if ev.ContentHash != want {
		t.Errorf("ContentHash = %s, want %s", ev.ContentHash, want)
	}
	if ev.SizeBytes != int64(len(content)) {
		t.Errorf("SizeBytes = %d, want %d", ev.SizeBytes, len(content))
	}
}

func TestHash_DeterministicForIdenticalRecords(t *testing.T) {
	e1 := &Evidence{
		ContentHash: "abc123",
		Filename:    "doc.txt",
		SizeBytes:   42,
		CapturedAt:  mustParseTime(t, "2026-08-20T10:00:00Z"),
	}
	e2 := &Evidence{
		ContentHash: "abc123",
		Filename:    "doc.txt",
		SizeBytes:   42,
		CapturedAt:  mustParseTime(t, "2026-08-20T10:00:00Z"),
	}

	h1, err := e1.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	h2, err := e2.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if h1 != h2 {
		t.Errorf("Hash() not deterministic: %s != %s for identical records", h1, h2)
	}
}

func TestHash_DiffersWhenAnyFieldChanges(t *testing.T) {
	base := &Evidence{
		ContentHash: "abc123",
		Filename:    "doc.txt",
		SizeBytes:   42,
		CapturedAt:  mustParseTime(t, "2026-08-20T10:00:00Z"),
	}
	baseHash, err := base.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	variants := []*Evidence{
		{ContentHash: "different", Filename: base.Filename, SizeBytes: base.SizeBytes, CapturedAt: base.CapturedAt},
		{ContentHash: base.ContentHash, Filename: "other.txt", SizeBytes: base.SizeBytes, CapturedAt: base.CapturedAt},
		{ContentHash: base.ContentHash, Filename: base.Filename, SizeBytes: 999, CapturedAt: base.CapturedAt},
		{ContentHash: base.ContentHash, Filename: base.Filename, SizeBytes: base.SizeBytes, CapturedAt: mustParseTime(t, "2026-08-20T11:00:00Z")},
	}

	for i, v := range variants {
		h, err := v.Hash()
		if err != nil {
			t.Fatalf("variant %d Hash: %v", i, err)
		}
		if h == baseHash {
			t.Errorf("variant %d: Hash() unchanged after modifying a field, want a different hash", i)
		}
	}
}

func TestEvidence_JSONRoundTripIsByteIdentical(t *testing.T) {
	// This is the determinism guarantee Hash() depends on: marshal,
	// unmarshal, marshal again — the bytes must match exactly, or the
	// hash chain built on top of Hash() would be unverifiable after any
	// serialize/deserialize cycle (e.g. writing the log to disk and
	// reading it back).
	original := &Evidence{
		ContentHash: "abc123",
		Filename:    "doc.txt",
		SizeBytes:   42,
		CapturedAt:  mustParseTime(t, "2026-08-20T10:00:00Z"),
	}

	b1, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}

	var roundTripped Evidence
	if err := json.Unmarshal(b1, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	b2, err := json.Marshal(&roundTripped)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}

	if string(b1) != string(b2) {
		t.Errorf("JSON round trip not byte-identical:\n  first:  %s\n  second: %s", b1, b2)
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	pt, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("mustParseTime(%q): %v", s, err)
	}
	return pt
}
