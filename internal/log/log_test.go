package log

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestLog(t *testing.T) (*Log, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l, path
}

func TestOpen_CreatesFileIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.jsonl")

	if _, err := os.Stat(path); err == nil {
		t.Fatal("file should not exist before Open")
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist after Open: %v", err)
	}

	if err := l.Verify(); err != nil {
		t.Errorf("Verify on empty log should succeed, got: %v", err)
	}
}

func TestAppend_RejectsEmptyHash(t *testing.T) {
	l, _ := newTestLog(t)
	_, err := l.Append("")
	if !errors.Is(err, ErrEmptyEvidenceHash) {
		t.Errorf("Append(\"\") error = %v, want ErrEmptyEvidenceHash", err)
	}
}

func TestAppend_FirstEntryHasEmptyPrevChainHash(t *testing.T) {
	l, _ := newTestLog(t)
	e, err := l.Append("hash-a")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.Index != 0 {
		t.Errorf("first entry Index = %d, want 0", e.Index)
	}
	if e.PrevChainHash != "" {
		t.Errorf("first entry PrevChainHash = %q, want empty", e.PrevChainHash)
	}
	if e.ChainHash == "" {
		t.Error("ChainHash should not be empty")
	}
}

func TestAppend_ChainsSequentialEntries(t *testing.T) {
	l, _ := newTestLog(t)

	e0, err := l.Append("hash-a")
	if err != nil {
		t.Fatalf("Append 0: %v", err)
	}
	e1, err := l.Append("hash-b")
	if err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	e2, err := l.Append("hash-c")
	if err != nil {
		t.Fatalf("Append 2: %v", err)
	}

	if e1.Index != 1 || e2.Index != 2 {
		t.Errorf("indices = %d, %d, want 1, 2", e1.Index, e2.Index)
	}
	if e1.PrevChainHash != e0.ChainHash {
		t.Error("entry 1's PrevChainHash should equal entry 0's ChainHash")
	}
	if e2.PrevChainHash != e1.ChainHash {
		t.Error("entry 2's PrevChainHash should equal entry 1's ChainHash")
	}

	if err := l.Verify(); err != nil {
		t.Errorf("Verify on untampered chain should succeed, got: %v", err)
	}
}

func TestVerify_ReadsFromDiskNotMemory(t *testing.T) {
	// Two independent Log handles over the same file: appends via one
	// must be visible to Verify on the other, proving Verify doesn't
	// rely on any in-memory state a Log might have cached.
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")

	writer, err := Open(path)
	if err != nil {
		t.Fatalf("Open writer: %v", err)
	}
	if _, err := writer.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := writer.Append("hash-b"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	reader, err := Open(path)
	if err != nil {
		t.Fatalf("Open reader: %v", err)
	}
	if err := reader.Verify(); err != nil {
		t.Errorf("Verify via independent handle should succeed, got: %v", err)
	}
}

func TestVerify_DetectsFieldTampering(t *testing.T) {
	l, path := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-b"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Tamper with the on-disk file directly: change entry 0's evidence
	// hash without recomputing its chain hash — exactly what an attacker
	// editing the file by hand would do.
	tamperEvidenceHashOnLine(t, path, 1, "hash-a", "hash-a-TAMPERED")

	err := l.Verify()
	if err == nil {
		t.Fatal("Verify should fail after field tampering, got nil")
	}
	if !errors.Is(err, ErrEntryTampered) {
		t.Errorf("Verify error = %v, want ErrEntryTampered", err)
	}
}

func TestVerify_DetectsDeletedEntry(t *testing.T) {
	l, path := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-b"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-c"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	deleteLine(t, path, 2) // remove the middle entry entirely

	err := l.Verify()
	if err == nil {
		t.Fatal("Verify should fail after deleting an entry, got nil")
	}
	// Deleting the middle entry breaks the index sequence (entry 2 now
	// appears where entry 1 was expected).
	if !errors.Is(err, ErrIndexOutOfSequence) {
		t.Errorf("Verify error = %v, want ErrIndexOutOfSequence", err)
	}
}

func TestVerify_DetectsReorderedEntries(t *testing.T) {
	l, path := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-b"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	swapLines(t, path, 1, 2)

	err := l.Verify()
	if err == nil {
		t.Fatal("Verify should fail after reordering entries, got nil")
	}
	// Index 0 now holds what was entry 1 -> index mismatch is the first
	// thing caught.
	if !errors.Is(err, ErrIndexOutOfSequence) {
		t.Errorf("Verify error = %v, want ErrIndexOutOfSequence", err)
	}
}

func TestVerify_DetectsCorruptLine(t *testing.T) {
	l, path := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corrupt append: %v", err)
	}
	if _, err := f.WriteString("{not valid json\n"); err != nil {
		t.Fatalf("write corrupt line: %v", err)
	}
	f.Close()

	err = l.Verify()
	if err == nil {
		t.Fatal("Verify should fail on corrupt JSON line, got nil")
	}
	if !errors.Is(err, ErrCorruptEntry) {
		t.Errorf("Verify error = %v, want ErrCorruptEntry", err)
	}
}

func TestVerify_EmptyLogSucceeds(t *testing.T) {
	l, _ := newTestLog(t)
	if err := l.Verify(); err != nil {
		t.Errorf("Verify on empty log should succeed, got: %v", err)
	}
}

// --- file-tampering test helpers -------------------------------------------

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	s := string(b)
	if len(s) == 0 {
		return nil
	}
	if s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

// tamperEvidenceHashOnLine replaces oldVal with newVal on the given
// 1-indexed line, simulating direct on-disk tampering.
func tamperEvidenceHashOnLine(t *testing.T, path string, lineNum int, oldVal, newVal string) {
	t.Helper()
	lines := readLines(t, path)
	idx := lineNum - 1
	if idx < 0 || idx >= len(lines) {
		t.Fatalf("tamperEvidenceHashOnLine: line %d out of range (have %d lines)", lineNum, len(lines))
	}
	replaced := replaceFirst(lines[idx], oldVal, newVal)
	lines[idx] = replaced
	writeLines(t, path, lines)
}

func replaceFirst(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func deleteLine(t *testing.T, path string, lineNum int) {
	t.Helper()
	lines := readLines(t, path)
	idx := lineNum - 1
	if idx < 0 || idx >= len(lines) {
		t.Fatalf("deleteLine: line %d out of range (have %d lines)", lineNum, len(lines))
	}
	lines = append(lines[:idx], lines[idx+1:]...)
	writeLines(t, path, lines)
}

func swapLines(t *testing.T, path string, a, b int) {
	t.Helper()
	lines := readLines(t, path)
	ai, bi := a-1, b-1
	if ai < 0 || ai >= len(lines) || bi < 0 || bi >= len(lines) {
		t.Fatalf("swapLines: line out of range (have %d lines)", len(lines))
	}
	lines[ai], lines[bi] = lines[bi], lines[ai]
	writeLines(t, path, lines)
}
