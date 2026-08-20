package log

import "testing"

func TestEntries_ReturnsAllInOrder(t *testing.T) {
	l, _ := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-b"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-c"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	want := []string{"hash-a", "hash-b", "hash-c"}
	for i, e := range entries {
		if e.EvidenceHash != want[i] {
			t.Errorf("entries[%d].EvidenceHash = %s, want %s", i, e.EvidenceHash, want[i])
		}
		if e.Index != uint64(i) {
			t.Errorf("entries[%d].Index = %d, want %d", i, e.Index, i)
		}
	}
}

func TestEntries_EmptyLogReturnsEmpty(t *testing.T) {
	l, _ := newTestLog(t)
	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

func TestFindByEvidenceHash_FindsMatch(t *testing.T) {
	l, _ := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := l.Append("hash-b"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	found, err := l.FindByEvidenceHash("hash-b")
	if err != nil {
		t.Fatalf("FindByEvidenceHash: %v", err)
	}
	if found == nil {
		t.Fatal("FindByEvidenceHash: want a match, got nil")
	}
	if found.Index != 1 {
		t.Errorf("found.Index = %d, want 1", found.Index)
	}
}

func TestFindByEvidenceHash_NoMatchReturnsNilNoError(t *testing.T) {
	l, _ := newTestLog(t)
	if _, err := l.Append("hash-a"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	found, err := l.FindByEvidenceHash("does-not-exist")
	if err != nil {
		t.Fatalf("FindByEvidenceHash: unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("found = %+v, want nil", found)
	}
}
