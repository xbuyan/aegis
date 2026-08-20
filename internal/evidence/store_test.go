package evidence

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_SaveAndLoad_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	original := &Evidence{
		ContentHash: "abc123",
		Filename:    "doc.txt",
		SizeBytes:   42,
		CapturedAt:  time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}
	if err := store.Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load("abc123")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.ContentHash != original.ContentHash ||
		loaded.Filename != original.Filename ||
		loaded.SizeBytes != original.SizeBytes ||
		!loaded.CapturedAt.Equal(original.CapturedAt) {
		t.Errorf("loaded record = %+v, want %+v", loaded, original)
	}

	// The whole point of the store: Hash() on the loaded record must
	// match Hash() on the original, since it preserves CapturedAt exactly.
	origHash, err := original.Hash()
	if err != nil {
		t.Fatalf("original.Hash: %v", err)
	}
	loadedHash, err := loaded.Hash()
	if err != nil {
		t.Fatalf("loaded.Hash: %v", err)
	}
	if origHash != loadedHash {
		t.Errorf("Hash() mismatch after round trip: %s != %s", origHash, loadedHash)
	}
}

func TestStore_Load_NonexistentRecordErrors(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_, err = store.Load("does-not-exist")
	if err == nil {
		t.Fatal("Load of a nonexistent record: want error, got nil")
	}
}

func TestStore_Save_RejectsEmptyContentHash(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	err = store.Save(&Evidence{Filename: "doc.txt"})
	if err == nil {
		t.Fatal("Save with empty ContentHash: want error, got nil")
	}
}

func TestNewStore_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	if _, err := NewStore(dir); err != nil {
		t.Fatalf("NewStore should create nested dirs: %v", err)
	}
}
