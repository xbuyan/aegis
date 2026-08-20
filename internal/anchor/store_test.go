package anchor

import (
	"bytes"
	"testing"
)

func TestAnchorStore_SaveAndLoad_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	raw := append([]byte{0x00}, pendingAttestationBytes("foo")...)

	pa := NewPendingAnchor(digest, "https://a.pool.opentimestamps.org", raw)
	if err := store.Save(pa); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load(pa.Digest)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Digest != pa.Digest {
		t.Errorf("Digest = %s, want %s", loaded.Digest, pa.Digest)
	}
	if loaded.CalendarURL != pa.CalendarURL {
		t.Errorf("CalendarURL = %s, want %s", loaded.CalendarURL, pa.CalendarURL)
	}
	if !bytes.Equal(loaded.RawProof, raw) {
		t.Errorf("RawProof = %x, want %x", loaded.RawProof, raw)
	}
	if !loaded.SubmittedAt.Equal(pa.SubmittedAt) {
		t.Errorf("SubmittedAt = %v, want %v", loaded.SubmittedAt, pa.SubmittedAt)
	}

	// The whole point: the loaded raw proof must still parse correctly.
	ts, err := DeserializeTimestamp(loaded.RawProof, digest)
	if err != nil {
		t.Fatalf("re-parsing loaded RawProof: %v", err)
	}
	if len(ts.Attestations) != 1 {
		t.Errorf("re-parsed attestation count = %d, want 1", len(ts.Attestations))
	}
}

func TestAnchorStore_Load_NonexistentErrors(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_, err = store.Load("does-not-exist")
	if err == nil {
		t.Fatal("Load of a nonexistent PendingAnchor: want error, got nil")
	}
}

func TestAnchorStore_ListDigests(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	raw := append([]byte{0x00}, pendingAttestationBytes("foo")...)
	digestA := make([]byte, 32)
	digestA[0] = 0xAA
	digestB := make([]byte, 32)
	digestB[0] = 0xBB

	if err := store.Save(NewPendingAnchor(digestA, "https://a.example", raw)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(NewPendingAnchor(digestB, "https://b.example", raw)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	digests, err := store.ListDigests()
	if err != nil {
		t.Fatalf("ListDigests: %v", err)
	}
	if len(digests) != 2 {
		t.Fatalf("got %d digests, want 2", len(digests))
	}
}

func TestAnchorStore_ListDigests_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	digests, err := store.ListDigests()
	if err != nil {
		t.Fatalf("ListDigests: %v", err)
	}
	if len(digests) != 0 {
		t.Errorf("got %d digests, want 0", len(digests))
	}
}

func TestAnchorStore_Save_RejectsEmptyDigest(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	err = store.Save(&PendingAnchor{CalendarURL: "https://example.com"})
	if err == nil {
		t.Fatal("Save with empty Digest: want error, got nil")
	}
}
