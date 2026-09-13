package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xbuyan/aegis/internal/anchor"
	"github.com/xbuyan/aegis/internal/evidence"
)

// --- test-only OTS proof fixture builders ---
//
// Aegis's anchor package deliberately implements OTS deserialization
// only, not serialization (see internal/anchor's own docs) — there is no
// production encoder to reuse here. These helpers hand-construct raw
// proof bytes using the exact wire format documented in
// internal/anchor/ots.go and varint.go, purely so these tests can
// exercise DeserializeTimestamp with real, valid input rather than mocks
// of it.

func encodeVarUint(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return out
}

func encodeVarBytes(b []byte) []byte {
	return append(encodeVarUint(uint64(len(b))), b...)
}

var (
	attestationTagPending = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	attestationTagBitcoin = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
)

// buildPendingProof constructs a minimal valid OTS proof: root message
// directly carries one PendingAttestation, no ops.
func buildPendingProof(uri string) []byte {
	innerPayload := encodeVarBytes([]byte(uri))
	attestation := append(append([]byte{}, attestationTagPending...), encodeVarBytes(innerPayload)...)
	return append([]byte{0x00}, attestation...)
}

// buildBitcoinProof constructs a minimal valid OTS proof: root message
// directly carries one BitcoinBlockHeaderAttestation at the given height.
func buildBitcoinProof(height uint64) []byte {
	innerPayload := encodeVarUint(height)
	attestation := append(append([]byte{}, attestationTagBitcoin...), encodeVarBytes(innerPayload)...)
	return append([]byte{0x00}, attestation...)
}

// fakeBlockSource is a controllable BlockHeaderSource for tests, avoiding
// any real network access.
type fakeBlockSource struct {
	headers map[uint64]*anchor.BlockHeader
	err     error
}

func (f *fakeBlockSource) BlockHeader(ctx context.Context, height uint64) (*anchor.BlockHeader, error) {
	if f.err != nil {
		return nil, f.err
	}
	h, ok := f.headers[height]
	if !ok {
		return nil, errors.New("fakeBlockSource: no header for that height")
	}
	return h, nil
}

func setupStores(t *testing.T) (evidenceDir, anchorDir string) {
	t.Helper()
	base := t.TempDir()
	evidenceDir = filepath.Join(base, "evidence")
	anchorDir = filepath.Join(base, "anchors")
	return evidenceDir, anchorDir
}

func saveTestEvidence(t *testing.T, evidenceDir, contentHash string) {
	t.Helper()
	store, err := evidence.NewStore(evidenceDir)
	if err != nil {
		t.Fatalf("evidence.NewStore failed: %v", err)
	}
	ev := &evidence.Evidence{
		ContentHash: contentHash,
		Filename:    "test-file.txt",
		SizeBytes:   42,
		CapturedAt:  time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := store.Save(ev); err != nil {
		t.Fatalf("evidence Save failed: %v", err)
	}
}

func saveTestAnchor(t *testing.T, anchorDir, contentHash string, rawProof []byte) {
	t.Helper()
	store, err := anchor.NewStore(anchorDir)
	if err != nil {
		t.Fatalf("anchor.NewStore failed: %v", err)
	}
	digestBytes, _ := hex.DecodeString(contentHash)
	pa := anchor.NewPendingAnchor(digestBytes, "https://a.pool.opentimestamps.org", rawProof)
	if err := store.Save(pa); err != nil {
		t.Fatalf("anchor Save failed: %v", err)
	}
}

func testContentHash() string {
	sum := sha256.Sum256([]byte("test content for verify package"))
	return hex.EncodeToString(sum[:])
}

func TestCheck_ContentNotFound(t *testing.T) {
	evidenceDir, anchorDir := setupStores(t)

	status, err := Check(context.Background(), evidenceDir, anchorDir, testContentHash(), &fakeBlockSource{})
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}
	if status.ContentFound {
		t.Fatal("expected ContentFound=false for a hash with no evidence record")
	}
	if status.AnchorStatus != AnchorNotFound {
		t.Fatalf("expected AnchorNotFound, got %v", status.AnchorStatus)
	}
}

func TestCheck_ContentFoundNoAnchor(t *testing.T) {
	evidenceDir, anchorDir := setupStores(t)
	hash := testContentHash()
	saveTestEvidence(t, evidenceDir, hash)

	status, err := Check(context.Background(), evidenceDir, anchorDir, hash, &fakeBlockSource{})
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}
	if !status.ContentFound {
		t.Fatal("expected ContentFound=true")
	}
	if status.Filename != "test-file.txt" {
		t.Errorf("expected Filename to be populated, got %q", status.Filename)
	}
	if status.AnchorStatus != AnchorNotFound {
		t.Fatalf("expected AnchorNotFound (no anchor submitted), got %v", status.AnchorStatus)
	}
}

func TestCheck_AnchorPending(t *testing.T) {
	evidenceDir, anchorDir := setupStores(t)
	hash := testContentHash()
	saveTestEvidence(t, evidenceDir, hash)
	saveTestAnchor(t, anchorDir, hash, buildPendingProof("https://a.pool.opentimestamps.org"))

	status, err := Check(context.Background(), evidenceDir, anchorDir, hash, &fakeBlockSource{})
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}
	if status.AnchorStatus != AnchorPending {
		t.Fatalf("expected AnchorPending, got %v", status.AnchorStatus)
	}
}

func TestCheck_AnchorConfirmed(t *testing.T) {
	evidenceDir, anchorDir := setupStores(t)
	hash := testContentHash()
	digestBytes, _ := hex.DecodeString(hash)
	saveTestEvidence(t, evidenceDir, hash)
	saveTestAnchor(t, anchorDir, hash, buildBitcoinProof(800000))

	var merkleRoot [32]byte
	copy(merkleRoot[:], digestBytes)
	blockTime := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	src := &fakeBlockSource{headers: map[uint64]*anchor.BlockHeader{
		800000: {Height: 800000, MerkleRoot: merkleRoot, Time: blockTime},
	}}

	status, err := Check(context.Background(), evidenceDir, anchorDir, hash, src)
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}
	if status.AnchorStatus != AnchorConfirmed {
		t.Fatalf("expected AnchorConfirmed, got %v", status.AnchorStatus)
	}
	if !status.ConfirmedAt.Equal(blockTime) {
		t.Errorf("expected ConfirmedAt=%v, got %v", blockTime, status.ConfirmedAt)
	}
	if status.ConfirmedBlockHeight != 800000 {
		t.Errorf("expected ConfirmedBlockHeight=800000, got %d", status.ConfirmedBlockHeight)
	}
}

func TestCheck_AnchorInvalidOnMerkleRootMismatch(t *testing.T) {
	evidenceDir, anchorDir := setupStores(t)
	hash := testContentHash()
	saveTestEvidence(t, evidenceDir, hash)
	saveTestAnchor(t, anchorDir, hash, buildBitcoinProof(800000))

	// Deliberately WRONG merkle root — simulates a fraudulent or
	// corrupted proof.
	var wrongRoot [32]byte
	wrongRoot[0] = 0xFF
	src := &fakeBlockSource{headers: map[uint64]*anchor.BlockHeader{
		800000: {Height: 800000, MerkleRoot: wrongRoot, Time: time.Now()},
	}}

	status, err := Check(context.Background(), evidenceDir, anchorDir, hash, src)
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}
	if status.AnchorStatus != AnchorInvalid {
		t.Fatalf("expected AnchorInvalid for a merkle root mismatch, got %v", status.AnchorStatus)
	}
}

func TestCheck_NetworkErrorDoesNotMaskAsInvalid(t *testing.T) {
	// A transient network failure fetching block data must NOT be
	// reported as AnchorInvalid — that label is reserved specifically
	// for a provably fraudulent proof, not "couldn't check right now."
	evidenceDir, anchorDir := setupStores(t)
	hash := testContentHash()
	saveTestEvidence(t, evidenceDir, hash)
	saveTestAnchor(t, anchorDir, hash, buildBitcoinProof(800000))

	src := &fakeBlockSource{err: errors.New("simulated network failure")}

	status, err := Check(context.Background(), evidenceDir, anchorDir, hash, src)
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}
	if status.AnchorStatus == AnchorInvalid {
		t.Fatal("a network failure must not be reported as AnchorInvalid")
	}
	if status.AnchorStatus != AnchorPending {
		t.Fatalf("expected AnchorPending (inconclusive) on network failure, got %v", status.AnchorStatus)
	}
}

func TestBuildFixtures_ProduceParsableProofs(t *testing.T) {
	// Sanity check on the test fixtures themselves: confirm
	// DeserializeTimestamp actually accepts what these helpers build,
	// independent of the higher-level Check tests above.
	digest := bytes.Repeat([]byte{0x42}, 32)

	pendingProof := buildPendingProof("https://example.com")
	ts, err := anchor.DeserializeTimestamp(pendingProof, digest)
	if err != nil {
		t.Fatalf("buildPendingProof produced unparseable bytes: %v", err)
	}
	atts := ts.AllAttestations()
	if len(atts) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(atts))
	}
	if _, ok := atts[0].Attestation.(anchor.PendingAttestation); !ok {
		t.Fatalf("expected PendingAttestation, got %T", atts[0].Attestation)
	}

	btcProof := buildBitcoinProof(12345)
	ts2, err := anchor.DeserializeTimestamp(btcProof, digest)
	if err != nil {
		t.Fatalf("buildBitcoinProof produced unparseable bytes: %v", err)
	}
	atts2 := ts2.AllAttestations()
	if len(atts2) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(atts2))
	}
	btcAtt, ok := atts2[0].Attestation.(anchor.BitcoinBlockHeaderAttestation)
	if !ok {
		t.Fatalf("expected BitcoinBlockHeaderAttestation, got %T", atts2[0].Attestation)
	}
	if btcAtt.Height != 12345 {
		t.Fatalf("expected height 12345, got %d", btcAtt.Height)
	}
}

func TestNewMempoolSource_ReturnsUsableInterface(t *testing.T) {
	// Confirms the public constructor compiles and returns something
	// satisfying BlockHeaderSource, without making a real network call.
	src := NewMempoolSource()
	if src == nil {
		t.Fatal("expected non-nil BlockHeaderSource")
	}
}

