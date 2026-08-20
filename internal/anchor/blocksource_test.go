package anchor

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	headers map[uint64]*BlockHeader
	err     error
}

func (f *fakeSource) BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error) {
	if f.err != nil {
		return nil, f.err
	}
	h, ok := f.headers[height]
	if !ok {
		return nil, errors.New("fakeSource: no header at that height")
	}
	return h, nil
}

func TestReverseBytes32_RoundTrips(t *testing.T) {
	var b [32]byte
	for i := range b {
		b[i] = byte(i)
	}
	reversed := reverseBytes32(b)
	if reversed[0] != b[31] || reversed[31] != b[0] {
		t.Fatalf("reverseBytes32 didn't reverse: got %x from %x", reversed, b)
	}
	roundTripped := reverseBytes32(reversed)
	if roundTripped != b {
		t.Errorf("reverseBytes32 applied twice should be identity: got %x, want %x", roundTripped, b)
	}
}

func TestVerifyBitcoinAttestation_MatchSucceeds(t *testing.T) {
	var merkleRoot [32]byte
	for i := range merkleRoot {
		merkleRoot[i] = byte(i)
	}
	wantTime := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	src := &fakeSource{headers: map[uint64]*BlockHeader{
		850000: {Height: 850000, MerkleRoot: merkleRoot, Time: wantTime},
	}}

	got, err := VerifyBitcoinAttestation(context.Background(), src, merkleRoot[:], BitcoinBlockHeaderAttestation{Height: 850000})
	if err != nil {
		t.Fatalf("VerifyBitcoinAttestation: %v", err)
	}
	if !got.Equal(wantTime) {
		t.Errorf("returned time = %v, want %v", got, wantTime)
	}
}

func TestVerifyBitcoinAttestation_MismatchFails(t *testing.T) {
	var actualRoot, claimedRoot [32]byte
	actualRoot[0] = 0xAA
	claimedRoot[0] = 0xBB // deliberately different

	src := &fakeSource{headers: map[uint64]*BlockHeader{
		850000: {Height: 850000, MerkleRoot: actualRoot, Time: time.Now()},
	}}

	_, err := VerifyBitcoinAttestation(context.Background(), src, claimedRoot[:], BitcoinBlockHeaderAttestation{Height: 850000})
	if err == nil {
		t.Fatal("VerifyBitcoinAttestation with mismatched roots: want error, got nil")
	}
	var mismatchErr *ErrMerkleRootMismatch
	if !errors.As(err, &mismatchErr) {
		t.Errorf("error type = %T, want *ErrMerkleRootMismatch", err)
	}
}

func TestVerifyBitcoinAttestation_WrongDigestLengthRejected(t *testing.T) {
	src := &fakeSource{headers: map[uint64]*BlockHeader{}}
	_, err := VerifyBitcoinAttestation(context.Background(), src, []byte{0x01, 0x02}, BitcoinBlockHeaderAttestation{Height: 1})
	if err == nil {
		t.Fatal("VerifyBitcoinAttestation with a non-32-byte digest: want error, got nil")
	}
}

func TestVerifyBitcoinAttestation_SourceErrorPropagates(t *testing.T) {
	src := &fakeSource{err: errors.New("network down")}
	_, err := VerifyBitcoinAttestation(context.Background(), src, make([]byte, 32), BitcoinBlockHeaderAttestation{Height: 1})
	if err == nil {
		t.Fatal("VerifyBitcoinAttestation with a failing source: want error, got nil")
	}
	var mismatchErr *ErrMerkleRootMismatch
	if errors.As(err, &mismatchErr) {
		t.Error("a source lookup failure should not present as ErrMerkleRootMismatch")
	}
}
