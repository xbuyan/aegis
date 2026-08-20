package anchor

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// BlockHeader is the minimal information Aegis needs about a Bitcoin
// block to verify an attestation: its merkle root, in the same internal
// (little-endian) byte order the OTS proof format uses — NOT the
// reversed/display hex order block explorers and Bitcoin Core RPC show
// to humans. Implementations of BlockHeaderSource are responsible for
// that reversal; callers of BlockHeaderSource never have to think about it.
type BlockHeader struct {
	Height     uint64
	MerkleRoot [32]byte
	Time       time.Time
}

// BlockHeaderSource fetches a Bitcoin block header by height. Aegis
// supports multiple implementations (a public block explorer API, a
// self-run Bitcoin Core node) behind this one interface, so verification
// logic doesn't care which the caller configured.
type BlockHeaderSource interface {
	BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error)
}

// reverseBytes32 returns a byte-order-reversed copy of a 32-byte hash.
// Bitcoin's internal/wire byte order (used in raw block headers, and in
// the msg values inside an OTS proof tree) is the reverse of the
// "display" hex order shown by block explorers and by Bitcoin Core's own
// RPC responses. Every BlockHeaderSource implementation must apply this
// exactly once when converting a source's display-hex hashes into the
// internal order BlockHeader.MerkleRoot uses.
func reverseBytes32(b [32]byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out
}

// ErrMerkleRootMismatch means the attestation's claimed digest does not
// match the real block's merkle root — the attestation is invalid. This
// should never happen for a genuine calendar, but a verifier must treat
// it as a hard failure, not a warning: an unverifiable Bitcoin attestation
// proves nothing.
type ErrMerkleRootMismatch struct {
	Height  uint64
	Claimed [32]byte
	Actual  [32]byte
}

func (e *ErrMerkleRootMismatch) Error() string {
	return fmt.Sprintf("anchor: block %d merkle root mismatch: proof claims %x, actual block has %x",
		e.Height, e.Claimed, e.Actual)
}

// VerifyBitcoinAttestation independently verifies a BitcoinBlockHeaderAttestation.
//
// digest is the msg value at the tree node the attestation was found on
// (from Timestamp.AllAttestations) — the value the calendar claims equals
// the merkle root of the block at att.Height. src supplies the real block
// data Aegis checks that claim against; VerifyBitcoinAttestation performs
// no network access itself, which keeps it fully unit-testable against a
// fake source.
//
// On success, returns the block's own timestamp: the moment Aegis can
// prove the evidence existed no later than, independent of anything the
// calendar said. On failure, returns *ErrMerkleRootMismatch specifically
// if the digest doesn't match (as opposed to a network/lookup error),
// since that distinction matters to a caller deciding how to react.
func VerifyBitcoinAttestation(ctx context.Context, src BlockHeaderSource, digest []byte, att BitcoinBlockHeaderAttestation) (time.Time, error) {
	if len(digest) != 32 {
		return time.Time{}, fmt.Errorf("anchor: digest must be 32 bytes, got %d", len(digest))
	}

	header, err := src.BlockHeader(ctx, att.Height)
	if err != nil {
		return time.Time{}, fmt.Errorf("anchor: fetch block %d header: %w", att.Height, err)
	}

	var claimed [32]byte
	copy(claimed[:], digest)

	if !bytes.Equal(claimed[:], header.MerkleRoot[:]) {
		return time.Time{}, &ErrMerkleRootMismatch{
			Height:  att.Height,
			Claimed: claimed,
			Actual:  header.MerkleRoot,
		}
	}

	return header.Time, nil
}
