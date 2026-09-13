// Package verify is Aegis's public verification API — the one place
// external consumers (like Sentinel) can check both a file's evidence
// record and its Bitcoin anchor status, without duplicating any of
// Aegis's hand-rolled OTS parsing or Bitcoin verification logic.
//
// This package exists specifically because Go forbids importing another
// module's internal/ packages: Sentinel (a separate module) cannot
// `import "github.com/xbuyan/aegis/internal/anchor"` even though both
// repos are public. Reimplementing that logic a second time inside
// Sentinel was considered and rejected — two independent copies of
// complex, security-critical binary-parsing and cryptographic
// verification code drifting apart over time is a worse outcome than
// adding one small public facade here. This package is that facade: it
// imports Aegis's own internal packages (allowed, since both are in the
// same module) and re-exposes exactly what an external verifier needs,
// through a stable, deliberately narrow public API.
//
// cmd/aegis's own `aegis verify` does not use this package — it continues
// to call internal/anchor and internal/evidence directly, unaffected by
// this addition. This package is purely an additive public surface for
// external consumers.
package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/xbuyan/aegis/internal/anchor"
	"github.com/xbuyan/aegis/internal/evidence"
)

// BlockHeaderSource is a type alias (not a new type) for
// anchor.BlockHeaderSource. Aliasing, rather than merely referencing the
// internal type in a function signature, means external callers can
// write verify.BlockHeaderSource directly in their own code (e.g. to
// declare a variable) without ever needing to import
// github.com/xbuyan/aegis/internal/anchor themselves.
type BlockHeaderSource = anchor.BlockHeaderSource

// NewMempoolSource returns a BlockHeaderSource backed by mempool.space's
// public API — Aegis's default, convenient but requires trusting that
// API not to lie about block data (see internal/anchor's own
// documentation of this trade-off, unchanged by this package).
func NewMempoolSource() BlockHeaderSource {
	return &anchor.MempoolSource{}
}

// AnchorStatus summarizes what could be determined about a piece of
// evidence's Bitcoin anchor.
type AnchorStatus string

const (
	// AnchorNotFound means no anchor submission exists at all for this
	// content hash — either it was never captured through Aegis, or the
	// hash is simply wrong.
	AnchorNotFound AnchorStatus = "not_found"
	// AnchorPending means a submission exists, but no Bitcoin block
	// attestation has confirmed yet — the calendar hasn't upgraded it,
	// or not enough time/confirmations have passed.
	AnchorPending AnchorStatus = "pending"
	// AnchorConfirmed means at least one Bitcoin block attestation in
	// the proof was independently verified against a real block's
	// merkle root.
	AnchorConfirmed AnchorStatus = "confirmed"
	// AnchorInvalid means a Bitcoin block attestation was found, but its
	// claimed merkle root does NOT match the real block's — a
	// deliberately distinct, more serious finding than AnchorPending.
	// This is not "not confirmed yet," it's "provably wrong": either the
	// proof was corrupted or the calendar lied. A caller should treat
	// this as a hard failure, not something that might resolve itself
	// later.
	AnchorInvalid AnchorStatus = "invalid"
)

// Status is the complete result of checking one piece of evidence.
type Status struct {
	// ContentFound is true if an Aegis evidence record exists for this
	// content hash at all.
	ContentFound bool
	Filename     string
	CapturedAt   time.Time

	AnchorStatus AnchorStatus
	// ConfirmedAt is the Bitcoin block's own timestamp, set only when
	// AnchorStatus is AnchorConfirmed. This is the moment Aegis can prove
	// the evidence existed no later than — independent of anything the
	// calendar claims, per internal/anchor's VerifyBitcoinAttestation.
	ConfirmedAt time.Time
	// ConfirmedBlockHeight is set only when AnchorStatus is
	// AnchorConfirmed.
	ConfirmedBlockHeight uint64
}

// Check verifies a piece of evidence, identified by its SHA-256 content
// hash (hex-encoded, matching what `aegis capture` printed and what
// evidence.Store/anchor.Store use as their on-disk filenames), against
// both Aegis's evidence-record store and its anchor store.
//
// evidenceDir and anchorDir are the same directories `aegis capture` was
// given (its -evidence and -anchors flags). src supplies real Bitcoin
// block data for independent anchor verification — use NewMempoolSource
// for Aegis's default, or supply your own BlockHeaderSource (e.g. backed
// by a self-run node) for the same trust-minimization option Aegis's own
// CLI offers.
//
// A content hash with no evidence record returns Status{ContentFound:
// false} and no error — that's a normal "nothing here" result, not a
// failure. An evidence record with no anchor submission yet returns
// AnchorStatus: AnchorNotFound. Errors are reserved for genuine failures
// (unreadable store directories, corrupted records, network failures
// talking to src) — not for "nothing found here" cases, which are
// signaled through the returned Status instead.
func Check(ctx context.Context, evidenceDir, anchorDir, contentHashHex string, src BlockHeaderSource) (Status, error) {
	var status Status

	evStore, err := evidence.NewStore(evidenceDir)
	if err != nil {
		return status, fmt.Errorf("verify: opening evidence store: %w", err)
	}
	ev, err := evStore.Load(contentHashHex)
	if err != nil {
		// Load's error wraps os.ReadFile's error; a missing file is a
		// normal "not found" case, not a failure worth returning as an
		// error — but Load doesn't distinguish "missing" from "corrupt"
		// in its error type, so this treats any Load failure as
		// not-found. A corrupted-but-present record and a genuinely
		// missing one both mean "nothing usable was found here."
		status.ContentFound = false
		status.AnchorStatus = AnchorNotFound
		return status, nil
	}
	status.ContentFound = true
	status.Filename = ev.Filename
	status.CapturedAt = ev.CapturedAt

	anchorStore, err := anchor.NewStore(anchorDir)
	if err != nil {
		return status, fmt.Errorf("verify: opening anchor store: %w", err)
	}
	pending, err := anchorStore.Load(contentHashHex)
	if err != nil {
		status.AnchorStatus = AnchorNotFound
		return status, nil
	}

	digestBytes, err := hex.DecodeString(contentHashHex)
	if err != nil {
		return status, fmt.Errorf("verify: content hash is not valid hex: %w", err)
	}

	timestamp, err := anchor.DeserializeTimestamp(pending.RawProof, digestBytes)
	if err != nil {
		return status, fmt.Errorf("verify: parsing stored OTS proof: %w", err)
	}

	status.AnchorStatus = AnchorPending // default unless a Bitcoin attestation verifies below

	for _, entry := range timestamp.AllAttestations() {
		btcAtt, ok := entry.Attestation.(anchor.BitcoinBlockHeaderAttestation)
		if !ok {
			continue // a PendingAttestation or other type — keep looking
		}
		confirmedAt, err := anchor.VerifyBitcoinAttestation(ctx, src, entry.Msg, btcAtt)
		if err != nil {
			var mismatchErr *anchor.ErrMerkleRootMismatch
			if errors.As(err, &mismatchErr) {
				// A provably fraudulent or corrupted proof — this is a
				// hard, immediate finding, not something to keep
				// searching past in case a later attestation looks
				// better. Report it and stop.
				status.AnchorStatus = AnchorInvalid
				return status, nil
			}
			// Any other failure (network error, source unavailable) is
			// inconclusive, not proof of fraud — keep checking any
			// remaining attestations in the tree rather than giving up
			// on the whole check over one failed lookup.
			continue
		}
		status.AnchorStatus = AnchorConfirmed
		status.ConfirmedAt = confirmedAt
		status.ConfirmedBlockHeight = btcAtt.Height
		break
	}

	return status, nil
}

