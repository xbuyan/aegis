package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/xbuyan/aegis/internal/anchor"
)

// runUpgrade re-queries the calendar for every pending anchor in the
// store and saves back whatever the calendar returns now — this is what
// eventually turns a PendingAttestation into a BitcoinBlockHeaderAttestation
// once the calendar's submission has actually been mined into a block
// (normally a matter of hours, not immediate).
func runUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	anchorsDir := fs.String("anchors", defaultAnchorsDir, "pending anchor store dir")
	fs.Parse(args)

	anchorStore, err := anchor.NewStore(*anchorsDir)
	if err != nil {
		return err
	}
	digests, err := anchorStore.ListDigests()
	if err != nil {
		return fmt.Errorf("list pending anchors: %w", err)
	}
	if len(digests) == 0 {
		fmt.Println("No pending anchors found.")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, digestHex := range digests {
		pa, err := anchorStore.Load(digestHex)
		if err != nil {
			fmt.Printf("%s: failed to load: %v\n", digestHex, err)
			continue
		}

		digestBytes, err := hex.DecodeString(pa.Digest)
		if err != nil {
			fmt.Printf("%s: stored digest is not valid hex: %v\n", digestHex, err)
			continue
		}

		cal := &anchor.Calendar{URL: pa.CalendarURL}
		ts, raw, err := cal.Upgrade(ctx, digestBytes)
		if errors.Is(err, anchor.ErrCommitmentNotFound) {
			fmt.Printf("%s: still pending\n", digestHex)
			continue
		}
		if err != nil {
			fmt.Printf("%s: upgrade check failed: %v\n", digestHex, err)
			continue
		}

		// Save back regardless of whether it's now confirmed — the
		// calendar's response may have grown (more of the merkle path
		// filled in) even before final Bitcoin confirmation.
		pa.RawProof = raw
		if err := anchorStore.Save(pa); err != nil {
			fmt.Printf("%s: fetched update but failed to save it: %v\n", digestHex, err)
			continue
		}

		confirmed := false
		for _, a := range ts.AllAttestations() {
			if _, ok := a.Attestation.(anchor.BitcoinBlockHeaderAttestation); ok {
				confirmed = true
			}
		}
		if confirmed {
			fmt.Printf("%s: now Bitcoin-confirmed — run 'aegis verify' on the original file to independently check it\n", digestHex)
		} else {
			fmt.Printf("%s: still pending\n", digestHex)
		}
	}

	return nil
}
