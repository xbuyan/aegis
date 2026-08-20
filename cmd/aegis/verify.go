package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"github.com/xbuyan/aegis/internal/anchor"
	"github.com/xbuyan/aegis/internal/evidence"
	"github.com/xbuyan/aegis/internal/log"
)

// runVerify checks a file against everything Aegis knows about it:
//
//  1. Was this exact content ever captured? (evidence store lookup by
//     freshly recomputed content hash — this alone proves the file
//     hasn't changed since capture, independent of the log or anchor.)
//  2. Does the tamper-evident log's chain still verify, and does it
//     actually contain an entry for this record?
//  3. Is there a Bitcoin anchor for this content hash, and if so, is it
//     still pending or does it independently verify against a real block?
//
// Any one of these three could fail independently of the others, and the
// output says which — a file can have valid content but a broken log
// (someone tampered with log entries unrelated to this file), or a valid
// log entry but no successful anchor yet (still pending), etc.
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	logPath := fs.String("log", defaultLogPath, "evidence log file")
	evidenceDir := fs.String("evidence", defaultEvidenceDir, "evidence record store dir")
	anchorsDir := fs.String("anchors", defaultAnchorsDir, "pending anchor store dir")
	useRPC := fs.String("bitcoin-rpc", "", "Bitcoin Core RPC URL for independent verification (default: use mempool.space)")
	rpcUser := fs.String("bitcoin-rpc-user", "", "Bitcoin Core RPC username")
	rpcPass := fs.String("bitcoin-rpc-pass", "", "Bitcoin Core RPC password")
	fs.Parse(args)

	if fs.NArg() != 1 {
		return fmt.Errorf("verify requires exactly one file argument")
	}
	filePath := fs.Arg(0)

	// 1. Recompute the file's content hash right now and see if we ever
	// captured content with this exact hash. This step alone proves file
	// integrity since capture, independent of the log or anchor.
	ev, err := evidence.NewEvidence(filePath)
	if err != nil {
		return fmt.Errorf("hash file: %w", err)
	}
	fmt.Printf("Current content hash: %s\n", ev.ContentHash)

	evStore, err := evidence.NewStore(*evidenceDir)
	if err != nil {
		return err
	}
	storedEv, err := evStore.Load(ev.ContentHash)
	if err != nil {
		fmt.Println("FAIL: no evidence record found for this content hash — file was never captured, or has changed since capture")
		return nil
	}
	fmt.Printf("OK: content matches a captured record (originally captured %s)\n", storedEv.CapturedAt.Format(time.RFC3339))

	// 2. Check the log: overall chain integrity, and that this specific
	// record is actually in it.
	recordHash, err := storedEv.Hash()
	if err != nil {
		return fmt.Errorf("hash stored evidence record: %w", err)
	}
	l, err := log.Open(*logPath)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	if err := l.Verify(); err != nil {
		fmt.Printf("FAIL: log chain integrity check failed: %v\n", err)
	} else {
		fmt.Println("OK: log chain integrity verified")
	}
	entry, err := l.FindByEvidenceHash(recordHash)
	if err != nil {
		return fmt.Errorf("search log: %w", err)
	}
	if entry == nil {
		fmt.Println("FAIL: no log entry found for this record — captured but never logged?")
	} else {
		fmt.Printf("OK: found log entry (index %d)\n", entry.Index)
	}

	// 3. Check the anchor.
	contentHashBytes, err := hex.DecodeString(ev.ContentHash)
	if err != nil {
		return fmt.Errorf("decode content hash: %w", err)
	}
	anchorStore, err := anchor.NewStore(*anchorsDir)
	if err != nil {
		return err
	}
	pa, err := anchorStore.Load(ev.ContentHash)
	if err != nil {
		fmt.Println("No anchor record found for this file (never submitted for anchoring, or anchors dir differs)")
		return nil
	}

	ts, err := anchor.DeserializeTimestamp(pa.RawProof, contentHashBytes)
	if err != nil {
		return fmt.Errorf("parse stored anchor proof: %w", err)
	}

	var src anchor.BlockHeaderSource
	if *useRPC != "" {
		src = &anchor.BitcoinRPCSource{URL: *useRPC, User: *rpcUser, Password: *rpcPass}
	} else {
		src = &anchor.MempoolSource{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	foundBitcoinAttestation := false
	for _, a := range ts.AllAttestations() {
		btcAtt, ok := a.Attestation.(anchor.BitcoinBlockHeaderAttestation)
		if !ok {
			continue
		}
		foundBitcoinAttestation = true
		blockTime, err := anchor.VerifyBitcoinAttestation(ctx, src, a.Msg, btcAtt)
		if err != nil {
			fmt.Printf("FAIL: Bitcoin attestation at height %d did not verify: %v\n", btcAtt.Height, err)
			continue
		}
		fmt.Printf("OK: Bitcoin-anchored — block %d, timestamp %s. This file provably existed no later than that moment.\n",
			btcAtt.Height, blockTime.Format(time.RFC3339))
	}
	if !foundBitcoinAttestation {
		fmt.Printf("Anchor still pending (submitted %s to %s) — run 'aegis upgrade' to check again\n",
			pa.SubmittedAt.Format(time.RFC3339), pa.CalendarURL)
	}

	return nil
}
