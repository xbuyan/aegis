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

func runCapture(args []string) error {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	logPath := fs.String("log", defaultLogPath, "evidence log file")
	evidenceDir := fs.String("evidence", defaultEvidenceDir, "evidence record store dir")
	anchorsDir := fs.String("anchors", defaultAnchorsDir, "pending anchor store dir")
	calendarURL := fs.String("calendar", defaultCalendarURL, "OTS calendar server")
	fs.Parse(args)

	if fs.NArg() != 1 {
		return fmt.Errorf("capture requires exactly one file argument")
	}
	filePath := fs.Arg(0)

	// Step 1: hash the file.
	ev, err := evidence.NewEvidence(filePath)
	if err != nil {
		return fmt.Errorf("capture evidence: %w", err)
	}
	fmt.Printf("Content hash: %s\n", ev.ContentHash)

	// Step 2: persist the evidence record (needed later so verify can
	// recover the exact original record, including CapturedAt).
	evStore, err := evidence.NewStore(*evidenceDir)
	if err != nil {
		return err
	}
	if err := evStore.Save(ev); err != nil {
		return fmt.Errorf("save evidence record: %w", err)
	}

	// Step 3: append to the tamper-evident log, chained on this record's
	// own hash (not the file's content hash — see verify.go's comment on
	// why these are deliberately different values).
	recordHash, err := ev.Hash()
	if err != nil {
		return fmt.Errorf("hash evidence record: %w", err)
	}
	l, err := log.Open(*logPath)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	entry, err := l.Append(recordHash)
	if err != nil {
		return fmt.Errorf("append to log: %w", err)
	}
	fmt.Printf("Logged: index %d, chain hash %s\n", entry.Index, entry.ChainHash)

	// Step 4: submit the file's content hash (not the record hash — see
	// the design note in verify.go) to a calendar for Bitcoin anchoring.
	contentHashBytes, err := hex.DecodeString(ev.ContentHash)
	if err != nil {
		return fmt.Errorf("decode content hash: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cal := &anchor.Calendar{URL: *calendarURL}
	_, raw, err := cal.Submit(ctx, contentHashBytes)
	if err != nil {
		return fmt.Errorf("submit to calendar %s: %w", *calendarURL, err)
	}

	anchorStore, err := anchor.NewStore(*anchorsDir)
	if err != nil {
		return err
	}
	pa := anchor.NewPendingAnchor(contentHashBytes, *calendarURL, raw)
	if err := anchorStore.Save(pa); err != nil {
		return fmt.Errorf("save pending anchor: %w", err)
	}

	fmt.Printf("Submitted for anchoring to %s (pending — run 'aegis upgrade' later to check)\n", *calendarURL)
	return nil
}
