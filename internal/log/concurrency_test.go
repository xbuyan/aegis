package log

import (
	"fmt"
	"sync"
	"testing"
)

func TestAppend_ConcurrentCallsDoNotRace(t *testing.T) {
	l, _ := newTestLog(t)

	const numGoroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := l.Append(fmt.Sprintf("hash-%d", i))
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Append: %v", i, err)
		}
	}

	// If locking worked, every index 0..19 was assigned exactly once —
	// no duplicates (two goroutines both computing the same "next index")
	// and no gaps (a write silently lost).
	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != numGoroutines {
		t.Fatalf("got %d entries, want %d (a race would produce duplicates or lost writes)", len(entries), numGoroutines)
	}

	seen := make(map[uint64]bool)
	for _, e := range entries {
		if seen[e.Index] {
			t.Errorf("duplicate index %d — Append race not prevented", e.Index)
		}
		seen[e.Index] = true
	}
	for i := uint64(0); i < numGoroutines; i++ {
		if !seen[i] {
			t.Errorf("missing index %d — Append race lost a write", i)
		}
	}

	// The chain itself must still verify — a race that scrambled
	// PrevChainHash linkage would show up here even if indices happened
	// to come out unique.
	if err := l.Verify(); err != nil {
		t.Errorf("Verify after concurrent appends: %v", err)
	}
}
