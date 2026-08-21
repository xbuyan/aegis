//go:build unix

package log

import (
	"fmt"
	"os"
	"syscall"
)

// lockFile acquires an exclusive advisory lock on f, blocking until it's
// available. This prevents two concurrent Aegis processes (or two
// concurrent Append calls) from racing on "read last entry, then write
// next entry" and corrupting the chain — e.g. both computing the same
// next Index, or one process's write landing between another's read and
// write.
//
// This is advisory locking: it only protects against other processes
// that also call lockFile, which every Append call does. It does not
// protect against a process crashing while holding the lock — on Linux
// and macOS, the OS releases the lock automatically when the holding
// process's file descriptor closes (including on crash), so a stale lock
// surviving a crash is not a concern on these platforms.
func lockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("log: acquire file lock: %w", err)
	}
	return nil
}

func unlockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("log: release file lock: %w", err)
	}
	return nil
}
