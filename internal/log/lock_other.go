//go:build !unix

package log

import "os"

// lockFile is a no-op on non-Unix platforms (Windows). Aegis's primary
// development and deployment target is Unix (Linux/macOS), where
// lock_unix.go provides real advisory locking via flock. On Windows,
// concurrent Append calls from separate processes are NOT protected
// against the race described in lock_unix.go's doc comment — this is a
// known, explicit gap, not a silently-assumed one.
func lockFile(f *os.File) error {
	return nil
}

func unlockFile(f *os.File) error {
	return nil
}
