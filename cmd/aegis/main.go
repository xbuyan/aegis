// Command aegis captures files as tamper-evident, Bitcoin-anchored
// evidence. See the subcommand help text for usage.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "capture":
		err = runCapture(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "upgrade":
		err = runUpgrade(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Aegis — tamper-evident, Bitcoin-anchored evidence capture.

Usage:
  aegis capture [flags] <file>   Hash, log, and submit a file for anchoring
  aegis verify [flags] <file>    Check a file against its log entry and anchor
  aegis upgrade [flags]          Check pending anchors for Bitcoin confirmation

Note: flags must come before the file argument, not after.

Common flags (all subcommands):
  -log <path>       evidence log file (default ./aegis-log.jsonl)
  -evidence <path>  evidence record store dir (default ./aegis-evidence)
  -anchors <path>   pending anchor store dir (default ./aegis-anchors)
  -calendar <url>   OTS calendar server (default https://a.pool.opentimestamps.org)

Run 'aegis <command> -h' for command-specific flags.
`)
}
