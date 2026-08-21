# Aegis Anchor

Cryptographic file integrity and Bitcoin-anchored timestamping for
activists and journalists — proof that a piece of evidence existed,
unaltered, at a specific point in time, verifiable by anyone without
trusting Aegis, its author, or any single server.

## Status

Core system built and working: capture, tamper-evident logging, Bitcoin
anchoring (submission and independent verification), and a CLI tying it
together. Proven against real production infrastructure — see
`THREAT_MODEL.md` for what is and isn't yet hardened for adversarial use.

## How it works

1. **Capture** (`internal/evidence`) — a file is hashed (SHA-256,
   streamed so large files don't need to fit in memory). This hash is the
   file's unforgeable fingerprint.
2. **Log** (`internal/log`) — the capture is appended to a local,
   hash-chained, append-only log. Each entry commits to the one before
   it, so deleting, reordering, or altering any entry breaks the chain
   from that point forward — detectable by anyone with the log file.
3. **Anchor** (`internal/anchor`) — the file's content hash is submitted
   to a public OpenTimestamps calendar server, which batches it toward a
   real Bitcoin transaction. Once mined into a block, the hash is
   permanently, publicly bound to that block — verifiable by anyone with
   the file and Bitcoin's own public ledger, independent of Aegis or the
   calendar.
4. **Verify** — later, given a file, Aegis independently re-checks all
   three: does the content still match what was captured, is the log
   chain still intact, and does the Bitcoin anchor still verify against a
   real block's merkle root.

The log and the anchor are deliberately separate guarantees: the log
proves nothing was tampered with *locally*; the Bitcoin anchor proves
*when*, and that proof survives even if the log itself is lost, since it
only requires the original file.

## Usage

Build:

```bash
go build -o aegis ./cmd/aegis
```

Capture a file (flags must come before the file path):

```bash
./aegis capture -log ./aegis-log.jsonl -evidence ./aegis-evidence \
  -anchors ./aegis-anchors -calendar https://a.pool.opentimestamps.org \
  /path/to/file
```

Verify it later:

```bash
./aegis verify -log ./aegis-log.jsonl -evidence ./aegis-evidence \
  -anchors ./aegis-anchors /path/to/file
```

Check pending anchors for Bitcoin confirmation (run this periodically,
hours after capture — confirmation isn't instant):

```bash
./aegis upgrade -anchors ./aegis-anchors
```

Run `./aegis -h` for the full flag reference, including
`-bitcoin-rpc`/`-bitcoin-rpc-user`/`-bitcoin-rpc-pass` on `verify` to
independently check against your own Bitcoin Core node instead of the
default public mempool.space API.

## Architecture

- `internal/evidence` — evidence record (content hash + capture
  metadata) and its on-disk store, keyed by content hash
- `internal/log` — hash-chained append-only log, with file locking for
  safe concurrent use
- `internal/anchor` — the OTS binary wire-format parser (hand-rolled,
  verified against the reference `python-opentimestamps` implementation),
  the calendar HTTP client, and independent Bitcoin block-header
  verification against either a public API or a self-run node
- `cmd/aegis` — the CLI

## Development

```bash
go build ./...
go vet ./...
go test ./... -race
```

## License

MIT — see LICENSE.
