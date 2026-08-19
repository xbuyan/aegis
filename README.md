# Aegis Anchor

Cryptographic file integrity and Bitcoin-anchored timestamping for
activists and journalists — proof that a piece of evidence existed,
unaltered, at a specific point in time, verifiable by anyone without
trusting Aegis itself.

## Status

Early development. See component status in commit history.

## Architecture

- `internal/evidence` — evidence record: file content hash + capture metadata
- `internal/log` — append-only, hash-chained log of evidence records
- `internal/anchor` — OpenTimestamps-based Bitcoin block anchoring
- `cmd/aegis` — CLI

## License

MIT — see LICENSE.
