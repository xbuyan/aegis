#!/usr/bin/env bash
# setup_aegis.sh — scaffolds the full Aegis repo structure.
# Safe to re-run: only creates what's missing, never overwrites existing files.
set -euo pipefail

REPO_DIR="${1:-$HOME/projects/aegis}"

echo "Scaffolding Aegis at: $REPO_DIR"
mkdir -p "$REPO_DIR"
cd "$REPO_DIR"

# --- git + go module -------------------------------------------------------
if [ ! -d .git ]; then
  git init
fi

if [ ! -f go.mod ]; then
  go mod init github.com/xbuyan/aegis
fi

# --- directory layout --------------------------------------------------
# internal/evidence — Component 1: evidence record + file hashing (done)
# internal/log       — Component 2: hash-chained evidence log
# internal/anchor    — Component 3: OpenTimestamps (Bitcoin) anchoring
# cmd/aegis          — Component 4: CLI tying the above together
mkdir -p internal/evidence
mkdir -p internal/log
mkdir -p internal/anchor
mkdir -p cmd/aegis
mkdir -p docs

# --- placeholder package files (only created if the package is empty) -----
# These exist so `go build ./...` succeeds before each component is written;
# each gets fully replaced when that component's actual build turn comes.
new_pkg_stub() {
  local dir="$1" pkg="$2" desc="$3"
  local file="$dir/$pkg.go"
  if [ ! -f "$file" ] && [ -z "$(find "$dir" -maxdepth 1 -name '*.go' 2>/dev/null)" ]; then
    cat > "$file" <<EOF
// Package $pkg — $desc
// Not yet implemented.
package $pkg
EOF
    echo "  created stub: $file"
  fi
}

new_pkg_stub internal/log log "hash-chained evidence log (Component 2)"
new_pkg_stub internal/anchor anchor "OpenTimestamps Bitcoin-anchored timestamping (Component 3)"

if [ ! -f cmd/aegis/main.go ]; then
  cat > cmd/aegis/main.go <<'EOF'
// Command aegis is the CLI entry point tying together evidence capture,
// hash-chained logging, and Bitcoin-anchored timestamping.
// Not yet implemented — Component 4.
package main

func main() {}
EOF
  echo "  created stub: cmd/aegis/main.go"
fi

# --- repo-level docs (only created if missing) -----------------------------
if [ ! -f README.md ]; then
  cat > README.md <<'EOF'
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
EOF
  echo "  created: README.md"
fi

if [ ! -f LICENSE ]; then
  cat > LICENSE <<EOF
MIT License

Copyright (c) $(date +%Y) xbuyan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
  echo "  created: LICENSE"
fi

if [ ! -f .gitignore ]; then
  cat > .gitignore <<'EOF'
# Go
*.exe
*.test
*.out
/bin/
/dist/

# Editor / OS
.DS_Store
.idea/
.vscode/

# Local env
*.env
.env.local
EOF
  echo "  created: .gitignore"
fi

if [ ! -f SECURITY.md ]; then
  cat > SECURITY.md <<'EOF'
# Security

Aegis handles evidence for activists and journalists — the threat model
assumes an adversary who wants to discredit, alter, or destroy that
evidence, potentially with state-level resources.

## Reporting a vulnerability

(to be filled in before public release)

## Threat model

See THREAT_MODEL.md.
EOF
  echo "  created: SECURITY.md"
fi

if [ ! -f THREAT_MODEL.md ]; then
  cat > THREAT_MODEL.md <<'EOF'
# Threat Model

(to be filled in as components are built — mirrors Kinga's THREAT_MODEL.md
structure: assets, adversaries, trust boundaries, out-of-scope threats)
EOF
  echo "  created: THREAT_MODEL.md"
fi

echo ""
echo "Done. Structure:"
find . -not -path './.git*' -type f | sort
