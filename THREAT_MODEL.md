# Kinga Threat Model

*Status: MVP-stage self-assessment, not a substitute for external audit. See [SECURITY.md](./SECURITY.md) for overall project status.*

## 1. What Kinga protects

The asset under protection is a person's Bitcoin savings, represented as
128 bits of entropy encoded into a 12-word BIP39 mnemonic. The core claim
Kinga makes: this secret can be split into 3 shares such that any 2
reconstruct it exactly, 1 alone reveals nothing, and shares can be
distributed to trusted guardians without a bank, company, or government
intermediary — using Bitcoin's own Lightning Network as the transport.

## 2. Actors

- **Owner** — the person whose savings this is. Holds one share personally.
- **Guardians** (2 per owner, in the current 2-of-3 design) — trusted
  individuals (family, community elders, pastors per the project's stated
  design intent) who each hold one share, received via an encrypted
  keysend payment.
- **Network observer** — anyone able to see Lightning Network traffic
  but not decrypt it (e.g., a roadblock checkpoint, an ISP, a
  surveillance actor).
- **Malicious or coerced guardian** — a guardian who is bribed, coerced,
  or independently decides to misuse their share.
- **Device attacker** — anyone with physical or remote access to the
  owner's or a guardian's device.

## 3. Threats and current mitigation, by component

### 3.1 Secret generation and splitting (`internal/bip39`, `internal/shamir`)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Weak/predictable entropy source | `crypto/rand` exclusively, never `math/rand`; verified via a defensive short-read check even though the OS API is documented never to short-read | Low — standard, well-understood mitigation |
| Bit-packing/checksum bug producing wrong mnemonics | Delegated to `go-bip39`, an externally audited library, rather than hand-rolled — a deliberate reversal from an initial hand-rolled draft | Low, bounded by that library's own audit history |
| Custom Shamir/GF(256) implementation bug | 11 unit tests including exhaustive verification of all 255 nonzero field-element inverses; ECDH portion uses `btcec`'s audited `GenerateSharedSecret` rather than hand-rolled elliptic curve arithmetic | **Not externally audited** — this is hand-rolled cryptographic code and is the single highest-risk component in the codebase today |
| Reconstructing with a wrong-threshold assumption (e.g. code expecting 3-of-3 silently "succeeding" on the wrong math) | `Combine` explicitly checks `len(shares) == threshold`; threshold is never inferred from share count | Low |

### 3.2 Distribution (`internal/keysend`)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Network observer reads a share in transit | ECIES: fresh ephemeral keypair per share, ECDH + HKDF-SHA256 + AES-256-GCM; the payload is encrypted end-to-end inside the Lightning payment, not merely hidden by onion routing | Low, standard construction |
| Tampered ciphertext accepted as valid | AES-GCM's built-in authentication; tested explicitly | Low |
| Wrong recipient decrypts a share | ECIES binds ciphertext to the intended recipient's private key; tested explicitly (wrong-key rejection) | Low |
| Guardian's Lightning node is compromised, revealing their share | **Not mitigated.** A compromised guardian device with the share already decrypted and stored is a real gap — no secret-hygiene measures (memory zeroing, encrypted-at-rest storage guidance) currently exist | **High — explicit known gap** |
| Sybil or eclipse attack against payment routing, preventing or intercepting distribution | **Not analyzed.** Lightning's routing layer has its own known attack surface (routing-node visibility, timing/amount correlation, channel-jamming); Kinga inherits whatever LND's own posture is, unmodified | **Unaddressed — flagged for future work** |
| Distributing node (the owner's) is itself compromised before distribution | **Not mitigated.** No hardening guidance yet for the machine running the split/distribute flow | **High — explicit known gap** |

### 3.3 Recovery (`internal/recovery`)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Shamir reconstruction "succeeds" on corrupted or mismatched shares, producing a wrong wallet silently | This was a real bug caught during development: BIP39's checksum alone could not detect this, since it's recomputed from whatever entropy `Combine` produces. Fixed with an independent SHA-256 fingerprint of the original entropy, checked before mnemonic conversion. Explicit test coverage. | Low — resolved, but the fact this shipped once as a real vulnerability is itself informative about how subtle this failure class is |
| Recovery attempted over a network, exposing reconstructed entropy | Recovery is explicitly local-only — `internal/recovery` has no network imports by design, verifiable by inspection | Low |

### 3.4 Distribution log (`internal/log`)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Log entries tampered with after the fact | Hash-chained records; `Verify` re-reads from disk (never trusts an in-memory cache) specifically so it catches tampering that happened outside the running process; tested against both single-field tampering and record reordering | Low |
| Log itself leaks the secret or a guardian's decryption capability | Log stores only a hash of the encrypted share (`SHA256` of the exact ciphertext bytes sent), never plaintext, never a key | Low |

## 4. Explicitly out of scope for the current MVP

These are not oversights so much as scoping decisions appropriate to an
MVP, listed here so they're visible rather than silently assumed away:

- Physical coercion of the owner or a guardian (rubber-hose cryptanalysis)
  is not something any software design fully solves; the 2-of-3 threshold
  limits a single coerced party's power but does not eliminate the risk.
- Guardian selection itself (who an owner chooses to trust) is a social,
  not cryptographic, problem, and is entirely the user's responsibility.
- No formal verification of the Shamir/GF(256) implementation has been
  done (e.g. no property-based testing beyond the exhaustive inverse
  check, no formal proof).
- Denial-of-service resistance for the distributing node has not been
  considered.

## 5. How this threat model extends to downstream projects

Kinga is the first project in a committed sequence: **Kinga → Aegis →
Orizu → Sentinel → Deni → Msafiri.** Each later project reuses a specific
piece of Kinga's foundation, which means Kinga's residual risks are
inherited, not reset, at each step:

- **Orizu** (dead man's switch using Shamir's Secret Sharing for digital
  inheritance) directly reuses Kinga's Shamir splitting logic. Any
  unaudited flaw in `internal/shamir` propagates directly into Orizu's
  security guarantees. Orizu should not be considered more trustworthy
  than Kinga's own audit status permits, regardless of what's built on
  top of it.
- **Deni** reuses Kinga's Lightning/keysend integration. The same
  routing-layer and node-compromise gaps noted in §3.2 apply there too,
  and Deni's own threat model will need to account for whatever new
  attack surface its specific use case adds on top of this shared base.
- **Aegis** and **Sentinel** both build on Kinga's hash-chained
  distribution log pattern (`internal/log`). The log's core guarantee —
  tamper-evidence, not tamper-prevention — needs to be understood
  correctly by anyone building on it: a hash chain proves *that*
  something was altered, after the fact; it does not prevent alteration
  or guarantee availability of the log itself.

The practical implication: **the audit gate stated in SECURITY.md for
Kinga is a prerequisite for the whole downstream sequence, not just for
Kinga in isolation.** Treating Kinga as "done enough" to build on top of,
without the audit, would mean every later project inherits an unaudited
cryptographic foundation. This is a deliberate reason to hold the line on
Kinga's own stated mainnet gate rather than let downstream momentum
pressure it.

## 6. Summary of highest-priority open risks

In rough priority order, based on the analysis above:

1. No external audit of the hand-rolled Shamir/GF(256) implementation.
2. No secret-hygiene hardening (memory zeroing, at-rest protection) on
   either the owner's or guardians' devices.
3. No analysis of Lightning routing-layer attack surface (Sybil/eclipse)
   as it applies to keysend-based share distribution specifically.
4. No guidance or hardening for the distributing node's own operational
   security.
5. No formal threat modeling yet done *per downstream project* — this
   document covers Kinga's own surface and flags inheritance, but Orizu,
   Deni, Aegis, and Sentinel will each need their own addendum once built.
