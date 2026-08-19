package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Op is a single edge in an OTS Timestamp tree: a transformation applied to
// a message to produce the message at the next node down.
type Op interface {
	// Apply transforms msg into the message committed to by the next node.
	Apply(msg []byte) ([]byte, error)
	// String returns a short human-readable form, e.g. "append 01ab" or "sha256".
	String() string
}

// OpAppend appends Arg to the message.
type OpAppend struct{ Arg []byte }

func (o OpAppend) Apply(msg []byte) ([]byte, error) {
	out := make([]byte, 0, len(msg)+len(o.Arg))
	out = append(out, msg...)
	out = append(out, o.Arg...)
	return out, nil
}
func (o OpAppend) String() string { return "append " + hex.EncodeToString(o.Arg) }

// OpPrepend prepends Arg to the message.
type OpPrepend struct{ Arg []byte }

func (o OpPrepend) Apply(msg []byte) ([]byte, error) {
	out := make([]byte, 0, len(msg)+len(o.Arg))
	out = append(out, o.Arg...)
	out = append(out, msg...)
	return out, nil
}
func (o OpPrepend) String() string { return "prepend " + hex.EncodeToString(o.Arg) }

// OpSHA256 replaces the message with its SHA-256 digest. This is the only
// crypto op the standard Bitcoin calendar path uses (via repeated
// SHA-256d-style chaining), so it's the only crypto op Aegis implements;
// other op tags in the spec (sha1, ripemd160) are recognized as known-tags
// but rejected with a clear error rather than silently mishandled, since
// they should never appear in a genuine calendar response for our use case.
type OpSHA256 struct{}

func (OpSHA256) Apply(msg []byte) ([]byte, error) {
	sum := sha256.Sum256(msg)
	return sum[:], nil
}
func (OpSHA256) String() string { return "sha256" }

// Op tag bytes, verified against opentimestamps/python-opentimestamps
// opentimestamps/core/op.py (the reference implementation).
const (
	opTagAppend  = 0xf0
	opTagPrepend = 0xf1
	opTagSHA1    = 0x02
	opTagRIPEMD  = 0x03
	opTagSHA256  = 0x08
)

// maxOpArgLength bounds a binary op's argument size, mirroring the
// reference implementation's Op.MAX_RESULT_LENGTH (4096).
const maxOpArgLength = 4096

// deserializeOp reads one op given its already-consumed tag byte.
func deserializeOp(r *bytes.Reader, tag byte) (Op, error) {
	switch tag {
	case opTagAppend:
		arg, err := readVarBytes(r, maxOpArgLength)
		if err != nil {
			return nil, fmt.Errorf("anchor: deserialize OpAppend: %w", err)
		}
		if len(arg) == 0 {
			return nil, fmt.Errorf("anchor: OpAppend argument must not be empty")
		}
		return OpAppend{Arg: arg}, nil
	case opTagPrepend:
		arg, err := readVarBytes(r, maxOpArgLength)
		if err != nil {
			return nil, fmt.Errorf("anchor: deserialize OpPrepend: %w", err)
		}
		if len(arg) == 0 {
			return nil, fmt.Errorf("anchor: OpPrepend argument must not be empty")
		}
		return OpPrepend{Arg: arg}, nil
	case opTagSHA256:
		return OpSHA256{}, nil
	case opTagSHA1, opTagRIPEMD:
		return nil, fmt.Errorf("anchor: operation tag 0x%02x (sha1/ripemd160) recognized but not implemented; unexpected in a standard Bitcoin calendar response", tag)
	default:
		return nil, fmt.Errorf("anchor: unknown operation tag 0x%02x", tag)
	}
}

// Attestation is a leaf claim in an OTS Timestamp tree: either a promise
// from a calendar that a Bitcoin attestation will exist eventually
// (PendingAttestation), or a claim that the message at this node equals
// the merkle root of a specific Bitcoin block (BitcoinBlockHeaderAttestation).
type Attestation interface {
	String() string
}

// PendingAttestation means the calendar at URI has committed to the
// message but hasn't yet produced a Bitcoin-confirmed attestation. Not
// independently verifiable — re-query the calendar later to upgrade it.
type PendingAttestation struct{ URI string }

func (a PendingAttestation) String() string { return "pending: " + a.URI }

// BitcoinBlockHeaderAttestation claims the message at this tree node
// equals the merkle root of the Bitcoin block at Height. This is the
// attestation type that makes a timestamp independently verifiable — see
// internal/anchor's Bitcoin verification (Component 3b).
type BitcoinBlockHeaderAttestation struct{ Height uint64 }

func (a BitcoinBlockHeaderAttestation) String() string {
	return fmt.Sprintf("bitcoin block %d", a.Height)
}

// UnknownAttestation preserves an attestation type Aegis doesn't
// recognize, rather than discarding it or failing the whole parse.
type UnknownAttestation struct {
	Tag     [8]byte
	Payload []byte
}

func (a UnknownAttestation) String() string {
	return "unknown attestation " + hex.EncodeToString(a.Tag[:])
}

// Attestation tag bytes (8 bytes each), verified against
// opentimestamps/python-opentimestamps opentimestamps/core/notary.py.
var (
	attestationTagPending = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	attestationTagBitcoin = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
)

const (
	maxAttestationPayload = 8192 // matches TimeAttestation.MAX_PAYLOAD_SIZE
	maxPendingURILength   = 1000 // matches PendingAttestation.MAX_URI_LENGTH
)

func deserializeAttestation(r *bytes.Reader) (Attestation, error) {
	var tagBuf [8]byte
	if err := readFull(r, tagBuf[:]); err != nil {
		return nil, fmt.Errorf("anchor: read attestation tag: %w", err)
	}

	payload, err := readVarBytes(r, maxAttestationPayload)
	if err != nil {
		return nil, fmt.Errorf("anchor: read attestation payload: %w", err)
	}
	payloadReader := bytes.NewReader(payload)

	switch tagBuf {
	case attestationTagPending:
		uri, err := readVarBytes(payloadReader, maxPendingURILength)
		if err != nil {
			return nil, fmt.Errorf("anchor: deserialize PendingAttestation: %w", err)
		}
		return PendingAttestation{URI: string(uri)}, nil
	case attestationTagBitcoin:
		height, err := readVarUint(payloadReader)
		if err != nil {
			return nil, fmt.Errorf("anchor: deserialize BitcoinBlockHeaderAttestation: %w", err)
		}
		return BitcoinBlockHeaderAttestation{Height: height}, nil
	default:
		return UnknownAttestation{Tag: tagBuf, Payload: payload}, nil
	}
}

func readFull(r *bytes.Reader, buf []byte) error {
	n, err := r.Read(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("short read: got %d bytes, want %d", n, len(buf))
	}
	return nil
}

// maxTimestampRecursionDepth guards against a maliciously or corruptly
// deep tree exhausting the stack, matching the reference implementation's
// recursion limit of 256.
const maxTimestampRecursionDepth = 256

// Timestamp is one node in the OTS commitment tree: the message at this
// node, any attestations directly claiming this message, and any further
// operations branching to child nodes.
type Timestamp struct {
	Msg          []byte
	Attestations []Attestation
	Ops          []OpEdge
}

// OpEdge is one branch: applying Op to the parent's Msg produces Sub.Msg.
type OpEdge struct {
	Op  Op
	Sub *Timestamp
}

// AllAttestations walks the tree and returns every (msg, attestation)
// pair found, at any depth — msg is the message that attestation directly
// commits to (needed later to verify a BitcoinBlockHeaderAttestation
// against a real block's merkle root).
func (t *Timestamp) AllAttestations() []struct {
	Msg         []byte
	Attestation Attestation
} {
	var out []struct {
		Msg         []byte
		Attestation Attestation
	}
	for _, a := range t.Attestations {
		out = append(out, struct {
			Msg         []byte
			Attestation Attestation
		}{Msg: t.Msg, Attestation: a})
	}
	for _, edge := range t.Ops {
		out = append(out, edge.Sub.AllAttestations()...)
	}
	return out
}

// deserializeTimestamp parses an OTS Timestamp tree, mirroring
// python-opentimestamps' Timestamp.deserialize exactly: read one tag byte;
// while it's 0xff, that signals "another branch follows, then keep
// reading"; a 0x00 tag means an attestation follows; any other tag byte is
// an operation, whose result becomes the message for a recursively parsed
// child Timestamp.
func deserializeTimestamp(r *bytes.Reader, msg []byte, depth int) (*Timestamp, error) {
	if depth > maxTimestampRecursionDepth {
		return nil, fmt.Errorf("anchor: timestamp nested too deeply (possible malformed or malicious proof)")
	}

	ts := &Timestamp{Msg: msg}

	handleTag := func(tag byte) error {
		if tag == 0x00 {
			a, err := deserializeAttestation(r)
			if err != nil {
				return err
			}
			ts.Attestations = append(ts.Attestations, a)
			return nil
		}
		op, err := deserializeOp(r, tag)
		if err != nil {
			return err
		}
		result, err := op.Apply(msg)
		if err != nil {
			return fmt.Errorf("anchor: apply op %s: %w", op, err)
		}
		sub, err := deserializeTimestamp(r, result, depth+1)
		if err != nil {
			return err
		}
		ts.Ops = append(ts.Ops, OpEdge{Op: op, Sub: sub})
		return nil
	}

	tagBuf := make([]byte, 1)
	if err := readFull(r, tagBuf); err != nil {
		return nil, fmt.Errorf("anchor: read timestamp tag: %w", err)
	}
	tag := tagBuf[0]

	for tag == 0xff {
		if err := readFull(r, tagBuf); err != nil {
			return nil, fmt.Errorf("anchor: read branch tag after 0xff: %w", err)
		}
		branchTag := tagBuf[0]
		if err := handleTag(branchTag); err != nil {
			return nil, err
		}
		if err := readFull(r, tagBuf); err != nil {
			return nil, fmt.Errorf("anchor: read timestamp tag: %w", err)
		}
		tag = tagBuf[0]
	}
	if err := handleTag(tag); err != nil {
		return nil, err
	}

	return ts, nil
}

// DeserializeTimestamp parses raw bytes as returned by a calendar server
// (POST /digest or GET /timestamp/<hex>) into a Timestamp tree, given the
// message (the digest) the tree is rooted at.
func DeserializeTimestamp(data []byte, rootMsg []byte) (*Timestamp, error) {
	r := bytes.NewReader(data)
	ts, err := deserializeTimestamp(r, rootMsg, 0)
	if err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("anchor: %d trailing bytes after parsing timestamp", r.Len())
	}
	return ts, nil
}
