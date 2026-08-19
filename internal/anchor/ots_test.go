package anchor

import (
	"bytes"
	"testing"
)

// pendingAttestationBytes builds the exact wire encoding for a single
// PendingAttestation, matching python-opentimestamps' test fixtures:
// TAG(8) + varbytes(varbytes(uri)) — i.e. outer length byte, inner length
// byte, then the URI bytes.
func pendingAttestationBytes(uri string) []byte {
	var buf bytes.Buffer
	buf.Write(attestationTagPending[:])
	inner := append([]byte{byte(len(uri))}, []byte(uri)...)
	buf.WriteByte(byte(len(inner)))
	buf.Write(inner)
	return buf.Bytes()
}

// TestDeserialize_SinglePendingAttestation mirrors the reference test
// vector exactly:
// T(stamp, b'\x00' + TAG + '07' + '06' + b'foobar')
func TestDeserialize_SinglePendingAttestation(t *testing.T) {
	data := append([]byte{0x00}, pendingAttestationBytes("foobar")...)

	ts, err := DeserializeTimestamp(data, []byte("foo"))
	if err != nil {
		t.Fatalf("DeserializeTimestamp: %v", err)
	}

	if len(ts.Attestations) != 1 {
		t.Fatalf("got %d attestations, want 1", len(ts.Attestations))
	}
	pa, ok := ts.Attestations[0].(PendingAttestation)
	if !ok {
		t.Fatalf("attestation type = %T, want PendingAttestation", ts.Attestations[0])
	}
	if pa.URI != "foobar" {
		t.Errorf("URI = %q, want %q", pa.URI, "foobar")
	}
	if string(ts.Msg) != "foo" {
		t.Errorf("Msg = %q, want %q", ts.Msg, "foo")
	}
}

// TestDeserialize_TwoPendingAttestations mirrors the reference vector:
// T(stamp, b'\xff' + (0x00+TAG+07+06+barfoo) + (0x00+TAG+07+06+foobar))
func TestDeserialize_TwoPendingAttestations(t *testing.T) {
	var data []byte
	data = append(data, 0xff)
	data = append(data, 0x00)
	data = append(data, pendingAttestationBytes("barfoo")...)
	data = append(data, 0x00)
	data = append(data, pendingAttestationBytes("foobar")...)

	ts, err := DeserializeTimestamp(data, []byte("foo"))
	if err != nil {
		t.Fatalf("DeserializeTimestamp: %v", err)
	}

	if len(ts.Attestations) != 2 {
		t.Fatalf("got %d attestations, want 2", len(ts.Attestations))
	}
	uris := map[string]bool{}
	for _, a := range ts.Attestations {
		pa, ok := a.(PendingAttestation)
		if !ok {
			t.Fatalf("attestation type = %T, want PendingAttestation", a)
		}
		uris[pa.URI] = true
	}
	if !uris["barfoo"] || !uris["foobar"] {
		t.Errorf("got URIs %v, want barfoo and foobar", uris)
	}
}

// TestDeserialize_OpThenAttestation mirrors the reference vector's final
// (deepest) case: b'\x08' (OpSHA256) + a Timestamp for sha256(msg)
// containing a single PendingAttestation("deeper").
func TestDeserialize_OpThenAttestation(t *testing.T) {
	var data []byte
	data = append(data, opTagSHA256)
	data = append(data, 0x00)
	data = append(data, pendingAttestationBytes("deeper")...)

	ts, err := DeserializeTimestamp(data, []byte("foo"))
	if err != nil {
		t.Fatalf("DeserializeTimestamp: %v", err)
	}

	if len(ts.Ops) != 1 {
		t.Fatalf("got %d ops, want 1", len(ts.Ops))
	}
	edge := ts.Ops[0]
	if _, ok := edge.Op.(OpSHA256); !ok {
		t.Fatalf("op type = %T, want OpSHA256", edge.Op)
	}
	wantMsg, _ := OpSHA256{}.Apply([]byte("foo"))
	if !bytes.Equal(edge.Sub.Msg, wantMsg) {
		t.Errorf("child Msg = %x, want %x (sha256 of parent msg)", edge.Sub.Msg, wantMsg)
	}
	if len(edge.Sub.Attestations) != 1 {
		t.Fatalf("child got %d attestations, want 1", len(edge.Sub.Attestations))
	}
	pa, ok := edge.Sub.Attestations[0].(PendingAttestation)
	if !ok || pa.URI != "deeper" {
		t.Errorf("child attestation = %v, want PendingAttestation(deeper)", edge.Sub.Attestations[0])
	}
}

func TestDeserialize_AppendThenBitcoinAttestation(t *testing.T) {
	// append "bar" to "foo" -> "foobar", then a Bitcoin attestation at
	// height 700000 claiming msg "foobar" is a block's merkle root.
	payload := varUintBytes(700000)

	var attBytes []byte
	attBytes = append(attBytes, attestationTagBitcoin[:]...)
	attBytes = append(attBytes, byte(len(payload)))
	attBytes = append(attBytes, payload...)

	var data []byte
	data = append(data, opTagAppend)
	data = append(data, 0x03) // varbytes length for "bar"
	data = append(data, []byte("bar")...)
	data = append(data, 0x00)
	data = append(data, attBytes...)

	ts, err := DeserializeTimestamp(data, []byte("foo"))
	if err != nil {
		t.Fatalf("DeserializeTimestamp: %v", err)
	}

	if len(ts.Ops) != 1 {
		t.Fatalf("got %d ops, want 1", len(ts.Ops))
	}
	edge := ts.Ops[0]
	appendOp, ok := edge.Op.(OpAppend)
	if !ok {
		t.Fatalf("op type = %T, want OpAppend", edge.Op)
	}
	if string(appendOp.Arg) != "bar" {
		t.Errorf("append arg = %q, want %q", appendOp.Arg, "bar")
	}
	if string(edge.Sub.Msg) != "foobar" {
		t.Errorf("child Msg = %q, want %q", edge.Sub.Msg, "foobar")
	}

	if len(edge.Sub.Attestations) != 1 {
		t.Fatalf("child got %d attestations, want 1", len(edge.Sub.Attestations))
	}
	ba, ok := edge.Sub.Attestations[0].(BitcoinBlockHeaderAttestation)
	if !ok {
		t.Fatalf("attestation type = %T, want BitcoinBlockHeaderAttestation", edge.Sub.Attestations[0])
	}
	if ba.Height != 700000 {
		t.Errorf("Height = %d, want 700000", ba.Height)
	}
}

// varUintBytes is a tiny test-only LEB128 encoder, used to build fixture
// bytes for attestation payloads (production code only ever decodes).
func varUintBytes(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v != 0 {
		b := byte(v & 0b01111111)
		v >>= 7
		if v != 0 {
			b |= 0b10000000
		}
		out = append(out, b)
	}
	return out
}

func TestDeserialize_UnknownOpTagRejected(t *testing.T) {
	data := []byte{0x42} // not a valid opcode, matches reference test's own example
	_, err := DeserializeTimestamp(data, []byte("foo"))
	if err == nil {
		t.Fatal("DeserializeTimestamp with unknown op tag: want error, got nil")
	}
}

func TestDeserialize_UnknownAttestationTagPreserved(t *testing.T) {
	var data []byte
	data = append(data, 0x00)
	data = append(data, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22) // unrecognized 8-byte tag
	data = append(data, 0x03)                                          // payload length
	data = append(data, []byte("xyz")...)

	ts, err := DeserializeTimestamp(data, []byte("foo"))
	if err != nil {
		t.Fatalf("DeserializeTimestamp: %v", err)
	}
	if len(ts.Attestations) != 1 {
		t.Fatalf("got %d attestations, want 1", len(ts.Attestations))
	}
	ua, ok := ts.Attestations[0].(UnknownAttestation)
	if !ok {
		t.Fatalf("attestation type = %T, want UnknownAttestation", ts.Attestations[0])
	}
	if string(ua.Payload) != "xyz" {
		t.Errorf("Payload = %q, want %q", ua.Payload, "xyz")
	}
}

func TestDeserialize_TruncatedDataErrors(t *testing.T) {
	data := []byte{0x00, 0x83, 0xdf} // attestation marker + partial tag
	_, err := DeserializeTimestamp(data, []byte("foo"))
	if err == nil {
		t.Fatal("DeserializeTimestamp on truncated data: want error, got nil")
	}
}

func TestDeserialize_TrailingBytesRejected(t *testing.T) {
	data := append(append([]byte{0x00}, pendingAttestationBytes("foobar")...), 0xFF, 0xFF)
	_, err := DeserializeTimestamp(data, []byte("foo"))
	if err == nil {
		t.Fatal("DeserializeTimestamp with trailing garbage: want error, got nil")
	}
}

func TestAllAttestations_WalksNestedTree(t *testing.T) {
	var data []byte
	data = append(data, opTagSHA256)
	data = append(data, 0x00)
	data = append(data, pendingAttestationBytes("deeper")...)

	ts, err := DeserializeTimestamp(data, []byte("foo"))
	if err != nil {
		t.Fatalf("DeserializeTimestamp: %v", err)
	}

	all := ts.AllAttestations()
	if len(all) != 1 {
		t.Fatalf("got %d total attestations, want 1", len(all))
	}
	wantMsg, _ := OpSHA256{}.Apply([]byte("foo"))
	if !bytes.Equal(all[0].Msg, wantMsg) {
		t.Errorf("attestation msg = %x, want %x", all[0].Msg, wantMsg)
	}
}
