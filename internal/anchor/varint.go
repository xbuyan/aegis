package anchor

import (
	"bytes"
	"fmt"
	"io"
)

// readVarUint reads an unsigned LEB128 variable-length integer: 7 payload
// bits per byte, low-to-high, with the top bit of each byte set to signal
// "more bytes follow". This is the integer encoding the OpenTimestamps wire
// format uses for lengths and block heights.
func readVarUint(r *bytes.Reader) (uint64, error) {
	var value uint64
	var shift uint
	for {
		if shift >= 64 {
			return 0, fmt.Errorf("anchor: varuint too long (overflow)")
		}
		b, err := r.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("anchor: read varuint: %w", err)
		}
		value |= uint64(b&0b01111111) << shift
		if b&0b10000000 == 0 {
			break
		}
		shift += 7
	}
	return value, nil
}

// readVarBytes reads a varuint length prefix followed by that many raw
// bytes. maxLen bounds the length to defend against a malicious or
// malformed calendar response claiming an absurd size.
func readVarBytes(r *bytes.Reader, maxLen int) ([]byte, error) {
	length, err := readVarUint(r)
	if err != nil {
		return nil, err
	}
	if length > uint64(maxLen) {
		return nil, fmt.Errorf("anchor: varbytes length %d exceeds max %d", length, maxLen)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("anchor: read varbytes body: %w", err)
	}
	return buf, nil
}
