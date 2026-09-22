package hyperlane

import (
	"encoding/binary"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// EvidenceHash returns the evidence hash the XIR runtime records for a Hyperlane
// hop and the analysis tooling recomputes.
//
// src/xir_lab/native/multihop_runner.py:1190-1200 (`_dispatch_hop`, protocol "H"):
//
//	evidence = keccak(encode(["uint32", "bytes32", "bytes"], [domain, sender, body]))
//
// where `domain` is the source role's Hyperlane domain, `sender` is the origin
// adapter address as bytes32 (12 zero bytes then the 20 address bytes), and `body`
// is the adapter's outbound body — `abi.encode(uint8 kind, bytes inner)` with
// kind 3 for an XIR bundle. The same triple is asserted against the parity
// vectors in go-runtime/testdata/vectors.json.
//
// The encoding is standard ABI encoding, not `abi.encodePacked`: three 32-byte
// head words (domain, sender, offset 96) followed by the length of body and the
// body padded to a 32-byte boundary. The domain occupies the low 4 bytes of its
// word and the high 28 bytes are zero.
func EvidenceHash(domain uint32, sender [32]byte, body []byte) [32]byte {
	bodyWords := (len(body) + 31) / 32
	encoded := make([]byte, (4+bodyWords)*32)
	binary.BigEndian.PutUint32(encoded[28:32], domain)
	copy(encoded[32:64], sender[:])
	binary.BigEndian.PutUint64(encoded[88:96], 96)
	binary.BigEndian.PutUint64(encoded[120:128], uint64(len(body)))
	copy(encoded[128:], body)
	return xir.Keccak256(encoded)
}
