package hyperlane

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// Message layout offsets, in bytes from the start of the packed message.
//
// solidity/contracts/libs/Message.sol:13-19.
const (
	VersionOffset     = 0
	NonceOffset       = 1
	OriginOffset      = 5
	SenderOffset      = 9
	DestinationOffset = 41
	RecipientOffset   = 45
	BodyOffset        = 77
)

// HeaderLength is the size of every Hyperlane message before its body.
//
// solidity/contracts/libs/Message.sol:18-19; the Rust encoder agrees with
// `HYPERLANE_MESSAGE_PREFIX_LEN = 77`
// (rust/main/hyperlane-core/src/types/message.rs:11).
const HeaderLength = BodyOffset

// Message is one packed Hyperlane message: seven fields concatenated with no
// length prefix and no padding.
//
// The type is a plain byte slice, so a decoded message read back from a
// `Dispatch` log or from calldata can be reinterpreted with a conversion. Every
// accessor is total: a slice shorter than the field it covers yields the zero
// value rather than panicking, and Validate reports the malformed length.
type Message []byte

// FormatMessage packs one Hyperlane message.
//
// solidity/contracts/libs/Message.sol:33-52 — `formatMessage` is
// `abi.encodePacked(version, nonce, origin, sender, destination, recipient,
// body)`, so the parameters are mirrored here in the contract's order:
//
//	version     uint8    1 byte  at offset 0
//	nonce       uint32   4 bytes at offset 1   big-endian
//	origin      uint32   4 bytes at offset 5   big-endian
//	sender      bytes32  32 bytes at offset 9  left-padded address
//	destination uint32   4 bytes at offset 41  big-endian
//	recipient   bytes32  32 bytes at offset 45  left-padded address
//	body        bytes    remaining, from offset 77, no padding
//
// The origin Mailbox builds the same bytes in Mailbox.sol:434-457 with
// `VERSION`, its own `nonce` and `localDomain`, and `msg.sender` as the sender.
func FormatMessage(
	version uint8,
	nonce uint32,
	origin uint32,
	sender [32]byte,
	destination uint32,
	recipient [32]byte,
	body []byte,
) []byte {
	message := make([]byte, 0, HeaderLength+len(body))
	message = append(message, version)
	message = binary.BigEndian.AppendUint32(message, nonce)
	message = binary.BigEndian.AppendUint32(message, origin)
	message = append(message, sender[:]...)
	message = binary.BigEndian.AppendUint32(message, destination)
	message = append(message, recipient[:]...)
	return append(message, body...)
}

// MessageID returns the id of a packed message.
//
// solidity/contracts/libs/Message.sol:59-61 — `keccak256(_message)`, computed
// over the raw packed bytes with no domain separator and no length prefix. The
// Mailbox emits this value as `DispatchId` (solidity/contracts/Mailbox.sol:300-303)
// and MerkleTreeHook inserts it as a tree leaf
// (solidity/contracts/hooks/MerkleTreeHook.sol:70-76).
func MessageID(message []byte) [32]byte {
	return xir.Keccak256(message)
}

// Validate reports whether the byte slice is long enough to be a message.
func (m Message) Validate() error {
	if len(m) < BodyOffset {
		return fmt.Errorf(
			"hyperlane: message length %d shorter than the %d-byte header", len(m), BodyOffset,
		)
	}
	return nil
}

// ID returns the id of the message.
func (m Message) ID() [32]byte {
	return MessageID(m)
}

// Version returns the message version (Message.sol:68-70).
func (m Message) Version() uint8 {
	if len(m) < NonceOffset {
		return 0
	}
	return m[VersionOffset]
}

// Nonce returns the message nonce (Message.sol:77-79).
func (m Message) Nonce() uint32 {
	if len(m) < OriginOffset {
		return 0
	}
	return binary.BigEndian.Uint32(m[NonceOffset:OriginOffset])
}

// Origin returns the origin domain (Message.sol:86-88).
func (m Message) Origin() uint32 {
	if len(m) < SenderOffset {
		return 0
	}
	return binary.BigEndian.Uint32(m[OriginOffset:SenderOffset])
}

// Sender returns the sender as bytes32 (Message.sol:95-97).
func (m Message) Sender() [32]byte {
	var sender [32]byte
	if len(m) < DestinationOffset {
		return sender
	}
	copy(sender[:], m[SenderOffset:DestinationOffset])
	return sender
}

// SenderAddress returns the sender as an address and rejects a sender whose
// upper 96 bits are non-zero (Message.sol:105-110 via TypeCasts.sol:11-17).
func (m Message) SenderAddress() (common.Address, error) {
	return Bytes32ToAddress(m.Sender())
}

// Destination returns the destination domain (Message.sol:115-119).
func (m Message) Destination() uint32 {
	if len(m) < RecipientOffset {
		return 0
	}
	return binary.BigEndian.Uint32(m[DestinationOffset:RecipientOffset])
}

// Recipient returns the recipient as bytes32 (Message.sol:126-130).
func (m Message) Recipient() [32]byte {
	var recipient [32]byte
	if len(m) < BodyOffset {
		return recipient
	}
	copy(recipient[:], m[RecipientOffset:BodyOffset])
	return recipient
}

// RecipientAddress returns the recipient as an address and rejects a recipient
// whose upper 96 bits are non-zero (Message.sol:137-142, the address
// `Mailbox.process` calls `handle` on).
func (m Message) RecipientAddress() (common.Address, error) {
	return Bytes32ToAddress(m.Recipient())
}

// Body returns the message body, i.e. everything from offset 77, as a view into
// the message (Message.sol:148-152). The result aliases the receiver.
func (m Message) Body() []byte {
	if len(m) < BodyOffset {
		return nil
	}
	return m[BodyOffset:]
}
