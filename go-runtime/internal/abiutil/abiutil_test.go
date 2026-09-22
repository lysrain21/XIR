package abiutil

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const verifyFragment = `[{"type":"function","name":"verify","stateMutability":"view",
 "inputs":[{"name":"profileHash","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"},
           {"name":"transitionHash","type":"bytes32"}],
 "outputs":[{"type":"bool"}]}]`

func TestPackCallPrefixesSelectorExactlyOnce(t *testing.T) {
	contract, err := New(verifyFragment)
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	method, ok := contract.ABI().Methods["verify"]
	if !ok {
		t.Fatal("verify method is missing")
	}
	data, err := contract.PackCall("verify", [32]byte{1}, [32]byte{2}, [32]byte{3})
	if err != nil {
		t.Fatalf("pack call: %v", err)
	}
	if !bytes.HasPrefix(data, method.ID[:]) {
		t.Fatalf("calldata does not start with the selector: %x", data[:8])
	}
	if bytes.HasPrefix(data[4:], method.ID[:]) {
		t.Fatalf("calldata repeats the selector: %x", data[:12])
	}
	if len(data) != 4+96 {
		t.Fatalf("calldata is %d bytes, want 100", len(data))
	}
}

func TestPackEncodeMatchesAbiEncodeLayout(t *testing.T) {
	fragments := `[{"name":"domain","type":"uint32"},{"name":"sender","type":"bytes32"},{"name":"body","type":"bytes"}]`
	encoded, err := PackEncode(fragments, uint32(7), [32]byte{8}, []byte{9, 9})
	if err != nil {
		t.Fatalf("pack encode: %v", err)
	}
	// abi.encode(uint32,bytes32,bytes): three head words, then length and data.
	if len(encoded) != 96+32+32 {
		t.Fatalf("abi.encode output is %d bytes, want 160", len(encoded))
	}
	if binary.BigEndian.Uint32(encoded[28:32]) != 7 {
		t.Fatalf("first word does not carry the uint32 value: %x", encoded[:32])
	}
	if encoded[32] != 8 || encoded[33] != 0 {
		t.Fatalf("second word does not carry the bytes32 value: %x", encoded[32:64])
	}
	if binary.BigEndian.Uint32(encoded[124:128]) != 2 {
		t.Fatalf("bytes length word is %d, want 2", binary.BigEndian.Uint32(encoded[124:128]))
	}
}

func TestPackArgumentRejectsMalformedFragments(t *testing.T) {
	if _, err := PackArgument(`{"name":"x","type":"uint257"}`, uint64(1)); err == nil {
		t.Fatal("malformed fragment was accepted")
	}
}

func TestDecodeHexRejectsNonHex(t *testing.T) {
	if _, err := DecodeHex("0xzz"); err == nil {
		t.Fatal("non-hex input was accepted")
	}
	if decoded, err := DecodeHex("0x0a0b"); err != nil || len(decoded) != 2 || decoded[1] != 0x0b {
		t.Fatalf("0x0a0b decoded to %x with error %v", decoded, err)
	}
}

const eventFragment = `[{"type":"event","name":"Routed","inputs":[
  {"name":"rid","type":"bytes32","indexed":true},
  {"name":"receiver","type":"address","indexed":true},
  {"name":"count","type":"uint64","indexed":false},
  {"name":"blob","type":"bytes","indexed":true}]}]`

func TestUnpackLogDecodesIndexedAndDataArguments(t *testing.T) {
	contract, err := New(eventFragment)
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	topic, err := contract.EventTopic("Routed")
	if err != nil {
		t.Fatalf("event topic: %v", err)
	}
	var rid common.Hash
	rid[31] = 9
	receiver := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	blobHash := common.HexToHash("0x11")
	log := &types.Log{
		Topics: []common.Hash{topic, rid, common.BytesToHash(receiver.Bytes()), blobHash},
		Data:   common.LeftPadBytes(big.NewInt(7).Bytes(), 32),
	}
	values, err := contract.UnpackLog("Routed", log)
	if err != nil {
		t.Fatalf("unpack log: %v", err)
	}
	if observed, ok := values["rid"].([32]byte); !ok || observed != [32]byte(rid) {
		t.Fatalf("rid decoded to %#v", values["rid"])
	}
	if observed, ok := values["receiver"].(common.Address); !ok || observed != receiver {
		t.Fatalf("receiver decoded to %#v", values["receiver"])
	}
	if observed, ok := values["count"].(uint64); !ok || observed != 7 {
		t.Fatalf("count decoded to %#v", values["count"])
	}
	if observed, ok := values["blob"].(common.Hash); !ok || observed != blobHash {
		t.Fatalf("dynamic indexed blob decoded to %#v", values["blob"])
	}
}

func TestUnpackLogRejectsTopicCountMismatch(t *testing.T) {
	contract, err := New(eventFragment)
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	topic, err := contract.EventTopic("Routed")
	if err != nil {
		t.Fatalf("event topic: %v", err)
	}
	log := &types.Log{Topics: []common.Hash{topic}, Data: make([]byte, 32)}
	if _, err := contract.UnpackLog("Routed", log); err == nil {
		t.Fatal("a log without its indexed topics was accepted")
	}
}

const createFragment = `[{"type":"function","name":"create","stateMutability":"nonpayable",
 "inputs":[{"name":"destination","type":"address"}],
 "outputs":[{"name":"rid","type":"bytes32"},{"name":"mid","type":"bytes32"}]},
 {"type":"function","name":"selfId","stateMutability":"view","inputs":[],
  "outputs":[{"name":"id","type":"address"}]}]`

func TestUnpackOutputsAcceptsSingleAndMultipleDestinations(t *testing.T) {
	contract, err := New(createFragment)
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	var rid, mid common.Hash
	rid[31] = 3
	mid[31] = 4
	data := append(rid.Bytes(), mid.Bytes()...)
	if err := contract.UnpackOutputs("create", data, &rid, &mid); err != nil {
		t.Fatalf("unpack two destinations: %v", err)
	}
	if rid[31] != 3 || mid[31] != 4 {
		t.Fatalf("decoded %x %x", rid, mid)
	}
	var id common.Address
	if err := contract.UnpackOutputs("selfId", common.LeftPadBytes([]byte{0xaa}, 32), &id); err != nil {
		t.Fatalf("unpack one destination: %v", err)
	}
	if id != common.HexToAddress("0x00000000000000000000000000000000000000aa") {
		t.Fatalf("selfId decoded to %s", id)
	}
	if err := contract.UnpackOutputs("create", data, &rid); err == nil {
		t.Fatal("a missing destination was accepted")
	}
}

func TestUnpackOutputsRejectsNonPointerDestination(t *testing.T) {
	contract, err := New(createFragment)
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	var rid, mid common.Hash
	data := append(rid.Bytes(), mid.Bytes()...)
	if err := contract.UnpackOutputs("create", data, rid, mid); err == nil {
		t.Fatal("non-pointer destinations were accepted")
	}
}
