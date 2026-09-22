package artifacts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// repositoryRoot is the checkout that carries the untracked forge output.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

// protocolRootOrSkip returns one protocol stack's forge output, or skips when
// the stack has not been built. The protocol projects are built in a developer
// checkout but not in CI, where only `contracts/out` exists.
func protocolRootOrSkip(t *testing.T, stack string) string {
	t.Helper()
	root := filepath.Join(repositoryRoot(t), "protocol-projects", stack, "out")
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Skipf("protocol artifacts are absent: %s is not a directory", root)
	}
	return root
}

func TestLoadXIRGateway(t *testing.T) {
	outRoot := filepath.Join(repositoryRoot(t), "contracts", "out")
	artifact, err := artifacts.Load(outRoot, "XIRGateway")
	if err != nil {
		t.Fatalf("load XIRGateway: %v", err)
	}
	path := filepath.Join(outRoot, "XIRGateway.sol", "XIRGateway.json")
	if artifact.Path != path {
		t.Errorf("artifact path = %q, want %q", artifact.Path, path)
	}
	if artifact.Name != "XIRGateway" {
		t.Errorf("artifact name = %q", artifact.Name)
	}
	if len(artifact.Bytecode) == 0 {
		t.Fatal("XIRGateway creation bytecode is empty")
	}
	if len(artifact.DeployedBytecode) == 0 {
		t.Fatal("XIRGateway deployed bytecode is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	digest := sha256.Sum256(raw)
	if artifact.SHA256 != hex.EncodeToString(digest[:]) {
		t.Errorf("artifact sha256 = %q, want %q", artifact.SHA256, hex.EncodeToString(digest[:]))
	}

	registry := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	identifier, err := xir.GatewayTypedID(3133701)
	if err != nil {
		t.Fatalf("gateway typed id: %v", err)
	}
	bare, err := artifact.ConstructorData()
	if err != nil {
		t.Fatalf("constructor data without arguments: %v", err)
	}
	if !bytes.Equal(bare, artifact.Bytecode) {
		t.Fatal("constructor data without arguments differs from the creation bytecode")
	}
	data, err := artifact.ConstructorData(registry, identifier.ABI())
	if err != nil {
		t.Fatalf("constructor data: %v", err)
	}
	// head: address argument || offset of the TypedId tuple; tail: kind,
	// offset of the identifier bytes, byte length, identifier bytes.
	if len(data) != len(artifact.Bytecode)+6*32 {
		t.Fatalf("constructor data length = %d, want %d", len(data), len(artifact.Bytecode)+6*32)
	}
	if !bytes.Equal(data[:len(artifact.Bytecode)], artifact.Bytecode) {
		t.Fatal("constructor data does not start with the creation bytecode")
	}
	args := data[len(artifact.Bytecode):]
	words := make([][]byte, 6)
	for index := range words {
		words[index] = args[index*32 : (index+1)*32]
	}
	if got := common.BytesToAddress(words[0][12:]); got != registry {
		t.Errorf("first argument = %s, want %s", got, registry)
	}
	if new(big.Int).SetBytes(words[1]).Uint64() != 0x40 {
		t.Errorf("TypedId tuple offset = %d, want 64", new(big.Int).SetBytes(words[1]))
	}
	if kind := words[2][31]; kind != xir.KindEVM {
		t.Errorf("TypedId kind = %d, want %d", kind, xir.KindEVM)
	}
	if offset := new(big.Int).SetBytes(words[3]).Uint64(); offset != 0x40 {
		t.Errorf("TypedId value offset = %d, want 64", offset)
	}
	if length := new(big.Int).SetBytes(words[4]).Uint64(); length != 20 {
		t.Errorf("TypedId value length = %d, want 20", length)
	}
	if !bytes.Equal(words[5][:20], identifier.Value) {
		t.Errorf("TypedId value = %x, want %x", words[5][:20], identifier.Value)
	}

	// The encoded arguments must decode back to the values they came from.
	decoded, err := artifact.ABI.ABI().Constructor.Inputs.Unpack(args)
	if err != nil {
		t.Fatalf("decode constructor arguments: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("decoded %d constructor arguments, want 2", len(decoded))
	}
	gotRegistry, err := decodedAddress(decoded[0])
	if err != nil {
		t.Fatalf("decode registry argument: %v", err)
	}
	if gotRegistry != registry {
		t.Errorf("decoded registry = %s, want %s", gotRegistry, registry)
	}
	gotKind, gotValue, err := decodedTypedID(decoded[1])
	if err != nil {
		t.Fatalf("decode identifier argument: %v", err)
	}
	if gotKind != identifier.Kind || !bytes.Equal(gotValue, identifier.Value) {
		t.Errorf(
			"decoded identifier = (%d, %x), want (%d, %x)",
			gotKind, gotValue, identifier.Kind, identifier.Value,
		)
	}
	if _, err := artifact.ConstructorData(registry); err == nil {
		t.Error("missing constructor arguments were accepted")
	}
}

// TestLoadEndpointV2 covers the LayerZero stack artifact. The protocol stacks
// are built in this checkout but not in CI, where only `contracts/out` is
// built, so the test skips when the stack has no forge output.
func TestLoadEndpointV2(t *testing.T) {
	outRoot := protocolRootOrSkip(t, "layerzero-native")
	artifact, err := artifacts.Load(outRoot, "EndpointV2")
	if err != nil {
		t.Fatalf("load EndpointV2: %v", err)
	}
	if len(artifact.Bytecode) == 0 || len(artifact.DeployedBytecode) == 0 {
		t.Fatal("EndpointV2 bytecode is empty")
	}
	if len(artifact.ABI.ABI().Constructor.Inputs) != 2 {
		t.Fatalf(
			"EndpointV2 constructor inputs = %d, want 2",
			len(artifact.ABI.ABI().Constructor.Inputs),
		)
	}
	owner := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	data, err := artifact.ConstructorData(uint32(3133701), owner)
	if err != nil {
		t.Fatalf("constructor data: %v", err)
	}
	if len(data) != len(artifact.Bytecode)+2*32 {
		t.Fatalf("constructor data length = %d, want %d", len(data), len(artifact.Bytecode)+64)
	}
	if !bytes.Equal(data[:len(artifact.Bytecode)], artifact.Bytecode) {
		t.Fatal("constructor data does not start with the creation bytecode")
	}
}

// TestLoadFromSourceFile covers artifacts whose source file name differs from
// the contract name, the only way to reach StaticMessageIdMultisigIsmFactory.
// Like the other protocol-stack test it skips when the stack has no forge
// output, which is the case in CI.
func TestLoadFromSourceFile(t *testing.T) {
	outRoot := protocolRootOrSkip(t, "hyperlane-native")
	if _, err := artifacts.Load(outRoot, "StaticMessageIdMultisigIsmFactory"); err == nil {
		t.Error("same-named artifact path was accepted for a contract in another source file")
	}
	artifact, err := artifacts.LoadFrom(
		outRoot, "StaticMultisigIsm.sol", "StaticMessageIdMultisigIsmFactory",
	)
	if err != nil {
		t.Fatalf("load StaticMessageIdMultisigIsmFactory: %v", err)
	}
	if len(artifact.Bytecode) == 0 {
		t.Fatal("StaticMessageIdMultisigIsmFactory bytecode is empty")
	}
	data, err := artifact.ConstructorData()
	if err != nil {
		t.Fatalf("constructor data: %v", err)
	}
	if !bytes.Equal(data, artifact.Bytecode) {
		t.Fatal("constructor data differs from the creation bytecode")
	}
}

func TestLoadFailsOnMissingInputs(t *testing.T) {
	outRoot := t.TempDir()
	if _, err := artifacts.Load(outRoot, "XIRGateway"); err == nil {
		t.Fatal("missing artifact file was accepted")
	} else if !strings.Contains(err.Error(), "XIRGateway") {
		t.Errorf("missing artifact error does not name the contract: %v", err)
	}
	if _, err := artifacts.Load(outRoot, "../XIRGateway"); err == nil {
		t.Fatal("path-traversing contract name was accepted")
	}
	writeFile(t, filepath.Join(outRoot, "NoABI.sol", "NoABI.json"), `{"bytecode":{"object":"0x00"}}`)
	if _, err := artifacts.Load(outRoot, "NoABI"); err == nil {
		t.Fatal("artifact without an ABI was accepted")
	} else if !strings.Contains(err.Error(), "ABI") {
		t.Errorf("missing ABI error does not mention the ABI: %v", err)
	}
}

func decodedAddress(value any) (common.Address, error) {
	switch typed := value.(type) {
	case common.Address:
		return typed, nil
	case *big.Int:
		return common.BigToAddress(typed), nil
	default:
		return common.Address{}, fmt.Errorf("unsupported address value %T", value)
	}
}

// decodedTypedID reads the (uint8 kind, bytes value) tuple that go-ethereum
// decodes into an anonymous struct.
func decodedTypedID(value any) (uint8, []byte, error) {
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Struct || reflected.NumField() != 2 {
		return 0, nil, fmt.Errorf("unsupported TypedId value %T", value)
	}
	numeric, ok := reflectUint(reflected.Field(0))
	if !ok {
		return 0, nil, fmt.Errorf("TypedId kind field is %s", reflected.Field(0).Kind())
	}
	raw, ok := reflected.Field(1).Interface().([]byte)
	if !ok {
		return 0, nil, fmt.Errorf("TypedId value field is %s", reflected.Field(1).Kind())
	}
	return uint8(numeric), raw, nil
}

func reflectUint(value reflect.Value) (uint64, bool) {
	switch value.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint(), true
	default:
		return 0, false
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
