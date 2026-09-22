// Package artifacts loads Foundry build artifacts.
//
// A forge artifact of the contract `Name` compiled from `Name.sol` lives at
// `<outRoot>/Name.sol/Name.json`, the layout that
// `src/xir_lab/native/deployer.py:_artifact` reads. Every field needed to
// broadcast a transaction is exposed: the parsed ABI (through
// internal/abiutil, so tuple arguments can be packed from the artifact's own
// ABI document), the creation bytecode, the deployed bytecode, the artifact
// path, and the sha256 of the artifact file.
package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
)

// Artifact is one loaded forge artifact.
type Artifact struct {
	// Name is the contract name, taken from the caller because a forge
	// artifact file does not always repeat it.
	Name string
	// ABI is the parsed ABI document of the contract.
	ABI *abiutil.Contract
	// Bytecode is the creation bytecode without constructor arguments.
	Bytecode []byte
	// DeployedBytecode is the runtime bytecode the contract ships with.
	DeployedBytecode []byte
	// Path is the artifact file the values were read from.
	Path string
	// SHA256 is the digest of the artifact file, a provenance anchor for the
	// deployment document.
	SHA256 string
}

// document is the subset of the forge artifact schema this package reads.
type document struct {
	ABI              json.RawMessage `json:"abi"`
	Bytecode         ctorObject      `json:"bytecode"`
	DeployedBytecode ctorObject      `json:"deployedBytecode"`
}

type ctorObject struct {
	Object string `json:"object"`
}

// Load reads `<outRoot>/<contractName>.sol/<contractName>.json`.
func Load(outRoot, contractName string) (Artifact, error) {
	if err := checkContractName(contractName); err != nil {
		return Artifact{}, err
	}
	return load(filepath.Join(outRoot, contractName+".sol"), contractName+".json", contractName)
}

// LoadFrom reads `<outRoot>/<sourceFile>/<contractName>.json` for artifacts
// whose source file name differs from the contract name, such as
// `StaticMessageIdMultisigIsmFactory` in `StaticMultisigIsm.sol`. A source
// file without the `.sol` suffix is completed.
func LoadFrom(outRoot, sourceFile, contractName string) (Artifact, error) {
	if err := checkContractName(contractName); err != nil {
		return Artifact{}, err
	}
	if strings.ContainsAny(sourceFile, `/\`) || sourceFile == "" {
		return Artifact{}, fmt.Errorf("artifacts: invalid source file %q", sourceFile)
	}
	if !strings.HasSuffix(sourceFile, ".sol") {
		sourceFile += ".sol"
	}
	return load(filepath.Join(outRoot, sourceFile), contractName+".json", contractName)
}

// ConstructorData returns the deployment transaction data: the creation
// bytecode followed by the ABI-encoded constructor arguments.
func (a Artifact) ConstructorData(args ...any) ([]byte, error) {
	if len(a.Bytecode) == 0 {
		return nil, fmt.Errorf("artifacts: %s has no creation bytecode", a.describe())
	}
	data := append([]byte(nil), a.Bytecode...)
	if len(args) == 0 {
		return data, nil
	}
	constructor := a.ABI.ABI().Constructor
	if len(constructor.Inputs) != len(args) {
		return nil, fmt.Errorf(
			"artifacts: %s constructor takes %d arguments, got %d",
			a.describe(), len(constructor.Inputs), len(args),
		)
	}
	encoded, err := constructor.Inputs.Pack(args...)
	if err != nil {
		return nil, fmt.Errorf("artifacts: pack %s constructor: %w", a.describe(), err)
	}
	return append(data, encoded...), nil
}

func (a Artifact) describe() string {
	if a.Name == "" {
		return a.Path
	}
	return a.Name
}

func load(dir, fileName, contractName string) (Artifact, error) {
	path := filepath.Join(dir, fileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("artifacts: read %s artifact %s: %w", contractName, path, err)
	}
	var parsed document
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Artifact{}, fmt.Errorf("artifacts: parse %s artifact %s: %w", contractName, path, err)
	}
	if len(parsed.ABI) == 0 {
		return Artifact{}, fmt.Errorf("artifacts: %s artifact %s has no ABI", contractName, path)
	}
	contract, err := abiutil.New(string(parsed.ABI))
	if err != nil {
		return Artifact{}, fmt.Errorf("artifacts: %s artifact %s: %w", contractName, path, err)
	}
	contract.SetName(contractName)
	bytecode, err := decodeObject(parsed.Bytecode.Object)
	if err != nil {
		return Artifact{}, fmt.Errorf("artifacts: %s artifact %s bytecode: %w", contractName, path, err)
	}
	deployed, err := decodeObject(parsed.DeployedBytecode.Object)
	if err != nil {
		return Artifact{}, fmt.Errorf(
			"artifacts: %s artifact %s deployedBytecode: %w", contractName, path, err,
		)
	}
	digest := sha256.Sum256(raw)
	return Artifact{
		Name:             contractName,
		ABI:              contract,
		Bytecode:         bytecode,
		DeployedBytecode: deployed,
		Path:             path,
		SHA256:           hex.EncodeToString(digest[:]),
	}, nil
}

func decodeObject(object string) ([]byte, error) {
	if object == "" {
		return nil, nil
	}
	if !strings.HasPrefix(object, "0x") {
		object = "0x" + object
	}
	return abiutil.DecodeHex(object)
}

func checkContractName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("artifacts: invalid contract name %q", name)
	}
	return nil
}
