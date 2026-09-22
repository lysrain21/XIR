package layerzero

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
)

// The ABI fragments below are the members of the official LayerZero V2
// contracts that this runtime encodes or decodes. They are copied verbatim from
// protocol-projects/layerzero-native/out/<Name>.sol/<Name>.json, because
// abiutil packs tuple arguments from ABI components rather than from type
// strings.
const dvnABIDocument = `[
  {
    "type": "function",
    "name": "execute",
    "stateMutability": "nonpayable",
    "inputs": [
      {
        "name": "_params",
        "type": "tuple[]",
        "internalType": "struct ExecuteParam[]",
        "components": [
          {"name": "vid", "type": "uint32", "internalType": "uint32"},
          {"name": "target", "type": "address", "internalType": "address"},
          {"name": "callData", "type": "bytes", "internalType": "bytes"},
          {"name": "expiration", "type": "uint256", "internalType": "uint256"},
          {"name": "signatures", "type": "bytes", "internalType": "bytes"}
        ]
      }
    ],
    "outputs": []
  }
]`

const receiveULNABIDocument = `[
  {
    "type": "function",
    "name": "verify",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "_packetHeader", "type": "bytes", "internalType": "bytes"},
      {"name": "_payloadHash", "type": "bytes32", "internalType": "bytes32"},
      {"name": "_confirmations", "type": "uint64", "internalType": "uint64"}
    ],
    "outputs": []
  },
  {
    "type": "function",
    "name": "commitVerification",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "_packetHeader", "type": "bytes", "internalType": "bytes"},
      {"name": "_payloadHash", "type": "bytes32", "internalType": "bytes32"}
    ],
    "outputs": []
  },
  {
    "type": "event",
    "name": "PayloadVerified",
    "anonymous": false,
    "inputs": [
      {"name": "dvn", "type": "address", "indexed": false, "internalType": "address"},
      {"name": "header", "type": "bytes", "indexed": false, "internalType": "bytes"},
      {"name": "confirmations", "type": "uint256", "indexed": false, "internalType": "uint256"},
      {"name": "proofHash", "type": "bytes32", "indexed": false, "internalType": "bytes32"}
    ]
  }
]`

const executorABIDocument = `[
  {
    "type": "function",
    "name": "execute302",
    "stateMutability": "payable",
    "inputs": [
      {
        "name": "_executionParams",
        "type": "tuple",
        "internalType": "struct IExecutor.ExecutionParams",
        "components": [
          {"name": "receiver", "type": "address", "internalType": "address"},
          {
            "name": "origin",
            "type": "tuple",
            "internalType": "struct Origin",
            "components": [
              {"name": "srcEid", "type": "uint32", "internalType": "uint32"},
              {"name": "sender", "type": "bytes32", "internalType": "bytes32"},
              {"name": "nonce", "type": "uint64", "internalType": "uint64"}
            ]
          },
          {"name": "guid", "type": "bytes32", "internalType": "bytes32"},
          {"name": "message", "type": "bytes", "internalType": "bytes"},
          {"name": "extraData", "type": "bytes", "internalType": "bytes"},
          {"name": "gasLimit", "type": "uint256", "internalType": "uint256"}
        ]
      }
    ],
    "outputs": []
  }
]`

const endpointV2ABIDocument = `[
  {
    "type": "event",
    "name": "PacketSent",
    "anonymous": false,
    "inputs": [
      {"name": "encodedPayload", "type": "bytes", "indexed": false, "internalType": "bytes"},
      {"name": "options", "type": "bytes", "indexed": false, "internalType": "bytes"},
      {"name": "sendLibrary", "type": "address", "indexed": false, "internalType": "address"}
    ]
  },
  {
    "type": "event",
    "name": "PacketVerified",
    "anonymous": false,
    "inputs": [
      {
        "name": "origin",
        "type": "tuple",
        "indexed": false,
        "internalType": "struct Origin",
        "components": [
          {"name": "srcEid", "type": "uint32", "indexed": false, "internalType": "uint32"},
          {"name": "sender", "type": "bytes32", "indexed": false, "internalType": "bytes32"},
          {"name": "nonce", "type": "uint64", "indexed": false, "internalType": "uint64"}
        ]
      },
      {"name": "receiver", "type": "address", "indexed": false, "internalType": "address"},
      {"name": "payloadHash", "type": "bytes32", "indexed": false, "internalType": "bytes32"}
    ]
  },
  {
    "type": "event",
    "name": "PacketDelivered",
    "anonymous": false,
    "inputs": [
      {
        "name": "origin",
        "type": "tuple",
        "indexed": false,
        "internalType": "struct Origin",
        "components": [
          {"name": "srcEid", "type": "uint32", "indexed": false, "internalType": "uint32"},
          {"name": "sender", "type": "bytes32", "indexed": false, "internalType": "bytes32"},
          {"name": "nonce", "type": "uint64", "indexed": false, "internalType": "uint64"}
        ]
      },
      {"name": "receiver", "type": "address", "indexed": false, "internalType": "address"}
    ]
  }
]`

// The parsed fragments. The documents are compile-time constants, so a parse
// failure would be a defect in this package; the tests parse them first.
var (
	dvnContract        = mustContract("DVN", dvnABIDocument)
	receiveULNContract = mustContract("ReceiveUln302", receiveULNABIDocument)
	executorContract   = mustContract("Executor", executorABIDocument)
	endpointV2Contract = mustContract("EndpointV2", endpointV2ABIDocument)
)

func mustContract(name, document string) *abiutil.Contract {
	contract, err := abiutil.New(document)
	if err != nil {
		panic(err)
	}
	contract.SetName(name)
	return contract
}

// dvnExecuteParam is the ABI shape of official DVN.ExecuteParam.
type dvnExecuteParam struct {
	VID        uint32         `abi:"vid"`
	Target     common.Address `abi:"target"`
	CallData   []byte         `abi:"callData"`
	Expiration *big.Int       `abi:"expiration"`
	Signatures []byte         `abi:"signatures"`
}

// originParam is the ABI shape of the official Origin struct.
type originParam struct {
	SourceEID uint32   `abi:"srcEid"`
	Sender    [32]byte `abi:"sender"`
	Nonce     uint64   `abi:"nonce"`
}

// executionParams is the ABI shape of IExecutor.ExecutionParams.
type executionParams struct {
	Receiver  common.Address `abi:"receiver"`
	Origin    originParam    `abi:"origin"`
	GUID      [32]byte       `abi:"guid"`
	Message   []byte         `abi:"message"`
	ExtraData []byte         `abi:"extraData"`
	GasLimit  *big.Int       `abi:"gasLimit"`
}

// DVNExpiration recovers the deadline from a single frozen execute instruction.
// Rebuilding with that deadline preserves both the signature and calldata; the
// transactor still checks the complete plan against the frozen identity.
func DVNExpiration(data []byte) (*big.Int, error) {
	method := dvnContract.ABI().Methods["execute"]
	if len(data) < 4 || !bytes.Equal(data[:4], method.ID) {
		return nil, fmt.Errorf("not DVN.execute calldata")
	}
	values, err := method.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, err
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("expected execute parameters")
	}
	params := *abi.ConvertType(values[0], new([]dvnExecuteParam)).(*[]dvnExecuteParam)
	if len(params) != 1 || params[0].Expiration == nil {
		return nil, fmt.Errorf("expected one DVN instruction")
	}
	return new(big.Int).Set(params[0].Expiration), nil
}
