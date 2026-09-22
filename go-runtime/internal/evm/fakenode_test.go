package evm

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// fakeNode is an in-process JSON-RPC node. It serves exactly the methods the
// runtime uses, and it records every broadcast so a test can prove that a
// resumed action was not sent twice.
type fakeNode struct {
	mu sync.Mutex

	chainID      uint64
	gasPrice     *big.Int
	pendingNonce uint64
	head         uint64

	finalizedSupported bool
	finalizedNumber    uint64
	validatorCount     int

	// blocksBeforeAdvance makes the node reveal one further block after that
	// many eth_blockNumber probes, which is how the QBFT successor wait
	// terminates.
	blocksBeforeAdvance int
	latestQueries       int

	receipts       map[common.Hash]map[string]any
	mineBroadcasts bool
	// mineCreation, when set, is the contract address the node reports for the
	// next mined transaction, i.e. a deployment.
	mineCreation *common.Address

	broadcasts     [][]byte
	broadcastError string

	requests map[string]int
}

type fakeNodeOption func(*fakeNode)

func withFinalizedTag(number uint64) fakeNodeOption {
	return func(node *fakeNode) {
		node.finalizedSupported = true
		node.finalizedNumber = number
	}
}

func withValidators(count int) fakeNodeOption {
	return func(node *fakeNode) { node.validatorCount = count }
}

func withHead(head uint64, blocksBeforeAdvance int) fakeNodeOption {
	return func(node *fakeNode) {
		node.head = head
		node.blocksBeforeAdvance = blocksBeforeAdvance
	}
}

func withPendingNonce(nonce uint64) fakeNodeOption {
	return func(node *fakeNode) { node.pendingNonce = nonce }
}

func withBroadcastError(message string) fakeNodeOption {
	return func(node *fakeNode) { node.broadcastError = message }
}

func withoutMining() fakeNodeOption {
	return func(node *fakeNode) { node.mineBroadcasts = false }
}

func newFakeNode(t *testing.T, options ...fakeNodeOption) *fakeNode {
	t.Helper()
	node := &fakeNode{
		chainID:        31337,
		gasPrice:       big.NewInt(1_500_000_000),
		pendingNonce:   5,
		head:           7,
		validatorCount: 4,
		receipts:       map[common.Hash]map[string]any{},
		mineBroadcasts: true,
		requests:       map[string]int{},
	}
	for _, option := range options {
		option(node)
	}
	return node
}

func fakeNodeServer(t *testing.T, node *fakeNode) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(node)
	t.Cleanup(server.Close)
	return server
}

func (n *fakeNode) requestCount(method string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.requests[method]
}

func (n *fakeNode) recordedBroadcasts() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([][]byte(nil), n.broadcasts...)
}

// seedReceipt registers the receipt a mined transaction would have.
func (n *fakeNode) seedReceipt(hash common.Hash, status uint64, block, gasUsed uint64, contract *common.Address) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.receipts[hash] = n.buildReceiptLocked(hash, status, block, gasUsed, contract)
}

func (n *fakeNode) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	var call struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      json.RawMessage   `json:"id"`
		Method  string            `json:"method"`
		Params  []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(request.Body).Decode(&call); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	n.requests[call.Method]++
	n.mu.Unlock()
	result, rpcError := n.dispatch(call.Method, call.Params)
	writer.Header().Set("Content-Type", "application/json")
	response := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(call.ID)}
	if rpcError != nil {
		response["error"] = rpcError
	} else {
		response["result"] = result
	}
	_ = json.NewEncoder(writer).Encode(response)
}

type rpcFailure struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (n *fakeNode) dispatch(method string, params []json.RawMessage) (any, *rpcFailure) {
	switch method {
	case "eth_chainId":
		return hexutil.EncodeUint64(n.chainID), nil
	case "eth_blockNumber":
		return n.blockNumber()
	case "eth_getTransactionCount":
		n.mu.Lock()
		defer n.mu.Unlock()
		return hexutil.EncodeUint64(n.pendingNonce), nil
	case "eth_gasPrice":
		n.mu.Lock()
		defer n.mu.Unlock()
		return hexutil.EncodeBig(n.gasPrice), nil
	case "eth_sendRawTransaction":
		return n.sendRaw(params)
	case "eth_getTransactionReceipt":
		return n.receipt(params)
	case "eth_getBlockByNumber":
		return n.block(params)
	case "qbft_getValidatorsByBlockNumber":
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.validatorCount == 0 {
			return nil, &rpcFailure{Code: -32601, Message: "the method qbft_getValidatorsByBlockNumber does not exist"}
		}
		validators := make([]string, 0, n.validatorCount)
		for index := 0; index < n.validatorCount; index++ {
			validators = append(validators, common.BigToAddress(big.NewInt(int64(index)+1)).Hex())
		}
		return validators, nil
	default:
		return nil, &rpcFailure{Code: -32601, Message: fmt.Sprintf("the method %s does not exist", method)}
	}
}

func (n *fakeNode) sendRaw(params []json.RawMessage) (any, *rpcFailure) {
	if len(params) != 1 {
		return nil, &rpcFailure{Code: -32602, Message: "eth_sendRawTransaction needs one parameter"}
	}
	var encoded string
	if err := json.Unmarshal(params[0], &encoded); err != nil {
		return nil, &rpcFailure{Code: -32602, Message: "the raw transaction is not hex"}
	}
	raw, err := hexutil.Decode(encoded)
	if err != nil {
		return nil, &rpcFailure{Code: -32602, Message: "the raw transaction is not hex"}
	}
	hash := crypto.Keccak256Hash(raw)
	n.mu.Lock()
	n.broadcasts = append(n.broadcasts, raw)
	if n.mineBroadcasts {
		if _, present := n.receipts[hash]; !present {
			n.receipts[hash] = n.buildReceiptLocked(hash, 1, n.head+1, 21_000, n.mineCreation)
		}
	}
	failure := n.broadcastError
	n.mu.Unlock()
	if failure != "" {
		return nil, &rpcFailure{Code: -32000, Message: failure}
	}
	return hash, nil
}

func (n *fakeNode) receipt(params []json.RawMessage) (any, *rpcFailure) {
	if len(params) != 1 {
		return nil, &rpcFailure{Code: -32602, Message: "eth_getTransactionReceipt needs one parameter"}
	}
	var encoded string
	if err := json.Unmarshal(params[0], &encoded); err != nil {
		return nil, &rpcFailure{Code: -32602, Message: "the transaction hash is not hex"}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	document, present := n.receipts[common.HexToHash(encoded)]
	if !present {
		return nil, nil
	}
	return document, nil
}

// blockNumber serves eth_blockNumber and is the probe the QBFT successor wait
// polls, so it is what makes the head advance.
func (n *fakeNode) blockNumber() (any, *rpcFailure) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.latestQueries++
	if n.blocksBeforeAdvance > 0 && n.latestQueries > n.blocksBeforeAdvance {
		n.head++
		n.blocksBeforeAdvance = 0
	}
	return hexutil.EncodeUint64(n.head), nil
}

func (n *fakeNode) block(params []json.RawMessage) (any, *rpcFailure) {
	if len(params) < 1 {
		return nil, &rpcFailure{Code: -32602, Message: "eth_getBlockByNumber needs a block number"}
	}
	var selector string
	if err := json.Unmarshal(params[0], &selector); err != nil {
		return nil, &rpcFailure{Code: -32602, Message: "the block selector is not a string"}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	switch selector {
	case "finalized":
		if !n.finalizedSupported {
			// Besu's wording for a tag it does not implement, which is the one
			// root_signer._finalized_number tolerates.
			return nil, &rpcFailure{Code: -32602, Message: "unknown block"}
		}
		return n.buildBlockLocked(n.finalizedNumber), nil
	case "latest":
		return n.buildBlockLocked(n.head), nil
	default:
		number, err := hexutil.DecodeUint64(selector)
		if err != nil {
			return nil, &rpcFailure{Code: -32602, Message: "the block selector is not a number"}
		}
		if number > n.head {
			return nil, &rpcFailure{Code: -32602, Message: "unknown block"}
		}
		return n.buildBlockLocked(number), nil
	}
}

// buildBlockLocked returns a header with the fields go-ethereum requires, derived
// deterministically from the block number so the header hash is stable and
// distinct per height.
func (n *fakeNode) buildBlockLocked(number uint64) map[string]any {
	numberHash := common.BigToHash(new(big.Int).SetUint64(number))
	parentHash := common.BigToHash(new(big.Int).SetUint64(number - 1))
	return map[string]any{
		"parentHash":       parentHash,
		"sha3Uncles":       common.Hash{},
		"miner":            common.Address{},
		"stateRoot":        numberHash,
		"transactionsRoot": numberHash,
		"receiptsRoot":     numberHash,
		"logsBloom":        hexutil.Bytes(make([]byte, 256)),
		"difficulty":       "0x1",
		"number":           hexutil.EncodeUint64(number),
		"gasLimit":         "0x1c9c380",
		"gasUsed":          "0x5208",
		"timestamp":        "0x1",
		"extraData":        hexutil.Bytes(numberHash.Bytes()),
		"mixHash":          common.Hash{},
		"nonce":            "0x0000000000000000",
		"baseFeePerGas":    "0x3b9aca00",
		"hash":             numberHash,
	}
}

func (n *fakeNode) buildReceiptLocked(
	hash common.Hash,
	status uint64,
	block uint64,
	gasUsed uint64,
	contract *common.Address,
) map[string]any {
	blockHash := common.BigToHash(new(big.Int).SetUint64(block))
	document := map[string]any{
		"transactionHash":   hash,
		"transactionIndex":  "0x0",
		"blockHash":         blockHash,
		"blockNumber":       hexutil.EncodeUint64(block),
		"from":              common.BigToAddress(big.NewInt(1)),
		"to":                common.BigToAddress(big.NewInt(2)),
		"cumulativeGasUsed": hexutil.EncodeUint64(gasUsed),
		"gasUsed":           hexutil.EncodeUint64(gasUsed),
		"effectiveGasPrice": "0x3b9aca00",
		"contractAddress":   nil,
		"logs":              []any{},
		"logsBloom":         hexutil.Bytes(make([]byte, 256)),
		"status":            hexutil.EncodeUint64(status),
		"type":              "0x2",
	}
	if contract != nil {
		document["contractAddress"] = strings.ToLower(contract.Hex())
	}
	return document
}
