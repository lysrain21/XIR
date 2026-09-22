// Package evm is the XIR Go runtime's EVM transport: a JSON-RPC client, an
// EIP-1559/personal-digest signer, and a transactor that keeps the
// intent -> frozen calldata -> signed -> submitted -> receipt chain durable
// across a process restart.
//
// The transport rules mirror the Python reference runtime:
//
//   - root_signer.Web3RootCreationSource._finalized_number reads the RPC
//     “finalized“ tag and falls back to Besu's private-QBFT rule (validator
//     quorum plus one successor block on the canonical chain);
//   - rpc.is_transient_rpc_error classifies a failure that is safe to retry
//     unchanged;
//   - multihop_runner.NativeMultihopRunner._transact/_validate_durable_raw
//     freeze the calldata digest, sign, persist the raw transaction, broadcast,
//     and re-validate every field before a rebroadcast.
package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// qbftConfirmationBlocks is the successor depth root_signer.py requires of a
// private QBFT network before it treats a block as final.
const qbftConfirmationBlocks = 1

// qbftValidatorQuorum is the validator count root_signer.py demands before it
// accepts the QBFT finality rule.
const qbftValidatorQuorum = 4

// finalizedPollInterval matches root_signer.py's 0.25 second wait between head
// observations.
const finalizedPollInterval = 250 * time.Millisecond

// Client is a JSON-RPC client bound to one chain, with a per-call deadline.
type Client struct {
	rpc        *rpc.Client
	eth        *ethclient.Client
	url        string
	timeout    time.Duration
	chainID    *big.Int
	qbftQuorum int
}

// Dial connects to url and verifies the chain identity before returning, so a
// transactor can never sign for the wrong network.
func Dial(ctx context.Context, url string, timeout time.Duration) (*Client, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("xir evm: empty RPC endpoint")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("xir evm: RPC timeout %s is not positive", timeout)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rpcClient, err := rpc.DialContext(callCtx, url)
	if err != nil {
		return nil, fmt.Errorf("xir evm: cannot dial %s: %w", url, err)
	}
	client := &Client{
		rpc:        rpcClient,
		eth:        ethclient.NewClient(rpcClient),
		url:        url,
		timeout:    timeout,
		qbftQuorum: qbftValidatorQuorum,
	}
	chainID, err := client.eth.ChainID(callCtx)
	if err != nil {
		rpcClient.Close()
		return nil, fmt.Errorf("xir evm: %s does not report a chain id: %w", url, err)
	}
	if chainID == nil || chainID.Sign() <= 0 {
		rpcClient.Close()
		return nil, fmt.Errorf("xir evm: %s reports chain id %v", url, chainID)
	}
	client.chainID = chainID
	return client, nil
}

// Close releases the underlying connection.
func (c *Client) Close() {
	if c == nil || c.rpc == nil {
		return
	}
	c.rpc.Close()
}

// ChainID returns the chain id observed at dial time.
func (c *Client) ChainID(ctx context.Context) (*big.Int, error) {
	observed, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (*big.Int, error) {
		return c.eth.ChainID(callCtx)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_chainId failed: %w", err)
	}
	return observed, nil
}

// BlockNumber returns the latest block height.
func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	number, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (uint64, error) {
		return c.eth.BlockNumber(callCtx)
	})
	if err != nil {
		return 0, fmt.Errorf("xir evm: eth_blockNumber failed: %w", err)
	}
	return number, nil
}

// PendingNonce returns the next nonce the chain would assign, counting the
// transactions still in the pool.
func (c *Client) PendingNonce(ctx context.Context, address common.Address) (uint64, error) {
	nonce, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (uint64, error) {
		return c.eth.PendingNonceAt(callCtx, address)
	})
	if err != nil {
		return 0, fmt.Errorf("xir evm: eth_getTransactionCount failed: %w", err)
	}
	return nonce, nil
}

// BalanceAt returns the account balance in wei.
func (c *Client) BalanceAt(ctx context.Context, address common.Address) (*big.Int, error) {
	balance, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (*big.Int, error) {
		return c.eth.BalanceAt(callCtx, address, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_getBalance failed: %w", err)
	}
	return balance, nil
}

// CodeAt returns the deployed bytecode of an account.
func (c *Client) CodeAt(ctx context.Context, address common.Address) ([]byte, error) {
	code, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) ([]byte, error) {
		return c.eth.CodeAt(callCtx, address, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_getCode failed: %w", err)
	}
	return code, nil
}

// CallContract performs an eth_call against the latest block.
func (c *Client) CallContract(ctx context.Context, to common.Address, data []byte) ([]byte, error) {
	result, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) ([]byte, error) {
		return c.eth.CallContract(callCtx, ethereum.CallMsg{To: &to, Data: data}, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_call failed: %w", err)
	}
	return result, nil
}

// CallContractAtHash reads the exact historical block that produced an event.
func (c *Client) CallContractAtHash(ctx context.Context, to common.Address, data []byte, hash common.Hash) ([]byte, error) {
	result, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) ([]byte, error) {
		return c.eth.CallContractAtHash(callCtx, ethereum.CallMsg{To: &to, Data: data}, hash)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: historical eth_call failed: %w", err)
	}
	return result, nil
}

// EstimateGas returns the node's gas estimate for a call message.
func (c *Client) EstimateGas(ctx context.Context, message ethereum.CallMsg) (uint64, error) {
	estimate, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (uint64, error) {
		return c.eth.EstimateGas(callCtx, message)
	})
	if err != nil {
		return 0, fmt.Errorf("xir evm: eth_estimateGas failed: %w", err)
	}
	return estimate, nil
}

// GasPrice returns the suggested gas price.
func (c *Client) GasPrice(ctx context.Context) (*big.Int, error) {
	price, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (*big.Int, error) {
		return c.eth.SuggestGasPrice(callCtx)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_gasPrice failed: %w", err)
	}
	return price, nil
}

// Receipt returns a mined receipt, or nil when the transaction is not mined yet.
func (c *Client) Receipt(ctx context.Context, hash common.Hash) (*types.Receipt, error) {
	_, receipt, err := c.ReceiptDocument(ctx, hash)
	return receipt, err
}

// ReceiptDocument returns both the node's raw receipt JSON (the exact document
// the runtime spools as evidence) and its decoded form. A transaction that is
// not mined yet yields (nil, nil, nil).
func (c *Client) ReceiptDocument(ctx context.Context, hash common.Hash) (json.RawMessage, *types.Receipt, error) {
	raw, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (json.RawMessage, error) {
		var result json.RawMessage
		if err := c.rpc.CallContext(callCtx, &result, "eth_getTransactionReceipt", hash); err != nil {
			return nil, err
		}
		return result, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("xir evm: eth_getTransactionReceipt failed: %w", err)
	}
	if isJSONNull(raw) {
		return nil, nil, nil
	}
	var receipt types.Receipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, nil, fmt.Errorf("xir evm: receipt %s is not decodable: %w", hash, err)
	}
	return raw, &receipt, nil
}

// Logs returns the logs matching a filter query.
func (c *Client) Logs(ctx context.Context, query ethereum.FilterQuery) ([]types.Log, error) {
	logs, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) ([]types.Log, error) {
		return c.eth.FilterLogs(callCtx, query)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_getLogs failed: %w", err)
	}
	return logs, nil
}

// HeaderByNumber returns one header; a nil number means the latest block, and
// the negative block tags (pending/finalized/safe) are accepted.
func (c *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	header, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (*types.Header, error) {
		return c.eth.HeaderByNumber(callCtx, number)
	})
	if err != nil {
		return nil, fmt.Errorf("xir evm: eth_getBlockByNumber failed: %w", err)
	}
	return header, nil
}

// SendRawTransaction broadcasts already-signed bytes.
func (c *Client) SendRawTransaction(ctx context.Context, raw []byte) error {
	if len(raw) == 0 {
		return errors.New("xir evm: empty raw transaction")
	}
	_, err := withTimeout(ctx, c.timeout, func(callCtx context.Context) (common.Hash, error) {
		var hash common.Hash
		if err := c.rpc.CallContext(callCtx, &hash, "eth_sendRawTransaction", hexutil.Encode(raw)); err != nil {
			return common.Hash{}, err
		}
		return hash, nil
	})
	if err != nil {
		return fmt.Errorf("xir evm: eth_sendRawTransaction failed: %w", err)
	}
	return nil
}

// WaitMined polls until the transaction has a receipt or the timeout elapses.
func (c *Client) WaitMined(ctx context.Context, hash common.Hash, timeout time.Duration) (*types.Receipt, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("xir evm: wait timeout %s is not positive", timeout)
	}
	deadline := time.Now().Add(timeout)
	for {
		receipt, err := c.Receipt(ctx, hash)
		switch {
		case err == nil && receipt != nil:
			return receipt, nil
		case err != nil && !IsTransientRPCError(err):
			return nil, fmt.Errorf("xir evm: cannot read receipt %s: %w", hash, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("xir evm: transaction %s was not mined within %s", hash, timeout)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("xir evm: transaction %s was not mined: %w", hash, ctx.Err())
		case <-time.After(finalizedPollInterval):
		}
	}
}

// FinalizedNumber returns the finalized height and the rule that produced it,
// mirroring root_signer.Web3RootCreationSource._finalized_number: the RPC
// “finalized“ tag when the node supports it, otherwise the private-QBFT rule
// of validator quorum plus one successor block on the canonical chain.
func (c *Client) FinalizedNumber(ctx context.Context) (uint64, string, error) {
	if number, rule, supported, err := c.finalizedTag(ctx); err != nil || supported {
		return number, rule, err
	}
	head, err := c.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, "", err
	}
	return c.qbftFinalized(ctx, head.Number.Uint64(), head.Hash())
}

// FinalizedNumberFor applies the same rule to one specific block, which is what
// a caller holding a receipt needs: the receipt block must be at or below the
// finalized height, and on the QBFT path it must still be canonical.
func (c *Client) FinalizedNumberFor(ctx context.Context, blockNumber uint64, blockHash common.Hash) (uint64, string, error) {
	if number, rule, supported, err := c.finalizedTag(ctx); err != nil || supported {
		return number, rule, err
	}
	return c.qbftFinalized(ctx, blockNumber, blockHash)
}

// finalizedTag reads the Ethereum “finalized“ block tag. supported is false
// when the node does not implement it, which is what private QBFT networks do.
func (c *Client) finalizedTag(ctx context.Context) (uint64, string, bool, error) {
	finalized := big.NewInt(int64(rpc.FinalizedBlockNumber))
	header, err := c.HeaderByNumber(ctx, finalized)
	if err != nil {
		if finalizedTagUnsupported(err) {
			return 0, "", false, nil
		}
		return 0, "", false, fmt.Errorf("xir evm: the finalized block tag failed: %w", err)
	}
	if header == nil {
		return 0, "", false, errors.New("xir evm: the finalized block tag returned no header")
	}
	return header.Number.Uint64(), "rpc-finalized-tag", true, nil
}

// qbftFinalized is the private-QBFT fallback. A QBFT block is final once the
// validator quorum has committed it, so the runtime additionally waits for one
// successor block and confirms the observed block is still canonical.
func (c *Client) qbftFinalized(ctx context.Context, blockNumber uint64, blockHash common.Hash) (uint64, string, error) {
	var validators []string
	if err := c.withTimeoutInto(ctx, func(callCtx context.Context) error {
		return c.rpc.CallContext(callCtx, &validators, "qbft_getValidatorsByBlockNumber", "latest")
	}); err != nil {
		return 0, "", fmt.Errorf("xir evm: QBFT validator quorum cannot be established: %w", err)
	}
	if len(validators) < c.qbftQuorum {
		return 0, "", fmt.Errorf(
			"xir evm: QBFT validator quorum cannot be established: %d validators, want %d",
			len(validators), c.qbftQuorum,
		)
	}
	required := blockNumber + qbftConfirmationBlocks
	latest, err := c.BlockNumber(ctx)
	if err != nil {
		return 0, "", err
	}
	deadline := time.Now().Add(c.timeout)
	for latest < required && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return 0, "", fmt.Errorf("xir evm: QBFT finality wait was cancelled: %w", ctx.Err())
		case <-time.After(finalizedPollInterval):
		}
		latest, err = c.BlockNumber(ctx)
		if err != nil {
			return 0, "", err
		}
	}
	if latest < required {
		return 0, "", fmt.Errorf(
			"xir evm: QBFT block %d lacks the successor depth (%d < %d)",
			blockNumber, latest, required,
		)
	}
	canonical, err := c.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return 0, "", err
	}
	if canonical == nil || canonical.Hash() != blockHash {
		return 0, "", fmt.Errorf(
			"xir evm: block %d is not in the canonical QBFT chain", blockNumber,
		)
	}
	return latest, fmt.Sprintf("qbft-committed-plus-%d", qbftConfirmationBlocks), nil
}

// IsTransientRPCError reports whether a failure is safe to retry unchanged,
// mirroring rpc.is_transient_rpc_error: any transport-level failure (the Python
// runtime retries requests.RequestException), and the one RPC error Besu
// returns while a validator is still catching up.
func IsTransientRPCError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var netError net.Error
	if errors.As(err, &netError) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	for _, syscallError := range []error{
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EPIPE, syscall.ETIMEDOUT, syscall.EHOSTUNREACH,
	} {
		if errors.Is(err, syscallError) {
			return true
		}
	}
	var rpcError rpc.Error
	if errors.As(err, &rpcError) {
		message := strings.ToLower(rpcError.Error())
		return strings.Contains(message, "transaction pool not enabled") &&
			strings.Contains(message, "node not yet in sync")
	}
	return false
}

// finalizedTagUnsupported reports whether a finality lookup failed because the
// node has no “finalized“ tag. The Python reference only tolerates Besu's
// "unknown block" wording; the remaining tokens cover the other nodes the
// runtime meets (Geth-style "header not found", Hardhat/Anvil rejections).
func finalizedTagUnsupported(err error) bool {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unknown block") || strings.Contains(message, "header not found") {
		return true
	}
	if strings.Contains(message, "finalized") &&
		(strings.Contains(message, "unsupported") || strings.Contains(message, "not supported")) {
		return true
	}
	return false
}

func isJSONNull(document json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(document))
	return trimmed == "" || trimmed == "null"
}

// withTimeout is a free function because Go methods cannot declare type
// parameters; every client call runs under the client's own RPC deadline.
func withTimeout[T any](ctx context.Context, timeout time.Duration, call func(context.Context) (T, error)) (T, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return call(callCtx)
}

func (c *Client) withTimeoutInto(ctx context.Context, call func(context.Context) error) error {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return call(callCtx)
}
