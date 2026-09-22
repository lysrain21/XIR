package evm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/lysrain21/XIR/go-runtime/internal/state"
)

// defaultTransactionTimeout is the receipt wait the Python deployer uses
// (NativeApplicationDeployer._send passes timeout=180).
const defaultTransactionTimeout = 180 * time.Second

// gasCeiling is the fallback gas limit deployer.py uses when eth_estimateGas
// cannot be answered.
const gasCeiling = 29_000_000

// estimatedGasFloor is the lower bound deployer.py applies to an estimate.
const estimatedGasFloor = 100_000

// gasEstimateNumerator/Denominator reproduce deployer.py's 30% headroom
// (estimated * 13 // 10).
const (
	gasEstimateNumerator   = 13
	gasEstimateDenominator = 10
)

// detailMaxFeePerGas and detailMaxPriorityFeePerGas are the keys under which the
// transactor freezes the EIP-1559 fees inside the action detail. They are frozen
// with the calldata so that re-signing a durable intent after a restart
// reproduces the identical raw transaction.
const (
	detailMaxFeePerGas         = "max_fee_per_gas"
	detailMaxPriorityFeePerGas = "max_priority_fee_per_gas"
)

// detailContractAddress is the detail key holding a creation transaction's
// deployed address.
const detailContractAddress = "contract_address"

// TxRequest is one transaction the runtime wants on chain.
type TxRequest struct {
	// ActionID identifies the durable action. It must be stable across restarts
	// because it is the ledger key the frozen intent is replayed under.
	ActionID string
	// AttemptID and Stage bind the action to the runner attempt ledger. When both
	// are set, the signed transaction is also mirrored into the Python runner's
	// stages/stage_history/durable_signed_transactions tables.
	AttemptID string
	Stage     string
	// ChainRole is the topology role the action belongs to ("a".."e", or
	// "deployment" for deployment actions).
	ChainRole string
	// To is the destination; the zero address means the transaction creates a
	// contract, in which case DeployCode supplies the init code.
	To common.Address
	// Data is the calldata. It must digest to the digest the ledger froze.
	Data []byte
	// Value is the transferred wei; nil means zero.
	Value *big.Int
	// Gas is the gas limit. Zero asks the node for an estimate and applies
	// deployer.py's headroom rule; multihop_runner's fixed 12_000_000 gas is
	// available by passing it explicitly.
	Gas uint64
	// DeployCode is the init code of a contract creation.
	DeployCode []byte
}

// Transactor submits transactions through one client and one signer while
// keeping every step durable in the store.
type Transactor struct {
	client    *Client
	signer    *Signer
	store     *state.Store
	spoolRoot string
	timeout   time.Duration

	nonceMu   sync.Mutex
	nonceNext map[string]uint64
	nonceSeen map[string]bool
}

// NewTransactor builds a transactor. rawSpoolRoot receives the raw signed
// transactions and the receipt documents; it is created with mode 0700 and every
// file is written with mode 0600 because the raw bytes reveal the signed
// transaction before it is mined.
func NewTransactor(
	client *Client,
	signer *Signer,
	store *state.Store,
	rawSpoolRoot string,
	transactionTimeout time.Duration,
) (*Transactor, error) {
	if client == nil || signer == nil || store == nil {
		return nil, errors.New("xir evm: a transactor needs a client, a signer and a store")
	}
	if strings.TrimSpace(rawSpoolRoot) == "" {
		return nil, errors.New("xir evm: a transactor needs a private raw spool root")
	}
	absolute, err := filepath.Abs(rawSpoolRoot)
	if err != nil {
		return nil, fmt.Errorf("xir evm: cannot resolve the raw spool root: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("xir evm: cannot create the raw spool root: %w", err)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("xir evm: cannot restrict the raw spool root: %w", err)
	}
	if transactionTimeout <= 0 {
		transactionTimeout = defaultTransactionTimeout
	}
	// A signer bound to a different chain than the endpoint is a silent
	// catastrophe: every signature would be invalid there.
	observed, err := client.ChainID(context.Background())
	if err != nil {
		return nil, err
	}
	if observed.Cmp(signer.ChainID()) != 0 {
		return nil, fmt.Errorf(
			"xir evm: the endpoint reports chain id %s but the signer is bound to %s",
			observed, signer.ChainID(),
		)
	}
	return &Transactor{
		client:    client,
		signer:    signer,
		store:     store,
		spoolRoot: absolute,
		timeout:   transactionTimeout,
		nonceNext: map[string]uint64{},
		nonceSeen: map[string]bool{},
	}, nil
}

// SpoolRoot returns the absolute private raw spool root. Callers record it as
// evidence rather than re-deriving it, because the transactor is what resolved
// and restricted it.
func (t *Transactor) SpoolRoot() string { return t.spoolRoot }

// ActionID derives the action identifier the Python deployer uses:
// sha256("{role}:{nonce}:{action}:{sha256(calldata)}"). Keeping the Go runtime on
// the same derivation means a deployment document produced by either runtime
// refers to the same action for the same intent.
func ActionID(chainRole string, nonce uint64, action string, data []byte) string {
	digest := sha256.Sum256(data)
	seed := fmt.Sprintf("%s:%d:%s:%s", chainRole, nonce, action, hex.EncodeToString(digest[:]))
	identifier := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(identifier[:])
}

// ReserveNonce reserves the next account nonce for the default chain role.
func (t *Transactor) ReserveNonce(ctx context.Context) (uint64, error) {
	return t.reserveNonce(ctx, "")
}

// reserveNonce reserves the next account nonce for one chain role. The counter is
// seeded lazily from the chain's pending nonce and from the highest nonce the
// ledger already holds for the chain, so a signed transaction that never reached
// the network cannot have its nonce handed out again.
func (t *Transactor) reserveNonce(ctx context.Context, chainRole string) (uint64, error) {
	t.nonceMu.Lock()
	defer t.nonceMu.Unlock()
	if !t.nonceSeen[chainRole] {
		pending, err := t.client.PendingNonce(ctx, t.signer.Address())
		if err != nil {
			return 0, err
		}
		seed := pending
		durable, found, err := t.store.MaxActionNonce(t.signer.ChainID().Uint64(), t.senderHex())
		if err != nil {
			return 0, err
		}
		if found && durable+1 > seed {
			seed = durable + 1
		}
		t.nonceNext[chainRole] = seed
		t.nonceSeen[chainRole] = true
	}
	nonce := t.nonceNext[chainRole]
	t.nonceNext[chainRole] = nonce + 1
	return nonce, nil
}

// senderHex is the lowercase hex address the signer signs as; it is the account
// key the nonce reservation and the ledger floor are scoped to.
func (t *Transactor) senderHex() string {
	return strings.ToLower(t.signer.Address().Hex())
}

// Call performs a read-only eth_call.
func (t *Transactor) Call(ctx context.Context, to common.Address, data []byte) ([]byte, error) {
	return t.client.CallContract(ctx, to, data)
}

// Execute drives one transaction from frozen intent to durable receipt.
//
// The order is fixed by the durability contract: the intent (including the
// calldata digest, the reserved nonce and the fee caps) is committed before
// signing, the raw transaction is committed and spooled before broadcasting, and
// the receipt document and its digest are committed before the action is marked
// succeeded. A restart therefore either replays the identical signed bytes or
// finds the receipt the previous process already paid for.
func (t *Transactor) Execute(ctx context.Context, request TxRequest) (state.ActionResult, error) {
	if err := validateTxRequest(request); err != nil {
		return state.ActionResult{}, err
	}
	var (
		data     []byte
		value    *big.Int
		creation bool
	)
	action, err := t.store.Action(request.ActionID)
	if err != nil {
		return state.ActionResult{}, err
	}
	if action == nil {
		// A fresh action: the request is the only source of the intent, so it has
		// to name a destination or carry deployment code.
		data, creation, err = requestCalldata(request)
		if err != nil {
			return state.ActionResult{}, err
		}
		value = request.Value
		if value == nil {
			value = new(big.Int)
		}
		action, err = t.freezeIntent(ctx, request, data, value, creation)
		if err != nil {
			return state.ActionResult{}, err
		}
	} else {
		// A durable action: the ledger is authoritative and the request may be as
		// small as the action id.
		if err := state.VerifyActionIdentity(action); err != nil {
			return state.ActionResult{}, err
		}
		data, creation, value, err = frozenRequest(request, action, t.senderHex())
		if err != nil {
			return state.ActionResult{}, err
		}
		if action.State == state.ActionFailed {
			return state.ActionResult{}, fmt.Errorf(
				"xir evm: action %s already failed on chain and cannot be resubmitted",
				action.ActionID,
			)
		}
		if action.State == state.ActionSucceeded {
			return t.finishedResult(action)
		}
	}
	raw, transactionHash, err := t.ensureSigned(action, data, value, creation)
	if err != nil {
		return state.ActionResult{}, err
	}
	if err := t.validateSignedBytes(action, raw, transactionHash, data, value, creation); err != nil {
		return state.ActionResult{}, err
	}
	// A receipt that already exists means a previous process paid for this
	// transaction; resuming must not broadcast a second time.
	rawDocument, receipt, err := t.client.ReceiptDocument(ctx, transactionHash)
	if err != nil {
		return state.ActionResult{}, err
	}
	if receipt == nil {
		if err := t.broadcast(ctx, raw); err != nil {
			return state.ActionResult{}, err
		}
		if err := t.store.Observe(request.ActionID, state.ActionSubmitted, map[string]any{
			"transaction_hash": transactionHash.Hex(),
			"raw_sha256":       sha256Hex(raw),
		}); err != nil {
			return state.ActionResult{}, err
		}
		rawDocument, receipt, err = t.awaitReceipt(ctx, transactionHash)
		if err != nil {
			return state.ActionResult{}, err
		}
	} else if err := t.store.Observe(request.ActionID, state.ActionSubmitted, map[string]any{
		"transaction_hash": transactionHash.Hex(),
		"raw_sha256":       sha256Hex(raw),
	}); err != nil {
		return state.ActionResult{}, err
	}
	spooled, err := t.spoolReceipt(transactionHash, rawDocument)
	if err != nil {
		return state.ActionResult{}, err
	}
	result := state.ActionResult{
		TransactionHash: transactionHash.Hex(),
		BlockNumber:     receipt.BlockNumber.Uint64(),
		GasUsed:         receipt.GasUsed,
		ReceiptPath:     spooled.path,
		ReceiptSHA256:   spooled.digest,
		Detail:          t.resultDetail(action, spooled, receipt, data, creation),
	}
	if creation {
		result.ContractAddress = receipt.ContractAddress.Hex()
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		if err := t.store.Observe(request.ActionID, state.ActionFailed, result.Detail); err != nil {
			return state.ActionResult{}, err
		}
		return state.ActionResult{}, fmt.Errorf(
			"xir evm: transaction %s reverted in block %d",
			result.TransactionHash, result.BlockNumber,
		)
	}
	if err := t.store.Succeed(request.ActionID, result); err != nil {
		return state.ActionResult{}, err
	}
	return result, nil
}

func validateTxRequest(request TxRequest) error {
	if strings.TrimSpace(request.ActionID) == "" {
		return errors.New("xir evm: a transaction request needs an action id")
	}
	return nil
}

// requestCalldata resolves the calldata and reports whether the request creates a
// contract. A creation carries init code and no destination; every other action
// carries a destination, whose calldata may legitimately be empty (a plain value
// transfer).
func requestCalldata(request TxRequest) ([]byte, bool, error) {
	creation := len(request.DeployCode) > 0
	if !creation {
		if request.To == (common.Address{}) {
			return nil, false, fmt.Errorf(
				"xir evm: action %s names neither a destination nor deployment code",
				request.ActionID,
			)
		}
		return request.Data, false, nil
	}
	if request.To != (common.Address{}) {
		return nil, false, fmt.Errorf(
			"xir evm: action %s sets both a destination and deployment code",
			request.ActionID,
		)
	}
	if len(request.Data) > 0 {
		return nil, false, fmt.Errorf(
			"xir evm: action %s sets both calldata and deployment code",
			request.ActionID,
		)
	}
	return request.DeployCode, true, nil
}

// freezeIntent commits the intent before anything is signed: reserved nonce, gas
// limit, calldata digest, value and the frozen fee caps.
func (t *Transactor) freezeIntent(
	ctx context.Context,
	request TxRequest,
	data []byte,
	value *big.Int,
	creation bool,
) (*state.Action, error) {
	nonce, err := t.reserveNonce(ctx, request.ChainRole)
	if err != nil {
		return nil, err
	}
	gas, err := t.resolveGas(ctx, request, data, value, creation)
	if err != nil {
		return nil, err
	}
	maxFee, maxPriority, err := t.resolveFees(ctx)
	if err != nil {
		return nil, err
	}
	target := ""
	if !creation {
		target = strings.ToLower(request.To.Hex())
	}
	detail := map[string]any{
		"role":                     request.ChainRole,
		"nonce":                    nonce,
		"target":                   target,
		"calldata_sha256":          sha256Hex(data),
		"calldata_bytes":           len(data),
		"chain_id":                 t.signer.ChainID().Uint64(),
		detailMaxFeePerGas:         maxFee.String(),
		detailMaxPriorityFeePerGas: maxPriority.String(),
	}
	if request.Stage != "" {
		detail["stage"] = request.Stage
	}
	detailJSON, err := state.CanonicalJSON(detail)
	if err != nil {
		return nil, err
	}
	return t.store.Intend(state.Action{
		ActionID:       request.ActionID,
		AttemptID:      request.AttemptID,
		Stage:          request.Stage,
		ChainRole:      request.ChainRole,
		ChainID:        t.signer.ChainID().Uint64(),
		Sender:         t.senderHex(),
		To:             target,
		CalldataHex:    "0x" + hex.EncodeToString(data),
		CalldataBytes:  len(data),
		CalldataSHA256: sha256Hex(data),
		Value:          value.String(),
		Gas:            gas,
		Nonce:          nonce,
		State:          state.ActionIntended,
		DetailJSON:     detailJSON,
	})
}

// resolveGas applies deployer.py's estimate rule: a 30% margin over the node's
// estimate, floored at 100_000 and capped at 29_000_000, with the ceiling as the
// fallback when the estimate cannot be produced.
func (t *Transactor) resolveGas(
	ctx context.Context,
	request TxRequest,
	data []byte,
	value *big.Int,
	creation bool,
) (uint64, error) {
	if request.Gas != 0 {
		return request.Gas, nil
	}
	message := ethereum.CallMsg{From: t.signer.Address(), Data: data, Value: value}
	if !creation {
		to := request.To
		message.To = &to
	}
	estimated, err := t.client.EstimateGas(ctx, message)
	if err != nil {
		if IsTransientRPCError(err) {
			return 0, err
		}
		return gasCeiling, nil
	}
	scaled := estimated * gasEstimateNumerator / gasEstimateDenominator
	if scaled < estimatedGasFloor {
		scaled = estimatedGasFloor
	}
	if scaled > gasCeiling {
		scaled = gasCeiling
	}
	return scaled, nil
}

// resolveFees reproduces multihop_runner's fee choice: maxFeePerGas is twice the
// suggested gas price (never below 1) and the priority fee is zero.
func (t *Transactor) resolveFees(ctx context.Context) (*big.Int, *big.Int, error) {
	price, err := t.client.GasPrice(ctx)
	if err != nil {
		return nil, nil, err
	}
	maxFee := new(big.Int).Mul(price, big.NewInt(2))
	if maxFee.Sign() <= 0 {
		maxFee = big.NewInt(1)
	}
	return maxFee, new(big.Int), nil
}

// frozenRequest resolves the calldata, the value and the creation flag of a
// durable action from the ledger, and rejects a request whose supplied fields
// disagree with the frozen intent. A resumed action may be requested with the
// action id alone.
func frozenRequest(request TxRequest, action *state.Action, sender string) ([]byte, bool, *big.Int, error) {
	drift := func(format string, arguments ...any) ([]byte, bool, *big.Int, error) {
		return nil, false, nil, fmt.Errorf("%w: %s", state.ErrDrift, fmt.Sprintf(format, arguments...))
	}
	data, err := decodeHex(action.CalldataHex)
	if err != nil {
		return drift("action %s carries undecodable calldata: %v", action.ActionID, err)
	}
	value, ok := new(big.Int).SetString(action.Value, 10)
	if !ok {
		return drift("action %s froze value %q", action.ActionID, action.Value)
	}
	creation := action.To == ""
	if action.Sender != "" && action.Sender != sender {
		return drift(
			"action %s belongs to account %s but this transactor signs as %s",
			action.ActionID, action.Sender, sender,
		)
	}
	if request.ChainRole != "" && request.ChainRole != action.ChainRole {
		return drift(
			"action %s belongs to chain role %s but the request says %s",
			action.ActionID, action.ChainRole, request.ChainRole,
		)
	}
	if request.AttemptID != "" && action.AttemptID != "" && request.AttemptID != action.AttemptID {
		return drift(
			"action %s belongs to attempt %s but the request says %s",
			action.ActionID, action.AttemptID, request.AttemptID,
		)
	}
	if request.Stage != "" && action.Stage != "" && request.Stage != action.Stage {
		return drift(
			"action %s belongs to stage %s but the request says %s",
			action.ActionID, action.Stage, request.Stage,
		)
	}
	if len(request.Data) > 0 && sha256Hex(request.Data) != action.CalldataSHA256 {
		return drift(
			"action %s froze calldata digest %s but the request carries %s",
			action.ActionID, action.CalldataSHA256, sha256Hex(request.Data),
		)
	}
	if len(request.DeployCode) > 0 {
		if !creation {
			return drift("action %s froze a destination but the request carries deployment code", action.ActionID)
		}
		if sha256Hex(request.DeployCode) != action.CalldataSHA256 {
			return drift(
				"action %s froze calldata digest %s but the request carries %s",
				action.ActionID, action.CalldataSHA256, sha256Hex(request.DeployCode),
			)
		}
	}
	if request.To != (common.Address{}) {
		if creation {
			return drift("action %s created a contract but the request names a destination", action.ActionID)
		}
		if strings.ToLower(request.To.Hex()) != action.To {
			return drift(
				"action %s froze target %q but the request names %q",
				action.ActionID, action.To, strings.ToLower(request.To.Hex()),
			)
		}
	}
	if request.Value != nil && request.Value.String() != action.Value {
		return drift(
			"action %s froze value %s but the request carries %s",
			action.ActionID, action.Value, request.Value.String(),
		)
	}
	if request.Gas != 0 && request.Gas != action.Gas {
		return drift(
			"action %s froze gas %d but the request carries %d",
			action.ActionID, action.Gas, request.Gas,
		)
	}
	return data, creation, value, nil
}

// ensureSigned returns the raw signed bytes for the action, restoring them from
// the ledger when they are already durable and signing the frozen intent
// otherwise.
func (t *Transactor) ensureSigned(
	action *state.Action,
	data []byte,
	value *big.Int,
	creation bool,
) ([]byte, common.Hash, error) {
	if action.RawTransactionHex != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(action.RawTransactionHex, "0x"))
		if err != nil {
			return nil, common.Hash{}, fmt.Errorf(
				"%w: action %s has undecodable raw bytes: %v",
				state.ErrDrift, action.ActionID, err,
			)
		}
		return raw, common.HexToHash(action.TransactionHash), nil
	}
	detail, err := action.Detail()
	if err != nil {
		return nil, common.Hash{}, err
	}
	maxFee, err := detailBigInt(detail, detailMaxFeePerGas, action.ActionID)
	if err != nil {
		return nil, common.Hash{}, err
	}
	maxPriority, err := detailBigInt(detail, detailMaxPriorityFeePerGas, action.ActionID)
	if err != nil {
		return nil, common.Hash{}, err
	}
	transaction := &types.DynamicFeeTx{
		ChainID:   t.signer.ChainID(),
		Nonce:     action.Nonce,
		GasTipCap: maxPriority,
		GasFeeCap: maxFee,
		Gas:       action.Gas,
		Value:     value,
		Data:      data,
	}
	if !creation {
		to := common.HexToAddress(action.To)
		transaction.To = &to
	}
	signed, err := t.signer.SignDynamicFee(transaction)
	if err != nil {
		return nil, common.Hash{}, err
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return nil, common.Hash{}, fmt.Errorf("xir evm: cannot encode the signed transaction: %w", err)
	}
	if err := t.writePrivateRaw(transactionHashPath(t.spoolRoot, signed.Hash()), raw); err != nil {
		return nil, common.Hash{}, err
	}
	if err := t.store.RecordSigned(action.ActionID, raw, signed.Hash().Hex()); err != nil {
		return nil, common.Hash{}, err
	}
	return raw, signed.Hash(), nil
}

func detailBigInt(detail map[string]any, key, actionID string) (*big.Int, error) {
	value, ok := detail[key]
	if !ok {
		return nil, fmt.Errorf(
			"xir evm: action %s has no frozen %s, so its intent cannot be replayed",
			actionID, key,
		)
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("xir evm: action %s froze %s as %T", actionID, key, value)
	}
	parsed, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, fmt.Errorf("xir evm: action %s froze %s as %q", actionID, key, text)
	}
	return parsed, nil
}

// validateSignedBytes re-derives the signed transaction's identity from its raw
// bytes, mirroring multihop_runner._validate_durable_raw: the recovered signer,
// the chain id, the nonce, the target, the calldata digest and the transaction
// hash all have to agree with the frozen ledger row.
func (t *Transactor) validateSignedBytes(
	action *state.Action,
	raw []byte,
	transactionHash common.Hash,
	data []byte,
	value *big.Int,
	creation bool,
) error {
	if observed := crypto.Keccak256Hash(raw); observed != transactionHash {
		return fmt.Errorf(
			"%w: action %s raw bytes hash to %s but were recorded as %s",
			state.ErrDrift, action.ActionID, observed, transactionHash,
		)
	}
	signer := types.LatestSignerForChainID(t.signer.ChainID())
	var transaction types.Transaction
	if err := transaction.UnmarshalBinary(raw); err != nil {
		return fmt.Errorf("%w: action %s raw bytes are not a transaction: %v", state.ErrDrift, action.ActionID, err)
	}
	decoded := &transaction
	recovered, err := types.Sender(signer, decoded)
	if err != nil {
		return fmt.Errorf("%w: action %s signature cannot be recovered: %v", state.ErrDrift, action.ActionID, err)
	}
	if recovered != t.signer.Address() {
		return fmt.Errorf(
			"%w: action %s was signed by %s, not %s",
			state.ErrDrift, action.ActionID, recovered, t.signer.Address(),
		)
	}
	if action.Sender != "" && action.Sender != strings.ToLower(recovered.Hex()) {
		return fmt.Errorf(
			"%w: action %s records account %s but its signature recovers %s",
			state.ErrDrift, action.ActionID, action.Sender, recovered,
		)
	}
	if decoded.ChainId().Cmp(t.signer.ChainID()) != 0 ||
		decoded.ChainId().Cmp(new(big.Int).SetUint64(action.ChainID)) != 0 {
		return fmt.Errorf(
			"%w: action %s is signed for chain id %s, not %s (frozen %d)",
			state.ErrDrift, action.ActionID, decoded.ChainId(), t.signer.ChainID(), action.ChainID,
		)
	}
	if decoded.Nonce() != action.Nonce {
		return fmt.Errorf(
			"%w: action %s is signed with nonce %d but froze %d",
			state.ErrDrift, action.ActionID, decoded.Nonce(), action.Nonce,
		)
	}
	if decoded.Gas() != action.Gas {
		return fmt.Errorf(
			"%w: action %s is signed with gas %d but froze %d",
			state.ErrDrift, action.ActionID, decoded.Gas(), action.Gas,
		)
	}
	if decoded.Value().Cmp(value) != 0 {
		return fmt.Errorf(
			"%w: action %s is signed for value %s but froze %s",
			state.ErrDrift, action.ActionID, decoded.Value(), value,
		)
	}
	frozenData := decoded.Data()
	if sha256Hex(frozenData) != action.CalldataSHA256 || len(frozenData) != action.CalldataBytes {
		return fmt.Errorf(
			"%w: action %s is signed with calldata digest %s but froze %s",
			state.ErrDrift, action.ActionID, sha256Hex(frozenData), action.CalldataSHA256,
		)
	}
	frozenTarget := ""
	if to := decoded.To(); to != nil {
		if creation {
			return fmt.Errorf(
				"%w: action %s is a deployment but its signed transaction names a destination",
				state.ErrDrift, action.ActionID,
			)
		}
		frozenTarget = strings.ToLower(to.Hex())
	} else if !creation {
		return fmt.Errorf(
			"%w: action %s is signed as a deployment but the ledger froze a destination",
			state.ErrDrift, action.ActionID,
		)
	}
	if frozenTarget != action.To {
		return fmt.Errorf(
			"%w: action %s is signed for target %q but froze %q",
			state.ErrDrift, action.ActionID, frozenTarget, action.To,
		)
	}
	return nil
}

// broadcast sends the raw bytes, accepting the three node answers that mean the
// transaction was already submitted (matching multihop_runner._transact).
func (t *Transactor) broadcast(ctx context.Context, raw []byte) error {
	err := t.client.SendRawTransaction(ctx, raw)
	if err == nil {
		return nil
	}
	if IsAcceptedPriorSubmission(err) {
		return nil
	}
	return err
}

// IsAcceptedPriorSubmission reports whether a broadcast failure means the node
// already holds this transaction: "already known", "known transaction", or
// "nonce too low" (the broadcast that consumed the nonce succeeded).
func IsAcceptedPriorSubmission(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, token := range []string{"already known", "known transaction", "nonce too low"} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

func (t *Transactor) awaitReceipt(ctx context.Context, hash common.Hash) (json.RawMessage, *types.Receipt, error) {
	if _, err := t.client.WaitMined(ctx, hash, t.timeout); err != nil {
		return nil, nil, err
	}
	return t.client.ReceiptDocument(ctx, hash)
}

// resultDetail reproduces the detail document multihop_runner._persist_receipt
// merges into the succeeded stage: the frozen intent fields plus the receipt
// evidence.
func (t *Transactor) resultDetail(
	action *state.Action,
	spooled spooledReceipt,
	receipt *types.Receipt,
	data []byte,
	creation bool,
) map[string]any {
	return map[string]any{
		"role":                action.ChainRole,
		"nonce":               action.Nonce,
		"target":              action.To,
		"calldata_sha256":     sha256Hex(data),
		"calldata_bytes":      len(data),
		"raw_sha256":          actionRawSHA256(action),
		"transaction_hash":    receipt.TxHash.Hex(),
		"receipt":             spooled.path,
		"receipt_sha256":      spooled.digest,
		"gas_used":            receipt.GasUsed,
		"block_number":        receipt.BlockNumber.Uint64(),
		"chain_id":            action.ChainID,
		"creation":            creation,
		detailContractAddress: contractAddressDetail(receipt, creation),
	}
}

func actionRawSHA256(action *state.Action) string {
	raw, err := hex.DecodeString(strings.TrimPrefix(action.RawTransactionHex, "0x"))
	if err != nil {
		return ""
	}
	return sha256Hex(raw)
}

func contractAddressDetail(receipt *types.Receipt, creation bool) any {
	if !creation {
		return nil
	}
	return receipt.ContractAddress.Hex()
}

// finishedResult rebuilds the result of an action that already succeeded,
// verifying the spooled receipt bytes before they are trusted again.
func (t *Transactor) finishedResult(action *state.Action) (state.ActionResult, error) {
	detail, err := action.Detail()
	if err != nil {
		return state.ActionResult{}, err
	}
	if action.ReceiptPath != "" {
		contents, err := os.ReadFile(action.ReceiptPath)
		if err != nil {
			return state.ActionResult{}, fmt.Errorf(
				"%w: action %s spooled its receipt at %s: %v",
				state.ErrDrift, action.ActionID, action.ReceiptPath, err,
			)
		}
		if observed := sha256Hex(contents); observed != action.ReceiptSHA256 {
			return state.ActionResult{}, fmt.Errorf(
				"%w: action %s receipt %s digests to %s, not %s",
				state.ErrDrift, action.ActionID, action.ReceiptPath, observed, action.ReceiptSHA256,
			)
		}
	}
	result := state.ActionResult{
		TransactionHash: action.TransactionHash,
		BlockNumber:     action.BlockNumber,
		GasUsed:         action.GasUsed,
		ReceiptPath:     action.ReceiptPath,
		ReceiptSHA256:   action.ReceiptSHA256,
		Detail:          detail,
	}
	if address, ok := detail[detailContractAddress].(string); ok {
		result.ContractAddress = address
	}
	return result, nil
}

// spooledReceipt is one materialized receipt document.
type spooledReceipt struct {
	path   string
	digest string
}

// spoolReceipt writes the node's receipt JSON into the private raw spool and
// returns its path and sha256. The document is rendered the way the Python
// runner renders it: sorted keys, two-space indent, trailing newline.
func (t *Transactor) spoolReceipt(hash common.Hash, document json.RawMessage) (spooledReceipt, error) {
	if isJSONNull(document) {
		return spooledReceipt{}, fmt.Errorf("xir evm: transaction %s has no receipt document", hash)
	}
	decoded, err := state.DecodeJSON(document)
	if err != nil {
		return spooledReceipt{}, fmt.Errorf("xir evm: receipt %s is not decodable: %w", hash, err)
	}
	rendered, err := state.CanonicalJSONIndent(decoded, 2)
	if err != nil {
		return spooledReceipt{}, err
	}
	path := transactionReceiptPath(t.spoolRoot, hash)
	contents := []byte(rendered + "\n")
	if err := t.writePrivateRaw(path, contents); err != nil {
		return spooledReceipt{}, err
	}
	return spooledReceipt{path: path, digest: sha256Hex(contents)}, nil
}

// writePrivateRaw materializes one private file durably, mirroring
// multihop_runner._write_private_raw_durably: an exclusive temporary in the same
// directory, fsynced and mode 0600, renamed over the target, then the directory
// itself fsynced. Re-writing identical bytes is a no-op; different bytes at the
// same path are drift.
func (t *Transactor) writePrivateRaw(path string, raw []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if !bytesEqual(existing, raw) {
			return fmt.Errorf("%w: %s already holds different bytes", state.ErrDrift, path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("xir evm: cannot read %s: %w", path, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("xir evm: cannot create a temporary spool file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("xir evm: cannot restrict %s: %w", temporaryName, err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("xir evm: cannot write %s: %w", temporaryName, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("xir evm: cannot flush %s: %w", temporaryName, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("xir evm: cannot close %s: %w", temporaryName, err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("xir evm: cannot publish %s: %w", path, err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("xir evm: cannot open the spool directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("xir evm: cannot flush the spool directory: %w", err)
	}
	return nil
}

// transactionHashPath is the raw signed-transaction path, matching
// multihop_runner's "<canonical hash>.raw".
func transactionHashPath(root string, hash common.Hash) string {
	return filepath.Join(root, canonicalHashHex(hash)+".raw")
}

// transactionReceiptPath is the receipt path, matching
// multihop_runner._persist_receipt's "<canonical hash>.json".
func transactionReceiptPath(root string, hash common.Hash) string {
	return filepath.Join(root, canonicalHashHex(hash)+".json")
}

func canonicalHashHex(hash common.Hash) string {
	return hex.EncodeToString(hash.Bytes())
}

// decodeHex decodes a 0x-prefixed hex string; an empty string decodes to no
// bytes, which is how a value transfer carries its calldata.
func decodeHex(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("hex string %q has an odd number of digits", value)
	}
	decoded, err := hex.DecodeString(strings.ToLower(trimmed))
	if err != nil {
		return nil, fmt.Errorf("hex string %q is not hexadecimal: %w", value, err)
	}
	return decoded, nil
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
