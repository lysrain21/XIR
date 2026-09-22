package runner

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"path/filepath"
	"sort"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/hyperlane"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// loadProtocol loads one contract of a pinned protocol stack. root is the
// protocol-projects directory that holds <stack>/out.
func loadProtocol(root, contractName string) (artifacts.Artifact, error) {
	stack := "hyperlane-native"
	switch contractName {
	case "EndpointV2", "SendUln302", "ReceiveUln302", "DVN", "Executor", "PriceFeed", "Treasury", "DVNFeeLib", "ExecutorFeeLib", "ERC1967Proxy":
		stack = "layerzero-native"
	}
	artifact, err := artifacts.Load(filepath.Join(root, stack, "out"), contractName)
	if err != nil {
		return artifacts.Artifact{}, fmt.Errorf("runner: load protocol contract %s: %w", contractName, err)
	}
	return artifact, nil
}

// checkpoint is the origin tree checkpoint one dispatched message belongs to.
type checkpoint struct {
	Root  [32]byte
	Index uint32
}

// readCheckpoint reads the origin Merkle tree hook checkpoint for the message
// that was inserted at the recorded index. The hook address comes from the
// InsertedIntoTree log of the dispatch receipt, not from an assumption about
// which mailbox hook maintains the tree.
func readCheckpoint(
	ctx context.Context,
	protocolRoot string,
	source *roleChain,
	delivery hyperlaneDelivery,
) (checkpoint, error) {
	hook := &bound{
		role:       delivery.SourceRole,
		key:        "hyperlane_tree_hook",
		address:    delivery.OriginHook,
		client:     source.client,
		transactor: source.transactor,
		gasLimit:   source.transactorGasLimit(),
	}
	artifact, err := loadProtocol(protocolRoot, "MerkleTreeHook")
	if err != nil {
		return checkpoint{}, err
	}
	hook.artifact = artifact
	receipt, err := source.client.Receipt(ctx, common.HexToHash(delivery.SourceResult.TransactionHash))
	if err != nil {
		return checkpoint{}, err
	}
	if receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
		return checkpoint{}, fmt.Errorf("runner: dispatch has no successful receipt")
	}
	header, err := source.client.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		return checkpoint{}, err
	}
	if header == nil || header.Hash() != receipt.BlockHash {
		return checkpoint{}, fmt.Errorf("runner: dispatch block is no longer canonical")
	}
	data, err := hook.artifact.ABI.PackCall("latestCheckpoint")
	if err != nil {
		return checkpoint{}, err
	}
	output, err := source.client.CallContractAtHash(ctx, hook.address, data, receipt.BlockHash)
	if err != nil {
		return checkpoint{}, err
	}
	values, err := hook.artifact.ABI.ABI().Methods["latestCheckpoint"].Outputs.Unpack(output)
	if err != nil {
		return checkpoint{}, err
	}
	if len(values) != 2 {
		return checkpoint{}, fmt.Errorf("runner: latestCheckpoint returned %d values", len(values))
	}
	root, ok := values[0].([32]byte)
	if !ok {
		return checkpoint{}, fmt.Errorf("runner: latestCheckpoint root is %T", values[0])
	}
	index, ok := values[1].(uint32)
	if !ok {
		return checkpoint{}, fmt.Errorf("runner: latestCheckpoint index is %T", values[1])
	}
	if index < delivery.InsertedIndex {
		return checkpoint{}, fmt.Errorf("runner: checkpoint precedes dispatch")
	}
	if index > delivery.InsertedIndex {
		// Several messages may be inserted in the same block. Historical calls
		// expose end-of-block state, so replay the authenticated hook's leaves
		// only up to this transaction's insertion rather than sign a later root.
		logs, err := source.client.Logs(ctx, ethereum.FilterQuery{
			FromBlock: big.NewInt(0), ToBlock: receipt.BlockNumber,
			Addresses: []common.Address{delivery.OriginHook},
			Topics:    [][]common.Hash{{hyperlane.InsertedIntoTreeTopic}},
		})
		if err != nil {
			return checkpoint{}, err
		}
		return checkpointAtInsertion(logs, delivery, receipt.BlockHash)
	}

	return checkpoint{Root: root, Index: index}, nil
}

// verifyStageTopic fails when a submitted stage receipt lacks its official
// success event, mirroring the LayerZero worker's post-transaction check.
func verifyStageTopic(
	ctx context.Context,
	client *evm.Client,
	result state.ActionResult,
	topic common.Hash,
	stage string,
) error {
	if topic == (common.Hash{}) {
		return nil
	}
	receipt, err := client.Receipt(ctx, common.HexToHash(result.TransactionHash))
	if err != nil {
		return err
	}
	for _, log := range receipt.Logs {
		if len(log.Topics) > 0 && log.Topics[0] == topic {
			return nil
		}
	}
	return fmt.Errorf("runner: %s stage lacks its official success event %s", stage, topic.Hex())
}

// insertedIntoTree decodes the InsertedIntoTree(bytes32,uint32) log of the
// origin Merkle tree hook. The data is two ABI words, so it is decoded
// directly rather than through an artifact lookup.
func insertedIntoTree(log *types.Log) (messageID [32]byte, index uint32, ok bool) {
	if len(log.Data) != 64 {
		return messageID, 0, false
	}
	copy(messageID[:], log.Data[:32])
	index = binary.BigEndian.Uint32(log.Data[60:64])
	return messageID, index, true
}

// checkpointAtInsertion reproduces the pinned IncrementalMerkle tree root.
func checkpointAtInsertion(logs []types.Log, delivery hyperlaneDelivery, blockHash common.Hash) (checkpoint, error) {
	sort.Slice(logs, func(i, j int) bool {
		if logs[i].BlockNumber != logs[j].BlockNumber {
			return logs[i].BlockNumber < logs[j].BlockNumber
		}
		return logs[i].Index < logs[j].Index
	})
	var branch [32][32]byte
	var count uint64
	for i := range logs {
		log := &logs[i]
		if log.Removed || log.Address != delivery.OriginHook || len(log.Topics) == 0 || log.Topics[0] != hyperlane.InsertedIntoTreeTopic {
			continue
		}
		leaf, index, ok := insertedIntoTree(log)
		if !ok || uint64(index) != count {
			return checkpoint{}, fmt.Errorf("runner: non-contiguous Merkle hook history at index %d", count)
		}
		count++
		node, size := leaf, count
		for height := 0; height < 32; height++ {
			if size&1 == 1 {
				branch[height] = node
				break
			}
			node = xir.Keccak256(branch[height][:], node[:])
			size >>= 1
		}
		if index != delivery.InsertedIndex {
			continue
		}
		if leaf != delivery.MessageID || log.TxHash != common.HexToHash(delivery.SourceResult.TransactionHash) || log.BlockHash != blockHash {
			return checkpoint{}, fmt.Errorf("runner: Merkle insertion does not match dispatch identity")
		}
		var root, zero [32]byte
		for height := 0; height < 32; height++ {
			if count&(uint64(1)<<height) != 0 {
				root = xir.Keccak256(branch[height][:], root[:])
			} else {
				root = xir.Keccak256(root[:], zero[:])
			}
			zero = xir.Keccak256(zero[:], zero[:])
		}
		return checkpoint{Root: root, Index: index}, nil
	}
	return checkpoint{}, fmt.Errorf("runner: dispatch insertion missing from hook history")
}
