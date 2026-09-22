package runner

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
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
	values, err := hook.call(ctx, "latestCheckpoint")
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
	if index != delivery.InsertedIndex {
		return checkpoint{}, fmt.Errorf(
			"runner: latest checkpoint index %d does not match the dispatched message index %d; the Go relayer only signs the checkpoint it observed for this dispatch",
			index, delivery.InsertedIndex,
		)
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
