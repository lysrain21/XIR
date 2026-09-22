package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// journal is the append-only JSON lines record of every action of one
// deployment, the Go counterpart of the Python deployer's
// `deployment-journal.jsonl`. The durable ledger of record is the state store
// behind the transactor; the journal is what the deployment document digests,
// so a reader can tell which rows the documented gas accounting covers.
type journal struct {
	path string
	file *os.File
}

func openJournal(path string) (*journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("deploy: create journal directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("deploy: open deployment journal: %w", err)
	}
	return &journal{path: path, file: file}, nil
}

// append writes one row and fsyncs it, so a deployment that dies immediately
// afterwards still has the row on disk.
func (j *journal) append(record actionRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("deploy: encode journal row: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := j.file.Write(payload); err != nil {
		return fmt.Errorf("deploy: write journal row: %w", err)
	}
	if err := j.file.Sync(); err != nil {
		return fmt.Errorf("deploy: sync journal: %w", err)
	}
	return nil
}

// digest is the sha256 of the journal as it stands on disk.
func (j *journal) digest() (string, error) {
	payload, err := os.ReadFile(j.path)
	if err != nil {
		return "", fmt.Errorf("deploy: read deployment journal: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (j *journal) close() error {
	if j.file == nil {
		return nil
	}
	return j.file.Close()
}
