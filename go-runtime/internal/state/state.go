// Package state is the durable SQLite ledger for the XIR Go runtime.
//
// The schema mirrors the Python reference runner: “RunnerState“ in
// src/xir_lab/native/runner.py defines attempts, stages, stage_history,
// attempt_errors and the gateway nonce reservation, while
// “MultihopRunnerState“ in src/xir_lab/native/multihop_runner.py adds events,
// the durable signed-transaction table, and the stage/event evidence pairs.
// The actions table is the Go runtime's own frozen-intent ledger: one row per
// transaction, keyed by action_id, carrying the frozen calldata digest, the
// signed raw transaction and the receipt evidence.
//
// Durability rules, all inherited from the Python runtime:
//
//   - journal_mode=WAL and synchronous=FULL, so a committed row has reached the
//     disk before the call returns and before the matching network action runs;
//   - a single writer (one pooled connection plus a process-wide mutex), so a
//     writer never observes a partially applied multi-row write;
//   - insert paths are idempotent, keyed by action_id or (attempt_id, stage);
//     replaying an already-durable write is a no-op, while a replayed write with
//     different bytes is reported as identity drift.
package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"

	sqlite "modernc.org/sqlite"
)

// driverName is the modernc.org/sqlite database/sql driver name.
const driverName = "sqlite"

// busyTimeoutMillis bounds how long SQLite waits for another writer's lock.
const busyTimeoutMillis = 5000

// Action states, in the order the transactor advances through them. “failed“
// is terminal evidence of a reverted transaction.
const (
	ActionIntended  = "intended"
	ActionSigned    = "signed"
	ActionSubmitted = "submitted"
	ActionSucceeded = "succeeded"
	ActionFailed    = "failed"
)

// Attempt statuses from the Python attempts table.
const (
	AttemptRunning   = "running"
	AttemptSucceeded = "succeeded"
)

// ErrClosed reports use of a closed store.
var ErrClosed = errors.New("xir state: store is closed")

// ErrDrift reports a durable row whose bytes disagree with the value the caller
// is re-recording. The Python runtime treats the same condition as fatal
// (LocalTopologyError / sqlite3.IntegrityError), never as a retryable conflict.
var ErrDrift = errors.New("xir state: durable identity drift")

// ErrStateTransition reports an invalid action state transition.
var ErrStateTransition = errors.New("xir state: invalid action state transition")

// durabilityPragmas are applied to every pooled connection, so a connection the
// database/sql pool discards after an error is replaced by an equally durable
// one. without these, a replacement connection would silently run with SQLite's
// default synchronous=NORMAL journal policy.
var durabilityPragmas = []string{
	"PRAGMA journal_mode=WAL",
	"PRAGMA synchronous=FULL",
	fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeoutMillis),
}

var (
	hookOnce  sync.Once
	hookMu    sync.Mutex
	hookPaths = map[string]struct{}{}
)

// registerDurabilityHook installs the process-wide connection hook exactly once
// and remembers which database paths belong to this package, so the hook never
// changes the pragmas of a connection opened by another package.
func registerDurabilityHook() {
	hookOnce.Do(func() {
		sqlite.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, dsn string) error {
			hookMu.Lock()
			_, known := hookPaths[dsn]
			hookMu.Unlock()
			if !known {
				return nil
			}
			for _, pragma := range durabilityPragmas {
				if _, err := conn.ExecContext(context.Background(), pragma, nil); err != nil {
					return fmt.Errorf("xir state: %q failed: %w", pragma, err)
				}
			}
			return nil
		})
	})
}

// Store is the durable runner ledger.
type Store struct {
	mu     sync.Mutex
	db     *sql.DB
	path   string
	bootID string
	closed bool
}

// Open opens (creating when absent) the runner database at path and applies the
// frozen schema. The parent directory is created with mode 0700 because the
// durable signed transactions are stored in this file.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("xir state: empty database path")
	}
	clean := filepath.Clean(path)
	if directory := filepath.Dir(clean); directory != "." && directory != "" {
		if _, err := os.Stat(directory); errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				return nil, fmt.Errorf("xir state: cannot create %s: %w", directory, err)
			}
		}
	}
	bootID, err := readBootID()
	if err != nil {
		return nil, err
	}
	registerDurabilityHook()
	hookMu.Lock()
	hookPaths[clean] = struct{}{}
	hookMu.Unlock()
	releaseHook := func() {
		hookMu.Lock()
		delete(hookPaths, clean)
		hookMu.Unlock()
	}
	db, err := sql.Open(driverName, clean)
	if err != nil {
		releaseHook()
		return nil, fmt.Errorf("xir state: cannot open %s: %w", clean, err)
	}
	// One writer: every statement in this process is serialized behind a single
	// connection, which is also what keeps the pragmas above in force.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	if err := db.Ping(); err != nil {
		db.Close()
		releaseHook()
		return nil, fmt.Errorf("xir state: cannot reach %s: %w", clean, err)
	}
	store := &Store{db: db, path: clean, bootID: bootID}
	if err := store.applySchema(); err != nil {
		db.Close()
		releaseHook()
		return nil, err
	}
	if err := store.verifyDurability(); err != nil {
		db.Close()
		releaseHook()
		return nil, err
	}
	if err := os.Chmod(clean, 0o600); err != nil {
		db.Close()
		releaseHook()
		return nil, fmt.Errorf("xir state: cannot restrict %s: %w", clean, err)
	}
	return store, nil
}

// Close releases the database handle. The final frames of the write-ahead log
// are already durable, so nothing further is required for crash safety.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	hookMu.Lock()
	delete(hookPaths, s.path)
	hookMu.Unlock()
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("xir state: cannot close %s: %w", s.path, err)
	}
	return nil
}

// Path returns the database path the store was opened with.
func (s *Store) Path() string { return s.path }

// BootID returns the host boot identity stamped into every event row.
func (s *Store) BootID() string { return s.bootID }

func readBootID() (string, error) {
	const bootIDPath = "/proc/sys/kernel/random/boot_id"
	raw, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", fmt.Errorf("xir state: host boot identity is unavailable: %w", err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", errors.New("xir state: host boot identity is empty")
	}
	return value, nil
}

// schemaTables mirror the Python runner DDL statement for statement, with two
// deliberate additions: the actions ledger, and the process_identity_sha256
// column that the Python multihop state adds by migration. Indexes are created
// after the column migrations, because one of them covers a migrated column.
var schemaTables = []string{
	`CREATE TABLE IF NOT EXISTS attempts(
          attempt_id TEXT PRIMARY KEY,
          phase TEXT NOT NULL,
          route TEXT NOT NULL,
          route_sequence INTEGER NOT NULL,
          coordinates_json TEXT NOT NULL,
          status TEXT NOT NULL,
          started_at REAL NOT NULL,
          finished_at REAL
        ) STRICT`,
	`CREATE TABLE IF NOT EXISTS stages(
          attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
          stage TEXT NOT NULL,
          state TEXT NOT NULL,
          transaction_hash TEXT,
          detail_json TEXT NOT NULL,
          observed_at REAL NOT NULL,
          PRIMARY KEY(attempt_id, stage)
        ) STRICT`,
	`CREATE TABLE IF NOT EXISTS stage_history(
          history_id INTEGER PRIMARY KEY AUTOINCREMENT,
          attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
          stage TEXT NOT NULL,
          state TEXT NOT NULL,
          transaction_hash TEXT,
          detail_json TEXT NOT NULL,
          observed_at REAL NOT NULL
        ) STRICT`,
	`CREATE TABLE IF NOT EXISTS attempt_errors(
          error_id INTEGER PRIMARY KEY AUTOINCREMENT,
          attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
          error_class TEXT NOT NULL,
          error_message TEXT NOT NULL,
          retry_index INTEGER NOT NULL,
          observed_at REAL NOT NULL
        ) STRICT`,
	`CREATE TABLE IF NOT EXISTS events(
          event_id INTEGER PRIMARY KEY AUTOINCREMENT,
          attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
          stage TEXT NOT NULL,
          event TEXT NOT NULL,
          source TEXT NOT NULL,
          chain_role TEXT,
          hop_index INTEGER,
          transaction_hash TEXT,
          utc_ns INTEGER NOT NULL,
          monotonic_ns INTEGER NOT NULL,
          boot_id TEXT NOT NULL,
          process_id INTEGER NOT NULL,
          process_identity_sha256 TEXT,
          thread_id INTEGER NOT NULL,
          detail_json TEXT NOT NULL
        ) STRICT`,
	`CREATE TABLE IF NOT EXISTS durable_signed_transactions(
          attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
          stage TEXT NOT NULL,
          transaction_hash TEXT NOT NULL UNIQUE,
          raw_transaction BLOB NOT NULL,
          raw_sha256 TEXT NOT NULL,
          detail_json TEXT NOT NULL,
          PRIMARY KEY(attempt_id, stage)
        ) STRICT`,
	`CREATE TABLE IF NOT EXISTS actions(
          action_id TEXT PRIMARY KEY,
          attempt_id TEXT NOT NULL,
          stage TEXT NOT NULL,
          chain_role TEXT NOT NULL,
          chain_id INTEGER NOT NULL,
          sender TEXT NOT NULL DEFAULT '',
          target TEXT NOT NULL,
          calldata_hex TEXT NOT NULL,
          calldata_bytes INTEGER NOT NULL,
          calldata_sha256 TEXT NOT NULL,
          value TEXT NOT NULL,
          gas INTEGER NOT NULL,
          nonce INTEGER NOT NULL,
          state TEXT NOT NULL,
          raw_transaction_hex TEXT,
          transaction_hash TEXT,
          receipt_path TEXT,
          receipt_sha256 TEXT,
          block_number INTEGER,
          gas_used INTEGER,
          detail_json TEXT NOT NULL,
          intended_at REAL NOT NULL,
          updated_at REAL NOT NULL
        ) STRICT`,
}

// schemaIndexes are created after the column migrations.
var schemaIndexes = []string{
	`CREATE UNIQUE INDEX IF NOT EXISTS events_unique_boundary
          ON events(attempt_id, stage, event, source)`,
	// One nonce is spent by exactly one action of one account, mirroring
	// native_action_intents' UNIQUE(chain_id, actor_public_id, nonce). A failed
	// action releases its nonce again.
	//
	// The earlier revision keyed this guard on the chain role instead of the
	// sender, which is wrong on a chain where the runtime and an embedded
	// protocol agent both act, and it left its rows without an account. Those
	// rows are excluded here: they cannot be attributed, so they neither raise a
	// nonce floor nor block a migration whose own constraint they used to
	// violate.
	`DROP INDEX IF EXISTS actions_nonce_unique`,
	`CREATE UNIQUE INDEX IF NOT EXISTS actions_nonce_sender_unique
          ON actions(chain_id, sender, nonce)
          WHERE state <> 'failed' AND sender <> ''`,
	`CREATE INDEX IF NOT EXISTS actions_attempt_stage
          ON actions(attempt_id, stage)`,
}

func (s *Store) applySchema() error {
	for _, statement := range schemaTables {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("xir state: schema statement failed: %w", err)
		}
	}
	if err := s.migrateEventColumns(); err != nil {
		return err
	}
	if err := s.migrateActionSender(); err != nil {
		return err
	}
	for _, statement := range schemaIndexes {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("xir state: schema index failed: %w", err)
		}
	}
	return nil
}

// migrateActionSender adds the sender column to an actions table created by an
// earlier revision. Rows written before the column existed keep an empty sender;
// they stay readable, but they no longer contribute to any account's nonce
// floor.
func (s *Store) migrateActionSender() error {
	present, err := s.columnPresent("actions", "sender")
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	if _, err := s.db.Exec("ALTER TABLE actions ADD COLUMN sender TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("xir state: cannot migrate actions: %w", err)
	}
	return nil
}

func (s *Store) columnPresent(table, column string) (bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, fmt.Errorf("xir state: cannot inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			index        int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(&index, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, fmt.Errorf("xir state: cannot inspect %s: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("xir state: cannot inspect %s: %w", table, err)
	}
	return false, nil
}

// migrateEventColumns adds process_identity_sha256 to an events table created by
// an earlier revision, exactly as MultihopRunnerState does.
func (s *Store) migrateEventColumns() error {
	present, err := s.columnPresent("events", "process_identity_sha256")
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	if _, err := s.db.Exec("ALTER TABLE events ADD COLUMN process_identity_sha256 TEXT"); err != nil {
		return fmt.Errorf("xir state: cannot migrate events: %w", err)
	}
	return nil
}

// verifyDurability proves the pragmas are in force before the store is used. A
// silent downgrade to synchronous=NORMAL would let a committed intent disappear
// in a crash, so a mismatch is fatal.
func (s *Store) verifyDurability() error {
	var journalMode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("xir state: cannot read journal_mode: %w", err)
	}
	if strings.ToLower(journalMode) != "wal" {
		return fmt.Errorf("xir state: journal_mode is %q, want \"wal\"", journalMode)
	}
	var synchronous int
	if err := s.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		return fmt.Errorf("xir state: cannot read synchronous: %w", err)
	}
	const synchronousFull = 2
	if synchronous != synchronousFull {
		return fmt.Errorf("xir state: synchronous is %d, want %d (FULL)", synchronous, synchronousFull)
	}
	var busyTimeout int
	if err := s.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return fmt.Errorf("xir state: cannot read busy_timeout: %w", err)
	}
	if busyTimeout != busyTimeoutMillis {
		return fmt.Errorf("xir state: busy_timeout is %d, want %d", busyTimeout, busyTimeoutMillis)
	}
	return nil
}

// transact runs fn inside one write transaction under the single-writer mutex.
// Commit returns only after the WAL frame carrying the change is fsynced
// (synchronous=FULL), which is why every recording path can hand control to a
// network action as soon as it returns.
func (s *Store) transact(fn func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("xir state: cannot begin a write: %w", err)
	}
	if err := fn(tx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return fmt.Errorf("%w (rollback also failed: %v)", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("xir state: cannot commit: %w", err)
	}
	return nil
}

func (s *Store) query(fn func(*sql.DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return fn(s.db)
}

// Action is one durable transaction intent with its frozen calldata, signed raw
// transaction, and receipt evidence.
type Action struct {
	ActionID  string
	AttemptID string
	Stage     string
	ChainRole string
	ChainID   uint64
	// Sender is the lowercase hex address of the account that signed the
	// transaction. Nonces are account-scoped, so the reservation floor must be
	// computed per (chain, sender) rather than per chain.
	Sender            string
	To                string
	CalldataHex       string
	CalldataBytes     int
	CalldataSHA256    string
	Value             string
	Gas               uint64
	Nonce             uint64
	State             string
	RawTransactionHex string
	TransactionHash   string
	ReceiptPath       string
	ReceiptSHA256     string
	BlockNumber       uint64
	GasUsed           uint64
	DetailJSON        string
}

// ActionResult is the evidence a caller records when an action succeeds.
type ActionResult struct {
	TransactionHash string
	BlockNumber     uint64
	GasUsed         uint64
	ReceiptPath     string
	ReceiptSHA256   string
	// ContractAddress is set for contract-creation transactions, matching
	// deployer.py's receipt["contractAddress"] lookup.
	ContractAddress string
	Detail          map[string]any
}

// AttemptRow mirrors one row of the attempts table.
type AttemptRow struct {
	AttemptID       string
	Phase           string
	Route           string
	RouteSequence   int
	CoordinatesJSON string
	Status          string
	StartedAt       float64
	FinishedAt      *float64
}

// StageRow mirrors one row of the stages table.
type StageRow struct {
	AttemptID       string
	Stage           string
	State           string
	TransactionHash *string
	DetailJSON      string
	ObservedAt      float64
}

// EventRow mirrors one row of the events table. RecordEvent stamps the dual
// clock, the host boot identity, the writing thread and the process id when the
// caller leaves them zero, exactly like MultihopRunnerState.record_event.
type EventRow struct {
	AttemptID             string
	Stage                 string
	Event                 string
	Source                string
	ChainRole             string
	HopIndex              *int
	TransactionHash       string
	UTCNs                 int64
	MonotonicNs           int64
	BootID                string
	ProcessID             int
	ProcessIdentitySHA256 string
	ThreadID              int
	DetailJSON            string
}

// Action returns one action row, or nil when it does not exist.
func (s *Store) Action(actionID string) (*Action, error) {
	if actionID == "" {
		return nil, errors.New("xir state: empty action id")
	}
	var action *Action
	err := s.query(func(db *sql.DB) error {
		row := db.QueryRow(actionSelect+" WHERE action_id = ?", actionID)
		scanned, err := scanAction(row)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		action = scanned
		return nil
	})
	if err != nil {
		return nil, err
	}
	return action, nil
}

// PendingActions returns every action that has signed bytes but no receipt yet,
// ordered like MultihopRunnerState.pending_signed_transactions so a restarted
// process revalidates and resubmits them in a stable order.
func (s *Store) PendingActions() ([]Action, error) {
	var actions []Action
	err := s.query(func(db *sql.DB) error {
		rows, err := db.Query(actionSelect + ` WHERE state IN ('signed','submitted')
                  ORDER BY attempt_id, stage`)
		if err != nil {
			return fmt.Errorf("xir state: cannot read pending actions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			action, err := scanAction(rows)
			if err != nil {
				return err
			}
			actions = append(actions, *action)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("xir state: cannot read pending actions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return actions, nil
}

// MaxActionNonce returns the highest nonce the given sender has claimed on one
// chain, which is what lets a restarted transactor avoid re-using the nonce of a
// signed transaction that never reached the network.
//
// The sender is part of the key because a nonce is spent per account: a chain in
// this runtime carries the runner and the embedded Hyperlane and LayerZero
// agents, so an unsigned transaction floor computed across accounts would hand
// the runner a nonce another account had already used. Rows written before the
// sender column existed carry an empty sender and therefore contribute nothing;
// an empty sender is refused rather than answered from those rows.
func (s *Store) MaxActionNonce(chainID uint64, sender string) (uint64, bool, error) {
	sender = strings.ToLower(strings.TrimSpace(sender))
	if sender == "" {
		return 0, false, errors.New("xir state: a nonce floor needs the signing account")
	}
	var (
		maximum sql.NullInt64
		found   bool
	)
	err := s.query(func(db *sql.DB) error {
		row := db.QueryRow(
			"SELECT MAX(nonce) FROM actions WHERE chain_id = ? AND sender = ?",
			int64(chainID), sender,
		)
		if err := row.Scan(&maximum); err != nil {
			return fmt.Errorf("xir state: cannot read the maximum action nonce: %w", err)
		}
		found = maximum.Valid
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	if !found {
		return 0, false, nil
	}
	return uint64(maximum.Int64), true, nil
}

const actionSelect = `SELECT action_id, attempt_id, stage, chain_role, chain_id, sender,
        target, calldata_hex, calldata_bytes, calldata_sha256, value, gas, nonce, state,
        raw_transaction_hex, transaction_hash, receipt_path, receipt_sha256,
        block_number, gas_used, detail_json
        FROM actions`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAction(row rowScanner) (*Action, error) {
	var (
		action        Action
		chainID       int64
		gas           int64
		nonce         int64
		blockNumber   sql.NullInt64
		gasUsed       sql.NullInt64
		rawTx         sql.NullString
		transaction   sql.NullString
		receiptPath   sql.NullString
		receiptSHA256 sql.NullString
	)
	if err := row.Scan(
		&action.ActionID,
		&action.AttemptID,
		&action.Stage,
		&action.ChainRole,
		&chainID,
		&action.Sender,
		&action.To,
		&action.CalldataHex,
		&action.CalldataBytes,
		&action.CalldataSHA256,
		&action.Value,
		&gas,
		&nonce,
		&action.State,
		&rawTx,
		&transaction,
		&receiptPath,
		&receiptSHA256,
		&blockNumber,
		&gasUsed,
		&action.DetailJSON,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("xir state: cannot decode an action row: %w", err)
	}
	action.ChainID = uint64(chainID)
	action.Gas = uint64(gas)
	action.Nonce = uint64(nonce)
	action.RawTransactionHex = rawTx.String
	action.TransactionHash = transaction.String
	action.ReceiptPath = receiptPath.String
	action.ReceiptSHA256 = receiptSHA256.String
	action.BlockNumber = uint64(blockNumber.Int64)
	action.GasUsed = uint64(gasUsed.Int64)
	return &action, nil
}

// Detail decodes the durable detail document of the action.
func (a Action) Detail() (map[string]any, error) {
	if strings.TrimSpace(a.DetailJSON) == "" {
		return map[string]any{}, nil
	}
	return decodeDetail(a.DetailJSON)
}

// Intend durably freezes one transaction intent. Replaying the identical intent
// returns the stored row; replaying the same action_id with different frozen
// bytes is identity drift.
func (s *Store) Intend(action Action) (*Action, error) {
	if err := validateIntend(action); err != nil {
		return nil, err
	}
	if action.State == "" {
		action.State = ActionIntended
	}
	if action.DetailJSON == "" {
		action.DetailJSON = "{}"
	}
	action.Sender = strings.ToLower(strings.TrimSpace(action.Sender))
	stored, err := s.Action(action.ActionID)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		if err := sameFrozenIdentity(*stored, action); err != nil {
			return nil, err
		}
		return stored, nil
	}
	now := epochSeconds(time.Now())
	err = s.transact(func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`INSERT INTO actions(
                          action_id, attempt_id, stage, chain_role, chain_id, sender,
                          target, calldata_hex, calldata_bytes, calldata_sha256, value,
                          gas, nonce, state, detail_json, intended_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			action.ActionID, action.AttemptID, action.Stage, action.ChainRole,
			int64(action.ChainID), action.Sender, action.To, action.CalldataHex,
			action.CalldataBytes, action.CalldataSHA256, action.Value,
			int64(action.Gas), int64(action.Nonce), action.State, action.DetailJSON,
			now, now,
		)
		if err != nil {
			return fmt.Errorf("xir state: cannot record action %s: %w", action.ActionID, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Action(action.ActionID)
}

func validateIntend(action Action) error {
	if action.ActionID == "" {
		return errors.New("xir state: an intent needs an action id")
	}
	if action.ChainRole == "" {
		return fmt.Errorf("xir state: action %s has no chain role", action.ActionID)
	}
	if action.Sender == "" {
		return fmt.Errorf("xir state: action %s has no sender account", action.ActionID)
	}
	if action.State != "" && action.State != ActionIntended {
		return fmt.Errorf(
			"xir state: action %s must be intended at insert time, got %q",
			action.ActionID, action.State,
		)
	}
	if action.Gas == 0 {
		return fmt.Errorf("xir state: action %s froze a zero gas limit", action.ActionID)
	}
	calldata, err := decodeHex(action.CalldataHex)
	if err != nil {
		return fmt.Errorf("xir state: action %s has invalid calldata: %w", action.ActionID, err)
	}
	if len(calldata) != action.CalldataBytes {
		return fmt.Errorf(
			"%w: action %s froze %d calldata bytes but carries %d",
			ErrDrift, action.ActionID, action.CalldataBytes, len(calldata),
		)
	}
	if err := requireDigest(action.CalldataSHA256, "calldata_sha256", action.ActionID); err != nil {
		return err
	}
	if observed := sha256Hex(calldata); observed != action.CalldataSHA256 {
		return fmt.Errorf(
			"%w: action %s froze calldata_sha256 %s but its bytes digest to %s",
			ErrDrift, action.ActionID, action.CalldataSHA256, observed,
		)
	}
	if action.Value == "" {
		return fmt.Errorf("xir state: action %s has no value", action.ActionID)
	}
	return nil
}

// sameFrozenIdentity compares the fields a restart must be able to re-derive
// byte for byte.
func sameFrozenIdentity(stored, requested Action) error {
	compare := []struct {
		name     string
		stored   string
		replayed string
	}{
		{"attempt_id", stored.AttemptID, requested.AttemptID},
		{"stage", stored.Stage, requested.Stage},
		{"chain_role", stored.ChainRole, requested.ChainRole},
		{"sender", stored.Sender, strings.ToLower(strings.TrimSpace(requested.Sender))},
		{"target", stored.To, requested.To},
		{"calldata_hex", stored.CalldataHex, requested.CalldataHex},
		{"calldata_sha256", stored.CalldataSHA256, requested.CalldataSHA256},
		{"value", stored.Value, requested.Value},
	}
	for _, field := range compare {
		if field.stored != field.replayed {
			return fmt.Errorf(
				"%w: action %s %s is %q in the ledger and %q in the replay",
				ErrDrift, stored.ActionID, field.name, field.stored, field.replayed,
			)
		}
	}
	if stored.ChainID != requested.ChainID {
		return fmt.Errorf(
			"%w: action %s chain_id is %d in the ledger and %d in the replay",
			ErrDrift, stored.ActionID, stored.ChainID, requested.ChainID,
		)
	}
	if stored.Gas != requested.Gas {
		return fmt.Errorf(
			"%w: action %s gas is %d in the ledger and %d in the replay",
			ErrDrift, stored.ActionID, stored.Gas, requested.Gas,
		)
	}
	if stored.Nonce != requested.Nonce {
		return fmt.Errorf(
			"%w: action %s nonce is %d in the ledger and %d in the replay",
			ErrDrift, stored.ActionID, stored.Nonce, requested.Nonce,
		)
	}
	if stored.CalldataBytes != requested.CalldataBytes {
		return fmt.Errorf(
			"%w: action %s calldata_bytes is %d in the ledger and %d in the replay",
			ErrDrift, stored.ActionID, stored.CalldataBytes, requested.CalldataBytes,
		)
	}
	return nil
}

// RecordSigned binds the raw signed transaction and its hash to the frozen
// intent, then mirrors the write into the Python runner's signed-transaction
// ledger when the action carries an attempt and a stage. The write is atomic:
// either the raw bytes, the transaction identity, the stage rows and the
// boundary events are all durable, or none of them are.
func (s *Store) RecordSigned(actionID string, rawTx []byte, txHash string) error {
	if actionID == "" {
		return errors.New("xir state: RecordSigned needs an action id")
	}
	if len(rawTx) == 0 {
		return fmt.Errorf("xir state: action %s has no raw transaction bytes", actionID)
	}
	canonical, err := canonicalHash(txHash)
	if err != nil {
		return fmt.Errorf("xir state: action %s: %w", actionID, err)
	}
	if observed := keccakHex(rawTx); observed != canonical {
		return fmt.Errorf(
			"%w: action %s was handed transaction hash %s but its bytes hash to %s",
			ErrDrift, actionID, canonical, observed,
		)
	}
	action, err := s.Action(actionID)
	if err != nil {
		return err
	}
	if action == nil {
		return fmt.Errorf("xir state: action %s was never intended", actionID)
	}
	if action.RawTransactionHex != "" {
		existing, err := decodeHex(action.RawTransactionHex)
		if err != nil {
			return fmt.Errorf("%w: action %s has undecodable raw bytes: %v", ErrDrift, actionID, err)
		}
		if !bytesEqual(existing, rawTx) || action.TransactionHash != canonical {
			return fmt.Errorf(
				"%w: action %s already holds signed transaction %s",
				ErrDrift, actionID, action.TransactionHash,
			)
		}
		if action.State == ActionSucceeded || action.State == ActionFailed {
			return nil
		}
	}
	if err := checkTransition(action.State, ActionSigned); err != nil {
		return err
	}
	signedDetail, err := s.signedDetail(action, rawTx)
	if err != nil {
		return err
	}
	rawSHA256 := sha256Hex(rawTx)
	now := epochSeconds(time.Now())
	err = s.transact(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`UPDATE actions
                            SET state = ?, raw_transaction_hex = ?, transaction_hash = ?,
                                detail_json = ?, updated_at = ?
                          WHERE action_id = ?`,
			ActionSigned, encodeHex(rawTx), canonical, signedDetail, now, actionID,
		); err != nil {
			return fmt.Errorf("xir state: cannot record signed action %s: %w", actionID, err)
		}
		if action.AttemptID == "" || action.Stage == "" {
			return nil
		}
		if err := insertDurableSigned(tx, action, canonical, rawTx, rawSHA256, signedDetail); err != nil {
			return err
		}
		intended, err := intendedDetail(action)
		if err != nil {
			return err
		}
		if err := insertStageAndEvent(tx, stageWrite{
			attemptID:       action.AttemptID,
			stage:           action.Stage,
			state:           ActionIntended,
			detailJSON:      intended,
			transactionHash: nil,
			observedAt:      now,
			updateCurrent:   false,
			chainRole:       action.ChainRole,
			bootID:          s.bootID,
		}); err != nil {
			return err
		}
		return insertStageAndEvent(tx, stageWrite{
			attemptID:       action.AttemptID,
			stage:           action.Stage,
			state:           ActionSigned,
			detailJSON:      signedDetail,
			transactionHash: &canonical,
			observedAt:      now,
			updateCurrent:   true,
			chainRole:       action.ChainRole,
			bootID:          s.bootID,
		})
	})
	if err != nil {
		return err
	}
	return nil
}

// signedDetail merges the frozen action identity with the caller's detail
// document and the raw transaction digest, mirroring the `signed_detail` the
// Python runner writes into durable_signed_transactions.
func (s *Store) signedDetail(action *Action, rawTx []byte) (string, error) {
	detail, err := intendedDetail(action)
	if err != nil {
		return "", err
	}
	fields, err := decodeDetail(detail)
	if err != nil {
		return "", err
	}
	fields["raw_sha256"] = sha256Hex(rawTx)
	return CanonicalJSON(fields)
}

// intendedDetail is the frozen-intent document the Python runner records before
// signing: the chain role, the reserved nonce, the target and the calldata
// digest, plus whatever the caller froze in the action detail.
func intendedDetail(action *Action) (string, error) {
	fields, err := action.Detail()
	if err != nil {
		return "", err
	}
	fields["role"] = action.ChainRole
	fields["nonce"] = action.Nonce
	fields["target"] = action.To
	fields["calldata_sha256"] = action.CalldataSHA256
	fields["chain_id"] = action.ChainID
	return CanonicalJSON(fields)
}

func insertDurableSigned(
	tx *sql.Tx,
	action *Action,
	txHash string,
	rawTx []byte,
	rawSHA256 string,
	detailJSON string,
) error {
	var (
		existingHash sql.NullString
		existingSHA  sql.NullString
		existingRaw  []byte
	)
	err := tx.QueryRow(
		`SELECT transaction_hash, raw_sha256, raw_transaction
                   FROM durable_signed_transactions
                  WHERE attempt_id = ? AND stage = ?`,
		action.AttemptID, action.Stage,
	).Scan(&existingHash, &existingSHA, &existingRaw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(
			`INSERT INTO durable_signed_transactions(
                           attempt_id, stage, transaction_hash, raw_transaction,
                           raw_sha256, detail_json
                         ) VALUES (?,?,?,?,?,?)`,
			action.AttemptID, action.Stage, txHash, rawTx, rawSHA256, detailJSON,
		); err != nil {
			return fmt.Errorf(
				"xir state: cannot record durable signed transaction for %s/%s: %w",
				action.AttemptID, action.Stage, err,
			)
		}
		return nil
	case err != nil:
		return fmt.Errorf("xir state: cannot read durable signed transactions: %w", err)
	}
	if existingHash.String != txHash || existingSHA.String != rawSHA256 || !bytesEqual(existingRaw, rawTx) {
		return fmt.Errorf(
			"%w: durable signed transaction for %s/%s already holds %s",
			ErrDrift, action.AttemptID, action.Stage, existingHash.String,
		)
	}
	return nil
}

// Observe advances an action to a new state and merges detail into its durable
// detail document, mirroring the runner's stage/event boundary recording.
func (s *Store) Observe(actionID, stateName string, detail map[string]any) error {
	if _, err := actionRank(stateName); err != nil {
		return err
	}
	action, err := s.Action(actionID)
	if err != nil {
		return err
	}
	if action == nil {
		return fmt.Errorf("xir state: action %s was never intended", actionID)
	}
	switch stateName {
	case ActionSigned, ActionSubmitted, ActionSucceeded:
		// A signed or submitted action without its raw bytes cannot be
		// revalidated after a restart, so the transition is refused here rather
		// than discovered later.
		if action.RawTransactionHex == "" {
			return fmt.Errorf(
				"xir state: action %s cannot become %s before its raw transaction is recorded",
				actionID, stateName,
			)
		}
	}
	if action.State == stateName {
		if len(detail) == 0 {
			return nil
		}
	} else if err := checkTransition(action.State, stateName); err != nil {
		return err
	}
	merged, err := mergeDetail(action.DetailJSON, detail)
	if err != nil {
		return err
	}
	var transactionHash *string
	if action.TransactionHash != "" {
		hash := action.TransactionHash
		transactionHash = &hash
	}
	now := epochSeconds(time.Now())
	return s.transact(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`UPDATE actions SET state = ?, detail_json = ?, updated_at = ?
                          WHERE action_id = ?`,
			stateName, merged, now, actionID,
		); err != nil {
			return fmt.Errorf("xir state: cannot observe action %s: %w", actionID, err)
		}
		if action.AttemptID == "" || action.Stage == "" {
			return nil
		}
		fields, err := decodeDetail(merged)
		if err != nil {
			return err
		}
		return insertStageAndEvent(tx, stageWrite{
			attemptID:       action.AttemptID,
			stage:           action.Stage,
			state:           stateName,
			detailJSON:      merged,
			transactionHash: transactionHash,
			observedAt:      now,
			updateCurrent:   true,
			chainRole:       actionDetailString(fields, "role"),
			hopIndex:        actionDetailInt(fields, "hop_index"),
			bootID:          s.bootID,
		})
	})
}

// Succeed records the final receipt evidence and closes the action.
func (s *Store) Succeed(actionID string, result ActionResult) error {
	canonical, err := canonicalHash(result.TransactionHash)
	if err != nil {
		return fmt.Errorf("xir state: action %s: %w", actionID, err)
	}
	if result.ReceiptPath != "" {
		if err := requireDigest(result.ReceiptSHA256, "receipt_sha256", actionID); err != nil {
			return err
		}
	}
	action, err := s.Action(actionID)
	if err != nil {
		return err
	}
	if action == nil {
		return fmt.Errorf("xir state: action %s was never intended", actionID)
	}
	if action.TransactionHash != "" && action.TransactionHash != canonical {
		return fmt.Errorf(
			"%w: action %s succeeded on %s but the ledger holds %s",
			ErrDrift, actionID, canonical, action.TransactionHash,
		)
	}
	if action.State == ActionSucceeded {
		if action.BlockNumber == result.BlockNumber && action.GasUsed == result.GasUsed {
			return nil
		}
		return fmt.Errorf(
			"%w: action %s already succeeded at block %d with %d gas",
			ErrDrift, actionID, action.BlockNumber, action.GasUsed,
		)
	}
	if err := checkTransition(action.State, ActionSucceeded); err != nil {
		return err
	}
	merged, err := mergeDetail(action.DetailJSON, result.Detail)
	if err != nil {
		return err
	}
	if result.ContractAddress != "" {
		merged, err = mergeDetail(merged, map[string]any{"contract_address": result.ContractAddress})
		if err != nil {
			return err
		}
	}
	if result.ReceiptPath != "" {
		merged, err = mergeDetail(merged, map[string]any{
			"receipt":        result.ReceiptPath,
			"receipt_sha256": result.ReceiptSHA256,
			"gas_used":       result.GasUsed,
			"block_number":   result.BlockNumber,
		})
		if err != nil {
			return err
		}
	}
	var transactionHash *string
	if canonical != "" {
		transactionHash = &canonical
	}
	now := epochSeconds(time.Now())
	return s.transact(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`UPDATE actions
                            SET state = ?, transaction_hash = COALESCE(NULLIF(?, ''), transaction_hash),
                                receipt_path = ?, receipt_sha256 = ?, block_number = ?,
                                gas_used = ?, detail_json = ?, updated_at = ?
                          WHERE action_id = ?`,
			ActionSucceeded, canonical, result.ReceiptPath, result.ReceiptSHA256,
			int64(result.BlockNumber), int64(result.GasUsed), merged, now, actionID,
		); err != nil {
			return fmt.Errorf("xir state: cannot complete action %s: %w", actionID, err)
		}
		if action.AttemptID == "" || action.Stage == "" {
			return nil
		}
		return insertStageAndEvent(tx, stageWrite{
			attemptID:       action.AttemptID,
			stage:           action.Stage,
			state:           ActionSucceeded,
			detailJSON:      merged,
			transactionHash: transactionHash,
			observedAt:      now,
			updateCurrent:   true,
			chainRole:       action.ChainRole,
			bootID:          s.bootID,
		})
	})
}

// BeginAttempt registers one attempt, or validates that a durable attempt still
// matches the frozen coordinates. It reports whether the caller should execute
// the attempt: false means it already succeeded. A durable attempt whose phase,
// route, sequence or coordinates differ from the frozen plan is drift.
func (s *Store) BeginAttempt(attempt AttemptRow) (bool, error) {
	if attempt.AttemptID == "" {
		return false, errors.New("xir state: an attempt needs an attempt id")
	}
	now := epochSeconds(time.Now())
	existing, err := s.attempt(attempt.AttemptID)
	if err != nil {
		return false, err
	}
	if existing != nil {
		fields := []struct {
			name   string
			stored string
			frozen string
		}{
			{"phase", existing.Phase, attempt.Phase},
			{"route", existing.Route, attempt.Route},
			{"coordinates_json", existing.CoordinatesJSON, attempt.CoordinatesJSON},
		}
		for _, field := range fields {
			if field.stored != field.frozen {
				return false, fmt.Errorf(
					"%w: attempt %s %s is %q in the ledger and %q in the frozen plan",
					ErrDrift, attempt.AttemptID, field.name, field.stored, field.frozen,
				)
			}
		}
		if existing.RouteSequence != attempt.RouteSequence {
			return false, fmt.Errorf(
				"%w: attempt %s route_sequence is %d in the ledger and %d in the frozen plan",
				ErrDrift, attempt.AttemptID, existing.RouteSequence, attempt.RouteSequence,
			)
		}
		return existing.Status != AttemptSucceeded, nil
	}
	err = s.transact(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`INSERT INTO attempts(
                          attempt_id, phase, route, route_sequence, coordinates_json,
                          status, started_at
                        ) VALUES (?,?,?,?,?,?,?)`,
			attempt.AttemptID, attempt.Phase, attempt.Route, attempt.RouteSequence,
			attempt.CoordinatesJSON, AttemptRunning, now,
		); err != nil {
			return fmt.Errorf("xir state: cannot begin attempt %s: %w", attempt.AttemptID, err)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// FinishAttempt marks the attempt succeeded and stamps its finish time.
func (s *Store) FinishAttempt(attemptID string) error {
	return s.transact(func(tx *sql.Tx) error {
		result, err := tx.Exec(
			"UPDATE attempts SET status = ?, finished_at = ? WHERE attempt_id = ?",
			AttemptSucceeded, epochSeconds(time.Now()), attemptID,
		)
		if err != nil {
			return fmt.Errorf("xir state: cannot finish attempt %s: %w", attemptID, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("xir state: cannot finish attempt %s: %w", attemptID, err)
		}
		if affected == 0 {
			return fmt.Errorf("xir state: attempt %s was never begun", attemptID)
		}
		return nil
	})
}

func (s *Store) attempt(attemptID string) (*AttemptRow, error) {
	var stored *AttemptRow
	err := s.query(func(db *sql.DB) error {
		row := db.QueryRow(
			`SELECT attempt_id, phase, route, route_sequence, coordinates_json,
                                status, started_at, finished_at
                           FROM attempts WHERE attempt_id = ?`,
			attemptID,
		)
		var (
			attempt    AttemptRow
			finishedAt sql.NullFloat64
			startedAt  float64
		)
		if err := row.Scan(
			&attempt.AttemptID, &attempt.Phase, &attempt.Route,
			&attempt.RouteSequence, &attempt.CoordinatesJSON, &attempt.Status,
			&startedAt, &finishedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("xir state: cannot decode an attempt row: %w", err)
		}
		attempt.StartedAt = startedAt
		if finishedAt.Valid {
			value := finishedAt.Float64
			attempt.FinishedAt = &value
		}
		stored = &attempt
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// RecordStage appends one stage boundary to stage_history, updates the current
// stage row, and records the matching idempotent event, exactly like
// MultihopRunnerState.record_stage.
func (s *Store) RecordStage(row StageRow) error {
	if row.AttemptID == "" || row.Stage == "" {
		return errors.New("xir state: a stage row needs an attempt id and a stage")
	}
	if row.DetailJSON == "" {
		row.DetailJSON = "{}"
	}
	if row.ObservedAt == 0 {
		row.ObservedAt = epochSeconds(time.Now())
	}
	return s.transact(func(tx *sql.Tx) error {
		return insertStageAndEvent(tx, stageWrite{
			attemptID:       row.AttemptID,
			stage:           row.Stage,
			state:           row.State,
			detailJSON:      row.DetailJSON,
			transactionHash: row.TransactionHash,
			observedAt:      row.ObservedAt,
			updateCurrent:   true,
			chainRole:       "",
			bootID:          s.bootID,
		})
	})
}

// Stage returns the current row for one attempt stage, or nil when the stage has
// not been recorded yet.
func (s *Store) Stage(attemptID, stage string) (*StageRow, error) {
	var stored *StageRow
	err := s.query(func(db *sql.DB) error {
		row := db.QueryRow(
			`SELECT attempt_id, stage, state, transaction_hash, detail_json, observed_at
                           FROM stages WHERE attempt_id = ? AND stage = ?`,
			attemptID, stage,
		)
		var (
			result      StageRow
			transaction sql.NullString
		)
		if err := row.Scan(
			&result.AttemptID, &result.Stage, &result.State, &transaction,
			&result.DetailJSON, &result.ObservedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("xir state: cannot decode a stage row: %w", err)
		}
		if transaction.Valid {
			value := transaction.String
			result.TransactionHash = &value
		}
		stored = &result
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// RecordEvent appends one durable event boundary. The events table carries a
// unique index on (attempt_id, stage, event, source), so replaying the same
// boundary after a restart is a no-op rather than a duplicate.
func (s *Store) RecordEvent(row EventRow) error {
	if row.AttemptID == "" || row.Stage == "" || row.Event == "" || row.Source == "" {
		return errors.New("xir state: an event row needs attempt, stage, event and source")
	}
	if row.DetailJSON == "" {
		row.DetailJSON = "{}"
	}
	if row.BootID == "" {
		row.BootID = s.bootID
	}
	if row.ProcessID == 0 {
		row.ProcessID = os.Getpid()
	}
	if row.ThreadID == 0 {
		row.ThreadID = threadID()
	}
	if row.UTCNs == 0 {
		row.UTCNs = time.Now().UnixNano()
	}
	if row.MonotonicNs == 0 {
		observed, err := monotonicNanos()
		if err != nil {
			return err
		}
		row.MonotonicNs = observed
	}
	return s.transact(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO events(
                          attempt_id, stage, event, source, chain_role, hop_index,
                          transaction_hash, utc_ns, monotonic_ns, boot_id, process_id,
                          process_identity_sha256, thread_id, detail_json
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			row.AttemptID, row.Stage, row.Event, row.Source,
			nullableString(row.ChainRole), nullableInt(row.HopIndex),
			nullableString(row.TransactionHash), row.UTCNs, row.MonotonicNs,
			row.BootID, row.ProcessID, nullableString(row.ProcessIdentitySHA256),
			row.ThreadID, row.DetailJSON,
		); err != nil {
			return fmt.Errorf("xir state: cannot record event %s/%s: %w", row.AttemptID, row.Event, err)
		}
		return nil
	})
}

// RecordError appends one transient failure with its per-attempt retry index,
// mirroring RunnerState.record_transient_error.
func (s *Store) RecordError(attemptID, class, message string) error {
	if attemptID == "" {
		return errors.New("xir state: an error row needs an attempt id")
	}
	if class == "" {
		return errors.New("xir state: an error row needs an error class")
	}
	return s.transact(func(tx *sql.Tx) error {
		var retryIndex int
		if err := tx.QueryRow(
			"SELECT COUNT(*) FROM attempt_errors WHERE attempt_id = ?", attemptID,
		).Scan(&retryIndex); err != nil {
			return fmt.Errorf("xir state: cannot count attempt errors: %w", err)
		}
		if _, err := tx.Exec(
			`INSERT INTO attempt_errors(
                          attempt_id, error_class, error_message, retry_index, observed_at
                        ) VALUES (?,?,?,?,?)`,
			attemptID, class, message, retryIndex+1, epochSeconds(time.Now()),
		); err != nil {
			return fmt.Errorf("xir state: cannot record an attempt error: %w", err)
		}
		return nil
	})
}

// NextReservedRootNonce returns the next gateway record nonce this ledger has
// reserved. Both Python runners derive it the same way from the highest
// `record_nonce` already frozen in a root stage; the stage name differs between
// them (multihop_runner uses root_create, runner.py uses xir_root_record), so
// both are considered.
func (s *Store) NextReservedRootNonce() (uint64, error) {
	var (
		maximum sql.NullInt64
		next    uint64
	)
	err := s.query(func(db *sql.DB) error {
		row := db.QueryRow(
			`SELECT MAX(CAST(json_extract(detail_json, '$.record_nonce') AS INTEGER)) AS maximum
                           FROM stages WHERE stage IN ('root_create', 'xir_root_record')`,
		)
		if err := row.Scan(&maximum); err != nil {
			return fmt.Errorf("xir state: cannot read the reserved root nonce: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if !maximum.Valid {
		return 0, nil
	}
	next = uint64(maximum.Int64) + 1
	return next, nil
}

// VerifyActionIdentity re-derives the frozen identity of an action row and
// rejects any mismatch: the calldata bytes must digest to the frozen calldata
// digest and have the frozen length, and the raw transaction must hash to the
// recorded transaction hash. A row edited outside the store therefore fails
// loudly instead of being rebroadcast.
func VerifyActionIdentity(action *Action) error {
	if action == nil {
		return errors.New("xir state: no action to verify")
	}
	if action.ActionID == "" {
		return errors.New("xir state: action row has no action id")
	}
	if action.ChainRole == "" {
		return fmt.Errorf("xir state: action %s has no chain role", action.ActionID)
	}
	if action.Sender == "" {
		return fmt.Errorf("xir state: action %s has no sender account", action.ActionID)
	}
	if _, err := actionRank(action.State); err != nil {
		return fmt.Errorf("xir state: action %s: %w", action.ActionID, err)
	}
	if action.Gas == 0 {
		return fmt.Errorf("xir state: action %s froze a zero gas limit", action.ActionID)
	}
	calldata, err := decodeHex(action.CalldataHex)
	if err != nil {
		return fmt.Errorf("%w: action %s has undecodable calldata: %v", ErrDrift, action.ActionID, err)
	}
	if len(calldata) != action.CalldataBytes {
		return fmt.Errorf(
			"%w: action %s carries %d calldata bytes but froze %d",
			ErrDrift, action.ActionID, len(calldata), action.CalldataBytes,
		)
	}
	if err := requireDigest(action.CalldataSHA256, "calldata_sha256", action.ActionID); err != nil {
		return err
	}
	if observed := sha256Hex(calldata); observed != action.CalldataSHA256 {
		return fmt.Errorf(
			"%w: action %s carries calldata digest %s but froze %s",
			ErrDrift, action.ActionID, observed, action.CalldataSHA256,
		)
	}
	if action.ReceiptSHA256 != "" {
		if err := requireDigest(action.ReceiptSHA256, "receipt_sha256", action.ActionID); err != nil {
			return err
		}
	}
	switch action.State {
	case ActionSigned, ActionSubmitted, ActionSucceeded:
	default:
		return nil
	}
	if action.RawTransactionHex == "" || action.TransactionHash == "" {
		return fmt.Errorf(
			"%w: action %s is %s but holds no signed transaction",
			ErrDrift, action.ActionID, action.State,
		)
	}
	raw, err := decodeHex(action.RawTransactionHex)
	if err != nil {
		return fmt.Errorf("%w: action %s has undecodable raw bytes: %v", ErrDrift, action.ActionID, err)
	}
	if observed := keccakHex(raw); observed != action.TransactionHash {
		return fmt.Errorf(
			"%w: action %s carries raw bytes hashing to %s but records %s",
			ErrDrift, action.ActionID, observed, action.TransactionHash,
		)
	}
	return nil
}

func actionRank(stateName string) (int, error) {
	switch stateName {
	case ActionIntended:
		return 0, nil
	case ActionSigned:
		return 1, nil
	case ActionSubmitted:
		return 2, nil
	case ActionSucceeded:
		return 3, nil
	case ActionFailed:
		return 4, nil
	default:
		return 0, fmt.Errorf("xir state: unknown action state %q", stateName)
	}
}

func checkTransition(from, to string) error {
	if from == "" {
		return nil
	}
	if from == to {
		return nil
	}
	fromRank, err := actionRank(from)
	if err != nil {
		return err
	}
	toRank, err := actionRank(to)
	if err != nil {
		return err
	}
	if from == ActionFailed {
		return fmt.Errorf("%w: %s is terminal and cannot become %s", ErrStateTransition, from, to)
	}
	if from == ActionSucceeded {
		return fmt.Errorf("%w: %s is terminal and cannot become %s", ErrStateTransition, from, to)
	}
	if to != ActionFailed && toRank < fromRank {
		return fmt.Errorf("%w: %s cannot regress to %s", ErrStateTransition, from, to)
	}
	return nil
}

type stageWrite struct {
	attemptID       string
	stage           string
	state           string
	detailJSON      string
	transactionHash *string
	observedAt      float64
	updateCurrent   bool
	chainRole       string
	hopIndex        *int
	bootID          string
}

// insertStageAndEvent implements the Python runner's shared stage/event write:
// one append to stage_history, an upsert of the current stage row when the
// caller asks for it, and one idempotent event boundary.
func insertStageAndEvent(tx *sql.Tx, write stageWrite) error {
	if _, err := tx.Exec(
		`INSERT INTO stage_history(
                  attempt_id, stage, state, transaction_hash, detail_json, observed_at
                ) VALUES (?,?,?,?,?,?)`,
		write.attemptID, write.stage, write.state, write.transactionHash,
		write.detailJSON, write.observedAt,
	); err != nil {
		return fmt.Errorf(
			"xir state: cannot record stage history for %s/%s: %w",
			write.attemptID, write.stage, err,
		)
	}
	if write.updateCurrent {
		if _, err := tx.Exec(
			`INSERT INTO stages(
                          attempt_id, stage, state, transaction_hash, detail_json, observed_at
                        ) VALUES (?,?,?,?,?,?)
                        ON CONFLICT(attempt_id, stage) DO UPDATE SET
                          state=excluded.state,
                          transaction_hash=excluded.transaction_hash,
                          detail_json=excluded.detail_json,
                          observed_at=excluded.observed_at`,
			write.attemptID, write.stage, write.state, write.transactionHash,
			write.detailJSON, write.observedAt,
		); err != nil {
			return fmt.Errorf(
				"xir state: cannot record stage %s/%s: %w", write.attemptID, write.stage, err,
			)
		}
	}
	fields, err := decodeDetail(write.detailJSON)
	if err != nil {
		return err
	}
	chainRole := write.chainRole
	if chainRole == "" {
		chainRole = actionDetailString(fields, "role")
	}
	hopIndex := write.hopIndex
	if hopIndex == nil {
		hopIndex = actionDetailInt(fields, "hop_index")
	}
	// The Python multihop state embeds its process identity in every event
	// detail document. The Go runtime leaves process identity to the caller
	// (runner orchestration), so the event detail is the stage detail itself.
	eventDetail, err := CanonicalJSON(fields)
	if err != nil {
		return err
	}
	utcNs := time.Now().UnixNano()
	monotonic, err := monotonicNanos()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO events(
                  attempt_id, stage, event, source, chain_role, hop_index,
                  transaction_hash, utc_ns, monotonic_ns, boot_id, process_id,
                  process_identity_sha256, thread_id, detail_json
                ) VALUES (?,?,?,'coordinator',?,?,?,?,?,?,?,?,?,?)`,
		write.attemptID, write.stage, write.state, nullableString(chainRole),
		nullableInt(hopIndex), nullableStringPointer(write.transactionHash),
		utcNs, monotonic, write.bootID, os.Getpid(), nil, threadID(), eventDetail,
	); err != nil {
		return fmt.Errorf(
			"xir state: cannot record the %s event for %s/%s: %w",
			write.state, write.attemptID, write.stage, err,
		)
	}
	return nil
}

func mergeDetail(existing string, addition map[string]any) (string, error) {
	fields, err := decodeDetail(existing)
	if err != nil {
		return "", err
	}
	return mergeDetailFields(fields, addition)
}

func mergeDetailFields(fields map[string]any, addition map[string]any) (string, error) {
	for key, value := range addition {
		fields[key] = value
	}
	return CanonicalJSON(fields)
}

func decodeDetail(document string) (map[string]any, error) {
	if strings.TrimSpace(document) == "" {
		return map[string]any{}, nil
	}
	decoded, err := decodeJSONValue(document)
	if err != nil {
		return nil, fmt.Errorf("xir state: detail document is not valid JSON: %w", err)
	}
	fields, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("xir state: detail document is a %T, want an object", decoded)
	}
	return fields, nil
}

func actionDetailString(fields map[string]any, key string) string {
	value, ok := fields[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

func actionDetailInt(fields map[string]any, key string) *int {
	value, ok := fields[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case int:
		return &typed
	case int64:
		converted := int(typed)
		return &converted
	case float64:
		converted := int(typed)
		return &converted
	case json.Number:
		converted, err := typed.Int64()
		if err != nil {
			return nil
		}
		value := int(converted)
		return &value
	default:
		return nil
	}
}

func requireDigest(value, field, actionID string) error {
	if len(value) != 64 {
		return fmt.Errorf(
			"xir state: action %s %s is %q, want 64 hex characters",
			actionID, field, value,
		)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("xir state: action %s %s is not hex: %w", actionID, field, err)
	}
	if strings.ToLower(value) != value {
		return fmt.Errorf("xir state: action %s %s is not lowercase hex", actionID, field)
	}
	return nil
}

// canonicalHash normalises a transaction hash to the 0x-prefixed lowercase form
// the Python runner writes ("0x" + value.lower().removeprefix("0x")).
func canonicalHash(value string) (string, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if trimmed == "" {
		return "", errors.New("empty transaction hash")
	}
	if len(trimmed)%2 != 0 {
		return "", fmt.Errorf("transaction hash %q has an odd number of hex digits", value)
	}
	decoded, err := hex.DecodeString(strings.ToLower(trimmed))
	if err != nil {
		return "", fmt.Errorf("transaction hash %q is not hex: %w", value, err)
	}
	return "0x" + hex.EncodeToString(decoded), nil
}

func decodeHex(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	trimmed = strings.TrimPrefix(trimmed, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("hex string has an odd number of digits")
	}
	decoded, err := hex.DecodeString(strings.ToLower(trimmed))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func encodeHex(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func keccakHex(value []byte) string {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(value)
	return "0x" + hex.EncodeToString(hasher.Sum(nil))
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

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func nullableStringPointer(value *string) any {
	if value == nil || *value == "" {
		return nil
	}
	return *value
}

// epochSeconds mirrors Python's time.time(): a float number of seconds since the
// epoch, stored in a REAL column.
func epochSeconds(now time.Time) float64 {
	return float64(now.UnixNano()) / float64(time.Second)
}
