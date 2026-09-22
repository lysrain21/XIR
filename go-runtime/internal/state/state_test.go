package state

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "runner", "runner.sqlite"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

func keccakHexOf(t *testing.T, raw []byte) string {
	t.Helper()
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(raw)
	return "0x" + hex.EncodeToString(hasher.Sum(nil))
}

func hexOf(data []byte) string { return "0x" + hex.EncodeToString(data) }

// testSender is the account the state tests freeze actions for.
const testSender = "0x00000000000000000000000000000000000000f0"

func testAction(calldata []byte, nonce uint64, role string) Action {
	return Action{
		ActionID:       fmt.Sprintf("action-%s-%d-%s", role, nonce, hexOf(calldata)[2:]),
		AttemptID:      "attempt-1",
		Stage:          "hop_0_h_dispatch",
		ChainRole:      role,
		ChainID:        3133701,
		Sender:         testSender,
		To:             "0x00000000000000000000000000000000000000aa",
		CalldataHex:    hexOf(calldata),
		CalldataBytes:  len(calldata),
		CalldataSHA256: sha256Hex(calldata),
		Value:          "0",
		Gas:            12_000_000,
		Nonce:          nonce,
		DetailJSON:     `{"role": "` + role + `"}`,
	}
}

func TestOpenAppliesDurablePragmas(t *testing.T) {
	store := openTestStore(t)
	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}
	var synchronous int
	if err := store.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("synchronous: %v", err)
	}
	if synchronous != 2 {
		t.Errorf("synchronous = %d, want 2 (FULL)", synchronous)
	}
	var busyTimeout int
	if err := store.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if busyTimeout != busyTimeoutMillis {
		t.Errorf("busy_timeout = %d, want %d", busyTimeout, busyTimeoutMillis)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("database mode = %o, want 600", mode)
	}
	directory, err := os.Stat(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if mode := directory.Mode().Perm(); mode != 0o700 {
		t.Errorf("database directory mode = %o, want 700", mode)
	}
}

func TestCanonicalJSONMatchesPythonDumps(t *testing.T) {
	compact, err := CanonicalJSON(map[string]any{
		"b": 1,
		"a": []any{1, 2, "x"},
		"u": "caf\u00e9",
		"f": 0.1,
		"n": nil,
		"t": true,
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	const wantCompact = `{"a": [1, 2, "x"], "b": 1, "f": 0.1, "n": null, "t": true, "u": "caf\u00e9"}`
	if compact != wantCompact {
		t.Errorf("CanonicalJSON =\n%s\nwant\n%s", compact, wantCompact)
	}
	indented, err := CanonicalJSONIndent(map[string]any{"b": 1, "a": map[string]any{"c": 2}, "e": []any{}}, 2)
	if err != nil {
		t.Fatalf("CanonicalJSONIndent: %v", err)
	}
	const wantIndented = "{\n  \"a\": {\n    \"c\": 2\n  },\n  \"b\": 1,\n  \"e\": []\n}"
	if indented != wantIndented {
		t.Errorf("CanonicalJSONIndent =\n%s\nwant\n%s", indented, wantIndented)
	}
}

// TestOpenMigratesALegacyActionsTable proves a store written by the revision
// before the sender column still opens: the column is added, the account-scoped
// nonce index replaces the role-scoped one, and the legacy rows stay readable
// without ever lifting another account's nonce floor.
func TestOpenMigratesALegacyActionsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy", "runner.sqlite")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	legacy, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("legacy open: %v", err)
	}
	legacyStatements := []string{
		`CREATE TABLE actions(
                  action_id TEXT PRIMARY KEY,
                  attempt_id TEXT NOT NULL,
                  stage TEXT NOT NULL,
                  chain_role TEXT NOT NULL,
                  chain_id INTEGER NOT NULL,
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
		`CREATE UNIQUE INDEX actions_nonce_unique
                  ON actions(chain_id, chain_role, nonce) WHERE state <> 'failed'`,
		// Two of the embedded agents shared a nonce on chain b under the older
		// revision, so the migrated store has to survive unattributable rows.
		`INSERT INTO actions(
                  action_id, attempt_id, stage, chain_role, chain_id, target,
                  calldata_hex, calldata_bytes, calldata_sha256, value, gas, nonce,
                  state, detail_json, intended_at, updated_at
                ) VALUES (
                  'legacy-agent-action', 'attempt-agent', 'hop_1_h_dispatch', 'b-relayer', 3133702,
                  '0x00000000000000000000000000000000000000ab', '0x03', 1,
                  '` + sha256Hex([]byte{3}) + `', '0', 12000000, 3, 'submitted', '{}', 1.0, 1.0
                )`,
		`INSERT INTO actions(
                  action_id, attempt_id, stage, chain_role, chain_id, target,
                  calldata_hex, calldata_bytes, calldata_sha256, value, gas, nonce,
                  state, raw_transaction_hex, transaction_hash, detail_json,
                  intended_at, updated_at
                ) VALUES (
                  'legacy-action', 'attempt-legacy', 'root_create', 'b', 3133702,
                  '0x00000000000000000000000000000000000000aa', '0x0102', 2,
                  '` + sha256Hex([]byte{1, 2}) + `', '0', 12000000, 3, 'submitted',
                  '0x02f86c0180', '0x` + strings.Repeat("77", 32) + `', '{}', 1.0, 1.0
                )`,
	}
	for _, statement := range legacyStatements {
		if _, err := legacy.Exec(statement); err != nil {
			legacy.Close()
			t.Fatalf("legacy schema: %v", err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("legacy close: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open a legacy store: %v", err)
	}
	defer store.Close()
	legacyAction, err := store.Action("legacy-action")
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if legacyAction == nil {
		t.Fatal("the legacy action disappeared")
	}
	if legacyAction.Sender != "" || legacyAction.State != ActionSubmitted {
		t.Fatalf("migrated legacy action = %+v", legacyAction)
	}
	if _, found, err := store.MaxActionNonce(3133702, testSender); err != nil {
		t.Fatalf("MaxActionNonce: %v", err)
	} else if found {
		t.Fatal("a legacy row with no sender must not report a nonce floor")
	}
	// A current account may still claim nonce 3 on that chain.
	replacement := testAction([]byte{9}, 3, "b")
	replacement.ActionID = "action-after-migration"
	replacement.ChainID = 3133702
	if _, err := store.Intend(replacement); err != nil {
		t.Fatalf("Intend after migration: %v", err)
	}
	present, err := store.columnPresent("actions", "sender")
	if err != nil || !present {
		t.Fatalf("columnPresent(sender) = %v, %v", present, err)
	}
	var indexes int
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'actions_nonce_sender_unique'",
	).Scan(&indexes); err != nil {
		t.Fatalf("index lookup: %v", err)
	}
	if indexes != 1 {
		t.Fatalf("account-scoped nonce index count = %d, want 1", indexes)
	}
}

func TestAttemptLedgerResumesAndRejectsDrift(t *testing.T) {
	store := openTestStore(t)
	attempt := AttemptRow{
		AttemptID:       "attempt-1",
		Phase:           "smoke",
		Route:           "HL",
		RouteSequence:   0,
		CoordinatesJSON: `{"attempt_id": "attempt-1", "route": "HL"}`,
	}
	shouldRun, err := store.BeginAttempt(attempt)
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	if !shouldRun {
		t.Fatal("a new attempt must run")
	}
	shouldRun, err = store.BeginAttempt(attempt)
	if err != nil {
		t.Fatalf("BeginAttempt replay: %v", err)
	}
	if !shouldRun {
		t.Fatal("a running attempt must be resumed")
	}
	drifted := attempt
	drifted.CoordinatesJSON = `{"attempt_id": "attempt-1", "route": "LH"}`
	if _, err := store.BeginAttempt(drifted); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted coordinates error = %v, want ErrDrift", err)
	}
	drifted = attempt
	drifted.RouteSequence = 3
	if _, err := store.BeginAttempt(drifted); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted route sequence error = %v, want ErrDrift", err)
	}
	if err := store.FinishAttempt(attempt.AttemptID); err != nil {
		t.Fatalf("FinishAttempt: %v", err)
	}
	shouldRun, err = store.BeginAttempt(attempt)
	if err != nil {
		t.Fatalf("BeginAttempt after success: %v", err)
	}
	if shouldRun {
		t.Fatal("a succeeded attempt must not run again")
	}
	if err := store.FinishAttempt("attempt-unknown"); err == nil {
		t.Fatal("FinishAttempt on an unknown attempt must fail")
	}
}

func TestStageEventAndErrorLedger(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.BeginAttempt(AttemptRow{
		AttemptID: "attempt-1", Phase: "smoke", Route: "HL",
		CoordinatesJSON: `{"attempt_id": "attempt-1"}`,
	}); err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	if err := store.RecordStage(StageRow{
		AttemptID:  "attempt-1",
		Stage:      "root_create",
		State:      "intended",
		DetailJSON: `{"role": "a", "hop_index": 0, "record_nonce": 4}`,
	}); err != nil {
		t.Fatalf("RecordStage intended: %v", err)
	}
	transactionHash := "0x" + strings.Repeat("ab", 32)
	if err := store.RecordStage(StageRow{
		AttemptID:       "attempt-1",
		Stage:           "root_create",
		State:           "succeeded",
		TransactionHash: &transactionHash,
		DetailJSON:      `{"role": "a", "hop_index": 0, "record_nonce": 4}`,
	}); err != nil {
		t.Fatalf("RecordStage succeeded: %v", err)
	}
	stage, err := store.Stage("attempt-1", "root_create")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if stage == nil || stage.State != "succeeded" || stage.TransactionHash == nil ||
		*stage.TransactionHash != transactionHash {
		t.Fatalf("Stage = %+v, want the succeeded boundary", stage)
	}
	if missing, err := store.Stage("attempt-1", "nowhere"); err != nil || missing != nil {
		t.Fatalf("Stage(nowhere) = %v, %v; want nil, nil", missing, err)
	}
	var history int
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM stage_history WHERE attempt_id = ? AND stage = ?",
		"attempt-1", "root_create",
	).Scan(&history); err != nil {
		t.Fatalf("stage_history count: %v", err)
	}
	if history != 2 {
		t.Errorf("stage_history rows = %d, want 2", history)
	}
	var events int
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM events WHERE attempt_id = ?", "attempt-1",
	).Scan(&events); err != nil {
		t.Fatalf("events count: %v", err)
	}
	if events != 2 {
		t.Errorf("event rows = %d, want 2 (intended, succeeded)", events)
	}
	// The events table carries a unique boundary index, so replaying the same
	// boundary after a restart must not duplicate it.
	if err := store.RecordStage(StageRow{
		AttemptID: "attempt-1", Stage: "root_create", State: "succeeded",
		TransactionHash: &transactionHash,
		DetailJSON:      `{"role": "a", "hop_index": 0, "record_nonce": 4}`,
	}); err != nil {
		t.Fatalf("RecordStage replay: %v", err)
	}
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM events WHERE attempt_id = ?", "attempt-1",
	).Scan(&events); err != nil {
		t.Fatalf("events count: %v", err)
	}
	if events != 2 {
		t.Errorf("event rows after replay = %d, want 2", events)
	}
	var bootID string
	var monotonic, utc int64
	var processID, threadID int
	if err := store.db.QueryRow(
		`SELECT boot_id, monotonic_ns, utc_ns, process_id, thread_id FROM events
                  WHERE attempt_id = ? AND event = 'succeeded'`, "attempt-1",
	).Scan(&bootID, &monotonic, &utc, &processID, &threadID); err != nil {
		t.Fatalf("event columns: %v", err)
	}
	if bootID != store.BootID() || bootID == "" {
		t.Errorf("boot_id = %q, want %q", bootID, store.BootID())
	}
	if monotonic <= 0 || utc <= 0 {
		t.Errorf("clocks = %d, %d; want positive", monotonic, utc)
	}
	if processID != os.Getpid() || threadID <= 0 {
		t.Errorf("process/thread = %d, %d", processID, threadID)
	}
	for index, want := range []int64{1, 2} {
		if err := store.RecordError("attempt-1", "TransportError", "rpc timed out"); err != nil {
			t.Fatalf("RecordError %d: %v", index, err)
		}
		var retryIndex int64
		if err := store.db.QueryRow(
			"SELECT MAX(retry_index) FROM attempt_errors WHERE attempt_id = ?", "attempt-1",
		).Scan(&retryIndex); err != nil {
			t.Fatalf("retry_index: %v", err)
		}
		if retryIndex != want {
			t.Fatalf("retry_index = %d, want %d", retryIndex, want)
		}
	}
	next, err := store.NextReservedRootNonce()
	if err != nil {
		t.Fatalf("NextReservedRootNonce: %v", err)
	}
	if next != 5 {
		t.Errorf("NextReservedRootNonce = %d, want 5 (record_nonce 4 + 1)", next)
	}
}

func TestNextReservedRootNonceWithoutRootStages(t *testing.T) {
	store := openTestStore(t)
	next, err := store.NextReservedRootNonce()
	if err != nil {
		t.Fatalf("NextReservedRootNonce: %v", err)
	}
	if next != 0 {
		t.Errorf("NextReservedRootNonce = %d, want 0", next)
	}
}

func TestIntendIsIdempotentAndRejectsDrift(t *testing.T) {
	store := openTestStore(t)
	action := testAction([]byte{1, 2, 3, 4}, 7, "a")
	stored, err := store.Intend(action)
	if err != nil {
		t.Fatalf("Intend: %v", err)
	}
	if stored.State != ActionIntended || stored.Nonce != 7 || stored.Gas != 12_000_000 {
		t.Fatalf("Intend = %+v", stored)
	}
	replayed, err := store.Intend(action)
	if err != nil {
		t.Fatalf("Intend replay: %v", err)
	}
	if replayed.ActionID != stored.ActionID || replayed.CalldataSHA256 != stored.CalldataSHA256 {
		t.Fatalf("Intend replay = %+v, want the stored row", replayed)
	}
	drifted := action
	drifted.Nonce = 8
	if _, err := store.Intend(drifted); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted nonce error = %v, want ErrDrift", err)
	}
	drifted = action
	drifted.Sender = "0x00000000000000000000000000000000000000f1"
	if _, err := store.Intend(drifted); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted sender error = %v, want ErrDrift", err)
	}
	drifted = action
	drifted.CalldataHex = hexOf([]byte{9, 9})
	drifted.CalldataBytes = 2
	drifted.CalldataSHA256 = sha256Hex([]byte{9, 9})
	if _, err := store.Intend(drifted); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted calldata error = %v, want ErrDrift", err)
	}
	noSender := testAction([]byte{1}, 12, "b")
	noSender.Sender = ""
	if _, err := store.Intend(noSender); err == nil {
		t.Fatal("an intent without an account must be rejected")
	}
	invalid := testAction([]byte{1}, 9, "b")
	invalid.Gas = 0
	if _, err := store.Intend(invalid); err == nil {
		t.Fatal("a zero gas intent must be rejected")
	}
	invalid = testAction([]byte{1}, 9, "b")
	invalid.CalldataSHA256 = strings.Repeat("0", 64)
	if _, err := store.Intend(invalid); !errors.Is(err, ErrDrift) {
		t.Fatalf("calldata digest mismatch error = %v, want ErrDrift", err)
	}
	invalid = testAction([]byte{1}, 9, "b")
	invalid.CalldataBytes = 5
	if _, err := store.Intend(invalid); !errors.Is(err, ErrDrift) {
		t.Fatalf("calldata length mismatch error = %v, want ErrDrift", err)
	}
}

func TestActionNonceIsSpentOnce(t *testing.T) {
	store := openTestStore(t)
	first := testAction([]byte{1}, 3, "a")
	if _, err := store.Intend(first); err != nil {
		t.Fatalf("Intend first: %v", err)
	}
	second := testAction([]byte{2}, 3, "a")
	second.ActionID = "action-second"
	if _, err := store.Intend(second); err == nil {
		t.Fatal("two live actions must not share a nonce")
	}
	// A failed action releases its nonce again.
	if err := store.Observe(first.ActionID, ActionFailed, map[string]any{"error_class": "Reverted"}); err != nil {
		t.Fatalf("Observe failed: %v", err)
	}
	if _, err := store.Intend(second); err != nil {
		t.Fatalf("Intend after the earlier action failed: %v", err)
	}
	resurrected, err := store.Intend(first)
	if err != nil {
		t.Fatalf("Intend replay of a failed action: %v", err)
	}
	if resurrected.State != ActionFailed {
		t.Fatalf("replaying a failed intent resurrected it as %q", resurrected.State)
	}
}

// TestMaxActionNonceIsAccountScoped is the regression guard for a real defect:
// the floor that protects a signed-but-unbroadcast nonce must be computed per
// account, because one chain in this runtime carries the runner and the embedded
// protocol agents, each with its own nonce space.
func TestMaxActionNonceIsAccountScoped(t *testing.T) {
	store := openTestStore(t)
	other := "0x00000000000000000000000000000000000000f1"
	first, err := store.Intend(testAction([]byte{1}, 5, "a"))
	if err != nil {
		t.Fatalf("Intend user A: %v", err)
	}
	second := testAction([]byte{2}, 2, "a")
	second.ActionID = "action-other-account"
	second.Sender = other
	if _, err := store.Intend(second); err != nil {
		t.Fatalf("Intend user B: %v", err)
	}
	maximum, found, err := store.MaxActionNonce(3133701, testSender)
	if err != nil {
		t.Fatalf("MaxActionNonce: %v", err)
	}
	if !found || maximum != 5 {
		t.Fatalf("MaxActionNonce(A) = %d, %v; want 5, true", maximum, found)
	}
	maximum, found, err = store.MaxActionNonce(3133701, other)
	if err != nil {
		t.Fatalf("MaxActionNonce: %v", err)
	}
	if !found || maximum != 2 {
		t.Fatalf("MaxActionNonce(B) = %d, %v; want 2, true", maximum, found)
	}
	if _, found, err = store.MaxActionNonce(3133701, "0x00000000000000000000000000000000000000f9"); err != nil {
		t.Fatalf("MaxActionNonce: %v", err)
	} else if found {
		t.Fatal("an account with no actions must not report a nonce floor")
	}
	if _, found, err = store.MaxActionNonce(999, testSender); err != nil {
		t.Fatalf("MaxActionNonce: %v", err)
	} else if found {
		t.Fatal("an unknown chain must not report a nonce floor")
	}
	if _, _, err := store.MaxActionNonce(3133701, ""); err == nil {
		t.Fatal("a nonce floor without an account must be refused")
	}
	// Two accounts may hold the same nonce on one chain; one account may not.
	third := testAction([]byte{3}, 5, "a")
	third.ActionID = "action-other-account-same-nonce"
	third.Sender = other
	if _, err := store.Intend(third); err != nil {
		t.Fatalf("a second account must be able to use the same nonce: %v", err)
	}
	clash := testAction([]byte{4}, 5, "a")
	clash.ActionID = "action-same-account-clash"
	if _, err := store.Intend(clash); err == nil {
		t.Fatalf("account %s used nonce 5 twice", first.Sender)
	}
}

func TestRecordSignedRecoversAfterReopen(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "runner")
	path := filepath.Join(directory, "runner.sqlite")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	action := testAction([]byte{0xde, 0xad}, 11, "a")
	if _, err := store.Intend(action); err != nil {
		t.Fatalf("Intend: %v", err)
	}
	raw := []byte{0x02, 0xf8, 0x70, 0x01, 0x02}
	transactionHash := keccakHexOf(t, raw)
	if err := store.RecordSigned(action.ActionID, raw, transactionHash); err != nil {
		t.Fatalf("RecordSigned: %v", err)
	}
	// The durable signed row and the stage boundary are written in the same
	// transaction as the action update.
	var rawSHA256 string
	var storedRaw []byte
	if err := store.db.QueryRow(
		`SELECT raw_sha256, raw_transaction FROM durable_signed_transactions
                  WHERE attempt_id = ? AND stage = ?`, action.AttemptID, action.Stage,
	).Scan(&rawSHA256, &storedRaw); err != nil {
		t.Fatalf("durable signed row: %v", err)
	}
	if rawSHA256 != sha256Hex(raw) || hexOf(storedRaw) != hexOf(raw) {
		t.Fatalf("durable signed row = %s, %s", rawSHA256, hexOf(storedRaw))
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	recovered, err := reopened.Action(action.ActionID)
	if err != nil {
		t.Fatalf("Action after reopen: %v", err)
	}
	if recovered == nil {
		t.Fatal("the action row disappeared across the reopen")
	}
	if recovered.State != ActionSigned || recovered.TransactionHash != transactionHash ||
		recovered.RawTransactionHex != hexOf(raw) || recovered.Nonce != 11 ||
		recovered.CalldataSHA256 != action.CalldataSHA256 {
		t.Fatalf("recovered action = %+v", recovered)
	}
	if err := VerifyActionIdentity(recovered); err != nil {
		t.Fatalf("VerifyActionIdentity: %v", err)
	}
	// Replaying the identical signed bytes is a no-op; different bytes are drift.
	if err := reopened.RecordSigned(action.ActionID, raw, transactionHash); err != nil {
		t.Fatalf("RecordSigned replay: %v", err)
	}
	other := []byte{0x02, 0xf8, 0x70, 0x01, 0x03}
	if err := reopened.RecordSigned(action.ActionID, other, keccakHexOf(t, other)); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted raw bytes error = %v, want ErrDrift", err)
	}
	if err := reopened.RecordSigned(action.ActionID, raw, "0x"+strings.Repeat("11", 32)); !errors.Is(err, ErrDrift) {
		t.Fatalf("hash/bytes mismatch error = %v, want ErrDrift", err)
	}
	pending, err := reopened.PendingActions()
	if err != nil {
		t.Fatalf("PendingActions: %v", err)
	}
	if len(pending) != 1 || pending[0].ActionID != action.ActionID {
		t.Fatalf("PendingActions = %+v, want the signed action", pending)
	}
}

func TestMutatedActionRowIsRejectedAsDrift(t *testing.T) {
	store := openTestStore(t)
	action := testAction([]byte{0xaa, 0xbb}, 4, "a")
	if _, err := store.Intend(action); err != nil {
		t.Fatalf("Intend: %v", err)
	}
	raw := []byte{0x02, 0xf8, 0x6c, 0x01}
	transactionHash := keccakHexOf(t, raw)
	if err := store.RecordSigned(action.ActionID, raw, transactionHash); err != nil {
		t.Fatalf("RecordSigned: %v", err)
	}
	mutations := []struct {
		name      string
		statement string
	}{
		{"calldata_sha256", "UPDATE actions SET calldata_sha256 = ? WHERE action_id = ?"},
		{"transaction_hash", "UPDATE actions SET transaction_hash = ? WHERE action_id = ?"},
		{"raw_transaction_hex", "UPDATE actions SET raw_transaction_hex = ? WHERE action_id = ?"},
		{"calldata_bytes", "UPDATE actions SET calldata_bytes = 99 WHERE action_id = ?"},
	}
	// Gas, nonce, value and the fee caps are frozen against the signed bytes
	// rather than the calldata, so they are re-derived from the raw transaction
	// by the transactor (evm.Transactor.validateSignedBytes).
	for _, mutation := range mutations {
		stored, err := store.Action(action.ActionID)
		if err != nil {
			t.Fatalf("%s: Action: %v", mutation.name, err)
		}
		if err := VerifyActionIdentity(stored); err != nil {
			t.Fatalf("%s: the untouched row must verify: %v", mutation.name, err)
		}
		applyMutation(t, store, mutation.statement, mutation.name, action.ActionID)
		mutated, err := store.Action(action.ActionID)
		if err != nil {
			t.Fatalf("%s: Action after mutation: %v", mutation.name, err)
		}
		if err := VerifyActionIdentity(mutated); !errors.Is(err, ErrDrift) {
			t.Fatalf("%s: mutated row error = %v, want ErrDrift", mutation.name, err)
		}
		restoreAction(t, store, stored)
	}
}

// applyMutation edits one column behind the store's back, the way a corrupted
// spill file or a stray manual edit would.
func applyMutation(t *testing.T, store *Store, statement, name, actionID string) {
	t.Helper()
	var err error
	switch name {
	case "calldata_sha256", "transaction_hash", "raw_transaction_hex":
		_, err = store.db.Exec(statement, strings.Repeat("ff", 32), actionID)
	default:
		_, err = store.db.Exec(statement, actionID)
	}
	if err != nil {
		t.Fatalf("mutation %s: %v", name, err)
	}
}

func restoreAction(t *testing.T, store *Store, action *Action) {
	t.Helper()
	if _, err := store.db.Exec(
		`UPDATE actions SET calldata_bytes = ?, calldata_sha256 = ?, raw_transaction_hex = ?,
                            transaction_hash = ?, gas = ? WHERE action_id = ?`,
		action.CalldataBytes, action.CalldataSHA256, action.RawTransactionHex,
		action.TransactionHash, int64(action.Gas), action.ActionID,
	); err != nil {
		t.Fatalf("restore: %v", err)
	}
}

func TestObserveAndSucceedStateMachine(t *testing.T) {
	store := openTestStore(t)
	action := testAction([]byte{0x01}, 5, "a")
	if _, err := store.Intend(action); err != nil {
		t.Fatalf("Intend: %v", err)
	}
	if err := store.Observe(action.ActionID, ActionSubmitted, nil); err == nil {
		t.Fatal("an action without signed bytes must not become submitted")
	}
	raw := []byte{0x02, 0xf8, 0x68, 0x01}
	transactionHash := keccakHexOf(t, raw)
	if err := store.RecordSigned(action.ActionID, raw, transactionHash); err != nil {
		t.Fatalf("RecordSigned: %v", err)
	}
	if err := store.Observe(action.ActionID, ActionSubmitted, map[string]any{"rpc": "accepted"}); err != nil {
		t.Fatalf("Observe submitted: %v", err)
	}
	receiptDigest := sha256Hex([]byte("receipt"))
	result := ActionResult{
		TransactionHash: transactionHash,
		BlockNumber:     12,
		GasUsed:         51_000,
		ReceiptPath:     filepath.Join(t.TempDir(), "receipt.json"),
		ReceiptSHA256:   receiptDigest,
		Detail:          map[string]any{"gas_used": 51_000},
	}
	if err := store.Succeed(action.ActionID, result); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	succeeded, err := store.Action(action.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if succeeded.State != ActionSucceeded || succeeded.BlockNumber != 12 || succeeded.GasUsed != 51_000 ||
		succeeded.ReceiptSHA256 != receiptDigest {
		t.Fatalf("succeeded action = %+v", succeeded)
	}
	detail, err := succeeded.Detail()
	if err != nil {
		t.Fatalf("Detail: %v", err)
	}
	if detail["rpc"] != "accepted" {
		t.Fatalf("merged detail lost the observed field: %#v", detail)
	}
	if number, ok := detail["gas_used"].(json.Number); !ok || number.String() != "51000" {
		t.Fatalf("merged detail gas_used = %#v", detail["gas_used"])
	}
	if err := store.Succeed(action.ActionID, result); err != nil {
		t.Fatalf("Succeed replay: %v", err)
	}
	drifted := result
	drifted.TransactionHash = "0x" + strings.Repeat("22", 32)
	if err := store.Succeed(action.ActionID, drifted); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted transaction error = %v, want ErrDrift", err)
	}
	other := result
	other.TransactionHash = transactionHash
	other.BlockNumber = 99
	if err := store.Succeed(action.ActionID, other); !errors.Is(err, ErrDrift) {
		t.Fatalf("drifted block error = %v, want ErrDrift", err)
	}
	if err := store.Observe(action.ActionID, ActionSubmitted, nil); !errors.Is(err, ErrStateTransition) {
		t.Fatalf("regressing a succeeded action error = %v, want ErrStateTransition", err)
	}
	missingDigest := result
	missingDigest.ReceiptSHA256 = ""
	if err := store.Succeed(action.ActionID, missingDigest); err == nil {
		t.Fatal("a receipt path without its digest must be rejected")
	}
	// A failed action is terminal.
	failing := testAction([]byte{0x02}, 6, "a")
	failing.ActionID = "action-failing"
	if _, err := store.Intend(failing); err != nil {
		t.Fatalf("Intend failing: %v", err)
	}
	if err := store.Observe(failing.ActionID, ActionFailed, map[string]any{"error_class": "Reverted"}); err != nil {
		t.Fatalf("Observe failed: %v", err)
	}
	if err := store.Observe(failing.ActionID, ActionFailed, nil); err != nil {
		t.Fatalf("Observe failed replay: %v", err)
	}
}
