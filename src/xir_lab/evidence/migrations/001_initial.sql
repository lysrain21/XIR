PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
    state TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE conditions (
    condition_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    carrier_sequence TEXT NOT NULL CHECK(carrier_sequence IN ('HH','HL','LH','LL')),
    state TEXT NOT NULL,
    UNIQUE(run_id, carrier_sequence)
) STRICT;

CREATE TABLE pairs (
    pair_id TEXT PRIMARY KEY,
    condition_id TEXT NOT NULL REFERENCES conditions(condition_id),
    slot_index INTEGER NOT NULL CHECK(slot_index >= 0),
    UNIQUE(condition_id, slot_index)
) STRICT;

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    condition_id TEXT NOT NULL REFERENCES conditions(condition_id),
    pair_id TEXT REFERENCES pairs(pair_id),
    arm TEXT NOT NULL CHECK(arm IN ('baseline','xir')),
    attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('pilot','warmup','primary','retry')),
    original_attempt_kind TEXT CHECK(original_attempt_kind IN ('pilot','warmup','primary')),
    retry_of TEXT REFERENCES attempts(attempt_id),
    schedule_index INTEGER CHECK(schedule_index IS NULL OR schedule_index >= 0),
    batch_index INTEGER CHECK(batch_index IS NULL OR batch_index >= 0),
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(
        (attempt_kind = 'retry' AND retry_of IS NOT NULL AND original_attempt_kind IS NOT NULL)
        OR
        (attempt_kind != 'retry' AND retry_of IS NULL AND original_attempt_kind IS NULL)
    )
) STRICT;

CREATE TABLE stages (
    stage_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    stage_name TEXT NOT NULL,
    stage_template_id TEXT,
    chain_id INTEGER,
    accounting_bucket TEXT CHECK(
        accounting_bucket IS NULL
        OR accounting_bucket IN ('source','intermediate','destination')
    ),
    logical_labels_json TEXT,
    state TEXT NOT NULL,
    UNIQUE(attempt_id, ordinal)
) STRICT;

CREATE TABLE intents (
    intent_id TEXT PRIMARY KEY,
    stage_id TEXT NOT NULL REFERENCES stages(stage_id),
    signer_operation_id TEXT NOT NULL UNIQUE,
    chain_id INTEGER NOT NULL,
    nonce INTEGER NOT NULL CHECK(nonce >= 0),
    state TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    approval_id TEXT,
    approval_payload_sha256 TEXT CHECK(
        approval_payload_sha256 IS NULL OR length(approval_payload_sha256) = 64
    ),
    signer_id TEXT,
    signer_identity_sha256 TEXT CHECK(
        signer_identity_sha256 IS NULL OR length(signer_identity_sha256) = 64
    ),
    network_identity_sha256 TEXT CHECK(
        network_identity_sha256 IS NULL OR length(network_identity_sha256) = 64
    ),
    quote_sha256 TEXT CHECK(
        quote_sha256 IS NULL OR length(quote_sha256) = 64
    ),
    quote_valid_until TEXT,
    simulation_sha256 TEXT CHECK(
        simulation_sha256 IS NULL OR length(simulation_sha256) = 64
    ),
    simulation_valid_until TEXT,
    reservation_id TEXT,
    reservation_stage_key TEXT,
    requested_wei INTEGER CHECK(requested_wei IS NULL OR requested_wei >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(chain_id, signer_operation_id)
) STRICT;

CREATE TABLE transactions (
    transaction_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL REFERENCES intents(intent_id),
    chain_id INTEGER NOT NULL,
    nonce INTEGER NOT NULL CHECK(nonce >= 0),
    transaction_hash TEXT,
    replaces_transaction_id TEXT REFERENCES transactions(transaction_id),
    state TEXT NOT NULL,
    signed_sha256 TEXT CHECK(
        signed_sha256 IS NULL OR length(signed_sha256) = 64
    ),
    signed_length INTEGER CHECK(signed_length IS NULL OR signed_length > 0),
    spool_relative_path TEXT,
    signer_returned_at TEXT,
    signed_hash_persisted_at TEXT,
    broadcast_started_at TEXT,
    submitted_at TEXT,
    included_at TEXT,
    finalized_at TEXT,
    UNIQUE(chain_id, transaction_hash)
) STRICT;

CREATE TABLE work_leases (
    lease_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    holder_id TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','released','expired')),
    released_at TEXT
) STRICT;

CREATE UNIQUE INDEX one_live_work_lease
ON work_leases(attempt_id) WHERE state = 'active';

CREATE TABLE nonce_leases (
    lease_id TEXT PRIMARY KEY,
    lineage_id TEXT NOT NULL UNIQUE,
    chain_id INTEGER NOT NULL,
    signer_id TEXT NOT NULL,
    holder_id TEXT NOT NULL,
    nonce INTEGER NOT NULL CHECK(nonce >= 0),
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    stage_key TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    intent_id TEXT REFERENCES intents(intent_id),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(
        state IN ('active','broadcast_unknown','submitted','included','finalized','released')
    ),
    locked INTEGER NOT NULL CHECK(locked IN (0,1)),
    released_at TEXT,
    UNIQUE(chain_id, signer_id, nonce),
    FOREIGN KEY(reservation_id, chain_id)
        REFERENCES budgets(reservation_id, chain_id)
) STRICT;

CREATE TABLE budgets (
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    batch_id TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    reserved_wei INTEGER NOT NULL CHECK(reserved_wei >= 0),
    provisional_wei INTEGER NOT NULL DEFAULT 0 CHECK(provisional_wei >= 0),
    finalized_wei INTEGER NOT NULL DEFAULT 0 CHECK(finalized_wei >= 0),
    source_in_flight INTEGER NOT NULL DEFAULT 0 CHECK(source_in_flight IN (0,1)),
    state TEXT NOT NULL CHECK(state IN ('reserved','in_flight','settled','released')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(reservation_id, chain_id),
    UNIQUE(attempt_id, chain_id)
) STRICT;

CREATE TABLE budget_limits (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    chain_id INTEGER NOT NULL,
    max_transaction_wei INTEGER NOT NULL CHECK(max_transaction_wei >= 0),
    max_batch_wei INTEGER NOT NULL CHECK(max_batch_wei >= 0),
    max_run_wei INTEGER NOT NULL CHECK(max_run_wei >= 0),
    minimum_runner_balance_wei INTEGER NOT NULL
        CHECK(minimum_runner_balance_wei >= 0),
    observed_runner_balance_wei INTEGER NOT NULL
        CHECK(observed_runner_balance_wei >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(run_id, chain_id)
) STRICT;

CREATE TABLE budget_totals (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    chain_id INTEGER NOT NULL,
    active_reserved_wei INTEGER NOT NULL CHECK(active_reserved_wei >= 0),
    provisional_wei INTEGER NOT NULL CHECK(provisional_wei >= 0),
    finalized_wei INTEGER NOT NULL CHECK(finalized_wei >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(run_id, chain_id),
    FOREIGN KEY(run_id, chain_id) REFERENCES budget_limits(run_id, chain_id)
) STRICT;

CREATE TABLE batch_budget_totals (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    batch_id TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    active_reserved_wei INTEGER NOT NULL CHECK(active_reserved_wei >= 0),
    provisional_wei INTEGER NOT NULL CHECK(provisional_wei >= 0),
    finalized_wei INTEGER NOT NULL CHECK(finalized_wei >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(run_id, batch_id, chain_id),
    FOREIGN KEY(run_id, chain_id) REFERENCES budget_limits(run_id, chain_id)
) STRICT;

CREATE TABLE transaction_subreservations (
    subreservation_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    stage_key TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    lineage_id TEXT UNIQUE,
    reserved_wei INTEGER NOT NULL CHECK(reserved_wei >= 0),
    allocated_wei INTEGER NOT NULL DEFAULT 0 CHECK(allocated_wei >= 0),
    provisional_wei INTEGER NOT NULL DEFAULT 0 CHECK(provisional_wei >= 0),
    finalized_wei INTEGER NOT NULL DEFAULT 0 CHECK(finalized_wei >= 0),
    state TEXT NOT NULL CHECK(
        state IN (
            'reserved','active','broadcast_unknown','submitted','included',
            'finalized','released','reopened'
        )
    ),
    release_proof_sha256 TEXT CHECK(
        release_proof_sha256 IS NULL OR length(release_proof_sha256) = 64
    ),
    manual_release_decision_sha256 TEXT CHECK(
        manual_release_decision_sha256 IS NULL
        OR length(manual_release_decision_sha256) = 64
    ),
    signed_bytes_destroyed INTEGER NOT NULL DEFAULT 0
        CHECK(signed_bytes_destroyed IN (0,1)),
    UNIQUE(reservation_id, stage_key),
    FOREIGN KEY(reservation_id, chain_id)
        REFERENCES budgets(reservation_id, chain_id)
) STRICT;

CREATE TABLE budget_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    batch_id TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    reservation_id TEXT NOT NULL,
    subreservation_id TEXT,
    event_type TEXT NOT NULL,
    reserved_delta_wei INTEGER NOT NULL,
    provisional_delta_wei INTEGER NOT NULL,
    finalized_delta_wei INTEGER NOT NULL,
    details_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
) STRICT;

CREATE TABLE run_controls (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
    mode TEXT NOT NULL CHECK(mode IN ('running','drain','halted','revoked')),
    reason_code TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    decision_sha256 TEXT NOT NULL CHECK(length(decision_sha256) = 64),
    approval_payload_sha256 TEXT CHECK(
        approval_payload_sha256 IS NULL OR length(approval_payload_sha256) = 64
    ),
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE control_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    from_mode TEXT,
    to_mode TEXT NOT NULL CHECK(
        to_mode IN ('running','drain','halted','revoked')
    ),
    reason_code TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    decision_sha256 TEXT NOT NULL CHECK(length(decision_sha256) = 64),
    approval_payload_sha256 TEXT CHECK(
        approval_payload_sha256 IS NULL OR length(approval_payload_sha256) = 64
    ),
    occurred_at TEXT NOT NULL,
    UNIQUE(run_id, decision_id)
) STRICT;

CREATE TABLE stop_policy_events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    category TEXT NOT NULL CHECK(
        category IN ('financial','execution','evidence_operations')
    ),
    policy_code TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('pass','triggered')),
    threshold_json TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
) STRICT;

CREATE TABLE execution_outcomes (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    outcome_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    failed INTEGER NOT NULL CHECK(failed IN (0,1)),
    timed_out INTEGER NOT NULL CHECK(timed_out IN (0,1)),
    occurred_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER budget_events_no_update
BEFORE UPDATE ON budget_events BEGIN
    SELECT RAISE(ABORT, 'budget events are append-only');
END;

CREATE TRIGGER budget_events_no_delete
BEFORE DELETE ON budget_events BEGIN
    SELECT RAISE(ABORT, 'budget events are append-only');
END;

CREATE TRIGGER control_events_no_update
BEFORE UPDATE ON control_events BEGIN
    SELECT RAISE(ABORT, 'control events are append-only');
END;

CREATE TRIGGER control_events_no_delete
BEFORE DELETE ON control_events BEGIN
    SELECT RAISE(ABORT, 'control events are append-only');
END;

CREATE TRIGGER stop_policy_events_no_update
BEFORE UPDATE ON stop_policy_events BEGIN
    SELECT RAISE(ABORT, 'stop policy events are append-only');
END;

CREATE TRIGGER stop_policy_events_no_delete
BEFORE DELETE ON stop_policy_events BEGIN
    SELECT RAISE(ABORT, 'stop policy events are append-only');
END;

CREATE TRIGGER execution_outcomes_no_update
BEFORE UPDATE ON execution_outcomes BEGIN
    SELECT RAISE(ABORT, 'execution outcomes are append-only');
END;

CREATE TRIGGER execution_outcomes_no_delete
BEFORE DELETE ON execution_outcomes BEGIN
    SELECT RAISE(ABORT, 'execution outcomes are append-only');
END;

CREATE TABLE raw_blobs (
    raw_sha256 TEXT PRIMARY KEY CHECK(length(raw_sha256) = 64),
    relative_path TEXT NOT NULL UNIQUE,
    exact_size INTEGER NOT NULL CHECK(exact_size >= 0),
    stored_size INTEGER NOT NULL CHECK(stored_size >= 0),
    compression TEXT NOT NULL CHECK(compression = 'gzip'),
    media_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    log_index INTEGER NOT NULL CHECK(log_index >= 0),
    topic0 TEXT,
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    UNIQUE(transaction_id, log_index)
) STRICT;

CREATE TABLE block_headers (
    chain_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    block_hash TEXT NOT NULL,
    parent_hash TEXT NOT NULL,
    block_timestamp INTEGER NOT NULL CHECK(block_timestamp >= 0),
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    PRIMARY KEY(chain_id, block_hash),
    UNIQUE(chain_id, block_number, block_hash)
) STRICT;

CREATE TABLE transaction_receipts (
    transaction_id TEXT PRIMARY KEY REFERENCES transactions(transaction_id),
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    block_hash TEXT NOT NULL,
    receipt_status INTEGER NOT NULL CHECK(receipt_status IN (0,1)),
    gas_used INTEGER NOT NULL CHECK(gas_used >= 0),
    effective_gas_price_wei TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256)
) STRICT;

CREATE TABLE transaction_resources (
    transaction_id TEXT PRIMARY KEY REFERENCES transactions(transaction_id),
    chain_id INTEGER NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT,
    input_bytes INTEGER NOT NULL CHECK(input_bytes >= 0),
    transaction_value_wei TEXT NOT NULL,
    gas_used INTEGER NOT NULL CHECK(gas_used >= 0),
    effective_gas_price_wei TEXT NOT NULL,
    execution_fee_wei TEXT NOT NULL,
    l1_data_fee_wei TEXT,
    l1_data_fee_unavailable_reason TEXT,
    carrier_payment_wei TEXT NOT NULL,
    funding_attribution TEXT NOT NULL CHECK(
        funding_attribution IN ('experiment','external')
    ),
    CHECK(
        (l1_data_fee_wei IS NOT NULL AND l1_data_fee_unavailable_reason IS NULL)
        OR
        (l1_data_fee_wei IS NULL AND l1_data_fee_unavailable_reason IS NOT NULL)
    )
) STRICT;

CREATE TABLE carrier_quote_observations (
    quote_observation_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    stage_id TEXT NOT NULL REFERENCES stages(stage_id),
    leg_index INTEGER NOT NULL CHECK(leg_index IN (0,1)),
    protocol TEXT NOT NULL CHECK(protocol IN ('hyperlane','layerzero-v2')),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
    carrier_payment_wei TEXT NOT NULL,
    gas_limit INTEGER NOT NULL CHECK(gas_limit >= 0),
    max_fee_per_gas_wei TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    quoted_at TEXT NOT NULL,
    UNIQUE(attempt_id, leg_index),
    UNIQUE(stage_id)
) STRICT;

CREATE TABLE carrier_messages (
    carrier_message_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    leg_index INTEGER NOT NULL DEFAULT 0 CHECK(leg_index IN (0,1)),
    protocol TEXT NOT NULL CHECK(protocol IN ('hyperlane','layerzero-v2')),
    protocol_identifier TEXT NOT NULL,
    source_selector INTEGER,
    destination_selector INTEGER,
    protocol_nonce INTEGER CHECK(protocol_nonce IS NULL OR protocol_nonce >= 0),
    payload_sha256 TEXT CHECK(
        payload_sha256 IS NULL OR length(payload_sha256) = 64
    ),
    source_transaction_id TEXT REFERENCES transactions(transaction_id),
    destination_transaction_id TEXT REFERENCES transactions(transaction_id),
    UNIQUE(protocol, protocol_identifier),
    UNIQUE(attempt_id, leg_index)
) STRICT;

CREATE TABLE xir_attempt_records (
    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
    rid TEXT NOT NULL,
    mid TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    profile_sha256 TEXT NOT NULL CHECK(length(profile_sha256) = 64),
    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
    transition_sha256 TEXT NOT NULL CHECK(length(transition_sha256) = 64),
    consumed_key TEXT NOT NULL,
    leg0_carrier_message_id TEXT NOT NULL
        REFERENCES carrier_messages(carrier_message_id),
    leg1_carrier_message_id TEXT NOT NULL
        REFERENCES carrier_messages(carrier_message_id),
    source_transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    intermediate_transaction_id TEXT NOT NULL
        REFERENCES transactions(transaction_id),
    destination_transaction_id TEXT NOT NULL
        REFERENCES transactions(transaction_id),
    intermediate_verified INTEGER NOT NULL CHECK(intermediate_verified IN (0,1)),
    destination_verified INTEGER NOT NULL CHECK(destination_verified IN (0,1)),
    destination_effect_id TEXT NOT NULL,
    effect_before_sha256 TEXT NOT NULL CHECK(length(effect_before_sha256) = 64),
    effect_after_sha256 TEXT NOT NULL CHECK(length(effect_after_sha256) = 64),
    effect_succeeded INTEGER NOT NULL CHECK(effect_succeeded IN (0,1)),
    UNIQUE(rid),
    UNIQUE(mid)
) STRICT;

CREATE TABLE destination_effects (
    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    destination_effect_id TEXT NOT NULL,
    predicate_sha256 TEXT NOT NULL CHECK(length(predicate_sha256) = 64),
    succeeded INTEGER NOT NULL CHECK(succeeded IN (0,1))
) STRICT;

CREATE TABLE observations (
    observation_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    supersedes_observation_id TEXT REFERENCES observations(observation_id),
    status TEXT NOT NULL
) STRICT;

CREATE TABLE checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    block_hash TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(chain_id, block_number, block_hash)
) STRICT;

CREATE TABLE collector_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    collector_key TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    chain_id INTEGER NOT NULL,
    contract_addresses_json TEXT NOT NULL,
    topics_json TEXT NOT NULL,
    exact_filter_json TEXT NOT NULL,
    approved_from_block INTEGER NOT NULL CHECK(approved_from_block >= 0),
    approved_to_block INTEGER NOT NULL CHECK(
        approved_to_block >= approved_from_block
    ),
    last_finalized_block_number INTEGER NOT NULL CHECK(
        last_finalized_block_number >= 0
    ),
    last_finalized_block_hash TEXT NOT NULL,
    overlap_blocks INTEGER NOT NULL CHECK(overlap_blocks >= 1),
    parser_version TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('ready','backlogged')),
    backlog_reason TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(collector_key, version)
) STRICT;

CREATE TABLE collector_calls (
    call_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id TEXT NOT NULL REFERENCES collector_checkpoints(checkpoint_id),
    strategy TEXT NOT NULL CHECK(
        strategy IN ('known_transaction_hash','exact_identifier','bounded_filter')
    ),
    query_value TEXT,
    from_block INTEGER,
    to_block INTEGER,
    page_token TEXT,
    result_count INTEGER NOT NULL CHECK(result_count >= 0),
    complete INTEGER NOT NULL CHECK(complete IN (0,1)),
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE collector_chain_events (
    collector_event_id TEXT PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    block_hash TEXT NOT NULL,
    transaction_hash TEXT NOT NULL,
    log_index INTEGER NOT NULL CHECK(log_index >= 0),
    contract_address TEXT NOT NULL,
    topic0 TEXT,
    exact_identifier_kind TEXT,
    exact_identifier TEXT,
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    first_call_sequence INTEGER NOT NULL
        REFERENCES collector_calls(call_sequence),
    UNIQUE(chain_id, block_hash, transaction_hash, log_index)
) STRICT;

CREATE TABLE auxiliary_carrier_observations (
    auxiliary_observation_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    protocol TEXT NOT NULL CHECK(protocol IN ('hyperlane','layerzero-v2')),
    protocol_identifier TEXT NOT NULL,
    reported_status TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE finality_policies (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    chain_id INTEGER NOT NULL,
    policy_kind TEXT NOT NULL CHECK(
        policy_kind IN ('confirmations','l2-safe','l2-finalized','l1-settlement')
    ),
    confirmation_count INTEGER CHECK(
        confirmation_count IS NULL OR confirmation_count >= 1
    ),
    registered_at TEXT NOT NULL,
    PRIMARY KEY(run_id, chain_id),
    CHECK(
        (policy_kind = 'confirmations' AND confirmation_count IS NOT NULL)
        OR
        (policy_kind != 'confirmations' AND confirmation_count IS NULL)
    )
) STRICT;

CREATE TABLE transaction_finality_observations (
    finality_observation_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    chain_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    block_hash TEXT NOT NULL,
    observation_state TEXT NOT NULL CHECK(
        observation_state IN ('included','finalized','orphaned')
    ),
    canonical INTEGER NOT NULL CHECK(canonical IN (0,1)),
    policy_kind TEXT NOT NULL CHECK(
        policy_kind IN ('confirmations','l2-safe','l2-finalized','l1-settlement')
    ),
    policy_head_block INTEGER,
    supersedes_observation_id TEXT UNIQUE
        REFERENCES transaction_finality_observations(finality_observation_id),
    observed_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER transaction_finality_observations_no_update
BEFORE UPDATE ON transaction_finality_observations BEGIN
    SELECT RAISE(ABORT, 'transaction finality observations are append-only');
END;

CREATE TRIGGER transaction_finality_observations_no_delete
BEFORE DELETE ON transaction_finality_observations BEGIN
    SELECT RAISE(ABORT, 'transaction finality observations are append-only');
END;

CREATE TABLE attempt_observation_windows (
    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
    approval_id TEXT NOT NULL REFERENCES approval_consumptions(approval_id),
    approval_payload_sha256 TEXT NOT NULL CHECK(
        length(approval_payload_sha256) = 64
    ),
    observer_session_id TEXT NOT NULL,
    started_utc TEXT NOT NULL,
    started_monotonic_ns INTEGER NOT NULL CHECK(started_monotonic_ns >= 0),
    deadline_utc TEXT NOT NULL,
    registered_at TEXT NOT NULL
) STRICT;

CREATE TABLE attempt_outcome_observations (
    outcome_observation_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    outcome_kind TEXT NOT NULL CHECK(
        outcome_kind IN ('deadline','eventual','failure')
    ),
    outcome TEXT NOT NULL,
    failure_source TEXT CHECK(
        failure_source IS NULL OR failure_source IN (
            'observer','evidence','submission','carrier','xir','destination'
        )
    ),
    failure_code TEXT,
    observation_horizon_ms INTEGER CHECK(
        observation_horizon_ms IS NULL OR observation_horizon_ms >= 0
    ),
    observed_utc TEXT NOT NULL,
    observer_session_id TEXT NOT NULL,
    observed_monotonic_ns INTEGER NOT NULL CHECK(observed_monotonic_ns >= 0),
    proof_finality_observation_id TEXT
        REFERENCES transaction_finality_observations(finality_observation_id),
    UNIQUE(attempt_id, outcome_kind)
) STRICT;

CREATE TABLE attempt_backfill_status (
    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
    state TEXT NOT NULL CHECK(state IN ('pending','resolved')),
    reason_code TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE observer_clock_observations (
    clock_observation_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    phase TEXT NOT NULL,
    observer_session_id TEXT NOT NULL,
    wall_utc TEXT NOT NULL,
    monotonic_ns INTEGER NOT NULL CHECK(monotonic_ns >= 0),
    wall_clock_discontinuity INTEGER NOT NULL CHECK(
        wall_clock_discontinuity IN (0,1)
    ),
    discontinuity_reason TEXT
) STRICT;

CREATE TABLE chain_clock_observations (
    chain_clock_observation_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    role TEXT NOT NULL CHECK(role IN ('source','intermediate','destination')),
    chain_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    block_hash TEXT NOT NULL,
    block_timestamp INTEGER NOT NULL CHECK(block_timestamp >= 0),
    UNIQUE(attempt_id, role, block_hash)
) STRICT;

CREATE TABLE clock_measurements (
    measurement_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    measurement_kind TEXT NOT NULL CHECK(
        measurement_kind IN ('observer_elapsed','cross_chain_block_interval')
    ),
    start_observation_id TEXT NOT NULL,
    end_observation_id TEXT NOT NULL,
    elapsed_ms INTEGER CHECK(elapsed_ms IS NULL OR elapsed_ms >= 0),
    unavailable_reason TEXT,
    clock_statement TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER attempt_outcome_observations_no_update
BEFORE UPDATE ON attempt_outcome_observations BEGIN
    SELECT RAISE(ABORT, 'attempt outcome observations are append-only');
END;

CREATE TRIGGER attempt_outcome_observations_no_delete
BEFORE DELETE ON attempt_outcome_observations BEGIN
    SELECT RAISE(ABORT, 'attempt outcome observations are append-only');
END;

CREATE TABLE account_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    attempt_id TEXT REFERENCES attempts(attempt_id),
    chain_id INTEGER NOT NULL,
    account TEXT NOT NULL,
    balance_wei TEXT NOT NULL,
    block_number INTEGER NOT NULL CHECK(block_number >= 0),
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256)
) STRICT;

CREATE TABLE invariant_violations (
    violation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    invariant_code TEXT NOT NULL,
    details_json TEXT NOT NULL,
    resolved_at TEXT
) STRICT;

CREATE TABLE transition_journal (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
) STRICT;

CREATE TABLE freezes (
    freeze_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    scope_json TEXT NOT NULL,
    database_sha256 TEXT NOT NULL CHECK(length(database_sha256) = 64),
    raw_manifest_sha256 TEXT NOT NULL CHECK(length(raw_manifest_sha256) = 64),
    journal_sha256 TEXT NOT NULL CHECK(length(journal_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE(run_id, version)
) STRICT;

CREATE TABLE declared_freeze_scopes (
    scope_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    attempt_ids_json TEXT NOT NULL,
    scope_sha256 TEXT NOT NULL CHECK(length(scope_sha256) = 64),
    prior_freeze_id TEXT REFERENCES freezes(freeze_id),
    prior_freeze_sha256 TEXT CHECK(
        prior_freeze_sha256 IS NULL OR length(prior_freeze_sha256) = 64
    ),
    declared_at TEXT NOT NULL,
    UNIQUE(run_id, version),
    CHECK(
        (prior_freeze_id IS NULL AND prior_freeze_sha256 IS NULL)
        OR
        (prior_freeze_id IS NOT NULL AND prior_freeze_sha256 IS NOT NULL)
    )
) STRICT;

CREATE TABLE pair_eligibility_decisions (
    pair_id TEXT PRIMARY KEY REFERENCES pairs(pair_id),
    baseline_attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    xir_attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    eligible INTEGER NOT NULL CHECK(eligible IN (0,1)),
    reasons_json TEXT NOT NULL,
    decided_at TEXT NOT NULL
) STRICT;

CREATE TABLE approval_consumptions (
    approval_id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL,
    approval_key_id TEXT NOT NULL,
    issuer_sequence INTEGER NOT NULL CHECK(issuer_sequence >= 1),
    operation_type TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    UNIQUE(issuer_id, issuer_sequence)
) STRICT;

CREATE TABLE approval_revocations (
    revocation_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    approval_key_id TEXT NOT NULL,
    issuer_sequence INTEGER NOT NULL CHECK(issuer_sequence >= 1),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    revoked_at TEXT NOT NULL,
    UNIQUE(issuer_id, issuer_sequence)
) STRICT;

CREATE VIEW current_observations AS
SELECT observation.*
FROM observations AS observation
WHERE NOT EXISTS (
    SELECT 1
    FROM observations AS correction
    WHERE correction.supersedes_observation_id = observation.observation_id
);

CREATE TRIGGER transition_journal_no_update
BEFORE UPDATE ON transition_journal BEGIN
    SELECT RAISE(ABORT, 'transition journal is append-only');
END;

CREATE TRIGGER transition_journal_no_delete
BEFORE DELETE ON transition_journal BEGIN
    SELECT RAISE(ABORT, 'transition journal is append-only');
END;

CREATE TRIGGER observations_no_update
BEFORE UPDATE ON observations BEGIN
    SELECT RAISE(ABORT, 'observations are append-only');
END;

CREATE TRIGGER observations_no_delete
BEFORE DELETE ON observations BEGIN
    SELECT RAISE(ABORT, 'observations are append-only');
END;
