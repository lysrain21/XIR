PRAGMA foreign_keys = ON;

CREATE TABLE native_attempt_coordinates (
    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
    phase TEXT NOT NULL CHECK(phase IN ('smoke','rehearsal','scale')),
    route TEXT NOT NULL CHECK(route IN ('HH','HL','LH','LL')),
    route_sequence INTEGER NOT NULL CHECK(route_sequence >= 0),
    first_protocol TEXT NOT NULL CHECK(first_protocol IN ('hyperlane','layerzero-v2')),
    second_protocol TEXT NOT NULL CHECK(second_protocol IN ('hyperlane','layerzero-v2')),
    xir_required INTEGER NOT NULL CHECK(xir_required IN (0,1)),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes > 0),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    UNIQUE(phase, route, route_sequence),
    CHECK(
        (route = 'HH' AND first_protocol = 'hyperlane'
            AND second_protocol = 'hyperlane' AND xir_required = 0)
        OR
        (route = 'HL' AND first_protocol = 'hyperlane'
            AND second_protocol = 'layerzero-v2' AND xir_required = 1)
        OR
        (route = 'LH' AND first_protocol = 'layerzero-v2'
            AND second_protocol = 'hyperlane' AND xir_required = 1)
        OR
        (route = 'LL' AND first_protocol = 'layerzero-v2'
            AND second_protocol = 'layerzero-v2' AND xir_required = 0)
    )
) STRICT;

CREATE TABLE native_component_artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    component_id TEXT NOT NULL CHECK(
        component_id IN ('hyperlane','layerzero-v2','layerzero-devtools','xir')
    ),
    official_repository TEXT,
    commit_sha TEXT CHECK(commit_sha IS NULL OR length(commit_sha) = 40),
    license_manifest_sha256 TEXT CHECK(
        license_manifest_sha256 IS NULL OR length(license_manifest_sha256) = 64
    ),
    build_log_sha256 TEXT CHECK(
        build_log_sha256 IS NULL OR length(build_log_sha256) = 64
    ),
    artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256) = 64),
    artifact_kind TEXT NOT NULL,
    admitted INTEGER NOT NULL CHECK(admitted IN (0,1)),
    recorded_at TEXT NOT NULL,
    UNIQUE(run_id, component_id, artifact_kind, artifact_sha256)
) STRICT;

CREATE TABLE native_deployments (
    deployment_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    component_id TEXT NOT NULL,
    contract_name TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    bytecode_sha256 TEXT NOT NULL CHECK(length(bytecode_sha256) = 64),
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    constructor_args_sha256 TEXT NOT NULL CHECK(length(constructor_args_sha256) = 64),
    mock_excluded INTEGER NOT NULL CHECK(mock_excluded IN (0,1)),
    UNIQUE(run_id, chain_id, address)
) STRICT;

CREATE TABLE native_configuration_observations (
    configuration_observation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    chain_id INTEGER NOT NULL,
    component_id TEXT NOT NULL,
    configuration_kind TEXT NOT NULL,
    subject_address TEXT NOT NULL,
    effective_value_sha256 TEXT NOT NULL CHECK(length(effective_value_sha256) = 64),
    raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    transaction_id TEXT REFERENCES transactions(transaction_id),
    observed_at TEXT NOT NULL,
    UNIQUE(run_id, chain_id, component_id, configuration_kind, subject_address)
) STRICT;

CREATE TABLE native_action_intents (
    action_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    attempt_id TEXT REFERENCES attempts(attempt_id),
    protocol TEXT NOT NULL CHECK(
        protocol IN ('hyperlane','layerzero-v2','xir','application','operations')
    ),
    action_kind TEXT NOT NULL,
    chain_id INTEGER,
    actor_public_id TEXT NOT NULL,
    nonce INTEGER CHECK(nonce IS NULL OR nonce >= 0),
    target TEXT,
    calldata_sha256 TEXT CHECK(
        calldata_sha256 IS NULL OR length(calldata_sha256) = 64
    ),
    calldata_bytes INTEGER CHECK(calldata_bytes IS NULL OR calldata_bytes >= 0),
    protocol_identifier TEXT,
    retry_of_action_id TEXT REFERENCES native_action_intents(action_id),
    retry_index INTEGER NOT NULL CHECK(retry_index >= 0),
    intended_at TEXT NOT NULL,
    UNIQUE(chain_id, actor_public_id, nonce),
    CHECK(
        (retry_of_action_id IS NULL AND retry_index = 0)
        OR
        (retry_of_action_id IS NOT NULL AND retry_index > 0)
    )
) STRICT;

CREATE TABLE native_action_observations (
    observation_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES native_action_intents(action_id),
    observation_index INTEGER NOT NULL CHECK(observation_index >= 0),
    state TEXT NOT NULL CHECK(
        state IN (
            'intended','signed','broadcast_unknown','submitted','included',
            'finalized','succeeded','failed','skipped'
        )
    ),
    transaction_id TEXT REFERENCES transactions(transaction_id),
    raw_sha256 TEXT REFERENCES raw_blobs(raw_sha256),
    error_class TEXT,
    details_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(action_id, observation_index)
) STRICT;

CREATE TABLE native_protocol_messages (
    native_message_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    leg_index INTEGER NOT NULL CHECK(leg_index IN (0,1)),
    protocol TEXT NOT NULL CHECK(protocol IN ('hyperlane','layerzero-v2')),
    protocol_identifier TEXT NOT NULL,
    protocol_nonce INTEGER CHECK(protocol_nonce IS NULL OR protocol_nonce >= 0),
    source_chain_id INTEGER NOT NULL,
    destination_chain_id INTEGER NOT NULL,
    source_transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    destination_transaction_id TEXT REFERENCES transactions(transaction_id),
    encoded_message_sha256 TEXT NOT NULL CHECK(length(encoded_message_sha256) = 64),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    dispatch_time TEXT NOT NULL,
    delivery_time TEXT,
    UNIQUE(protocol, protocol_identifier),
    UNIQUE(attempt_id, leg_index)
) STRICT;

CREATE TABLE hyperlane_checkpoint_observations (
    checkpoint_observation_id TEXT PRIMARY KEY,
    native_message_id TEXT NOT NULL REFERENCES native_protocol_messages(native_message_id),
    origin_domain INTEGER NOT NULL,
    checkpoint_index INTEGER NOT NULL CHECK(checkpoint_index >= 0),
    checkpoint_root TEXT NOT NULL,
    validator_public_id TEXT NOT NULL,
    signature_sha256 TEXT NOT NULL CHECK(length(signature_sha256) = 64),
    checkpoint_raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    relayer_decision_raw_sha256 TEXT REFERENCES raw_blobs(raw_sha256),
    observed_at TEXT NOT NULL,
    UNIQUE(native_message_id, validator_public_id, checkpoint_index)
) STRICT;

CREATE TABLE layerzero_packet_observations (
    packet_observation_id TEXT PRIMARY KEY,
    native_message_id TEXT NOT NULL UNIQUE
        REFERENCES native_protocol_messages(native_message_id),
    guid TEXT NOT NULL UNIQUE,
    protocol_nonce INTEGER NOT NULL CHECK(protocol_nonce >= 0),
    source_eid INTEGER NOT NULL,
    destination_eid INTEGER NOT NULL,
    packet_header_sha256 TEXT NOT NULL CHECK(length(packet_header_sha256) = 64),
    payload_hash TEXT NOT NULL,
    encoded_packet_raw_sha256 TEXT NOT NULL REFERENCES raw_blobs(raw_sha256),
    source_confirmation_block INTEGER NOT NULL CHECK(source_confirmation_block >= 0),
    packet_sent_transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    payload_verified_transaction_id TEXT REFERENCES transactions(transaction_id),
    packet_verified_transaction_id TEXT REFERENCES transactions(transaction_id),
    executor_transaction_id TEXT REFERENCES transactions(transaction_id),
    packet_delivered_transaction_id TEXT REFERENCES transactions(transaction_id)
) STRICT;

CREATE TABLE layerzero_dvn_instructions (
    instruction_id TEXT PRIMARY KEY,
    packet_observation_id TEXT NOT NULL
        REFERENCES layerzero_packet_observations(packet_observation_id),
    destination_chain_id INTEGER NOT NULL,
    dvn_address TEXT NOT NULL,
    target_address TEXT NOT NULL,
    call_data_sha256 TEXT NOT NULL CHECK(length(call_data_sha256) = 64),
    expiration INTEGER NOT NULL CHECK(expiration > 0),
    instruction_hash TEXT NOT NULL UNIQUE,
    signature_sha256 TEXT NOT NULL CHECK(length(signature_sha256) = 64),
    action_id TEXT NOT NULL REFERENCES native_action_intents(action_id),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE native_xir_transitions (
    transition_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
    inbound_native_message_id TEXT NOT NULL
        REFERENCES native_protocol_messages(native_message_id),
    outbound_native_message_id TEXT NOT NULL
        REFERENCES native_protocol_messages(native_message_id),
    transition_sha256 TEXT NOT NULL UNIQUE CHECK(length(transition_sha256) = 64),
    recomputed_sha256 TEXT NOT NULL CHECK(length(recomputed_sha256) = 64),
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    verified INTEGER NOT NULL CHECK(verified IN (0,1)),
    CHECK(transition_sha256 = recomputed_sha256)
) STRICT;

CREATE TABLE native_application_effects (
    effect_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
    native_message_id TEXT NOT NULL
        REFERENCES native_protocol_messages(native_message_id),
    message_identity TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    before_state_sha256 TEXT NOT NULL CHECK(length(before_state_sha256) = 64),
    after_state_sha256 TEXT NOT NULL CHECK(length(after_state_sha256) = 64),
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE native_lineage_edges (
    edge_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    predecessor_kind TEXT NOT NULL,
    predecessor_id TEXT NOT NULL,
    successor_kind TEXT NOT NULL,
    successor_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    observed INTEGER NOT NULL CHECK(observed IN (0,1)),
    UNIQUE(attempt_id, predecessor_kind, predecessor_id, successor_kind, successor_id, relation)
) STRICT;

CREATE TABLE native_process_samples (
    sample_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    phase TEXT NOT NULL CHECK(phase IN ('smoke','rehearsal','scale','recovery')),
    process_kind TEXT NOT NULL,
    process_id TEXT NOT NULL,
    pid INTEGER CHECK(pid IS NULL OR pid > 0),
    cpu_percent REAL,
    rss_bytes INTEGER CHECK(rss_bytes IS NULL OR rss_bytes >= 0),
    read_bytes INTEGER CHECK(read_bytes IS NULL OR read_bytes >= 0),
    write_bytes INTEGER CHECK(write_bytes IS NULL OR write_bytes >= 0),
    network_rx_bytes INTEGER CHECK(network_rx_bytes IS NULL OR network_rx_bytes >= 0),
    network_tx_bytes INTEGER CHECK(network_tx_bytes IS NULL OR network_tx_bytes >= 0),
    queue_depth INTEGER CHECK(queue_depth IS NULL OR queue_depth >= 0),
    healthy INTEGER CHECK(healthy IS NULL OR healthy IN (0,1)),
    gap_error TEXT,
    observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE native_host_health_samples (
    sample_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    phase TEXT NOT NULL CHECK(phase IN ('smoke','rehearsal','scale','recovery')),
    load_1 REAL,
    available_memory_bytes INTEGER CHECK(
        available_memory_bytes IS NULL OR available_memory_bytes >= 0
    ),
    docker_available_bytes INTEGER CHECK(
        docker_available_bytes IS NULL OR docker_available_bytes >= 0
    ),
    gpfs_available_bytes INTEGER CHECK(
        gpfs_available_bytes IS NULL OR gpfs_available_bytes >= 0
    ),
    evidence_bytes INTEGER CHECK(evidence_bytes IS NULL OR evidence_bytes >= 0),
    chain_health_json TEXT NOT NULL,
    gap_error TEXT,
    observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE native_process_restarts (
    restart_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    phase TEXT NOT NULL CHECK(phase IN ('smoke','rehearsal','scale','recovery')),
    process_kind TEXT NOT NULL,
    process_id TEXT NOT NULL,
    prior_pid INTEGER,
    new_pid INTEGER,
    detected_at TEXT NOT NULL,
    reason TEXT NOT NULL
) STRICT;

CREATE TABLE native_reconciliation_findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    phase TEXT NOT NULL CHECK(phase IN ('smoke','rehearsal','scale','recovery')),
    attempt_id TEXT REFERENCES attempts(attempt_id),
    invariant_code TEXT NOT NULL,
    passed INTEGER NOT NULL CHECK(passed IN (0,1)),
    expected_json TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    details_json TEXT NOT NULL,
    checked_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER native_action_observations_no_update
BEFORE UPDATE ON native_action_observations BEGIN
    SELECT RAISE(ABORT, 'native action observations are append-only');
END;

CREATE TRIGGER native_action_observations_no_delete
BEFORE DELETE ON native_action_observations BEGIN
    SELECT RAISE(ABORT, 'native action observations are append-only');
END;

CREATE TRIGGER native_process_samples_no_update
BEFORE UPDATE ON native_process_samples BEGIN
    SELECT RAISE(ABORT, 'native process samples are append-only');
END;

CREATE TRIGGER native_process_samples_no_delete
BEFORE DELETE ON native_process_samples BEGIN
    SELECT RAISE(ABORT, 'native process samples are append-only');
END;

CREATE TRIGGER native_host_health_samples_no_update
BEFORE UPDATE ON native_host_health_samples BEGIN
    SELECT RAISE(ABORT, 'native host health samples are append-only');
END;

CREATE TRIGGER native_host_health_samples_no_delete
BEFORE DELETE ON native_host_health_samples BEGIN
    SELECT RAISE(ABORT, 'native host health samples are append-only');
END;

CREATE TRIGGER native_reconciliation_findings_no_update
BEFORE UPDATE ON native_reconciliation_findings BEGIN
    SELECT RAISE(ABORT, 'native reconciliation findings are append-only');
END;

CREATE TRIGGER native_reconciliation_findings_no_delete
BEFORE DELETE ON native_reconciliation_findings BEGIN
    SELECT RAISE(ABORT, 'native reconciliation findings are append-only');
END;
