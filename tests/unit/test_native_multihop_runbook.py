from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
RUNBOOK = (
    Path(__file__).parents[3]
    / "openspec/changes/measure-multihop-switching-scalability/artifacts/remote-runbook-v1.md"
)
CAMPAIGN = ROOT / "scripts/native_multihop_campaign.sh"
PROCESSES = ROOT / "scripts/native_multihop_processes.sh"
LEASE_CLI = ROOT / "scripts/native_multihop_lease.py"
AGENTS = ROOT / "scripts/multihop_hyperlane_agents.sh"
IDENTITY = ROOT / "scripts/native_multihop_process_identity.py"
VOLUME_BOOTSTRAP = ROOT / "scripts/stage_native_multihop_validator_volumes.py"
PROTOCOL_BOOTSTRAP = ROOT / "scripts/bootstrap_native_protocols.sh"
PREFLIGHT = ROOT / "scripts/preflight_native_multihop.py"
PROVISION = ROOT / "scripts/provision_native_accounts.py"
WORKER_ROLES = ROOT / "scripts/configure_layerzero_worker_roles.py"
LAYERZERO_DEPLOY = ROOT / "scripts/deploy_layerzero_native.sh"
LAYERZERO_WORKER = ROOT / "scripts/layerzero_worker.py"
MULTIHOP_PROFILE = ROOT / "configs/profiles/native-multihop-five-chain-v1.json"
MULTIHOP_TOPOLOGY = ROOT / "configs/local/topology-multihop-remote-v1.json"
FAILPOINTS = (
    "review_gate",
    "lease",
    "preflight",
    "runner_launch",
    "runner_sigstop",
    "freeze",
    "rebuild",
    "handoff",
    "service_stop",
    "sync",
)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def test_runbook_requires_one_fail_closed_versioned_executable() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    script = CAMPAIGN.read_text(encoding="utf-8")
    assert "only authorized campaign entry point" in text
    assert "scripts/native_multihop_campaign.sh" in text
    assert script.startswith("#!/usr/bin/env bash\nset -Eeuo pipefail\n")
    assert 'wait_for_stopped_process "$runner_pid"' in script
    assert "runner-stop-handshake-complete" in script
    assert "trap on_exit EXIT" in script
    assert 'stop_pidfile "$run_root/runner.pid" 1' in script
    assert 'record "all-phase-writers-dead"' in script
    assert 'record "lease-released-after-writers-dead"' in script
    assert "cleanup incomplete; canonical writer lease retained" in script
    assert "XIR_MULTIHOP_HOST_LEASE_BASE" in script
    assert 'HOST_LEASE_BASE="/run/lock/xir-lab-runtime-leases"' in script
    assert 'HOST_LEASE_BASE="/run/user/' not in script
    assert 'export PYTHONPATH="$REPO/src"' in script
    assert "--target-blocks" in script and "--completion" in script
    assert "wait_for_durable_ready" in script
    assert "prior-observer-completion-quarantined" in script
    assert "hyperlane-observer-failed-during-run" in script
    assert "phase-runner-complete-evidence-tail-reconstruction" in script
    assert "hyperlane-observer-failed-at-runner-tail" in script
    assert "campaign-signal-resume-required" in script
    assert "hyperlane_observer_process_failed" in script
    assert "resource_monitor_process_failed" in script
    assert "SECONDS + 150" in script
    assert "hyperlane-observer-ready" in script
    assert "resource-monitor-ready" in script
    assert "resource-monitor-failed-during-run" in script
    assert "stage_native_multihop_validator_volumes.py" in script
    assert script.index("stage_native_multihop_validator_volumes.py") < script.index(
        "up --detach"
    )
    assert 'down --remove-orphans' in script
    assert "validator_containers_absent" in script
    assert "validator_volume_command remove-existing" in script
    assert "validator_volume_command verify-existing" in script
    assert "resolve-blocked-cleanup" in text
    protocol_bootstrap = PROTOCOL_BOOTSTRAP.read_text(encoding="utf-8")
    assert "preflight_native_toolchain.py" in protocol_bootstrap
    assert "LIBCLANG_PATH" in protocol_bootstrap
    assert 'repository_root=$(cd "$(dirname "$0")/.." && pwd)' in protocol_bootstrap
    assert 'if [[ "$mode" = fetch || "$mode" = build || "$mode" = all ]]' in protocol_bootstrap
    assert protocol_bootstrap.index("preflight_native_toolchain.py") < protocol_bootstrap.index(
        '    fetch_component "$component_id"'
    )
    assert "toolchain-preflight.json" in protocol_bootstrap
    assert script.index("phase_writers_dead") < script.index(
        "validator_volume_command remove-existing"
    )
    assert script.index("wait_for_durable_ready") < script.index("signal SIGCONT")
    assert "verify_phase_handoff" in script
    assert "build_native_multihop_publication_handoff.py" in script
    assert "approve_native_multihop_figure8.py" in text
    assert "--resume" in text
    assert CAMPAIGN.stat().st_mode & 0o111


def test_cleanup_distinguishes_natural_exit_from_live_identity_mismatch() -> None:
    campaign = CAMPAIGN.read_text(encoding="utf-8")
    processes = PROCESSES.read_text(encoding="utf-8")
    agents = AGENTS.read_text(encoding="utf-8")

    # Identity verification remains mandatory for every live process, but a
    # process that exits between kill(0) and pidfd verification is successful
    # cleanup rather than a live identity mismatch.
    assert '>/dev/null 2>&1' in campaign
    assert 'owned_process_alive "$pidfile" || {\n    if ! alive "$pid"; then' in campaign
    assert campaign.count('if ! alive "$pid"; then\n      complete_pidfile "$pidfile"') >= 3
    assert '>/dev/null 2>&1' in processes
    assert 'if kill -0 "$pid" 2>/dev/null; then\n    echo "$label exited; reused PID left untouched"' in processes
    assert '>/dev/null 2>&1' in agents
    assert (
        'if ! "$python" "$identity_cli" signal' in agents
        and 'if kill -0 "$pid" 2>/dev/null; then\n'
        '              echo "$name PID identity mismatch; refusing signal"' in agents
    )


def test_cleanup_stops_runner_before_resource_monitor_and_rechecks_tail() -> None:
    script = CAMPAIGN.read_text(encoding="utf-8")
    cleanup = script[script.index("cleanup_multihop_runtime()") :]
    cleanup = cleanup[: cleanup.index("on_exit()")]
    final_stop = script[script.index("stop_campaign_services()") :]
    final_stop = final_stop[: final_stop.index("finalize_stop_and_publish()")]
    for body in (cleanup, final_stop):
        assert 'touch "$run_root/submission.stop" "$run_root/hyperlane-observer.stop"' in body
        assert 'touch "$run_root/monitor.stop"' not in body
        assert body.index('stop_pidfile "$run_root/runner.pid" 1') < body.index(
            'stop_resource_monitor_pidfile "$run_root"'
        )
    assert "resource_completion_covers_runner_tail" in script
    assert 'SELECT COALESCE(MAX(utc_ns),0) FROM events' in script
    assert '.last_utc_ns >= $runner_utc' in script
    assert "quarantine_resource_segment" in script


def test_production_publication_namespace_is_derived_from_runtime_identity() -> None:
    script = CAMPAIGN.read_text(encoding="utf-8")
    assert 'RUN_ID=$(basename "$RUNTIME")' in script
    assert "production runtime basename must be run-NNN" in script
    assert (
        "local local_public=$WORKSPACE/experiment-results/"
        "native-multihop-switching-v1/$RUN_ID"
    ) in script
    for terminal_run in ("run-001", "run-002", "run-003"):
        assert (
            "local local_public=$WORKSPACE/experiment-results/"
            f"native-multihop-switching-v1/{terminal_run}"
        ) not in script
    assert "independent-readonly-closure-v1.json" not in script
    assert ".review_gate.closure_audit_path" in script
    assert 'REVIEW=$(realpath -e "$WORKSPACE/$REVIEW_REL")' in script


def test_formal_compose_project_matches_the_frozen_topology_identity() -> None:
    script = CAMPAIGN.read_text(encoding="utf-8")
    topology = json.loads(MULTIHOP_TOPOLOGY.read_text(encoding="utf-8"))
    project = topology["project_name"]
    assert project == "xir-native-multihop-v1"
    assert 'COMPOSE_PROJECT=$(jq -er' in script
    assert '[[ $COMPOSE_PROJECT == xir-native-multihop-v1 ]]' in script
    compose_commands = re.findall(
        r"docker compose --project-name ([^ \\\n]+)",
        script,
    )
    assert compose_commands == ['"$COMPOSE_PROJECT"'] * 4
    assert "--project-name xir-multihop-v1" not in script
    live_gate = script.index("start_and_admit_validator_containers()")
    assert script.index("up --detach --wait --wait-timeout 150", live_gate) < script.index(
        "validator_volume_command verify-existing", live_gate
    )
    deploy = script.index("deploy_and_preflight()")
    assert script.index("start_and_admit_validator_containers", deploy) < script.index(
        "bootstrap_native_protocols.sh", deploy
    )
    resume = script.index('record "validator-volumes-reverified-before-resume"')
    assert script.index("start_and_admit_validator_containers", resume) < script.index(
        "start-agents", resume
    )


def test_production_entry_rejects_nonversioned_runtime_before_writes(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "not-a-versioned-run"
    result = subprocess.run(
        [str(CAMPAIGN), str(ROOT.parent), str(runtime)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "production runtime basename must be run-NNN" in result.stderr
    assert not runtime.exists()


def test_volume_bootstrap_direct_entry_requires_review_and_live_lease_before_state(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "run-900"
    attestation = runtime / "provenance/validator-volume-bootstrap.json"
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(VOLUME_BOOTSTRAP),
            "stage",
            "--workspace-root",
            str(ROOT.parent),
            "--repository-root",
            str(ROOT),
            "--runtime-root",
            str(runtime),
            "--topology",
            str(ROOT / "configs/local/topology-multihop-remote-v1.json"),
            "--identity-manifest",
            str(runtime / "private/identity-must-not-be-read.json"),
            "--compose",
            str(runtime / "compose-must-not-be-read.yaml"),
            "--preregistration",
            str(
                ROOT.parent
                / "openspec/changes/measure-multihop-switching-scalability/"
                "artifacts/preregistration-v1.json"
            ),
            "--review-gate",
            str(runtime / "missing-review-gate.json"),
            "--lease",
            str(runtime / "missing-lease.json"),
            "--lease-token",
            str(runtime / "private/missing-token"),
            "--attestation",
            str(attestation),
            "--journal",
            str(runtime / "provenance/validator-volume-transaction.json"),
            "--failure-output",
            str(runtime / "provenance/bootstrap-failure.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode != 0
    assert "independent review closure has not enabled execution" in result.stderr
    assert not runtime.exists()


def test_live_preflight_requires_review_and_lease_before_volume_probe_or_output(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "run-901"
    output = runtime / "preflight-must-not-exist.json"
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(PREFLIGHT),
            "--workspace-root",
            str(ROOT.parent),
            "--repository-root",
            str(ROOT),
            "--runtime-root",
            str(runtime),
            "--topology",
            str(runtime / "must-not-read-topology.json"),
            "--identity",
            str(runtime / "must-not-read-identity.json"),
            "--config",
            str(runtime / "must-not-read-config.json"),
            "--deployment",
            str(runtime / "must-not-read-deployment.json"),
            "--preregistration",
            str(
                ROOT.parent
                / "openspec/changes/measure-multihop-switching-scalability/"
                "artifacts/preregistration-v1.json"
            ),
            "--review-gate",
            str(runtime / "missing-review-gate.json"),
            "--lease",
            str(runtime / "missing-lease.json"),
            "--lease-token",
            str(runtime / "private/missing-token"),
            "--validator-volume-attestation",
            str(runtime / "must-not-read-attestation.json"),
            "--validator-volume-journal",
            str(runtime / "must-not-read-journal.json"),
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode != 0
    assert "independent review closure has not enabled execution" in result.stderr
    assert not runtime.exists()


def test_every_runbook_shell_block_and_campaign_are_syntactically_valid() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\n(.*?)```", runbook, re.S)
    assert blocks
    for block in blocks:
        subprocess.run(["bash", "-n"], input=block, text=True, check=True)
    subprocess.run(["bash", "-n", str(CAMPAIGN)], check=True)
    direct_python_lines = [
        line for line in runbook.splitlines() if ".venv/bin/python" in line
    ]
    assert len(direct_python_lines) == 3
    assert all(
        line.startswith('PYTHONPATH="$REPO/src" ') for line in direct_python_lines
    )


@pytest.mark.parametrize("script", (PROVISION, WORKER_ROLES))
def test_direct_python_multihop_writers_reject_missing_review_and_lease_before_keys(
    tmp_path: Path, script: Path
) -> None:
    command = [
        str(ROOT / ".venv/bin/python"),
        str(script),
        "--runtime-root",
        str(tmp_path / "runtime"),
        "--profile",
        str(MULTIHOP_PROFILE),
        "--deployer-key-file",
        str(tmp_path / "missing-deployer.key"),
    ]
    if script == WORKER_ROLES:
        command.extend(["--worker-key-file", str(tmp_path / "missing-worker.key")])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode != 0
    assert "requires review closure and live lease authority" in result.stderr
    assert not (tmp_path / "runtime").exists()


@pytest.mark.parametrize("script", (PROVISION, WORKER_ROLES))
@pytest.mark.parametrize("schema_version", (None, "wrong-schema-v1"))
def test_direct_five_chain_writers_reject_schema_downgrade_before_keys(
    tmp_path: Path, script: Path, schema_version: str | None
) -> None:
    profile = json.loads(MULTIHOP_PROFILE.read_text(encoding="utf-8"))
    if schema_version is None:
        profile.pop("schema_version")
    else:
        profile["schema_version"] = schema_version
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile) + "\n", encoding="utf-8")
    command = [
        str(ROOT / ".venv/bin/python"),
        str(script),
        "--runtime-root",
        str(tmp_path / "runtime"),
        "--profile",
        str(profile_path),
        "--deployer-key-file",
        str(tmp_path / "missing-deployer.key"),
    ]
    if script == WORKER_ROLES:
        command.extend(["--worker-key-file", str(tmp_path / "missing-worker.key")])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode != 0
    assert "five-chain multihop profile schema is missing or invalid" in result.stderr
    assert not (tmp_path / "runtime").exists()


def test_direct_layerzero_multihop_writer_requires_full_authority_arguments(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [
            str(LAYERZERO_DEPLOY),
            str(tmp_path / "runtime"),
            str(MULTIHOP_PROFILE),
            str(tmp_path / "missing-deployer.key"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "<review-gate> <lease> <token>" in result.stderr
    assert not (tmp_path / "runtime").exists()


def test_lease_cli_rejects_noncanonical_root_by_default(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "provenance").mkdir(parents=True)
    preregistration = tmp_path / "preregistration.json"
    preregistration.write_text("{}\n", encoding="utf-8")
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(LEASE_CLI),
            "acquire",
            "--runtime-root",
            str(runtime),
            "--preregistration",
            str(preregistration),
            "--lease",
            str(runtime / "provenance/exclusive-writer-lease/lease.json"),
            "--token",
            str(runtime / "private/token"),
            "--holder",
            "invalid-root",
            "--global-lock-root",
            str(tmp_path / "arbitrary-root"),
            "--supervisor-pid",
            str(os.getpid()),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires canonical production --global-lock-root" in result.stderr
    assert not (tmp_path / "arbitrary-root").exists()
    assert not (runtime / "private/token").exists()


@pytest.mark.parametrize("action", ("start-agents", "start-worker"))
def test_multihop_service_wrapper_rejects_missing_authority_before_runtime_writes(
    tmp_path: Path, action: str
) -> None:
    runtime = tmp_path / "runtime"
    result = subprocess.run(
        [str(PROCESSES), action, str(runtime)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires workspace, preregistration, review gate, lease, and token" in result.stderr
    assert not runtime.exists()


def test_layerzero_worker_rejects_multihop_profile_without_authority_before_key_or_state(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "profile.json").write_bytes(MULTIHOP_PROFILE.read_bytes())
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(LAYERZERO_WORKER),
            "once",
            "--config",
            str(runtime / "missing-config.json"),
            "--key-file",
            str(runtime / "missing.key"),
            "--state",
            str(runtime / "worker.sqlite"),
            "--raw-root",
            str(runtime / "raw"),
            "--runtime-root",
            str(runtime),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "requires review closure and live lease authority" in result.stderr
    assert not (runtime / "worker.sqlite").exists()
    assert not (runtime / "raw").exists()


def test_layerzero_worker_cannot_omit_runtime_authority_for_five_chain_config(
    tmp_path: Path,
) -> None:
    config = tmp_path / "worker-config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "xir-lab-layerzero-worker-config-v1",
                "chains": [{"chain_id": index} for index in range(5)],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(LAYERZERO_WORKER),
            "once",
            "--config",
            str(config),
            "--key-file",
            str(tmp_path / "missing.key"),
            "--state",
            str(tmp_path / "worker.sqlite"),
            "--raw-root",
            str(tmp_path / "raw"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "requires review closure and live lease authority" in result.stderr
    assert not (tmp_path / "worker.sqlite").exists()
    assert not (tmp_path / "raw").exists()


@pytest.mark.parametrize("schema_version", (None, "wrong-schema-v1"))
def test_layerzero_worker_rejects_five_chain_config_schema_downgrade_before_state(
    tmp_path: Path, schema_version: str | None
) -> None:
    document: dict[str, object] = {
        "chains": [{"chain_id": index} for index in range(5)]
    }
    if schema_version is not None:
        document["schema_version"] = schema_version
    config = tmp_path / "worker-config.json"
    config.write_text(json.dumps(document) + "\n", encoding="utf-8")
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(LAYERZERO_WORKER),
            "once",
            "--config",
            str(config),
            "--key-file",
            str(tmp_path / "missing.key"),
            "--state",
            str(tmp_path / "worker.sqlite"),
            "--raw-root",
            str(tmp_path / "raw"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "five-chain multihop worker config schema is missing or invalid" in result.stderr
    assert not (tmp_path / "worker.sqlite").exists()
    assert not (tmp_path / "raw").exists()


@pytest.mark.parametrize("failpoint", FAILPOINTS)
def test_every_campaign_boundary_failure_cleans_writers_before_lease_release(
    tmp_path: Path, failpoint: str
) -> None:
    workspace = tmp_path / "workspace"
    runtime = tmp_path / f"runtime-{failpoint}"
    env = os.environ.copy()
    host_lease_base = tmp_path / "host-global-leases"
    env["XIR_MULTIHOP_HOST_LEASE_BASE"] = str(host_lease_base)
    result = subprocess.run(
        [
            str(CAMPAIGN),
            str(workspace),
            str(runtime),
            "--fault-injection-dry-run",
            failpoint,
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
        env=env,
    )
    assert result.returncode == 97, result.stderr
    lifecycle = (runtime / "provenance/campaign-lifecycle.log").read_text(encoding="utf-8")
    assert f"boundary:{failpoint}" in lifecycle
    if failpoint == "review_gate":
        assert "no-lease-acquired" in lifecycle
        assert "lease-released-after-writers-dead" not in lifecycle
    else:
        assert lifecycle.index("all-phase-writers-dead") < lifecycle.index(
            "lease-released-after-writers-dead"
        )
    assert lifecycle.rstrip().endswith("cleanup-complete")
    for pidfile in (runtime / "runs").glob("*/*.pid"):
        assert not _alive(int(pidfile.read_text(encoding="ascii").strip()))
    assert not (host_lease_base / "native-multihop-switching-v1").exists()
    assert not (runtime / "provenance/exclusive-writer-lease/lease.json").exists()


def test_cleanup_failure_retains_a_live_supervisor_and_canonical_lease(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime-cleanup-failure"
    env = os.environ.copy()
    env["XIR_TEST_FORCE_CLEANUP_FAILURE"] = "1"
    host_lease_base = tmp_path / "host-global-leases"
    env["XIR_MULTIHOP_HOST_LEASE_BASE"] = str(host_lease_base)
    result = subprocess.run(
        [
            str(CAMPAIGN),
            str(workspace),
            str(runtime),
            "--fault-injection-dry-run",
            "sync",
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
        env=env,
    )
    assert result.returncode != 0
    lifecycle = (runtime / "provenance/campaign-lifecycle.log").read_text(encoding="utf-8")
    assert "cleanup-incomplete-lease-supervisor-active" in lifecycle
    assert "cleanup-incomplete-lease-retained" in lifecycle
    assert "lease-released-after-writers-dead" not in lifecycle
    supervisor_pid = int(
        (runtime / "provenance/lease-supervisor.pid").read_text(encoding="ascii").strip()
    )
    assert _alive(supervisor_pid)
    heartbeat = runtime / "provenance/lease-supervisor-heartbeat-ns"
    before = int(heartbeat.read_text(encoding="ascii"))
    subprocess.run(["sleep", "1.2"], check=True)
    after = int(heartbeat.read_text(encoding="ascii"))
    assert after > before
    global_lock = host_lease_base / "native-multihop-switching-v1"
    assert (global_lock / "owner.json").is_file()
    competing = subprocess.run(
        [
            str(CAMPAIGN),
            str(workspace),
            str(tmp_path / "runtime-competing"),
            "--fault-injection-dry-run",
            "lease",
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert competing.returncode != 0
    assert (global_lock / "owner.json").is_file()
    (runtime / "provenance/lease-supervisor.stop").touch()
    subprocess.run(["sleep", "1.2"], check=True)
    assert not _alive(supervisor_pid)


def test_host_global_lease_conflicts_across_distinct_workspaces(tmp_path: Path) -> None:
    first_workspace = tmp_path / "checkout-a"
    second_workspace = tmp_path / "checkout-b"
    first_runtime = tmp_path / "runtime-a"
    second_runtime = tmp_path / "runtime-b"
    host_lease_base = tmp_path / "host-global-leases"
    env = os.environ.copy()
    env["XIR_MULTIHOP_HOST_LEASE_BASE"] = str(host_lease_base)
    env["XIR_TEST_FORCE_CLEANUP_FAILURE"] = "1"
    first = subprocess.run(
        [
            str(CAMPAIGN),
            str(first_workspace),
            str(first_runtime),
            "--fault-injection-dry-run",
            "sync",
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
        env=env,
    )
    assert first.returncode != 0
    owner = host_lease_base / "native-multihop-switching-v1/owner.json"
    assert owner.is_file()
    second = subprocess.run(
        [
            str(CAMPAIGN),
            str(second_workspace),
            str(second_runtime),
            "--fault-injection-dry-run",
            "lease",
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
        env=env,
    )
    assert second.returncode != 0
    assert owner.is_file()
    supervisor_pid = int(
        (first_runtime / "provenance/lease-supervisor.pid").read_text(encoding="ascii").strip()
    )
    (first_runtime / "provenance/lease-supervisor.stop").touch()
    subprocess.run(["sleep", "1.2"], check=True)
    assert not _alive(supervisor_pid)


def _mismatched_identity(runtime: Path, pid_file: Path, pid: int) -> None:
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f"{pid}\n", encoding="ascii")
    identity = pid_file.with_name(pid_file.stem + ".identity.json")
    subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(IDENTITY),
            "record",
            "--identity",
            str(identity),
            "--pid",
            str(pid),
            "--runtime-root",
            str(runtime),
            "--expected-token",
            str(runtime),
        ],
        check=True,
    )
    document = __import__("json").loads(identity.read_text(encoding="utf-8"))
    document["starttime_ticks"] = int(document["starttime_ticks"]) - 1
    identity.write_text(__import__("json").dumps(document) + "\n", encoding="utf-8")


def test_worker_start_requires_authority_before_examining_a_live_pid(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime-worker"
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", str(runtime)])
    try:
        _mismatched_identity(runtime, runtime / "pids/layerzero-worker.pid", process.pid)
        result = subprocess.run(
            [str(PROCESSES), "start-worker", str(runtime)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        assert "requires workspace, preregistration, review gate, lease, and token" in result.stderr
        assert _alive(process.pid)
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_agent_start_requires_authority_before_examining_a_live_relayer(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime-agents"
    binary_root = runtime / "protocols/hyperlane/rust/main/target/release"
    binary_root.mkdir(parents=True)
    for name in ("validator", "relayer"):
        path = binary_root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        path.chmod(0o755)
    private = runtime / "private"
    private.mkdir(parents=True)
    validator_key = private / "validator.key"
    relayer_key = private / "relayer.key"
    validator_key.write_text("11" * 32 + "\n", encoding="ascii")
    relayer_key.write_text("22" * 32 + "\n", encoding="ascii")
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", str(runtime)])
    try:
        _mismatched_identity(
            runtime,
            runtime / "hyperlane/agents/pids/relayer.pid",
            process.pid,
        )
        result = subprocess.run(
            [str(AGENTS), "start", str(runtime), str(validator_key), str(relayer_key)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        assert "requires review closure and live lease authority" in result.stderr
        assert _alive(process.pid)
    finally:
        process.terminate()
        process.wait(timeout=5)
