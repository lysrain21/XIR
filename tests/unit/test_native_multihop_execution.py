from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import xir_lab.native.multihop_execution as execution
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_execution import (
    PRODUCTION_GLOBAL_LEASE_ROOT,
    acquire_writer_lease,
    activate_writer_lease_resume,
    continue_writer_lease,
    heartbeat_writer_lease,
    immutable_writer_lease_identity_sha256,
    mark_writer_lease_resume_pending,
    recover_stale_writer_lease,
    release_writer_lease,
    resolve_blocked_writer_lease_after_audited_cleanup,
    retain_writer_lease_after_cleanup_failure,
    verify_execution_authority,
    verify_multihop_profile_write_authority,
    verify_writer_lease,
)


def _inputs(tmp_path: Path, name: str = "runtime") -> tuple[Path, Path, Path, Path]:
    runtime = tmp_path / name
    (runtime / "provenance").mkdir(parents=True)
    preregistration = tmp_path / "preregistration.json"
    preregistration.write_text('{"frozen":true}\n', encoding="utf-8")
    token = tmp_path / "private/lease-token.txt"
    return runtime, preregistration, token, tmp_path / "host-global-writer.lock"


def test_writer_lease_is_exclusive_heartbeat_bound_and_releasable(
    tmp_path: Path,
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquired = acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    assert acquired["status"] == "active"
    assert token.stat().st_mode & 0o777 == 0o600
    assert lease_path.is_symlink()
    assert lease_path.resolve() == (global_lock / "owner.json").resolve()
    verified = verify_writer_lease(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    assert verified["holder"] == "reviewed-multihop-run"
    with pytest.raises(LocalTopologyError, match="already exists"):
        acquire_writer_lease(
            runtime_root=runtime,
            holder="conflicting-writer",
            ttl_seconds=600,
            preregistration_path=preregistration,
            token_output=tmp_path / "other-token",
            global_lock_root=global_lock,
            supervisor_pid=os.getpid(),
        )
    before = int(verified["heartbeat_utc_ns"])
    immutable_before = immutable_writer_lease_identity_sha256(verified)
    heartbeat = heartbeat_writer_lease(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    assert int(heartbeat["heartbeat_utc_ns"]) >= before
    assert int(heartbeat["expires_utc_ns"]) > int(acquired["expires_utc_ns"])
    assert immutable_writer_lease_identity_sha256(heartbeat) == immutable_before
    released = release_writer_lease(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    assert released["status"] == "released"
    assert not lease_path.parent.exists()
    assert (runtime / "provenance/released-writer-lease.json").is_file()
    assert not global_lock.exists()


def test_writer_lease_rejects_token_preregistration_and_expiry_drift(
    tmp_path: Path,
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    bad_token = tmp_path / "private/bad-token.txt"
    bad_token.write_text("wrong\n", encoding="ascii")
    with pytest.raises(LocalTopologyError, match="token"):
        verify_writer_lease(
            lease_path=lease_path,
            token_path=bad_token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    preregistration.write_text('{"frozen":false}\n', encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="preregistration"):
        verify_writer_lease(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    preregistration.write_text('{"frozen":true}\n', encoding="utf-8")
    lease = json.loads(lease_path.read_text(encoding="utf-8"))
    lease["expires_utc_ns"] = 0
    payload = json.dumps(lease) + "\n"
    (global_lock / "owner.json").write_text(payload, encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="not_expired"):
        verify_writer_lease(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )


def test_host_global_lease_blocks_a_different_fresh_runtime(tmp_path: Path) -> None:
    runtime_a, preregistration, token_a, global_lock = _inputs(tmp_path, "runtime-a")
    runtime_b = tmp_path / "runtime-b"
    (runtime_b / "provenance").mkdir(parents=True)
    acquire_writer_lease(
        runtime_root=runtime_a,
        holder="first",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token_a,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    with pytest.raises(LocalTopologyError, match="host-global"):
        acquire_writer_lease(
            runtime_root=runtime_b,
            holder="second",
            ttl_seconds=600,
            preregistration_path=preregistration,
            token_output=tmp_path / "private/second-token.txt",
            global_lock_root=global_lock,
            supervisor_pid=os.getpid(),
        )


def test_expired_lease_can_release_and_dead_holder_can_be_recovered(
    tmp_path: Path,
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    lease = json.loads(lease_path.read_text(encoding="utf-8"))
    lease["expires_utc_ns"] = 0
    lease["heartbeat_utc_ns"] = 0
    lease["process_id"] = os.getpid()
    payload = json.dumps(lease, sort_keys=True) + "\n"
    (global_lock / "owner.json").write_text(payload, encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="still alive"):
        recover_stale_writer_lease(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    lease["process_id"] = 2**31 - 1
    payload = json.dumps(lease, sort_keys=True) + "\n"
    (global_lock / "owner.json").write_text(payload, encoding="utf-8")
    recovered = recover_stale_writer_lease(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    assert recovered["status"] == "recovered_stale"
    assert (runtime / "provenance/recovered-writer-lease.json").is_file()
    assert not global_lock.exists()


def test_cleanup_failure_marker_blocks_recovery_even_if_supervisor_later_dies(
    tmp_path: Path,
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    retained = retain_writer_lease_after_cleanup_failure(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
        supervisor_pid=os.getpid(),
    )
    assert retained["recovery_blocked"] is True
    assert retained["continuation_state"] == "cleanup_incomplete_blocked"
    with pytest.raises(LocalTopologyError, match="blocked after incomplete cleanup"):
        verify_writer_lease(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    with pytest.raises(LocalTopologyError, match="blocked cleanup cannot be resumed"):
        activate_writer_lease_resume(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    retained["expires_utc_ns"] = 0
    retained["heartbeat_utc_ns"] = 0
    retained["process_id"] = 2**31 - 1
    (global_lock / "owner.json").write_text(
        json.dumps(retained, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(LocalTopologyError, match="blocked after incomplete cleanup"):
        recover_stale_writer_lease(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    assert (global_lock / "owner.json").is_file()


@pytest.mark.parametrize("attestation_present", [True, False])
def test_blocked_cleanup_requires_exact_audited_resolution_before_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation_present: bool,
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    closure = tmp_path / "closure.json"
    closure.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
    preregistration.write_text(
        json.dumps(
            {
                "review_gate": {
                    "closure_audit_sha256": hashlib.sha256(
                        closure.read_bytes()
                    ).hexdigest()
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    acquired = acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
        review_closure_path=closure,
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    retain_writer_lease_after_cleanup_failure(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
        supervisor_pid=os.getpid(),
    )
    evidence_path = tmp_path / "cleanup-resolution.json"
    current_gate = {"valid": True, "closure_sha256": "a" * 64}
    current_gate_path = tmp_path / "current-review-gate.json"
    current_gate_path.write_text(json.dumps(current_gate) + "\n", encoding="utf-8")
    current_preregistration = tmp_path / "current-preregistration.json"
    current_preregistration.write_text("{}\n", encoding="utf-8")
    import xir_lab.localnet.multihop_volume_bootstrap as volume_bootstrap

    monkeypatch.setattr(execution, "verify_multihop_review_gate", lambda **_kwargs: current_gate)
    monkeypatch.setattr(execution, "_runtime_processes_alive", lambda **_kwargs: [4321])
    monkeypatch.setattr(volume_bootstrap, "build_validator_volume_plan", lambda **_kwargs: ())
    monkeypatch.setattr(
        volume_bootstrap, "validator_volume_container_references", lambda **_kwargs: {}
    )
    monkeypatch.setattr(
        volume_bootstrap, "remove_existing_validator_volumes", lambda **_kwargs: None
    )
    monkeypatch.setattr(volume_bootstrap, "verify_validator_volumes_absent", lambda **_kwargs: None)
    recovery = tmp_path / "volume-recovery.json"
    attestation_path = tmp_path / "attestation.json"
    if attestation_present:
        attestation_path.write_text("{}\n", encoding="utf-8")
    journal_path = tmp_path / "journal.json"
    journal_path.write_text('{"state":"recovered"}\n', encoding="utf-8")
    recovery.write_text(
        json.dumps(
            {
                "valid": True,
                "journal_sha256": hashlib.sha256(journal_path.read_bytes()).hexdigest(),
                "remaining_volume_names": [],
                "remaining_container_names": [],
                "cleanup_errors": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    call = {
        "lease_path": lease_path,
        "token_path": token,
        "runtime_root": runtime,
        "acquisition_preregistration_path": runtime
        / "provenance/lease-preregistration-at-acquisition.json",
        "acquisition_review_closure_path": runtime
        / "provenance/lease-review-closure-at-acquisition.json",
        "workspace_root": tmp_path,
        "repository_root": tmp_path,
        "current_preregistration_path": current_preregistration,
        "current_review_gate_path": current_gate_path,
        "topology_path": tmp_path / "topology.json",
        "identity_manifest_path": tmp_path / "identity.json",
        "compose_path": tmp_path / "compose.yaml",
        "validator_volume_attestation_path": attestation_path,
        "validator_volume_journal_path": journal_path,
        "validator_volume_recovery_path": recovery,
        "cleanup_evidence_output_path": evidence_path,
    }
    with pytest.raises(LocalTopologyError, match="live writers"):
        resolve_blocked_writer_lease_after_audited_cleanup(
            **call,
        )
    assert (global_lock / "owner.json").is_file()
    monkeypatch.setattr(execution, "_runtime_processes_alive", lambda **_kwargs: [])
    monkeypatch.setattr(
        volume_bootstrap,
        "validator_volume_container_references",
        lambda **_kwargs: {"validator-a-1": ["active-validator"]},
    )
    with pytest.raises(LocalTopologyError, match="live writers/services/containers"):
        resolve_blocked_writer_lease_after_audited_cleanup(**call)
    assert (global_lock / "owner.json").is_file()
    stale_blocked = json.loads((global_lock / "owner.json").read_text(encoding="utf-8"))
    stale_blocked["heartbeat_utc_ns"] = 0
    stale_blocked["expires_utc_ns"] = 0
    (global_lock / "owner.json").write_text(
        json.dumps(stale_blocked, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        volume_bootstrap, "validator_volume_container_references", lambda **_kwargs: {}
    )
    resolved = resolve_blocked_writer_lease_after_audited_cleanup(
        **call,
    )
    assert resolved["status"] == "released_after_audited_blocked_cleanup"
    assert resolved["continuation_state"] == "cleanup_resolved_release_only"
    assert resolved["cleanup_resolution_sha256"] == hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    assert json.loads(evidence_path.read_text(encoding="utf-8"))[
        "validator_volumes_absent"
    ] is True
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["validator_volume_attestation_present"] is attestation_present
    assert evidence["validator_volume_attestation_sha256"] == (
        hashlib.sha256(attestation_path.read_bytes()).hexdigest()
        if attestation_present
        else None
    )
    assert not global_lock.exists()
    assert not lease_path.is_symlink()
    assert json.loads(evidence_path.read_text(encoding="utf-8"))[
        "lease_identity_sha256"
    ] == immutable_writer_lease_identity_sha256(acquired)


def test_continuation_keeps_immutable_identity_across_heartbeat_and_new_supervisor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquired = acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    identity = immutable_writer_lease_identity_sha256(acquired)
    pending = mark_writer_lease_resume_pending(
        lease_path=runtime / "provenance/exclusive-writer-lease/lease.json",
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    assert pending["continuation_state"] == "resume_pending_clean_shutdown"
    monkeypatch.setattr(execution, "_process_is_alive", lambda pid: pid == 424242)
    continued = continue_writer_lease(
        lease_path=runtime / "provenance/exclusive-writer-lease/lease.json",
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
        supervisor_pid=424242,
    )
    assert immutable_writer_lease_identity_sha256(continued) == identity
    assert continued["process_id"] == 424242
    assert len(continued["continuations"]) == 1
    activated = activate_writer_lease_resume(
        lease_path=runtime / "provenance/exclusive-writer-lease/lease.json",
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    assert activated["continuation_state"] == "active"
    assert immutable_writer_lease_identity_sha256(activated) == identity


def test_blocked_cleanup_exempts_only_a_stably_verified_supervisor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    provenance = runtime / "provenance"
    provenance.mkdir(parents=True)
    pid = os.getpid()
    (provenance / "lease-supervisor.pid").write_text(f"{pid}\n", encoding="ascii")

    monkeypatch.setattr(
        execution,
        "verify_process_identity",
        lambda _path: {"pid": pid, "runtime_root": str(runtime.resolve())},
    )
    assert execution._runtime_processes_alive(runtime_root=runtime, exempt_pid=pid) == []

    def missing_identity(_path: Path) -> dict[str, object]:
        raise LocalTopologyError("process identity document is unavailable")

    monkeypatch.setattr(execution, "verify_process_identity", missing_identity)
    assert execution._runtime_processes_alive(runtime_root=runtime, exempt_pid=pid) == [pid]

    monkeypatch.setattr(
        execution,
        "verify_process_identity",
        lambda _path: {"pid": pid + 1, "runtime_root": str(runtime.resolve())},
    )
    assert execution._runtime_processes_alive(runtime_root=runtime, exempt_pid=pid) == [pid]

    monkeypatch.setattr(
        execution,
        "verify_process_identity",
        lambda _path: {"pid": pid, "runtime_root": str(tmp_path / "other-runtime")},
    )
    assert execution._runtime_processes_alive(runtime_root=runtime, exempt_pid=pid) == [pid]


def test_cross_boot_continuation_is_forbidden_but_acquisition_identity_stays_immutable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    monkeypatch.setattr(execution, "_boot_id", lambda: "boot-a")
    acquired = acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    identity = immutable_writer_lease_identity_sha256(acquired)
    mark_writer_lease_resume_pending(
        lease_path=runtime / "provenance/exclusive-writer-lease/lease.json",
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )
    monkeypatch.setattr(execution, "_boot_id", lambda: "boot-b")
    monkeypatch.setattr(execution, "_process_is_alive", lambda pid: pid == 424242)
    with pytest.raises(LocalTopologyError, match="cross-boot execution continuation"):
        continue_writer_lease(
            lease_path=runtime / "provenance/exclusive-writer-lease/lease.json",
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
            supervisor_pid=424242,
        )
    current = json.loads((global_lock / "owner.json").read_text(encoding="utf-8"))
    assert current["acquisition_boot_id"] == "boot-a"
    assert immutable_writer_lease_identity_sha256(current) == identity


def test_concurrent_heartbeats_update_one_owner_visible_through_locator(
    tmp_path: Path,
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquire_writer_lease(
        runtime_root=runtime,
        holder="reviewed-multihop-run",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _index: heartbeat_writer_lease(
                    lease_path=lease_path,
                    token_path=token,
                    runtime_root=runtime,
                    preregistration_path=preregistration,
                ),
                range(12),
            )
        )
    assert len(results) == 12
    assert json.loads(lease_path.read_text(encoding="utf-8")) == json.loads(
        (global_lock / "owner.json").read_text(encoding="utf-8")
    )
    assert lease_path.is_symlink()


def test_acquisition_interruption_after_owner_commit_is_authenticated_and_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    real_symlink = Path.symlink_to

    def interrupt_locator(self: Path, target: Path, *args: object, **kwargs: object) -> None:
        del self, target, args, kwargs
        raise OSError("injected locator interruption")

    monkeypatch.setattr(Path, "symlink_to", interrupt_locator)
    with pytest.raises(OSError, match="injected"):
        acquire_writer_lease(
            runtime_root=runtime,
            holder="interrupted",
            ttl_seconds=600,
            preregistration_path=preregistration,
            token_output=token,
            global_lock_root=global_lock,
            supervisor_pid=os.getpid(),
        )
    assert (global_lock / "owner.json").is_file()
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    assert not lease_path.exists()
    owner = json.loads((global_lock / "owner.json").read_text(encoding="utf-8"))
    owner["expires_utc_ns"] = 0
    owner["heartbeat_utc_ns"] = 0
    owner["process_id"] = 2**31 - 1
    (global_lock / "owner.json").write_text(json.dumps(owner) + "\n", encoding="utf-8")
    monkeypatch.setattr(Path, "symlink_to", real_symlink)
    wrong = tmp_path / "private/wrong-token.txt"
    wrong.write_text("wrong\n", encoding="ascii")
    runtime_b = tmp_path / "runtime-b"
    (runtime_b / "provenance").mkdir(parents=True)
    with pytest.raises(LocalTopologyError, match="host-global"):
        acquire_writer_lease(
            runtime_root=runtime_b,
            holder="conflict-during-recovery",
            ttl_seconds=600,
            preregistration_path=preregistration,
            token_output=tmp_path / "private/conflict-token.txt",
            global_lock_root=global_lock,
            supervisor_pid=os.getpid(),
        )
    with pytest.raises(LocalTopologyError, match="recovery authority"):
        recover_stale_writer_lease(
            lease_path=lease_path,
            token_path=wrong,
            runtime_root=runtime,
            preregistration_path=preregistration,
            global_lock_root=global_lock,
        )
    recovered = recover_stale_writer_lease(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
        global_lock_root=global_lock,
    )
    assert recovered["status"] == "recovered_stale"
    assert not global_lock.exists()


def test_heartbeat_interruption_cannot_split_canonical_and_runtime_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, preregistration, token, global_lock = _inputs(tmp_path)
    acquire_writer_lease(
        runtime_root=runtime,
        holder="heartbeat-interruption",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=global_lock,
        supervisor_pid=os.getpid(),
    )
    lease_path = runtime / "provenance/exclusive-writer-lease/lease.json"
    before = lease_path.read_bytes()
    original = execution._atomic_write_json

    def interrupt(_path: Path, _document: dict[str, object]) -> None:
        raise OSError("injected atomic heartbeat interruption")

    monkeypatch.setattr(execution, "_atomic_write_json", interrupt)
    with pytest.raises(OSError, match="heartbeat interruption"):
        heartbeat_writer_lease(
            lease_path=lease_path,
            token_path=token,
            runtime_root=runtime,
            preregistration_path=preregistration,
        )
    assert lease_path.read_bytes() == before
    assert lease_path.is_symlink()
    monkeypatch.setattr(execution, "_atomic_write_json", original)
    heartbeat_writer_lease(
        lease_path=lease_path,
        token_path=token,
        runtime_root=runtime,
        preregistration_path=preregistration,
    )


def test_direct_multihop_write_boundary_requires_and_forwards_exact_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = {
        "schema_version": "xir-lab-native-multihop-five-chain-profile-v1",
        "chains": [{} for _ in range(5)],
    }
    runtime = tmp_path / "runtime"
    with pytest.raises(LocalTopologyError, match="review closure and live lease"):
        verify_multihop_profile_write_authority(
            profile=profile,
            workspace_root=None,
            repository_root=None,
            runtime_root=runtime,
            preregistration_path=None,
            review_gate_path=None,
            lease_path=None,
            lease_token_path=None,
        )
    paths = {
        "workspace_root": tmp_path / "workspace",
        "repository_root": tmp_path / "repository",
        "preregistration_path": tmp_path / "preregistration.json",
        "review_gate_path": tmp_path / "review-gate.json",
        "lease_path": tmp_path / "lease.json",
        "lease_token_path": tmp_path / "wrong-token.txt",
    }
    observed: dict[str, object] = {}

    def reject_wrong_token(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        raise LocalTopologyError("exclusive writer lease token differs")

    monkeypatch.setattr(execution, "verify_execution_authority", reject_wrong_token)
    with pytest.raises(LocalTopologyError, match="token differs"):
        verify_multihop_profile_write_authority(
            profile=profile, runtime_root=runtime, **paths
        )
    assert observed == {"runtime_root": runtime, **paths}


@pytest.mark.parametrize("schema_version", (None, "wrong-schema-v1"))
def test_five_chain_profile_cannot_downgrade_authority_by_changing_schema(
    tmp_path: Path, schema_version: str | None
) -> None:
    profile: dict[str, object] = {"chains": [{} for _ in range(5)]}
    if schema_version is not None:
        profile["schema_version"] = schema_version
    with pytest.raises(LocalTopologyError, match="schema is missing or invalid"):
        verify_multihop_profile_write_authority(
            profile=profile,
            workspace_root=None,
            repository_root=None,
            runtime_root=tmp_path / "runtime",
            preregistration_path=None,
            review_gate_path=None,
            lease_path=None,
            lease_token_path=None,
        )


def test_legacy_profile_write_boundary_does_not_claim_multihop_authority(
    tmp_path: Path,
) -> None:
    assert (
        verify_multihop_profile_write_authority(
            profile={"schema_version": "xir-lab-native-stack-profile-v1"},
            workspace_root=None,
            repository_root=None,
            runtime_root=tmp_path,
            preregistration_path=None,
            review_gate_path=None,
            lease_path=None,
            lease_token_path=None,
        )
        is None
    )


@pytest.mark.parametrize("root_name", ("arbitrary-root-a", "arbitrary-root-b"))
def test_direct_writer_authority_rejects_noncanonical_global_lease_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_name: str
) -> None:
    runtime, preregistration, token, _unused = _inputs(tmp_path)
    arbitrary_root = tmp_path / root_name
    acquire_writer_lease(
        runtime_root=runtime,
        holder="noncanonical-direct-writer",
        ttl_seconds=600,
        preregistration_path=preregistration,
        token_output=token,
        global_lock_root=arbitrary_root,
        supervisor_pid=os.getpid(),
    )
    gate = {"valid": True, "closure_sha256": "ab" * 32}
    gate_path = tmp_path / "review-gate.json"
    gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")
    monkeypatch.setattr(execution, "verify_multihop_review_gate", lambda **_kwargs: gate)
    with pytest.raises(LocalTopologyError, match="canonical production root"):
        verify_execution_authority(
            workspace_root=tmp_path,
            repository_root=tmp_path,
            runtime_root=runtime,
            preregistration_path=preregistration,
            review_gate_path=gate_path,
            lease_path=runtime / "provenance/exclusive-writer-lease/lease.json",
            lease_token_path=token,
        )
    assert arbitrary_root.resolve() != PRODUCTION_GLOBAL_LEASE_ROOT
