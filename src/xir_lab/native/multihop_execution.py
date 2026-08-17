"""Atomic writer lease and review-bound authority for multihop writes."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, cast

import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_preflight import verify_multihop_review_gate
from xir_lab.native.multihop_process_identity import verify_process_identity

LEASE_SCHEMA = "xir-lab-native-multihop-exclusive-writer-lease-v3"
PRODUCTION_GLOBAL_LEASE_ROOT = Path(
    "/run/lock/xir-lab-runtime-leases/native-multihop-switching-v1"
)
HEARTBEAT_GRACE_SECONDS = 120
IMMUTABLE_LEASE_IDENTITY_FIELDS = (
    "schema_version",
    "holder",
    "token_sha256",
    "runtime_root",
    "global_lock_root",
    "acquisition_hostname",
    "acquisition_boot_id",
    "acquired_utc_ns",
    "ttl_seconds",
    "preregistration_sha256",
    "review_closure_sha256",
)
LEASE_CONTINUATION_ACTIVE = "active"
LEASE_CONTINUATION_RESUME_PENDING = "resume_pending_clean_shutdown"
LEASE_CONTINUATION_BLOCKED = "cleanup_incomplete_blocked"
LEASE_CONTINUATION_STATES = {
    LEASE_CONTINUATION_ACTIVE,
    LEASE_CONTINUATION_RESUME_PENDING,
    LEASE_CONTINUATION_BLOCKED,
}


@contextmanager
def _lease_mutex(global_lock_root: Path) -> Iterator[None]:
    """Serialize mutations of the host-global lease and its runtime mirror."""

    mutex_path = global_lock_root.with_name(global_lock_root.name + ".mutex")
    with mutex_path.open("a+", encoding="ascii") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _process_is_alive(process_id: int) -> bool:
    if process_id <= 0:
        return False
    try:
        os.kill(process_id, 0)
    except OSError:
        return False
    return True


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise LocalTopologyError("writer lease boot identity is empty")
    return value


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"writer authority input is unavailable: {path}") from exc
    if not isinstance(value, dict):
        raise LocalTopologyError("writer authority JSON root must be an object")
    return cast(dict[str, Any], value)


def immutable_writer_lease_identity(lease: dict[str, Any]) -> dict[str, Any]:
    """Return acquisition-time lease identity, excluding mutable liveness."""

    identity = {field: lease.get(field) for field in IMMUTABLE_LEASE_IDENTITY_FIELDS}
    required = set(IMMUTABLE_LEASE_IDENTITY_FIELDS) - {"review_closure_sha256"}
    if any(identity[field] is None for field in required):
        raise LocalTopologyError("exclusive writer lease immutable identity is incomplete")
    identity["acquired_utc_ns"] = str(identity["acquired_utc_ns"])
    return identity


def immutable_writer_lease_identity_sha256(lease: dict[str, Any]) -> str:
    """Hash only acquisition-time lease identity, excluding mutable liveness."""

    return hashlib.sha256(rfc8785.dumps(immutable_writer_lease_identity(lease))).hexdigest()


def acquire_writer_lease(
    *,
    runtime_root: Path,
    holder: str,
    ttl_seconds: int,
    preregistration_path: Path,
    token_output: Path,
    global_lock_root: Path,
    supervisor_pid: int,
    review_closure_path: Path | None = None,
) -> dict[str, Any]:
    """Acquire one canonical host-global lease plus a runtime-local locator."""

    if not holder or ttl_seconds < 60:
        raise LocalTopologyError("writer lease holder/TTL is invalid")
    if not _process_is_alive(supervisor_pid):
        raise LocalTopologyError("writer lease supervisor process is not alive")
    runtime_root = runtime_root.resolve()
    global_lock_root = global_lock_root.resolve()
    lease_root = runtime_root / "provenance/exclusive-writer-lease"
    if global_lock_root == lease_root or runtime_root in global_lock_root.parents:
        raise LocalTopologyError("global writer lock must be outside the fresh runtime")
    try:
        lease_root.mkdir(parents=False)
    except FileExistsError as exc:
        raise LocalTopologyError("runtime exclusive writer lease already exists") from exc
    token_output.parent.mkdir(parents=True, exist_ok=True)
    snapshot_root = runtime_root / "provenance"
    snapshot_root.mkdir(parents=True, exist_ok=True)
    preregistration_snapshot = snapshot_root / "lease-preregistration-at-acquisition.json"
    if preregistration_snapshot.exists():
        raise LocalTopologyError("lease preregistration snapshot already exists")
    preregistration_snapshot.write_bytes(preregistration_path.read_bytes())
    with preregistration_snapshot.open("rb") as stream:
        os.fsync(stream.fileno())
    if review_closure_path is not None:
        closure_snapshot = snapshot_root / "lease-review-closure-at-acquisition.json"
        if closure_snapshot.exists():
            raise LocalTopologyError("lease review-closure snapshot already exists")
        closure_snapshot.write_bytes(review_closure_path.read_bytes())
        with closure_snapshot.open("rb") as stream:
            os.fsync(stream.fileno())
        preregistration = _load(preregistration_path)
        review_gate = cast(dict[str, Any], preregistration.get("review_gate", {}))
        if review_gate.get("closure_audit_sha256") != _sha(closure_snapshot):
            raise LocalTopologyError("lease review-closure snapshot differs from preregistration")
    snapshot_directory = os.open(snapshot_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(snapshot_directory)
    finally:
        os.close(snapshot_directory)
    token = secrets.token_hex(32)
    try:
        with token_output.open("x", encoding="ascii") as stream:
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(token_output, 0o600)
    except BaseException:
        lease_root.rmdir()
        raise
    with _lease_mutex(global_lock_root):
        try:
            global_lock_root.mkdir(parents=False)
        except FileExistsError as exc:
            token_output.unlink()
            lease_root.rmdir()
            raise LocalTopologyError("host-global exclusive writer lease already exists") from exc
        os.chmod(global_lock_root, 0o700)
        root_stat = global_lock_root.stat()
        if root_stat.st_uid != os.getuid() or (root_stat.st_mode & 0o777) != 0o700:
            token_output.unlink()
            global_lock_root.rmdir()
            lease_root.rmdir()
            raise LocalTopologyError("host-global writer lease ownership/mode is invalid")
        now = time.time_ns()
        preregistration = _load(preregistration_path)
        review_gate = cast(dict[str, Any], preregistration.get("review_gate", {}))
        hostname = platform.node()
        boot_id = _boot_id()
        document: dict[str, Any] = {
            "schema_version": LEASE_SCHEMA,
            "status": "active",
            "recovery_blocked": False,
            "continuation_state": LEASE_CONTINUATION_ACTIVE,
            "holder": holder,
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "runtime_root": str(runtime_root),
            "global_lock_root": str(global_lock_root),
            "acquisition_hostname": hostname,
            "acquisition_boot_id": boot_id,
            "current_supervisor_hostname": hostname,
            "current_supervisor_boot_id": boot_id,
            "process_id": supervisor_pid,
            "acquired_utc_ns": now,
            "heartbeat_utc_ns": now,
            "expires_utc_ns": now + ttl_seconds * 1_000_000_000,
            "ttl_seconds": ttl_seconds,
            "preregistration_sha256": _sha(preregistration_path),
            "review_closure_sha256": review_gate.get("closure_audit_sha256"),
        }
        owner_path = global_lock_root / "owner.json"
        _atomic_write_json(owner_path, document)
        # The runtime path is a locator, never a second mutable authority.  A
        # crash before this symlink is recoverable from owner.json + the token.
        (lease_root / "lease.json").symlink_to(owner_path)
    return document


def _verify_writer_lease(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    preregistration_path: Path,
    require_fresh: bool,
) -> dict[str, Any]:
    if not lease_path.is_symlink():
        raise LocalTopologyError("runtime writer lease locator is not a symlink")
    lease = _load(lease_path)
    try:
        token = token_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise LocalTopologyError("writer lease token is unavailable") from exc
    now = time.time_ns()
    global_lock_value = lease.get("global_lock_root")
    if not isinstance(global_lock_value, str):
        raise LocalTopologyError("exclusive writer lease has no global lock binding")
    global_lock_root = Path(global_lock_value)
    global_owner = _load(global_lock_root / "owner.json")
    global_root_stat = global_lock_root.stat()
    preregistration = _load(preregistration_path)
    review_gate = cast(dict[str, Any], preregistration.get("review_gate", {}))
    checks = {
        "schema": lease.get("schema_version") == LEASE_SCHEMA,
        "active": lease.get("status") == "active",
        "token": lease.get("token_sha256") == hashlib.sha256(token.encode()).hexdigest(),
        "runtime": lease.get("runtime_root") == str(runtime_root.resolve()),
        "global_owner": global_owner == lease,
        "global_root_owner": global_root_stat.st_uid == os.getuid(),
        "global_root_mode": (global_root_stat.st_mode & 0o777) == 0o700,
        "canonical_locator": lease_path.resolve() == (global_lock_root / "owner.json").resolve(),
        "global_root_outside_runtime": runtime_root.resolve()
        not in global_lock_root.resolve().parents,
        "acquisition_hostname_identity": isinstance(
            lease.get("acquisition_hostname"), str
        )
        and bool(lease.get("acquisition_hostname")),
        "acquisition_boot_identity": isinstance(
            lease.get("acquisition_boot_id"), str
        )
        and bool(lease.get("acquisition_boot_id")),
        "current_hostname_identity": isinstance(
            lease.get("current_supervisor_hostname"), str
        )
        and bool(lease.get("current_supervisor_hostname")),
        "current_boot_identity": isinstance(
            lease.get("current_supervisor_boot_id"), str
        )
        and bool(lease.get("current_supervisor_boot_id")),
        "continuation_state": lease.get("continuation_state")
        in LEASE_CONTINUATION_STATES,
        "blocked_state_consistent": (
            lease.get("recovery_blocked") is True
        )
        == (lease.get("continuation_state") == LEASE_CONTINUATION_BLOCKED),
        "ttl": int(lease.get("ttl_seconds", 0)) >= 60,
        "preregistration": lease.get("preregistration_sha256") == _sha(preregistration_path),
        "review_closure": lease.get("review_closure_sha256")
        == review_gate.get("closure_audit_sha256"),
    }
    if require_fresh:
        checks.update(
            {
                "current_hostname": lease.get("current_supervisor_hostname")
                == platform.node(),
                "current_boot": lease.get("current_supervisor_boot_id") == _boot_id(),
                "not_expired": int(lease.get("expires_utc_ns", 0)) > now,
                "heartbeat_fresh": now - int(lease.get("heartbeat_utc_ns", 0))
                <= HEARTBEAT_GRACE_SECONDS * 1_000_000_000,
                "supervisor_alive": _process_is_alive(int(lease.get("process_id", -1))),
            }
        )
    failed = sorted(name for name, valid in checks.items() if not valid)
    if failed:
        raise LocalTopologyError("exclusive writer lease invalid: " + ", ".join(failed))
    return lease


def verify_writer_lease(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    preregistration_path: Path,
) -> dict[str, Any]:
    lease = _load(lease_path)
    global_root = Path(str(lease.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=True,
        )
        if lease.get("recovery_blocked") is True:
            raise LocalTopologyError("writer authority is blocked after incomplete cleanup")
        if lease.get("continuation_state") != LEASE_CONTINUATION_ACTIVE:
            raise LocalTopologyError("writer authority is not active for execution")
        return lease


def _atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def heartbeat_writer_lease(
    *, lease_path: Path, token_path: Path, runtime_root: Path, preregistration_path: Path
) -> dict[str, Any]:
    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=False,
        )
        now = time.time_ns()
        lease["heartbeat_utc_ns"] = now
        lease["expires_utc_ns"] = now + int(lease["ttl_seconds"]) * 1_000_000_000
        _atomic_write_json(global_root / "owner.json", lease)
        return lease


def retain_writer_lease_after_cleanup_failure(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    preregistration_path: Path,
    supervisor_pid: int,
) -> dict[str, Any]:
    """Durably prohibit stale recovery after an incomplete cleanup."""

    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=False,
        )
        if not _process_is_alive(supervisor_pid):
            raise LocalTopologyError("replacement lease supervisor process is not alive")
        now = time.time_ns()
        lease["recovery_blocked"] = True
        lease["continuation_state"] = LEASE_CONTINUATION_BLOCKED
        lease["process_id"] = supervisor_pid
        lease["current_supervisor_hostname"] = platform.node()
        lease["current_supervisor_boot_id"] = _boot_id()
        lease["cleanup_incomplete_utc_ns"] = now
        lease["heartbeat_utc_ns"] = now
        lease["expires_utc_ns"] = now + int(lease["ttl_seconds"]) * 1_000_000_000
        _atomic_write_json(global_root / "owner.json", lease)
        return lease


def _runtime_processes_alive(*, runtime_root: Path, exempt_pid: int) -> list[int]:
    """Find retained campaign/service processes without trusting boolean evidence."""

    alive: set[int] = set()
    verified_exempt_pid: int | None = None
    supervisor_identity_path = runtime_root / "provenance/lease-supervisor.identity.json"
    try:
        supervisor_identity = verify_process_identity(supervisor_identity_path)
    except LocalTopologyError:
        supervisor_identity = None
    if (
        supervisor_identity is not None
        and int(supervisor_identity.get("pid", -1)) == exempt_pid
        and supervisor_identity.get("runtime_root") == str(runtime_root.resolve())
    ):
        verified_exempt_pid = exempt_pid
    elif _process_is_alive(exempt_pid):
        # A missing/mismatched stable identity means the numeric PID may have
        # been reused.  Treat that live process as a blocker, never an exemption.
        alive.add(exempt_pid)
    for pid_path in runtime_root.rglob("*.pid"):
        try:
            pid = int(pid_path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            continue
        if pid != verified_exempt_pid and _process_is_alive(pid):
            alive.add(pid)
    ancestors = {os.getpid()}
    current = os.getpid()
    while current > 1:
        try:
            stat = Path(f"/proc/{current}/stat").read_text(encoding="ascii")
            close = stat.rfind(")")
            current = int(stat[close + 2 :].split()[1])
        except (OSError, ValueError, IndexError):
            break
        ancestors.add(current)
    markers = (
        "run_native_multihop",
        "analyze_native_multihop",
        "rebuild_native_multihop",
        "render_native_multihop",
        "monitor_native_multihop",
        "observe_native_multihop",
        "layerzero_worker.py",
        "/target/release/validator",
        "/target/release/relayer",
    )
    runtime_text = str(runtime_root.resolve())
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        pid = int(proc.name)
        if pid == verified_exempt_pid or pid in ancestors:
            continue
        try:
            cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except (OSError, UnicodeDecodeError):
            continue
        if runtime_text in cmdline and any(marker in cmdline for marker in markers):
            alive.add(pid)
    return sorted(alive)


def resolve_blocked_writer_lease_after_audited_cleanup(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    acquisition_preregistration_path: Path,
    acquisition_review_closure_path: Path,
    workspace_root: Path,
    repository_root: Path,
    current_preregistration_path: Path,
    current_review_gate_path: Path,
    topology_path: Path,
    identity_manifest_path: Path,
    compose_path: Path,
    validator_volume_attestation_path: Path,
    validator_volume_journal_path: Path,
    validator_volume_recovery_path: Path,
    cleanup_evidence_output_path: Path,
    docker_runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Clean and atomically release a blocked lease without reopening writes."""

    from xir_lab.localnet.multihop_volume_bootstrap import (
        build_validator_volume_plan,
        remove_existing_validator_volumes,
        validator_volume_container_references,
        verify_validator_volumes_absent,
    )

    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=acquisition_preregistration_path,
            # A blocked lease deliberately survives a dead heartbeat supervisor.
            # The original token and acquisition snapshots, not mutable liveness,
            # authorize this release-only cleanup path.
            require_fresh=False,
        )
        current_gate = verify_multihop_review_gate(
            workspace_root=workspace_root,
            repository_root=repository_root,
            preregistration_path=current_preregistration_path,
        )
        persisted_gate = _load(current_review_gate_path)
        acquisition_preregistration = _load(acquisition_preregistration_path)
        acquisition_review_gate = cast(
            dict[str, Any], acquisition_preregistration.get("review_gate", {})
        )
        checks = {
            "blocked": lease.get("recovery_blocked") is True
            and lease.get("continuation_state") == LEASE_CONTINUATION_BLOCKED,
            "acquisition_preregistration": _sha(acquisition_preregistration_path)
            == lease.get("preregistration_sha256"),
            "acquisition_closure": _sha(acquisition_review_closure_path)
            == lease.get("review_closure_sha256")
            == acquisition_review_gate.get("closure_audit_sha256"),
            "current_review_gate": persisted_gate == current_gate,
            "current_review_closed": current_gate.get("valid") is True,
        }
        failed = sorted(name for name, valid in checks.items() if not valid)
        if failed:
            raise LocalTopologyError(
                "audited blocked-cleanup resolution invalid: " + ", ".join(failed)
            )
        plan = build_validator_volume_plan(
            runtime_root=runtime_root,
            topology_path=topology_path,
            identity_manifest_path=identity_manifest_path,
            compose_path=compose_path,
        )
        supervisor_pid = int(lease.get("process_id", -1))
        processes = _runtime_processes_alive(
            runtime_root=runtime_root, exempt_pid=supervisor_pid
        )
        references = validator_volume_container_references(
            plan=plan, runner=docker_runner
        )
        if processes or references:
            raise LocalTopologyError(
                "audited blocked cleanup found live writers/services/containers: "
                + json.dumps(
                    {"process_ids": processes, "volume_references": references},
                    sort_keys=True,
                )
            )
        journal_before_cleanup = _load(validator_volume_journal_path)
        attestation_present = validator_volume_attestation_path.is_file()
        if journal_before_cleanup.get("state") == "committed" and not attestation_present:
            raise LocalTopologyError(
                "committed validator volumes require their bootstrap attestation"
            )
        remove_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime_root,
            attestation_path=validator_volume_attestation_path,
            journal_path=validator_volume_journal_path,
            recovery_output_path=validator_volume_recovery_path,
            runner=docker_runner,
        )
        verify_validator_volumes_absent(plan=plan, runner=docker_runner)
        references = validator_volume_container_references(
            plan=plan, runner=docker_runner
        )
        processes = _runtime_processes_alive(
            runtime_root=runtime_root, exempt_pid=supervisor_pid
        )
        if processes or references:
            raise LocalTopologyError("audited blocked cleanup live-state recheck failed")
        recovered_journal = _load(validator_volume_journal_path)
        recovery = _load(validator_volume_recovery_path)
        recovery_checks = {
            "journal_recovered": recovered_journal.get("state") == "recovered",
            "recovery_valid": recovery.get("valid") is True,
            "recovery_journal": recovery.get("journal_sha256")
            == _sha(validator_volume_journal_path),
            "recovery_volumes_absent": recovery.get("remaining_volume_names") == [],
            "recovery_containers_absent": recovery.get("remaining_container_names")
            == [],
            "recovery_errors_absent": recovery.get("cleanup_errors") == [],
        }
        failed_recovery = sorted(
            name for name, valid in recovery_checks.items() if not valid
        )
        if failed_recovery:
            raise LocalTopologyError(
                "audited blocked cleanup recovery evidence invalid: "
                + ", ".join(failed_recovery)
            )
        evidence: dict[str, Any] = {
            "schema_version": "xir-lab-native-multihop-audited-cleanup-resolution-v2",
            "valid": True,
            "runtime_root": str(runtime_root.resolve()),
            "lease_identity_sha256": immutable_writer_lease_identity_sha256(lease),
            "acquisition_preregistration_sha256": _sha(
                acquisition_preregistration_path
            ),
            "acquisition_review_closure_sha256": _sha(
                acquisition_review_closure_path
            ),
            "current_preregistration_sha256": _sha(current_preregistration_path),
            "current_review_gate_sha256": _sha(current_review_gate_path),
            "validator_volume_attestation_present": attestation_present,
            "validator_volume_attestation_sha256": (
                _sha(validator_volume_attestation_path)
                if attestation_present
                else None
            ),
            "validator_volume_journal_sha256": _sha(validator_volume_journal_path),
            "validator_volume_recovery_sha256": _sha(validator_volume_recovery_path),
            "all_phase_writers_dead": True,
            "protocol_services_absent": True,
            "validator_containers_absent": True,
            "validator_volumes_absent": True,
            "remaining_process_ids": [],
            "remaining_volume_references": {},
        }
        evidence["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(evidence)).hexdigest()
        _atomic_write_json(cleanup_evidence_output_path, evidence)
        now = time.time_ns()
        lease["status"] = "released_after_audited_blocked_cleanup"
        lease["continuation_state"] = "cleanup_resolved_release_only"
        lease["cleanup_resolution_utc_ns"] = now
        lease["cleanup_resolution_sha256"] = _sha(cleanup_evidence_output_path)
        lease["released_utc_ns"] = now
        release_path = lease_path.parent.parent / "released-writer-lease.json"
        _atomic_write_json(release_path, lease)
        lease_path.unlink()
        lease_path.parent.rmdir()
        shutil.rmtree(global_root)
        return lease


def continue_writer_lease(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    preregistration_path: Path,
    supervisor_pid: int,
) -> dict[str, Any]:
    """Continue the same lease identity after its prior supervisor died."""

    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=False,
        )
        if lease.get("recovery_blocked") is True:
            raise LocalTopologyError("lease continuation is blocked after incomplete cleanup")
        if lease.get("continuation_state") != LEASE_CONTINUATION_RESUME_PENDING:
            raise LocalTopologyError("lease is not in the resumable clean-shutdown state")
        prior_pid = int(lease.get("process_id", -1))
        prior_hostname = lease.get("current_supervisor_hostname")
        prior_boot_id = lease.get("current_supervisor_boot_id")
        same_boot = prior_hostname == platform.node() and prior_boot_id == _boot_id()
        if not same_boot:
            raise LocalTopologyError(
                "cross-boot execution continuation is forbidden; recover the stale lease"
            )
        if same_boot and _process_is_alive(prior_pid):
            raise LocalTopologyError("prior lease supervisor process is still alive")
        if not _process_is_alive(supervisor_pid):
            raise LocalTopologyError("continuation lease supervisor process is not alive")
        now = time.time_ns()
        history = cast(list[dict[str, Any]], lease.setdefault("continuations", []))
        history.append(
            {
                "prior_process_id": prior_pid,
                "prior_supervisor_hostname": prior_hostname,
                "prior_supervisor_boot_id": prior_boot_id,
                "process_id": supervisor_pid,
                "supervisor_hostname": platform.node(),
                "supervisor_boot_id": _boot_id(),
                "continued_utc_ns": now,
            }
        )
        lease["process_id"] = supervisor_pid
        lease["current_supervisor_hostname"] = platform.node()
        lease["current_supervisor_boot_id"] = _boot_id()
        lease["heartbeat_utc_ns"] = now
        lease["expires_utc_ns"] = now + int(lease["ttl_seconds"]) * 1_000_000_000
        _atomic_write_json(global_root / "owner.json", lease)
        return lease


def mark_writer_lease_resume_pending(
    *, lease_path: Path, token_path: Path, runtime_root: Path, preregistration_path: Path
) -> dict[str, Any]:
    """Disable writes after a clean interruption while preserving continuation authority."""

    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=True,
        )
        if lease.get("recovery_blocked") is True:
            raise LocalTopologyError("blocked cleanup cannot become resume-pending")
        if lease.get("continuation_state") != LEASE_CONTINUATION_ACTIVE:
            raise LocalTopologyError("only an active lease can become resume-pending")
        lease["continuation_state"] = LEASE_CONTINUATION_RESUME_PENDING
        lease["resume_pending_utc_ns"] = time.time_ns()
        _atomic_write_json(global_root / "owner.json", lease)
        return lease


def activate_writer_lease_resume(
    *, lease_path: Path, token_path: Path, runtime_root: Path, preregistration_path: Path
) -> dict[str, Any]:
    """Re-enable writes only from an authenticated clean-shutdown continuation."""

    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=True,
        )
        if lease.get("recovery_blocked") is True:
            raise LocalTopologyError("blocked cleanup cannot be resumed")
        if lease.get("continuation_state") != LEASE_CONTINUATION_RESUME_PENDING:
            raise LocalTopologyError("lease is not in the resumable clean-shutdown state")
        lease["continuation_state"] = LEASE_CONTINUATION_ACTIVE
        lease["resumed_utc_ns"] = time.time_ns()
        _atomic_write_json(global_root / "owner.json", lease)
        return lease


def release_writer_lease(
    *, lease_path: Path, token_path: Path, runtime_root: Path, preregistration_path: Path
) -> dict[str, Any]:
    initial = _load(lease_path)
    global_root = Path(str(initial.get("global_lock_root", "")))
    with _lease_mutex(global_root):
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=False,
        )
        if lease.get("recovery_blocked") is True:
            raise LocalTopologyError("blocked cleanup lease requires audited recovery")
        if lease.get("continuation_state") != LEASE_CONTINUATION_ACTIVE:
            raise LocalTopologyError("resume-pending lease cannot be released")
        lease["status"] = "released"
        lease["released_utc_ns"] = time.time_ns()
        release_path = lease_path.parent.parent / "released-writer-lease.json"
        release_path.write_text(
            json.dumps(lease, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        lease_path.unlink()
        lease_path.parent.rmdir()
        shutil.rmtree(global_root)
        return lease


def _restore_runtime_locator(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    global_lock_root: Path,
) -> None:
    """Restore a missing locator after acquisition stopped after owner commit."""

    owner_path = global_lock_root / "owner.json"
    owner = _load(owner_path)
    try:
        token = token_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise LocalTopologyError("writer lease token is unavailable") from exc
    if (
        owner.get("runtime_root") != str(runtime_root.resolve())
        or owner.get("global_lock_root") != str(global_lock_root.resolve())
        or owner.get("token_sha256") != hashlib.sha256(token.encode()).hexdigest()
    ):
        raise LocalTopologyError("incomplete writer lease recovery authority is invalid")
    expected = runtime_root.resolve() / "provenance/exclusive-writer-lease/lease.json"
    if lease_path.resolve(strict=False) != expected:
        raise LocalTopologyError("runtime writer lease locator path is invalid")
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    if lease_path.exists() or lease_path.is_symlink():
        raise LocalTopologyError("runtime writer lease locator already exists")
    lease_path.symlink_to(owner_path.resolve())


def recover_stale_writer_lease(
    *,
    lease_path: Path,
    token_path: Path,
    runtime_root: Path,
    preregistration_path: Path,
    global_lock_root: Path | None = None,
) -> dict[str, Any]:
    """Recover an authenticated stale lease only after its recorded process died."""

    if lease_path.is_symlink():
        initial = _load(lease_path)
        global_root = Path(str(initial.get("global_lock_root", "")))
    else:
        if global_lock_root is None:
            raise LocalTopologyError("missing lease locator requires the global lock root")
        global_root = global_lock_root.resolve()
    with _lease_mutex(global_root):
        if not lease_path.is_symlink():
            _restore_runtime_locator(
                lease_path=lease_path,
                token_path=token_path,
                runtime_root=runtime_root,
                global_lock_root=global_root,
            )
        lease = _verify_writer_lease(
            lease_path=lease_path,
            token_path=token_path,
            runtime_root=runtime_root,
            preregistration_path=preregistration_path,
            require_fresh=False,
        )
        if lease.get("recovery_blocked") is True:
            raise LocalTopologyError(
                "stale writer lease recovery is blocked after incomplete cleanup"
            )
        now = time.time_ns()
        stale = (
            int(lease.get("expires_utc_ns", 0)) <= now
            or now - int(lease.get("heartbeat_utc_ns", 0)) > HEARTBEAT_GRACE_SECONDS * 1_000_000_000
        )
        if not stale:
            raise LocalTopologyError("exclusive writer lease is not stale")
        process_alive = False
        if (
            lease.get("current_supervisor_hostname") == platform.node()
            and lease.get("current_supervisor_boot_id") == _boot_id()
        ):
            process_alive = _process_is_alive(int(lease.get("process_id", -1)))
        if process_alive:
            raise LocalTopologyError("stale writer lease holder process is still alive")
        lease["status"] = "recovered_stale"
        lease["recovered_utc_ns"] = now
        recovery_path = lease_path.parent.parent / "recovered-writer-lease.json"
        recovery_path.write_text(
            json.dumps(lease, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        lease_path.unlink()
        lease_path.parent.rmdir()
        shutil.rmtree(global_root)
        return lease


def verify_execution_authority(
    *,
    workspace_root: Path,
    repository_root: Path,
    runtime_root: Path,
    preregistration_path: Path,
    review_gate_path: Path,
    lease_path: Path,
    lease_token_path: Path,
) -> dict[str, Any]:
    """Require reviewed sources, an exact gate artifact, and a live lease."""

    gate = verify_multihop_review_gate(
        workspace_root=workspace_root,
        repository_root=repository_root,
        preregistration_path=preregistration_path,
    )
    persisted_gate = _load(review_gate_path)
    if persisted_gate != gate:
        raise LocalTopologyError("predeployment review gate differs from current review state")
    lease = verify_writer_lease(
        lease_path=lease_path,
        token_path=lease_token_path,
        runtime_root=runtime_root,
        preregistration_path=preregistration_path,
    )
    if Path(str(lease.get("global_lock_root", ""))).resolve() != (
        PRODUCTION_GLOBAL_LEASE_ROOT
    ):
        raise LocalTopologyError("writer lease does not use the canonical production root")
    lease_identity = immutable_writer_lease_identity(lease)
    return {
        "review_gate_sha256": _sha(review_gate_path),
        "review_closure_sha256": gate["closure_sha256"],
        "lease_identity_sha256": immutable_writer_lease_identity_sha256(lease),
        "lease_identity": lease_identity,
        "lease_holder": lease["holder"],
        "lease_heartbeat_utc_ns": lease["heartbeat_utc_ns"],
    }


def verify_multihop_profile_write_authority(
    *,
    profile: dict[str, Any],
    workspace_root: Path | None,
    repository_root: Path | None,
    runtime_root: Path,
    preregistration_path: Path | None,
    review_gate_path: Path | None,
    lease_path: Path | None,
    lease_token_path: Path | None,
) -> dict[str, Any] | None:
    """Gate every direct chain-writing CLI when the five-chain profile is used."""

    expected_schema = "xir-lab-native-multihop-five-chain-profile-v1"
    chains = profile.get("chains")
    has_five_chain_shape = isinstance(chains, list) and len(chains) == 5
    has_formal_schema = profile.get("schema_version") == expected_schema
    if not has_five_chain_shape and not has_formal_schema:
        return None
    if not has_formal_schema:
        raise LocalTopologyError(
            "five-chain multihop profile schema is missing or invalid"
        )
    required = (
        workspace_root,
        repository_root,
        preregistration_path,
        review_gate_path,
        lease_path,
        lease_token_path,
    )
    if any(path is None for path in required):
        raise LocalTopologyError(
            "multihop chain write requires review closure and live lease authority"
        )
    return verify_execution_authority(
        workspace_root=cast(Path, workspace_root),
        repository_root=cast(Path, repository_root),
        runtime_root=runtime_root,
        preregistration_path=cast(Path, preregistration_path),
        review_gate_path=cast(Path, review_gate_path),
        lease_path=cast(Path, lease_path),
        lease_token_path=cast(Path, lease_token_path),
    )
