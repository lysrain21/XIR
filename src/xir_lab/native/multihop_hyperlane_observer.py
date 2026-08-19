"""Durable dual-clock observation of the independent Hyperlane relayer."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, cast

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_deployer import CHAIN_ROLES
from xir_lab.native.multihop_process_identity import (
    current_process_identity,
    process_identity_sha256,
    public_process_identity,
    verify_process_identity,
)

SCHEMA = "xir-lab-native-multihop-hyperlane-observer-event-v1"


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise LocalTopologyError("Hyperlane observer boot identity is empty")
    return value


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"Hyperlane observer RPC failed: {method}") from exc
    if not isinstance(document, dict) or document.get("error") is not None:
        raise LocalTopologyError(f"Hyperlane observer RPC error: {method}")
    return document.get("result")


def _relayer_pid(pid_path: Path) -> int:
    try:
        pid = int(pid_path.read_text(encoding="ascii").strip())
        os.kill(pid, 0)
    except (OSError, ValueError) as exc:
        raise LocalTopologyError("Hyperlane relayer PID is unavailable") from exc
    return pid


def _pending_transactions(rpc_url: str) -> list[dict[str, Any]]:
    """Return pending transactions through Besu's enabled standard ETH API.

    Besu 26.4 does not register Geth's ``eth_pendingTransactions`` extension.
    The EIP-1898-style ``pending`` block tag is available through the ETH
    namespace already admitted by the five-chain topology and returns the same
    full transaction objects needed by this observer.
    """

    pending_block = _rpc(rpc_url, "eth_getBlockByNumber", ["pending", True])
    if not isinstance(pending_block, dict) or not isinstance(
        pending_block.get("transactions"), list
    ):
        # Besu may temporarily return a null/partial pending block while the
        # mined-block fallback remains available. Treat this poll as empty;
        # submission evidence is still required from a later pending poll or
        # the mined block scan.
        return []
    transactions = cast(list[Any], pending_block["transactions"])
    transactions = [transaction for transaction in transactions if isinstance(transaction, dict)]
    return cast(list[dict[str, Any]], transactions)


def _append_event(
    path: Path,
    *,
    event: str,
    runtime_root: Path,
    relayer_pid_path: Path,
    chain_role: str | None = None,
    transaction_hash: str | None = None,
    block_number: int | None = None,
    source: str = "observer",
) -> dict[str, Any]:
    relayer_identity_path = relayer_pid_path.with_name(relayer_pid_path.stem + ".identity.json")
    relayer_identity = verify_process_identity(relayer_identity_path)
    relayer_pid = int(relayer_identity["pid"])
    observer_identity = current_process_identity(runtime_root=runtime_root)
    row = {
        "schema_version": SCHEMA,
        "event": event,
        "source": source,
        "chain_role": chain_role,
        "transaction_hash": transaction_hash,
        "block_number": block_number,
        "utc_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "boot_id": _boot_id(),
        "observer_process_id": os.getpid(),
        "relayer_process_id": relayer_pid,
        "observer_process_identity_sha256": observer_identity["identity_sha256"],
        "relayer_process_identity_sha256": process_identity_sha256(relayer_identity),
        "observer_process_identity": public_process_identity(observer_identity),
        "relayer_process_identity": public_process_identity(relayer_identity),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return row


def _write_ready(path: Path, *, output_path: Path, started: dict[str, Any]) -> None:
    if path.exists():
        raise LocalTopologyError("Hyperlane observer readiness output already exists")
    document = {
        "schema_version": "xir-lab-native-multihop-hyperlane-observer-ready-v1",
        "valid": True,
        "ledger_path": output_path.name,
        "observer_process_id": started["observer_process_id"],
        "relayer_process_id": started["relayer_process_id"],
        "boot_id": started["boot_id"],
        "started_utc_ns": started["utc_ns"],
        "started_monotonic_ns": started["monotonic_ns"],
        "started_row_sha256": hashlib.sha256(
            json.dumps(started, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
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


def observe_hyperlane_relayer(
    *,
    profile_path: Path,
    runtime_root: Path,
    relayer_address: str,
    start_blocks: dict[str, int],
    output_path: Path,
    stop_file: Path,
    poll_seconds: float = 0.25,
    append: bool = False,
    target_blocks_path: Path | None = None,
    completion_path: Path | None = None,
    ready_path: Path | None = None,
) -> None:
    """Poll pending/full blocks and persist relayer submission/mining identities."""

    if (output_path.exists() and not append) or poll_seconds <= 0:
        raise LocalTopologyError("Hyperlane observer output/poll interval is invalid")
    if append and not output_path.is_file():
        raise LocalTopologyError("Hyperlane observer append target is absent")
    profile = cast(dict[str, Any], json.loads(profile_path.read_text(encoding="utf-8")))
    chains = cast(list[dict[str, Any]], profile["chains"])
    role_rpc = {
        role: str(chain["rpc_url"]) for role, chain in zip(CHAIN_ROLES, chains, strict=True)
    }
    next_block = {role: int(start_blocks[role]) for role in CHAIN_ROLES}
    relayer_address = relayer_address.lower()
    seen_submitted: set[str] = set()
    seen_mined: set[str] = set()
    if append:
        prior_rows = load_hyperlane_observer_events(output_path, allow_incomplete_tail=True)
        seen_submitted = {
            str(row["transaction_hash"]).lower()
            for row in prior_rows
            if row.get("event") == "submitted_observed" and row.get("transaction_hash")
        }
        seen_mined = {
            str(row["transaction_hash"]).lower()
            for row in prior_rows
            if row.get("event") == "mined_observed" and row.get("transaction_hash")
        }
    pid_path = runtime_root / "hyperlane/agents/pids/relayer.pid"
    started = _append_event(
        output_path,
        event="observer_started",
        runtime_root=runtime_root,
        relayer_pid_path=pid_path,
    )
    if ready_path is not None:
        _write_ready(ready_path, output_path=output_path, started=started)
    target_blocks: dict[str, int] | None = None
    while True:
        _relayer_pid(pid_path)
        for role, rpc_url in role_rpc.items():
            for transaction in _pending_transactions(rpc_url):
                transaction_hash = str(transaction.get("hash", "")).lower()
                if (
                    str(transaction.get("from", "")).lower() == relayer_address
                    and transaction_hash not in seen_submitted
                ):
                    _append_event(
                        output_path,
                        event="submitted_observed",
                        runtime_root=runtime_root,
                        relayer_pid_path=pid_path,
                        chain_role=role,
                        transaction_hash=transaction_hash,
                        source="eth_getBlockByNumber:pending",
                    )
                    seen_submitted.add(transaction_hash)
            head = int(str(_rpc(rpc_url, "eth_blockNumber", [])), 16)
            while next_block[role] <= head:
                block_number = next_block[role]
                block = _rpc(rpc_url, "eth_getBlockByNumber", [hex(block_number), True])
                if not isinstance(block, dict) or not isinstance(block.get("transactions"), list):
                    raise LocalTopologyError("Hyperlane observer block is invalid")
                for transaction in cast(list[dict[str, Any]], block["transactions"]):
                    if str(transaction.get("from", "")).lower() != relayer_address:
                        continue
                    transaction_hash = str(transaction.get("hash", "")).lower()
                    if transaction_hash not in seen_submitted:
                        _append_event(
                            output_path,
                            event="submitted_observed",
                            runtime_root=runtime_root,
                            relayer_pid_path=pid_path,
                            chain_role=role,
                            transaction_hash=transaction_hash,
                            block_number=block_number,
                            source="mined_block_fallback",
                        )
                        seen_submitted.add(transaction_hash)
                    if transaction_hash not in seen_mined:
                        _append_event(
                            output_path,
                            event="mined_observed",
                            runtime_root=runtime_root,
                            relayer_pid_path=pid_path,
                            chain_role=role,
                            transaction_hash=transaction_hash,
                            block_number=block_number,
                            source="eth_getBlockByNumber",
                        )
                        seen_mined.add(transaction_hash)
                next_block[role] += 1
        if stop_file.exists():
            if target_blocks is None:
                if target_blocks_path is not None and target_blocks_path.is_file():
                    target_blocks = {
                        str(role): int(value)
                        for role, value in cast(
                            dict[str, Any],
                            json.loads(target_blocks_path.read_text(encoding="utf-8")),
                        ).items()
                    }
                else:
                    target_blocks = {
                        role: int(str(_rpc(rpc_url, "eth_blockNumber", [])), 16)
                        for role, rpc_url in role_rpc.items()
                    }
            if all(next_block[role] > target_blocks[role] for role in CHAIN_ROLES):
                break
        time.sleep(poll_seconds)
    _append_event(
        output_path,
        event="observer_stopped",
        runtime_root=runtime_root,
        relayer_pid_path=pid_path,
    )
    if completion_path is not None:
        completion = {
            "schema_version": "xir-lab-native-multihop-hyperlane-observer-completion-v1",
            "valid": True,
            "ledger_path": output_path.name,
            "ledger_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
            "target_blocks": target_blocks,
            "next_blocks": next_block,
            "all_targets_scanned": target_blocks is not None
            and all(next_block[role] > target_blocks[role] for role in CHAIN_ROLES),
        }
        temporary = completion_path.with_name(f".{completion_path.name}.{os.getpid()}.tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(completion, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, completion_path)
        directory_fd = os.open(completion_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def load_hyperlane_observer_events(
    path: Path, *, allow_incomplete_tail: bool = False
) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        if not allow_incomplete_tail:
            raise LocalTopologyError("Hyperlane observer event ledger has a torn tail")
        boundary = raw.rfind(b"\n") + 1
        fragment = raw[boundary:]
        quarantine = path.with_name(
            f"{path.name}.torn-tail-{hashlib.sha256(fragment).hexdigest()[:16]}.fragment"
        )
        if quarantine.exists():
            if quarantine.read_bytes() != fragment:
                raise LocalTopologyError("Hyperlane observer torn-tail quarantine differs")
        else:
            with quarantine.open("xb") as stream:
                stream.write(fragment)
                stream.flush()
                os.fsync(stream.fileno())
        with path.open("r+b") as stream:
            stream.truncate(boundary)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        raw = raw[:boundary]
    try:
        rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalTopologyError("Hyperlane observer event ledger JSON is invalid") from exc
    if (
        not rows
        or rows[0].get("event") != "observer_started"
        or (not allow_incomplete_tail and rows[-1].get("event") != "observer_stopped")
        or any(row.get("schema_version") != SCHEMA for row in rows)
        or any(int(row.get("utc_ns", 0)) <= 0 for row in rows)
        or any(int(row.get("monotonic_ns", 0)) <= 0 for row in rows)
    ):
        raise LocalTopologyError("Hyperlane observer event ledger is invalid")
    for row in rows:
        for prefix in ("observer", "relayer"):
            identity = row.get(f"{prefix}_process_identity")
            digest = str(row.get(f"{prefix}_process_identity_sha256", ""))
            if (
                not isinstance(identity, dict)
                or identity.get("schema_version") != "xir-lab-native-multihop-process-identity-v1"
                or process_identity_sha256(cast(dict[str, Any], identity)) != digest
                or int(identity.get("pid", -1)) != int(row.get(f"{prefix}_process_id", -2))
            ):
                raise LocalTopologyError(f"Hyperlane {prefix} stable process identity is invalid")
        observer_identity = cast(dict[str, Any], row["observer_process_identity"])
        if str(observer_identity.get("boot_id")) != str(row.get("boot_id")):
            raise LocalTopologyError("Hyperlane observer boot identity differs")
    by_transaction: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        transaction_hash = row.get("transaction_hash")
        if isinstance(transaction_hash, str) and transaction_hash:
            by_transaction.setdefault(transaction_hash.lower(), []).append(row)
    for boundaries in by_transaction.values():
        submitted = [row for row in boundaries if row.get("event") == "submitted_observed"]
        mined = [row for row in boundaries if row.get("event") == "mined_observed"]
        valid_incomplete = allow_incomplete_tail and len(submitted) == 1 and not mined
        valid_complete = (
            len(submitted) == 1
            and len(mined) == 1
            and int(submitted[0]["utc_ns"]) <= int(mined[0]["utc_ns"])
            and int(submitted[0]["monotonic_ns"]) <= int(mined[0]["monotonic_ns"])
        )
        if not valid_incomplete and not valid_complete:
            raise LocalTopologyError(
                "Hyperlane observer transaction boundaries are incomplete or unordered"
            )
    return cast(list[dict[str, Any]], rows)
