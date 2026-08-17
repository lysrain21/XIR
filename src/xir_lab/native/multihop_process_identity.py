"""Boot- and start-time-bound process identities for multihop cleanup."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import signal
import time
from pathlib import Path
from typing import Any, cast

from xir_lab.localnet.topology import LocalTopologyError

_LIBC = ctypes.CDLL(None, use_errno=True)
_SYS_PIDFD_OPEN = 434
_SYS_PIDFD_SEND_SIGNAL = 424


def _pidfd_open(pid: int) -> int:
    descriptor = int(_LIBC.syscall(_SYS_PIDFD_OPEN, pid, 0))
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


def _pidfd_send_signal(pidfd: int, selected: signal.Signals) -> None:
    result = int(_LIBC.syscall(_SYS_PIDFD_SEND_SIGNAL, pidfd, int(selected), 0, 0))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _proc(pid: int) -> tuple[int, str]:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
    except OSError as exc:
        raise LocalTopologyError(f"process identity is unavailable for pid {pid}") from exc
    close = stat.rfind(")")
    if close < 0:
        raise LocalTopologyError("process stat format is invalid")
    fields = stat[close + 2 :].split()
    return int(fields[19]), cmdline


def process_identity_sha256(identity: dict[str, Any]) -> str:
    """Hash the immutable process identity fields used by latency sensitivity."""

    fields = {
        key: identity.get(key)
        for key in (
            "pid",
            "boot_id",
            "starttime_ticks",
            "runtime_root",
            "executable",
            "cmdline_sha256",
        )
    }
    if any(value in (None, "") for value in fields.values()):
        raise LocalTopologyError("stable process identity is incomplete")
    return hashlib.sha256(
        json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def public_process_identity(identity: dict[str, Any]) -> dict[str, Any]:
    """Return the secret-free immutable tuple and its verified digest."""

    document = {
        "schema_version": "xir-lab-native-multihop-process-identity-v1",
        **{
            key: identity.get(key)
            for key in (
                "pid",
                "boot_id",
                "starttime_ticks",
                "runtime_root",
                "executable",
                "cmdline_sha256",
            )
        },
    }
    document["identity_sha256"] = process_identity_sha256(document)
    return document


def current_process_identity(*, runtime_root: Path, pid: int | None = None) -> dict[str, Any]:
    """Capture one immutable boot/start/executable/cmdline/runtime identity."""

    selected = os.getpid() if pid is None else pid
    starttime, cmdline = _proc(selected)
    try:
        executable = str(Path(f"/proc/{selected}/exe").resolve(strict=True))
    except OSError as exc:
        raise LocalTopologyError("process executable identity is unavailable") from exc
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-process-identity-v1",
        "pid": selected,
        "boot_id": _boot_id(),
        "starttime_ticks": starttime,
        "runtime_root": str(runtime_root.resolve()),
        "executable": executable,
        "cmdline_sha256": hashlib.sha256(cmdline.encode()).hexdigest(),
    }
    document["identity_sha256"] = process_identity_sha256(document)
    return document


def record_process_identity(
    *, pid: int, identity_path: Path, runtime_root: Path, expected_token: str
) -> dict[str, Any]:
    if pid <= 1 or not expected_token or expected_token not in str(runtime_root):
        raise LocalTopologyError("process identity arguments are invalid")
    deadline = time.monotonic() + 2.0
    while True:
        starttime, cmdline = _proc(pid)
        if expected_token in cmdline:
            break
        if time.monotonic() >= deadline:
            raise LocalTopologyError("process command does not contain expected runtime identity")
        time.sleep(0.01)
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-process-identity-v1",
        "pid": pid,
        "boot_id": _boot_id(),
        "starttime_ticks": starttime,
        "runtime_root": str(runtime_root.resolve()),
        "expected_token": expected_token,
        "recorded_cmdline": cmdline,
        "executable": str(Path(f"/proc/{pid}/exe").resolve(strict=True)),
        "cmdline_sha256": hashlib.sha256(cmdline.encode()).hexdigest(),
    }
    document["identity_sha256"] = process_identity_sha256(document)
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return document


def verify_process_identity(identity_path: Path) -> dict[str, Any]:
    try:
        document = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError("process identity document is unavailable") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("process identity document must be an object")
    identity = cast(dict[str, Any], document)
    pid = int(identity.get("pid", -1))
    starttime, cmdline = _proc(pid)
    checks = {
        "schema": identity.get("schema_version") == "xir-lab-native-multihop-process-identity-v1",
        "boot": identity.get("boot_id") == _boot_id(),
        "starttime": int(identity.get("starttime_ticks", -1)) == starttime,
        "runtime": identity.get("runtime_root")
        == str(Path(str(identity.get("runtime_root", ""))).resolve()),
        "command": str(identity.get("expected_token", "")) in cmdline,
    }
    failed = sorted(name for name, valid in checks.items() if not valid)
    if failed:
        raise LocalTopologyError("process identity mismatch: " + ", ".join(failed))
    return identity


def signal_verified_process(identity_path: Path, signal_name: str) -> dict[str, Any]:
    identity = verify_process_identity(identity_path)
    pid = int(identity["pid"])
    try:
        pidfd = _pidfd_open(pid)
    except (OSError, AttributeError) as exc:
        raise LocalTopologyError("process disappeared before pidfd acquisition") from exc
    try:
        # Revalidate after pinning the task. The descriptor prevents PID reuse
        # from redirecting the signal between this check and delivery.
        verify_process_identity(identity_path)
        try:
            selected = getattr(signal, signal_name)
        except AttributeError as exc:
            raise LocalTopologyError("unsupported process signal") from exc
        _pidfd_send_signal(pidfd, selected)
    finally:
        os.close(pidfd)
    return identity
