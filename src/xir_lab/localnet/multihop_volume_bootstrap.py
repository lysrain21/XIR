"""Transactional Docker-volume bootstrap for the five-chain validators."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import rfc8785
import yaml

from xir_lab.localnet.multihop_topology import (
    load_multihop_identity_manifest,
    load_multihop_topology,
)
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_process_identity import _pidfd_open

DockerRunner = Callable[..., subprocess.CompletedProcess[str]]
ATTESTATION_SCHEMA = "xir-lab-native-multihop-validator-volume-bootstrap-v1"
JOURNAL_SCHEMA = "xir-lab-native-multihop-validator-volume-transaction-v1"
RECOVERY_SCHEMA = "xir-lab-native-multihop-validator-volume-recovery-v1"
NAMESPACE = "native-multihop-switching-v1"
LABEL_NAMESPACE = "org.xir.namespace"
LABEL_TRANSACTION = "org.xir.bootstrap-transaction"
LABEL_RUNTIME = "org.xir.runtime-root-sha256"


@dataclass(frozen=True)
class ValidatorVolumeBootstrap:
    compose_project: str
    network_id: str
    validator_id: str
    service_name: str
    image: str
    runtime_uid: int
    runtime_gid: int
    volume_name: str
    genesis_path: str
    genesis_sha256: str
    private_key_path: str
    private_key_sha256: str


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runtime_digest(runtime_root: Path) -> str:
    return hashlib.sha256(str(runtime_root).encode()).hexdigest()


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LocalTopologyError(f"{label} must be an object")
    return value


def _docker(
    runner: DockerRunner,
    arguments: Sequence[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = runner(["docker", *arguments], check=False, text=True, capture_output=True)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LocalTopologyError(
            f"docker {' '.join(arguments[:3])} failed" + (f": {detail}" if detail else "")
        )
    return result


def _is_proven_absent(result: subprocess.CompletedProcess[str], *, kind: str) -> bool:
    detail = (result.stderr or result.stdout).strip().lower()
    return result.returncode == 1 and f"no such {kind}" in detail


def _inspect(runner: DockerRunner, *, kind: str, name: str) -> dict[str, Any] | None:
    result = _docker(runner, [kind, "inspect", name], check=False)
    if _is_proven_absent(result, kind=kind):
        return None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LocalTopologyError(f"docker {kind} inspect failed closed: {detail}")
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LocalTopologyError(f"docker {kind} inspect returned invalid JSON") from exc
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise LocalTopologyError(f"docker {kind} inspect returned an invalid shape")
    return cast(dict[str, Any], rows[0])


def _labels(document: dict[str, Any], *, kind: str) -> dict[str, str]:
    source: object
    if kind == "volume":
        source = document.get("Labels")
    else:
        source = _mapping(document.get("Config"), label="container.Config").get("Labels")
    if not isinstance(source, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in source.items()
    ):
        raise LocalTopologyError(f"docker {kind} labels are invalid")
    return cast(dict[str, str], source)


def build_validator_volume_plan(
    *,
    runtime_root: Path,
    topology_path: Path,
    identity_manifest_path: Path,
    compose_path: Path,
) -> tuple[ValidatorVolumeBootstrap, ...]:
    runtime = runtime_root.resolve()
    if runtime != runtime_root or runtime_root.is_symlink():
        raise LocalTopologyError("runtime root must be canonical and non-symlink")
    topology = load_multihop_topology(topology_path)
    if topology.validator_data_storage != "docker-volume":
        raise LocalTopologyError("multihop formal execution requires docker-volume storage")
    manifest = load_multihop_identity_manifest(identity_manifest_path, topology=topology)
    compose = _mapping(yaml.safe_load(compose_path.read_text(encoding="utf-8")), label="compose")
    services = _mapping(compose.get("services"), label="compose.services")
    volumes = _mapping(compose.get("volumes"), label="compose.volumes")
    rows: list[ValidatorVolumeBootstrap] = []
    seen: set[str] = set()
    for network in manifest.networks:
        genesis = runtime / network.genesis_path
        if not genesis.is_file():
            raise LocalTopologyError(f"genesis file is absent: {network.genesis_path}")
        for validator in network.validators:
            service_name = f"{network.network_id}-{validator.validator_id}"
            service = _mapping(services.get(service_name), label=f"service {service_name}")
            image = service.get("image")
            runtime_user = service.get("user")
            mounts = service.get("volumes")
            if (
                not isinstance(image, str)
                or not image
                or not isinstance(runtime_user, str)
                or runtime_user != topology.validator_runtime_user
                or re.fullmatch(r"[1-9][0-9]*:[0-9]+", runtime_user) is None
                or not isinstance(mounts, list)
            ):
                raise LocalTopologyError(f"service {service_name} is incomplete")
            uid_text, gid_text = runtime_user.split(":", 1)
            runtime_uid, runtime_gid = int(uid_text), int(gid_text)
            data_mounts = [
                item for item in mounts if isinstance(item, dict) and item.get("target") == "/data"
            ]
            if len(data_mounts) != 1:
                raise LocalTopologyError(
                    f"service {service_name} must have exactly one /data volume"
                )
            source = data_mounts[0].get("source")
            if not isinstance(source, str) or source not in volumes:
                raise LocalTopologyError(f"service {service_name} volume source is invalid")
            volume_name = _mapping(volumes[source], label=f"volume {source}").get("name")
            expected = f"{topology.project_name}-{network.network_id}-{validator.validator_id}-data"
            if volume_name != expected or volume_name in seen:
                raise LocalTopologyError(f"service {service_name} volume identity is invalid")
            seen.add(volume_name)
            key = runtime / validator.private_key_path
            if not key.is_file():
                raise LocalTopologyError(f"validator key is absent: {validator.private_key_path}")
            rows.append(
                ValidatorVolumeBootstrap(
                    compose_project=topology.project_name,
                    network_id=network.network_id,
                    validator_id=validator.validator_id,
                    service_name=service_name,
                    image=image,
                    runtime_uid=runtime_uid,
                    runtime_gid=runtime_gid,
                    volume_name=volume_name,
                    genesis_path=network.genesis_path,
                    genesis_sha256=_sha256(genesis),
                    private_key_path=validator.private_key_path,
                    private_key_sha256=_sha256(key),
                )
            )
    if (
        len(rows) != 20
        or len(seen) != 20
        or len({row.image for row in rows}) != 1
        or len({(row.runtime_uid, row.runtime_gid) for row in rows}) != 1
    ):
        raise LocalTopologyError("validator volume plan must be exactly 20 rows and one image")
    return tuple(rows)


def _image_identity(runner: DockerRunner, *, image: str) -> str:
    result = _docker(runner, ["image", "inspect", image])
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LocalTopologyError("Besu image inspect returned invalid JSON") from exc
    if (
        not isinstance(rows, list)
        or len(rows) != 1
        or not isinstance(rows[0], dict)
        or not isinstance(rows[0].get("Id"), str)
        or not rows[0]["Id"]
    ):
        raise LocalTopologyError("Besu image identity is invalid")
    return cast(str, rows[0]["Id"])


def _probe_labels(*, transaction_id: str, runtime_digest: str, role: str) -> dict[str, str]:
    return {
        LABEL_NAMESPACE: NAMESPACE,
        LABEL_TRANSACTION: transaction_id,
        LABEL_RUNTIME: runtime_digest,
        "org.xir.probe-role": role,
    }


def _probe_rows(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    transaction_id: str,
    runtime_digest: str,
) -> list[dict[str, Any]]:
    prefix = f"xir-multihop-probe-{transaction_id[:16]}"
    definitions: list[tuple[str, str, str | None]] = [(f"{prefix}-image-user", "image-user", None)]
    for index, row in enumerate(plan):
        definitions.extend(
            (
                (f"{prefix}-observe-{index}", "volume-observe", row.volume_name),
                (f"{prefix}-write-{index}", "volume-write", row.volume_name),
            )
        )
    return [
        {
            "probe_name": name,
            "probe_role": role,
            "volume_name": volume_name,
            "probe_labels": _probe_labels(
                transaction_id=transaction_id,
                runtime_digest=runtime_digest,
                role=role,
            ),
            "create_intent": False,
            "created": False,
            "start_intent": False,
            "started": False,
            "remove_intent": False,
            "removed": False,
        }
        for name, role, volume_name in definitions
    ]


def _execute_probe(
    runner: DockerRunner,
    *,
    journal: dict[str, Any],
    journal_path: Path,
    probe: dict[str, Any],
    create_arguments: list[str],
) -> subprocess.CompletedProcess[str]:
    name = cast(str, probe["probe_name"])
    labels = cast(dict[str, str], probe["probe_labels"])
    if _inspect(runner, kind="container", name=name) is not None:
        raise LocalTopologyError(f"validator probe already exists: {name}")
    arguments = ["create", "--name", name]
    for key, value in labels.items():
        arguments.extend(["--label", f"{key}={value}"])
    arguments.extend(create_arguments)
    probe["create_intent"] = True
    _write_semantic_document(journal_path, journal)
    _docker(runner, arguments)
    document = _inspect(runner, kind="container", name=name)
    if document is None:
        raise LocalTopologyError("validator probe disappeared after create")
    _require_owned(document, kind="container", expected_labels=labels)
    probe["created"] = True
    _write_semantic_document(journal_path, journal)
    probe["start_intent"] = True
    _write_semantic_document(journal_path, journal)
    result = _docker(runner, ["start", "--attach", name], check=False)
    probe["started"] = True
    _write_semantic_document(journal_path, journal)
    completed = _inspect(runner, kind="container", name=name)
    if completed is None:
        raise LocalTopologyError("validator probe disappeared after start")
    state = _mapping(completed.get("State"), label="container.State")
    exit_code = state.get("ExitCode")
    running = state.get("Running")
    logs = _docker(runner, ["logs", name], check=False)
    probe["remove_intent"] = True
    _write_semantic_document(journal_path, journal)
    _remove_owned(
        runner,
        kind="container",
        name=name,
        expected_labels=labels,
    )
    probe["removed"] = True
    _write_semantic_document(journal_path, journal)
    if (
        result.returncode != 0
        or logs.returncode != 0
        or running is not False
        or exit_code != 0
    ):
        raise LocalTopologyError(
            "validator probe process failed: "
            f"docker_returncode={result.returncode!r}, "
            f"logs_returncode={logs.returncode!r}, "
            f"running={running!r}, exit_code={exit_code!r}"
        )
    return logs


def _image_user(
    runner: DockerRunner,
    *,
    image: str,
    expected_uid: int,
    expected_gid: int,
    journal: dict[str, Any],
    journal_path: Path,
) -> tuple[int, int]:
    probe = cast(list[dict[str, Any]], journal["probes"])[0]
    result = _execute_probe(
        runner,
        journal=journal,
        journal_path=journal_path,
        probe=probe,
        create_arguments=[
            "--user",
            f"{expected_uid}:{expected_gid}",
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            'printf "%s:%s\\n" "$(id -u)" "$(id -g)"',
        ],
    )
    try:
        identity_fields = result.stdout.replace(":", " ").split()
        if len(identity_fields) != 2:
            raise ValueError("expected exactly one UID and one GID")
        uid, gid = (int(field) for field in identity_fields)
    except (ValueError, AttributeError) as exc:
        raise LocalTopologyError("Besu image runtime UID/GID probe is invalid") from exc
    if uid == 0:
        raise LocalTopologyError("Besu validator image must not run as root")
    if (uid, gid) != (expected_uid, expected_gid):
        raise LocalTopologyError("Besu image runtime UID/GID differs from Compose")
    return uid, gid


def _observe(
    runner: DockerRunner,
    *,
    row: ValidatorVolumeBootstrap,
    uid: int,
    gid: int,
    journal: dict[str, Any],
    journal_path: Path,
    observe_probe: dict[str, Any],
    write_probe: dict[str, Any],
) -> dict[str, Any]:
    command = (
        "set -eu; "
        "printf '%s\\n' "
        "\"$(sha256sum /stage/bootstrap/genesis.json | cut -d' ' -f1)\" "
        "\"$(sha256sum /stage/bootstrap/key | cut -d' ' -f1)\" "
        '"$(stat -c %u /stage)" "$(stat -c %g /stage)" "$(stat -c %a /stage)" '
        '"$(stat -c %u /stage/bootstrap)" "$(stat -c %g /stage/bootstrap)" '
        '"$(stat -c %a /stage/bootstrap)" '
        '"$(stat -c %u /stage/bootstrap/genesis.json)" '
        '"$(stat -c %g /stage/bootstrap/genesis.json)" '
        '"$(stat -c %a /stage/bootstrap/genesis.json)" '
        '"$(stat -c %u /stage/bootstrap/key)" '
        '"$(stat -c %g /stage/bootstrap/key)" '
        '"$(stat -c %a /stage/bootstrap/key)"'
    )
    result = _execute_probe(
        runner,
        journal=journal,
        journal_path=journal_path,
        probe=observe_probe,
        create_arguments=[
            "--user",
            "0",
            "--entrypoint",
            "/bin/sh",
            "--mount",
            f"type=volume,source={row.volume_name},target=/stage",
            row.image,
            "-c",
            command,
        ],
    )
    values = result.stdout.splitlines()
    if len(values) != 14:
        raise LocalTopologyError("validator volume observation shape is invalid")
    observed = {
        "genesis_sha256": values[0],
        "validator_key_sha256": values[1],
        "root_uid": int(values[2]),
        "root_gid": int(values[3]),
        "root_mode": values[4],
        "bootstrap_uid": int(values[5]),
        "bootstrap_gid": int(values[6]),
        "bootstrap_mode": values[7],
        "genesis_uid": int(values[8]),
        "genesis_gid": int(values[9]),
        "genesis_mode": values[10],
        "key_uid": int(values[11]),
        "key_gid": int(values[12]),
        "key_mode": values[13],
        "runtime_uid": uid,
        "runtime_gid": gid,
    }
    expected = {
        "genesis_sha256": row.genesis_sha256,
        "validator_key_sha256": row.private_key_sha256,
        "root_uid": uid,
        "root_gid": gid,
        "root_mode": "700",
        "bootstrap_uid": uid,
        "bootstrap_gid": gid,
        "bootstrap_mode": "700",
        "genesis_uid": uid,
        "genesis_gid": gid,
        "genesis_mode": "644",
        "key_uid": uid,
        "key_gid": gid,
        "key_mode": "600",
        "runtime_uid": uid,
        "runtime_gid": gid,
    }
    if observed != expected:
        raise LocalTopologyError(f"validator volume metadata mismatch: {row.volume_name}")
    _execute_probe(
        runner,
        journal=journal,
        journal_path=journal_path,
        probe=write_probe,
        create_arguments=[
            "--user",
            f"{uid}:{gid}",
            "--entrypoint",
            "/bin/sh",
            "--mount",
            f"type=volume,source={row.volume_name},target=/stage",
            row.image,
            "-c",
            "set -eu; umask 077; printf x > /stage/.xir-write-probe; "
            "sync; rm /stage/.xir-write-probe",
        ],
    )
    inspection = _inspect(runner, kind="volume", name=row.volume_name)
    if inspection is None:
        raise LocalTopologyError(f"validator volume is missing: {row.volume_name}")
    host_uid, host_gid = _host_volume_owner(inspection, row=row)
    observed["host_runtime_uid"] = host_uid
    observed["host_runtime_gid"] = host_gid
    return observed


def _host_volume_owner(
    document: dict[str, Any], *, row: ValidatorVolumeBootstrap
) -> tuple[int, int]:
    mountpoint = document.get("Mountpoint")
    if not isinstance(mountpoint, str) or not mountpoint:
        raise LocalTopologyError("validator volume mountpoint is invalid")
    root = Path(mountpoint)
    paths = (root, root / "bootstrap", root / "bootstrap/genesis.json", root / "bootstrap/key")
    if (
        not root.is_absolute()
        or root.is_symlink()
        or root.resolve() != root
        or any(path.is_symlink() or not path.exists() for path in paths)
    ):
        raise LocalTopologyError("validator volume mounted content is incomplete")
    owners = {
        (status.st_uid, status.st_gid)
        for status in (path.stat(follow_symlinks=False) for path in paths)
    }
    if len(owners) != 1:
        raise LocalTopologyError(f"validator volume ownership mismatch: {row.volume_name}")
    return next(iter(owners))


def _map_namespace_identifier(mapping: str, identifier: int, *, label: str) -> int:
    if identifier < 0:
        raise LocalTopologyError(f"{label} identifier is invalid")
    matches: list[int] = []
    for raw_line in mapping.splitlines():
        fields = raw_line.split()
        if len(fields) != 3:
            raise LocalTopologyError(f"{label} namespace map is invalid")
        try:
            inside, outside, length = (int(value) for value in fields)
        except ValueError as exc:
            raise LocalTopologyError(f"{label} namespace map is invalid") from exc
        if min(inside, outside) < 0 or length <= 0:
            raise LocalTopologyError(f"{label} namespace map is invalid")
        if inside <= identifier < inside + length:
            matches.append(outside + identifier - inside)
    if len(matches) != 1:
        raise LocalTopologyError(f"{label} namespace map does not uniquely cover runtime id")
    return matches[0]


def _runtime_host_ownership(
    runner: DockerRunner,
    *,
    row: ValidatorVolumeBootstrap,
    uid: int,
    gid: int,
    proc_root: Path = Path("/proc"),
    volume_root: Path | None = None,
) -> tuple[int, int]:
    def starttime(pid: int) -> int:
        try:
            raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
        except OSError as exc:
            raise LocalTopologyError("validator runtime process identity is unavailable") from exc
        close = raw.rfind(")")
        if close < 0:
            raise LocalTopologyError("validator runtime process stat is invalid")
        fields = raw[close + 2 :].split()
        try:
            return int(fields[19])
        except (IndexError, ValueError) as exc:
            raise LocalTopologyError("validator runtime process stat is invalid") from exc

    def runtime_identity(document: dict[str, Any]) -> tuple[int, str, str]:
        config = _mapping(document.get("Config"), label="container.Config")
        state = _mapping(document.get("State"), label="container.State")
        labels = config.get("Labels")
        mounts = document.get("Mounts")
        pid = state.get("Pid")
        container_id = document.get("Id")
        started_at = state.get("StartedAt")
        restart_count = document.get("RestartCount")
        expected_labels = {
            "com.docker.compose.project": row.compose_project,
            "com.docker.compose.service": row.service_name,
            "org.xir.environment": "controlled-local-qbft",
            "org.xir.network-id": row.network_id,
            "org.xir.validator-id": row.validator_id,
        }
        if (
            config.get("User") != f"{uid}:{gid}"
            or config.get("Image") != row.image
            or state.get("Running") is not True
            or not isinstance(container_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", container_id)
            or not isinstance(started_at, str)
            or not started_at
            or not isinstance(restart_count, int)
            or isinstance(restart_count, bool)
            or restart_count < 0
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not isinstance(labels, dict)
            or any(labels.get(key) != value for key, value in expected_labels.items())
            or not isinstance(mounts, list)
        ):
            raise LocalTopologyError("validator runtime container identity is invalid")
        data_mounts = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("Destination") == "/data"
        ]
        if (
            len(data_mounts) != 1
            or data_mounts[0].get("Type") != "volume"
            or data_mounts[0].get("Name") != row.volume_name
            or data_mounts[0].get("RW") is not True
        ):
            raise LocalTopologyError("validator runtime /data mount identity is invalid")
        image_id = document.get("Image")
        if not isinstance(image_id, str) or image_id != _image_identity(runner, image=row.image):
            raise LocalTopologyError("validator runtime image identity is invalid")
        return pid, image_id, json.dumps(
            {
                "container_id": container_id,
                "started_at": started_at,
                "restart_count": restart_count,
                "labels": labels,
                "mount": data_mounts[0],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    result = _docker(
        runner,
        [
            "container",
            "ls",
            "--all",
            "--filter",
            f"volume={row.volume_name}",
            "--format",
            "{{.Names}}",
        ],
    )
    names = sorted(filter(None, result.stdout.splitlines()))
    if len(names) != 1:
        raise LocalTopologyError(
            f"validator volume must have one runtime container: {row.volume_name}"
        )
    name = names[0]
    before = _inspect(runner, kind="container", name=name)
    if before is None:
        raise LocalTopologyError("validator runtime container disappeared")
    pid, image_id, stable_identity = runtime_identity(before)
    pidfd: int | None = None
    try:
        pidfd = _pidfd_open(pid)
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise LocalTopologyError("validator runtime pidfd is unavailable") from exc
    if pidfd is not None:
        try:
            try:
                process_starttime = starttime(pid)
                uid_map = (proc_root / str(pid) / "uid_map").read_text(encoding="ascii")
                gid_map = (proc_root / str(pid) / "gid_map").read_text(encoding="ascii")
            except OSError as exc:
                raise LocalTopologyError(
                    "validator runtime namespace map is unavailable"
                ) from exc
            host_uid = _map_namespace_identifier(uid_map, uid, label="uid")
            host_gid = _map_namespace_identifier(gid_map, gid, label="gid")
            after = _inspect(runner, kind="container", name=name)
            if after is None:
                raise LocalTopologyError("validator runtime container disappeared")
            after_pid, after_image_id, after_identity = runtime_identity(after)
            stable_starttime = starttime(pid)
        finally:
            os.close(pidfd)
        if stable_starttime != process_starttime:
            raise LocalTopologyError(
                "validator runtime process changed during namespace proof"
            )
    else:
        if volume_root is None:
            raise LocalTopologyError(
                "validator runtime external-daemon proof lacks a bound volume root"
            )
        uid_map, gid_map = _external_daemon_namespace_maps(
            runner,
            name=name,
            volume_root=volume_root,
            uid=uid,
            gid=gid,
        )
        host_uid = _map_namespace_identifier(uid_map, uid, label="uid")
        host_gid = _map_namespace_identifier(gid_map, gid, label="gid")
        after = _inspect(runner, kind="container", name=name)
        if after is None:
            raise LocalTopologyError("validator runtime container disappeared")
        after_pid, after_image_id, after_identity = runtime_identity(after)
    if (
        after_pid != pid
        or after_image_id != image_id
        or after_identity != stable_identity
    ):
        raise LocalTopologyError("validator runtime container changed during namespace proof")
    return host_uid, host_gid


def _external_daemon_namespace_maps(
    runner: DockerRunner,
    *,
    name: str,
    volume_root: Path,
    uid: int,
    gid: int,
    timeout_seconds: float = 10.0,
) -> tuple[str, str]:
    """Read maps through an async Docker exec using a bound volume sentinel."""

    if timeout_seconds <= 0:
        raise LocalTopologyError("validator namespace proof timeout is invalid")
    directory = os.open(
        volume_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    probe_name = f".xir-namespace-map-{secrets.token_hex(16)}"
    temporary_name = f"{probe_name}.tmp"
    script = (
        "set -euo pipefail; umask 077; "
        "test ! -e \"/data/$1\"; test ! -e \"/data/$1.tmp\"; "
        "{ printf 'xir-uid-map-v1\\n'; cat /proc/self/uid_map; "
        "printf 'xir-gid-map-v1\\n'; cat /proc/self/gid_map; "
        "printf 'xir-map-complete-v1\\n'; } > \"/data/$1.tmp\"; "
        "sync \"/data/$1.tmp\"; mv \"/data/$1.tmp\" \"/data/$1\"; sync /data"
    )
    descriptor: int | None = None
    try:
        _docker(
            runner,
            [
                "container",
                "exec",
                "--user",
                f"{uid}:{gid}",
                name,
                "/bin/bash",
                "-c",
                script,
                "bash",
                probe_name,
            ],
        )
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                descriptor = os.open(
                    probe_name,
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise LocalTopologyError(
                        "validator runtime namespace map sentinel timed out"
                    ) from None
                time.sleep(0.05)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_nlink != 1
            or not 1 <= status.st_size <= 4096
        ):
            raise LocalTopologyError(
                "validator runtime namespace map sentinel is invalid"
            )
        payload = b""
        while len(payload) <= 4096:
            chunk = os.read(descriptor, 4097 - len(payload))
            if not chunk:
                break
            payload += chunk
        if len(payload) > 4096:
            raise LocalTopologyError(
                "validator runtime namespace map sentinel is oversized"
            )
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise LocalTopologyError(
                "validator runtime namespace map sentinel is invalid"
            ) from exc
        uid_marker = "xir-uid-map-v1\n"
        gid_marker = "xir-gid-map-v1\n"
        complete_marker = "xir-map-complete-v1\n"
        if (
            not text.startswith(uid_marker)
            or text.count(gid_marker) != 1
            or not text.endswith(complete_marker)
        ):
            raise LocalTopologyError(
                "validator runtime namespace map sentinel is incomplete"
            )
        maps = text[len(uid_marker) : -len(complete_marker)]
        uid_map, gid_map = maps.split(gid_marker, 1)
        return uid_map, gid_map
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for candidate in (probe_name, temporary_name):
            try:
                os.unlink(candidate, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.fsync(directory)
        os.close(directory)


def _observe_volume_mount(
    document: dict[str, Any],
    *,
    row: ValidatorVolumeBootstrap,
    attested_observed: dict[str, Any],
    uid: int,
    gid: int,
    runner: DockerRunner,
) -> dict[str, Any]:
    mountpoint = document.get("Mountpoint")
    if not isinstance(mountpoint, str) or not mountpoint:
        raise LocalTopologyError("validator volume mountpoint is invalid")
    root = Path(mountpoint)
    if not root.is_absolute() or root.is_symlink() or root.resolve() != root or not root.is_dir():
        raise LocalTopologyError("validator volume mountpoint is unsafe")
    bootstrap = root / "bootstrap"
    genesis = bootstrap / "genesis.json"
    key = bootstrap / "key"
    if any(path.is_symlink() or not path.exists() for path in (bootstrap, genesis, key)):
        raise LocalTopologyError("validator volume mounted content is incomplete")

    def metadata(path: Path) -> tuple[int, int, str]:
        status = path.stat(follow_symlinks=False)
        return status.st_uid, status.st_gid, f"{stat.S_IMODE(status.st_mode):o}"

    root_uid, root_gid, root_mode = metadata(root)
    bootstrap_uid, bootstrap_gid, bootstrap_mode = metadata(bootstrap)
    genesis_uid, genesis_gid, genesis_mode = metadata(genesis)
    key_uid, key_gid, key_mode = metadata(key)
    host_owners = {
        (root_uid, root_gid),
        (bootstrap_uid, bootstrap_gid),
        (genesis_uid, genesis_gid),
        (key_uid, key_gid),
    }
    attested_host_uid = attested_observed.get("host_runtime_uid")
    attested_host_gid = attested_observed.get("host_runtime_gid")
    if (
        not isinstance(attested_host_uid, int)
        or isinstance(attested_host_uid, bool)
        or attested_host_uid <= 0
        or not isinstance(attested_host_gid, int)
        or isinstance(attested_host_gid, bool)
        or attested_host_gid <= 0
    ):
        raise LocalTopologyError("validator volume attested host ownership is invalid")
    host_uid, host_gid = attested_host_uid, attested_host_gid
    if host_owners != {(host_uid, host_gid)}:
        raise LocalTopologyError(f"validator volume ownership mismatch: {row.volume_name}")
    references = _docker(
        runner,
        [
            "container",
            "ls",
            "--all",
            "--filter",
            f"volume={row.volume_name}",
            "--format",
            "{{.Names}}",
        ],
    )
    names = sorted(filter(None, references.stdout.splitlines()))
    if len(names) > 1:
        raise LocalTopologyError(
            f"validator volume has multiple runtime containers: {row.volume_name}"
        )
    if names and _runtime_host_ownership(
        runner,
        row=row,
        uid=uid,
        gid=gid,
        volume_root=root,
    ) != (host_uid, host_gid):
        raise LocalTopologyError(
            f"validator runtime namespace ownership mismatch: {row.volume_name}"
        )
    host_observed = {
        "genesis_sha256": _sha256(genesis),
        "validator_key_sha256": _sha256(key),
        "root_uid": root_uid,
        "root_gid": root_gid,
        "root_mode": root_mode,
        "bootstrap_uid": bootstrap_uid,
        "bootstrap_gid": bootstrap_gid,
        "bootstrap_mode": bootstrap_mode,
        "genesis_uid": genesis_uid,
        "genesis_gid": genesis_gid,
        "genesis_mode": genesis_mode,
        "key_uid": key_uid,
        "key_gid": key_gid,
        "key_mode": key_mode,
        "runtime_uid": uid,
        "runtime_gid": gid,
    }
    host_expected = {
        "genesis_sha256": row.genesis_sha256,
        "validator_key_sha256": row.private_key_sha256,
        "root_uid": host_uid,
        "root_gid": host_gid,
        "root_mode": "700",
        "bootstrap_uid": host_uid,
        "bootstrap_gid": host_gid,
        "bootstrap_mode": "700",
        "genesis_uid": host_uid,
        "genesis_gid": host_gid,
        "genesis_mode": "644",
        "key_uid": host_uid,
        "key_gid": host_gid,
        "key_mode": "600",
        "runtime_uid": uid,
        "runtime_gid": gid,
    }
    if host_observed != host_expected:
        drift = sorted(
            key for key, value in host_observed.items() if host_expected.get(key) != value
        )
        raise LocalTopologyError(
            f"validator volume metadata mismatch: {row.volume_name}: {','.join(drift)}"
        )
    # The bootstrap attestation is expressed in the container namespace.  Keep
    # that stable schema after proving the exact host-side user-namespace map.
    observed = dict(host_observed)
    for prefix in ("root", "bootstrap", "genesis", "key"):
        observed[f"{prefix}_uid"] = uid
        observed[f"{prefix}_gid"] = gid
    observed["host_runtime_uid"] = host_uid
    observed["host_runtime_gid"] = host_gid
    _probe_host_volume_write(
        root,
        runtime_uid=uid,
        host_uid=host_uid,
        host_gid=host_gid,
    )
    return observed


def _probe_host_volume_write(
    root: Path, *, runtime_uid: int, host_uid: int, host_gid: int
) -> None:
    original_euid, original_egid = os.geteuid(), os.getegid()
    original_groups = tuple(os.getgroups())
    identity_changed = (original_euid, original_egid) != (host_uid, host_gid)
    if identity_changed and original_euid != 0:
        raise LocalTopologyError(
            "validator volume non-root write probe cannot assume the runtime identity"
        )
    directory = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    directory_stat = os.fstat(directory)
    if not stat.S_ISDIR(directory_stat.st_mode):
        os.close(directory)
        raise LocalTopologyError("validator volume write probe root is not a directory")
    identity_entered = False
    try:
        if identity_changed:
            os.setgroups([host_gid])
            try:
                os.setegid(host_gid)
                try:
                    os.seteuid(host_uid)
                except BaseException:
                    os.setegid(original_egid)
                    raise
            except BaseException:
                os.setgroups(list(original_groups))
                raise
            identity_entered = True
        active_groups = tuple(os.getgroups())
        if (
            (os.geteuid(), os.getegid()) != (host_uid, host_gid)
            or (identity_entered and active_groups != (host_gid,))
            or (not identity_entered and 0 in active_groups)
            or runtime_uid == 0
            or host_uid == 0
        ):
            raise LocalTopologyError("validator volume write probe identity is invalid")
        descriptor = os.open(
            ".xir-write-probe",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            os.write(descriptor, b"x")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.unlink(".xir-write-probe", dir_fd=directory)
        os.fsync(directory)
    finally:
        if identity_entered:
            os.seteuid(original_euid)
            os.setgroups(list(original_groups))
            os.setegid(original_egid)
        os.close(directory)


def _owned_labels(
    *, transaction_id: str, runtime_digest: str, row: ValidatorVolumeBootstrap
) -> dict[str, str]:
    return {
        "org.xir.environment": "controlled-local-qbft",
        "org.xir.purpose": "validator-data",
        LABEL_NAMESPACE: NAMESPACE,
        LABEL_TRANSACTION: transaction_id,
        LABEL_RUNTIME: runtime_digest,
        "org.xir.network-id": row.network_id,
        "org.xir.validator-id": row.validator_id,
    }


def _attestation_row(
    *, row: ValidatorVolumeBootstrap, labels: dict[str, str], observed: dict[str, Any]
) -> dict[str, Any]:
    return {
        "compose_project": row.compose_project,
        "network_id": row.network_id,
        "validator_id": row.validator_id,
        "service_name": row.service_name,
        "image": row.image,
        "volume_name": row.volume_name,
        "genesis_path": row.genesis_path,
        "genesis_sha256": row.genesis_sha256,
        "validator_key_path": row.private_key_path,
        "validator_key_sha256": row.private_key_sha256,
        "labels": labels,
        "observed": observed,
    }


def _require_owned(
    document: dict[str, Any],
    *,
    kind: str,
    expected_labels: dict[str, str],
) -> None:
    labels = _labels(document, kind=kind)
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise LocalTopologyError(f"{kind} transaction ownership labels mismatch")


def _remove_owned(
    runner: DockerRunner,
    *,
    kind: str,
    name: str,
    expected_labels: dict[str, str],
) -> bool:
    document = _inspect(runner, kind=kind, name=name)
    if document is None:
        return True
    _require_owned(document, kind=kind, expected_labels=expected_labels)
    arguments = [kind, "rm"]
    if kind == "container":
        arguments.append("--force")
    arguments.append(name)
    _docker(runner, arguments)
    if _inspect(runner, kind=kind, name=name) is not None:
        raise LocalTopologyError(f"owned {kind} cleanup did not remove {name}")
    return True


def _semantic(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("semantic_sha256", None)
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _write_json_atomic(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_semantic_document(path: Path, document: dict[str, Any]) -> None:
    document["semantic_sha256"] = _semantic(document)
    _write_json_atomic(path, document)


def _journal_rows(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    transaction_id: str,
    runtime_digest: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(plan):
        rows.append(
            {
                "volume_name": row.volume_name,
                "volume_labels": _owned_labels(
                    transaction_id=transaction_id,
                    runtime_digest=runtime_digest,
                    row=row,
                ),
                "volume_create_intent": False,
                "volume_created": False,
                "volume_remove_intent": False,
                "volume_removed": False,
                "stager_name": f"xir-multihop-stager-{transaction_id[:16]}-{index}",
                "stager_labels": {
                    LABEL_NAMESPACE: NAMESPACE,
                    LABEL_TRANSACTION: transaction_id,
                    LABEL_RUNTIME: runtime_digest,
                },
                "stager_create_intent": False,
                "stager_created": False,
                "stager_start_intent": False,
                "stager_started": False,
                "stager_remove_intent": False,
                "stager_removed": False,
            }
        )
    return rows


def _validate_journal(
    *,
    document: dict[str, Any],
    plan: Sequence[ValidatorVolumeBootstrap],
    runtime_root: Path,
) -> list[dict[str, Any]]:
    rows = document.get("resources")
    probes = document.get("probes")
    if (
        document.get("schema_version") != JOURNAL_SCHEMA
        or document.get("namespace") != NAMESPACE
        or document.get("semantic_sha256") != _semantic(document)
        or document.get("runtime_root_sha256") != _runtime_digest(runtime_root)
        or not isinstance(document.get("transaction_id"), str)
        or len(cast(str, document["transaction_id"])) < 32
        or not isinstance(rows, list)
        or len(rows) != 20
        or not isinstance(probes, list)
        or len(probes) != 41
    ):
        raise LocalTopologyError("validator volume transaction journal is invalid")
    expected = _journal_rows(
        plan=plan,
        transaction_id=cast(str, document["transaction_id"]),
        runtime_digest=_runtime_digest(runtime_root),
    )
    expected_probes = _probe_rows(
        plan=plan,
        transaction_id=cast(str, document["transaction_id"]),
        runtime_digest=_runtime_digest(runtime_root),
    )
    for actual, expected_row in zip(cast(list[dict[str, Any]], rows), expected, strict=True):
        for key in (
            "volume_name",
            "volume_labels",
            "stager_name",
            "stager_labels",
        ):
            if actual.get(key) != expected_row[key]:
                raise LocalTopologyError("validator volume transaction journal plan drift")
        if any(
            not isinstance(actual.get(key), bool)
            for key in (
                "volume_create_intent",
                "volume_created",
                "volume_remove_intent",
                "volume_removed",
                "stager_create_intent",
                "stager_created",
                "stager_start_intent",
                "stager_started",
                "stager_remove_intent",
                "stager_removed",
            )
        ):
            raise LocalTopologyError("validator volume transaction journal flags are invalid")
    for actual, expected_probe in zip(
        cast(list[dict[str, Any]], probes), expected_probes, strict=True
    ):
        for key in (
            "probe_name",
            "probe_role",
            "volume_name",
            "probe_labels",
        ):
            if actual.get(key) != expected_probe[key]:
                raise LocalTopologyError("validator volume probe journal plan drift")
        if any(
            not isinstance(actual.get(key), bool)
            for key in (
                "create_intent",
                "created",
                "start_intent",
                "started",
                "remove_intent",
                "removed",
            )
        ):
            raise LocalTopologyError("validator volume probe journal flags are invalid")
    return cast(list[dict[str, Any]], rows)


def validate_validator_volume_provenance(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runtime_root: Path,
    attestation_path: Path,
    journal_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate secret-free bootstrap provenance without touching Docker."""

    attestation, journal = validate_validator_volume_provenance_files(
        attestation_path=attestation_path,
        journal_path=journal_path,
    )
    journal_rows = _validate_journal(document=journal, plan=plan, runtime_root=runtime_root)
    attestation_rows = attestation.get("volumes")
    expected_names = {row.volume_name for row in plan}
    if (
        attestation.get("schema_version") != ATTESTATION_SCHEMA
        or attestation.get("namespace") != NAMESPACE
        or attestation.get("valid") is not True
        or attestation.get("semantic_sha256") != _semantic(attestation)
        or attestation.get("runtime_root_sha256") != _runtime_digest(runtime_root)
        or attestation.get("transaction_id") != journal.get("transaction_id")
        or attestation.get("image") != plan[0].image
        or int(attestation.get("validator_volume_count", -1)) != 20
        or not isinstance(attestation_rows, list)
        or len(attestation_rows) != 20
        or {row.get("volume_name") for row in cast(list[dict[str, Any]], attestation_rows)}
        != expected_names
        or journal.get("state") != "committed"
        or journal.get("attestation_sha256") != _sha256(attestation_path)
        or journal.get("attestation_semantic_sha256") != attestation.get("semantic_sha256")
        or {row.get("volume_name") for row in journal_rows} != expected_names
    ):
        raise LocalTopologyError("validator volume bootstrap provenance is invalid")
    attested = {
        item.get("volume_name"): item for item in cast(list[dict[str, Any]], attestation_rows)
    }
    for row in plan:
        journal_row = next(
            item for item in journal_rows if item.get("volume_name") == row.volume_name
        )
        labels = cast(dict[str, str], journal_row["volume_labels"])
        observed = cast(dict[str, Any], attested[row.volume_name].get("observed"))
        if attested[row.volume_name] != _attestation_row(row=row, labels=labels, observed=observed):
            raise LocalTopologyError("validator volume bootstrap plan binding is invalid")
    return attestation, journal


def validate_validator_volume_provenance_files(
    *, attestation_path: Path, journal_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Offline schema and cross-file admission for copied bootstrap provenance."""

    attestation = cast(dict[str, Any], json.loads(attestation_path.read_text(encoding="utf-8")))
    journal = cast(dict[str, Any], json.loads(journal_path.read_text(encoding="utf-8")))
    attestation_rows = attestation.get("volumes")
    journal_rows = journal.get("resources")
    probe_rows = journal.get("probes")
    transaction = journal.get("transaction_id")
    runtime_digest = journal.get("runtime_root_sha256")
    uid = attestation.get("runtime_uid")
    gid = attestation.get("runtime_gid")
    image_id = attestation.get("image_id")
    if (
        attestation.get("schema_version") != ATTESTATION_SCHEMA
        or journal.get("schema_version") != JOURNAL_SCHEMA
        or attestation.get("namespace") != NAMESPACE
        or journal.get("namespace") != NAMESPACE
        or attestation.get("valid") is not True
        or attestation.get("semantic_sha256") != _semantic(attestation)
        or journal.get("semantic_sha256") != _semantic(journal)
        or not isinstance(transaction, str)
        or len(transaction) < 32
        or not _is_sha256_text(runtime_digest)
        or attestation.get("transaction_id") != transaction
        or attestation.get("runtime_root_sha256") != runtime_digest
        or not isinstance(attestation.get("image"), str)
        or not attestation.get("image")
        or not isinstance(image_id, str)
        or not image_id
        or journal.get("image_id") != image_id
        or not isinstance(uid, int)
        or uid <= 0
        or not isinstance(gid, int)
        or int(attestation.get("validator_volume_count", -1)) != 20
        or int(journal.get("validator_volume_count", -1)) != 20
        or journal.get("state") != "committed"
        or not isinstance(attestation_rows, list)
        or len(attestation_rows) != 20
        or not isinstance(journal_rows, list)
        or len(journal_rows) != 20
        or not isinstance(probe_rows, list)
        or len(probe_rows) != 41
        or journal.get("attestation_sha256") != _sha256(attestation_path)
        or journal.get("attestation_semantic_sha256") != attestation.get("semantic_sha256")
    ):
        raise LocalTopologyError("validator volume bootstrap provenance is invalid")
    attested = {row.get("volume_name"): row for row in cast(list[dict[str, Any]], attestation_rows)}
    journalled = {row.get("volume_name"): row for row in cast(list[dict[str, Any]], journal_rows)}
    if len(attested) != 20 or set(attested) != set(journalled) or None in attested:
        raise LocalTopologyError("validator volume bootstrap inventory is invalid")
    expected_probe_roles = ["image-user"] + [
        role for _ in range(20) for role in ("volume-observe", "volume-write")
    ]
    if [
        row.get("probe_role") for row in cast(list[dict[str, Any]], probe_rows)
    ] != expected_probe_roles:
        raise LocalTopologyError("validator volume probe inventory is invalid")
    for probe in cast(list[dict[str, Any]], probe_rows):
        labels = probe.get("probe_labels")
        if (
            not isinstance(probe.get("probe_name"), str)
            or not isinstance(labels, dict)
            or labels.get(LABEL_NAMESPACE) != NAMESPACE
            or labels.get(LABEL_TRANSACTION) != transaction
            or labels.get(LABEL_RUNTIME) != runtime_digest
            or labels.get("org.xir.probe-role") != probe.get("probe_role")
            or any(
                probe.get(key) is not True
                for key in (
                    "create_intent",
                    "created",
                    "start_intent",
                    "started",
                    "remove_intent",
                    "removed",
                )
            )
        ):
            raise LocalTopologyError("validator volume probe provenance is invalid")
    expected_observed = {
        "root_uid": uid,
        "root_gid": gid,
        "root_mode": "700",
        "bootstrap_uid": uid,
        "bootstrap_gid": gid,
        "bootstrap_mode": "700",
        "genesis_uid": uid,
        "genesis_gid": gid,
        "genesis_mode": "644",
        "key_uid": uid,
        "key_gid": gid,
        "key_mode": "600",
        "runtime_uid": uid,
        "runtime_gid": gid,
    }
    for name in sorted(cast(set[str], set(attested))):
        attested_row = attested[name]
        journal_row = journalled[name]
        labels = journal_row.get("volume_labels")
        stager_labels = journal_row.get("stager_labels")
        observed = attested_row.get("observed")
        if (
            attested_row.get("labels") != labels
            or not isinstance(labels, dict)
            or labels.get(LABEL_NAMESPACE) != NAMESPACE
            or labels.get(LABEL_TRANSACTION) != transaction
            or labels.get(LABEL_RUNTIME) != runtime_digest
            or not labels.get("org.xir.network-id")
            or not labels.get("org.xir.validator-id")
            or not isinstance(stager_labels, dict)
            or stager_labels.get(LABEL_NAMESPACE) != NAMESPACE
            or stager_labels.get(LABEL_TRANSACTION) != transaction
            or stager_labels.get(LABEL_RUNTIME) != runtime_digest
            or not isinstance(journal_row.get("stager_name"), str)
            or any(
                journal_row.get(key) is not True
                for key in (
                    "volume_create_intent",
                    "volume_created",
                    "stager_create_intent",
                    "stager_created",
                    "stager_start_intent",
                    "stager_started",
                    "stager_remove_intent",
                    "stager_removed",
                )
            )
            or journal_row.get("volume_remove_intent") is not False
            or journal_row.get("volume_removed") is not False
            or not isinstance(observed, dict)
            or any(observed.get(key) != value for key, value in expected_observed.items())
            or observed.get("genesis_sha256") != attested_row.get("genesis_sha256")
            or observed.get("validator_key_sha256") != attested_row.get("validator_key_sha256")
        ):
            raise LocalTopologyError("validator volume bootstrap row is invalid")
    return attestation, journal


def _is_sha256_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def stage_validator_volumes(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runtime_root: Path,
    output_path: Path,
    journal_path: Path,
    failure_output_path: Path,
    runner: DockerRunner = subprocess.run,
    transaction_id: str | None = None,
) -> dict[str, Any]:
    if output_path.exists() or journal_path.exists() or failure_output_path.exists():
        raise LocalTopologyError("validator volume bootstrap output already exists")
    if len(plan) != 20 or len({row.volume_name for row in plan}) != 20:
        raise LocalTopologyError("refusing a non-exact validator volume plan")
    transaction = transaction_id or secrets.token_hex(24)
    if len(transaction) < 32:
        raise LocalTopologyError("validator volume transaction ID is too short")
    runtime_digest = _runtime_digest(runtime_root)
    journal: dict[str, Any] = {
        "schema_version": JOURNAL_SCHEMA,
        "namespace": NAMESPACE,
        "state": "prepared",
        "transaction_id": transaction,
        "runtime_root_sha256": runtime_digest,
        "image": plan[0].image,
        "validator_volume_count": len(plan),
        "resources": _journal_rows(
            plan=plan,
            transaction_id=transaction,
            runtime_digest=runtime_digest,
        ),
        "probes": _probe_rows(
            plan=plan,
            transaction_id=transaction,
            runtime_digest=runtime_digest,
        ),
    }
    _write_semantic_document(journal_path, journal)
    image_id = _image_identity(runner, image=plan[0].image)
    uid, gid = _image_user(
        runner,
        image=plan[0].image,
        expected_uid=plan[0].runtime_uid,
        expected_gid=plan[0].runtime_gid,
        journal=journal,
        journal_path=journal_path,
    )
    owned_volumes: list[tuple[ValidatorVolumeBootstrap, dict[str, str]]] = []
    owned_stager: tuple[str, dict[str, str]] | None = None
    observed_rows: list[dict[str, Any]] = []
    try:
        for index, row in enumerate(plan):
            journal_row = cast(list[dict[str, Any]], journal["resources"])[index]
            inspection = _docker(runner, ["volume", "inspect", row.volume_name], check=False)
            if inspection.returncode == 0:
                raise LocalTopologyError(f"validator volume already exists: {row.volume_name}")
            if not _is_proven_absent(inspection, kind="volume"):
                detail = (inspection.stderr or inspection.stdout).strip()
                raise LocalTopologyError(f"validator volume inspect failed closed: {detail}")
            labels = _owned_labels(
                transaction_id=transaction, runtime_digest=runtime_digest, row=row
            )
            create_args = ["volume", "create"]
            for key, value in labels.items():
                create_args.extend(["--label", f"{key}={value}"])
            create_args.append(row.volume_name)
            journal_row["volume_create_intent"] = True
            _write_semantic_document(journal_path, journal)
            _docker(runner, create_args)
            created = _inspect(runner, kind="volume", name=row.volume_name)
            if created is None:
                raise LocalTopologyError("new validator volume disappeared after create")
            _require_owned(created, kind="volume", expected_labels=labels)
            owned_volumes.append((row, labels))
            journal_row["volume_created"] = True
            _write_semantic_document(journal_path, journal)

            stager = cast(str, journal_row["stager_name"])
            stager_labels = cast(dict[str, str], journal_row["stager_labels"])
            create_container = ["create", "--name", stager]
            for key, value in stager_labels.items():
                create_container.extend(["--label", f"{key}={value}"])
            create_container.extend(
                [
                    "--user",
                    "0",
                    "--entrypoint",
                    "/bin/sh",
                    "--mount",
                    f"type=volume,source={row.volume_name},target=/stage",
                    row.image,
                    "-c",
                    "set -eu; mkdir -p /stage/bootstrap; "
                    "mv /stage/genesis.json /stage/bootstrap/genesis.json; "
                    "mv /stage/key /stage/bootstrap/key; "
                    f"chown -R {uid}:{gid} /stage; chmod 700 /stage /stage/bootstrap; "
                    "chmod 600 /stage/bootstrap/key; chmod 644 /stage/bootstrap/genesis.json",
                ]
            )
            journal_row["stager_create_intent"] = True
            _write_semantic_document(journal_path, journal)
            _docker(runner, create_container)
            stager_document = _inspect(runner, kind="container", name=stager)
            if stager_document is None:
                raise LocalTopologyError("validator stager disappeared after create")
            _require_owned(stager_document, kind="container", expected_labels=stager_labels)
            owned_stager = (stager, stager_labels)
            journal_row["stager_created"] = True
            _write_semantic_document(journal_path, journal)
            _docker(
                runner,
                ["cp", str(runtime_root / row.genesis_path), f"{stager}:/stage/genesis.json"],
            )
            _docker(
                runner,
                ["cp", str(runtime_root / row.private_key_path), f"{stager}:/stage/key"],
            )
            journal_row["stager_start_intent"] = True
            _write_semantic_document(journal_path, journal)
            stager_result = _docker(
                runner, ["start", "--attach", stager], check=False
            )
            journal_row["stager_started"] = True
            _write_semantic_document(journal_path, journal)
            stager_completed = _inspect(runner, kind="container", name=stager)
            if stager_completed is None:
                raise LocalTopologyError("validator stager disappeared after start")
            stager_state = _mapping(
                stager_completed.get("State"), label="stager container.State"
            )
            journal_row["stager_remove_intent"] = True
            _write_semantic_document(journal_path, journal)
            _remove_owned(
                runner,
                kind="container",
                name=stager,
                expected_labels=stager_labels,
            )
            owned_stager = None
            journal_row["stager_removed"] = True
            _write_semantic_document(journal_path, journal)
            if (
                stager_result.returncode != 0
                or stager_state.get("Running") is not False
                or stager_state.get("ExitCode") != 0
            ):
                raise LocalTopologyError(
                    "validator stager process failed: "
                    f"docker_returncode={stager_result.returncode!r}, "
                    f"running={stager_state.get('Running')!r}, "
                    f"exit_code={stager_state.get('ExitCode')!r}"
                )
            observed_rows.append(
                _attestation_row(
                    row=row,
                    labels=labels,
                    observed=_observe(
                        runner,
                        row=row,
                        uid=uid,
                        gid=gid,
                        journal=journal,
                        journal_path=journal_path,
                        observe_probe=cast(list[dict[str, Any]], journal["probes"])[1 + 2 * index],
                        write_probe=cast(list[dict[str, Any]], journal["probes"])[2 + 2 * index],
                    ),
                )
            )
    except BaseException as original:
        cleanup_errors: list[str] = []
        for probe in reversed(cast(list[dict[str, Any]], journal["probes"])):
            try:
                probe["remove_intent"] = True
                _write_semantic_document(journal_path, journal)
                _remove_owned(
                    runner,
                    kind="container",
                    name=cast(str, probe["probe_name"]),
                    expected_labels=cast(dict[str, str], probe["probe_labels"]),
                )
                probe["removed"] = True
                _write_semantic_document(journal_path, journal)
            except LocalTopologyError as exc:
                cleanup_errors.append(str(exc))
        if owned_stager is not None:
            try:
                matching = next(
                    row
                    for row in cast(list[dict[str, Any]], journal["resources"])
                    if row["stager_name"] == owned_stager[0]
                )
                matching["stager_remove_intent"] = True
                _write_semantic_document(journal_path, journal)
                _remove_owned(
                    runner,
                    kind="container",
                    name=owned_stager[0],
                    expected_labels=owned_stager[1],
                )
                matching["stager_removed"] = True
                _write_semantic_document(journal_path, journal)
            except LocalTopologyError as exc:
                cleanup_errors.append(str(exc))
        for row, labels in reversed(owned_volumes):
            try:
                matching = next(
                    item
                    for item in cast(list[dict[str, Any]], journal["resources"])
                    if item["volume_name"] == row.volume_name
                )
                matching["volume_remove_intent"] = True
                _write_semantic_document(journal_path, journal)
                _remove_owned(
                    runner,
                    kind="volume",
                    name=row.volume_name,
                    expected_labels=labels,
                )
                matching["volume_removed"] = True
                _write_semantic_document(journal_path, journal)
            except LocalTopologyError as exc:
                cleanup_errors.append(str(exc))
        journal["state"] = "recovery_required" if cleanup_errors else "rolled_back"
        journal["cleanup_errors"] = cleanup_errors
        _write_semantic_document(journal_path, journal)
        failure = {
            "schema_version": "xir-lab-native-multihop-validator-volume-bootstrap-failure-v1",
            "transaction_id": transaction,
            "cleanup_complete": not cleanup_errors,
            "cleanup_errors": cleanup_errors,
            "owned_volume_names": [row.volume_name for row, _ in owned_volumes],
        }
        _write_semantic_document(failure_output_path, failure)
        if cleanup_errors:
            raise LocalTopologyError(
                "validator volume bootstrap and owned-resource rollback failed: "
                + "; ".join(cleanup_errors)
            ) from original
        raise

    document: dict[str, Any] = {
        "schema_version": ATTESTATION_SCHEMA,
        "namespace": NAMESPACE,
        "valid": True,
        "transaction_id": transaction,
        "runtime_root_sha256": runtime_digest,
        "image": plan[0].image,
        "image_id": image_id,
        "runtime_uid": uid,
        "runtime_gid": gid,
        "validator_volume_count": len(plan),
        "volumes": observed_rows,
    }
    _write_semantic_document(output_path, document)
    journal["state"] = "committed"
    journal["runtime_uid"] = uid
    journal["runtime_gid"] = gid
    journal["image_id"] = image_id
    journal["attestation_sha256"] = _sha256(output_path)
    journal["attestation_semantic_sha256"] = document["semantic_sha256"]
    journal["cleanup_errors"] = []
    _write_semantic_document(journal_path, journal)
    return document


def verify_existing_validator_volumes(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runtime_root: Path,
    attestation_path: Path,
    journal_path: Path,
    runner: DockerRunner = subprocess.run,
) -> dict[str, Any]:
    document, journal = validate_validator_volume_provenance(
        plan=plan,
        runtime_root=runtime_root,
        attestation_path=attestation_path,
        journal_path=journal_path,
    )
    rows = document.get("volumes")
    if not isinstance(rows, list) or len(rows) != 20:
        raise LocalTopologyError("validator volume attestation rows are invalid")
    transaction = cast(str, journal["transaction_id"])
    live_image_id = _image_identity(runner, image=plan[0].image)
    if document.get("image") != plan[0].image or document.get("image_id") != live_image_id:
        raise LocalTopologyError("Besu image runtime identity differs from attestation")
    expected_names = {row.volume_name for row in plan}
    listed = _docker(
        runner,
        [
            "volume",
            "ls",
            "--filter",
            f"label={LABEL_NAMESPACE}={NAMESPACE}",
            "--filter",
            f"label={LABEL_RUNTIME}={_runtime_digest(runtime_root)}",
            "--format",
            "{{.Name}}",
        ],
    )
    if set(filter(None, listed.stdout.splitlines())) != expected_names:
        raise LocalTopologyError("validator volume inventory differs from exact 20")
    attested = {cast(dict[str, Any], row).get("volume_name"): row for row in rows}
    if set(attested) != expected_names:
        raise LocalTopologyError("validator volume attestation inventory is invalid")
    for row in plan:
        labels = _owned_labels(
            transaction_id=transaction,
            runtime_digest=_runtime_digest(runtime_root),
            row=row,
        )
        inspection = _inspect(runner, kind="volume", name=row.volume_name)
        if inspection is None:
            raise LocalTopologyError(f"validator volume is missing: {row.volume_name}")
        _require_owned(inspection, kind="volume", expected_labels=labels)
        attested_row = cast(dict[str, Any], attested[row.volume_name])
        attested_observed = _mapping(
            attested_row.get("observed"), label="validator volume attested observation"
        )
        observed = _observe_volume_mount(
            inspection,
            row=row,
            attested_observed=attested_observed,
            uid=int(document["runtime_uid"]),
            gid=int(document["runtime_gid"]),
            runner=runner,
        )
        expected_row = _attestation_row(row=row, labels=labels, observed=observed)
        if attested[row.volume_name] != expected_row:
            raise LocalTopologyError(f"validator volume attestation drift: {row.volume_name}")
    return document


def validator_volume_container_references(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runner: DockerRunner = subprocess.run,
) -> dict[str, list[str]]:
    """Return every running or stopped container using an exact planned volume."""

    referenced: dict[str, list[str]] = {}
    for row in plan:
        active = _docker(
            runner,
            [
                "container",
                "ls",
                "--all",
                "--filter",
                f"volume={row.volume_name}",
                "--format",
                "{{.Names}}",
            ],
        )
        names = sorted(filter(None, active.stdout.splitlines()))
        if names:
            referenced[row.volume_name] = names
    return referenced


def verify_validator_volumes_absent(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runner: DockerRunner = subprocess.run,
) -> None:
    remaining = [
        row.volume_name
        for row in plan
        if _inspect(runner, kind="volume", name=row.volume_name) is not None
    ]
    if remaining:
        raise LocalTopologyError(
            "validator volumes remain after audited cleanup: "
            + json.dumps(sorted(remaining))
        )


def remove_existing_validator_volumes(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runtime_root: Path,
    attestation_path: Path,
    journal_path: Path,
    recovery_output_path: Path,
    runner: DockerRunner = subprocess.run,
) -> None:
    journal = cast(dict[str, Any], json.loads(journal_path.read_text(encoding="utf-8")))
    _validate_journal(document=journal, plan=plan, runtime_root=runtime_root)
    if journal.get("state") == "committed":
        document, validated_journal = validate_validator_volume_provenance(
            plan=plan,
            runtime_root=runtime_root,
            attestation_path=attestation_path,
            journal_path=journal_path,
        )
        transaction = cast(str, validated_journal["transaction_id"])
        runtime_digest = _runtime_digest(runtime_root)
        # Compose validator containers do not carry the bootstrap transaction
        # labels used by probes and stagers.  Prove that no container (running
        # or stopped) references any exact planned volume before changing the
        # journal state or issuing the first removal.
        referenced = validator_volume_container_references(plan=plan, runner=runner)
        if referenced:
            raise LocalTopologyError(
                "validator containers remain during volume removal: "
                + json.dumps(referenced, sort_keys=True)
            )
        expected_names = {row.volume_name for row in plan}
        listed = _docker(
            runner,
            [
                "volume",
                "ls",
                "--filter",
                f"label={LABEL_NAMESPACE}={NAMESPACE}",
                "--filter",
                f"label={LABEL_RUNTIME}={runtime_digest}",
                "--format",
                "{{.Name}}",
            ],
        )
        if set(filter(None, listed.stdout.splitlines())) != expected_names:
            raise LocalTopologyError("validator volume removal inventory differs from exact 20")
        for row in plan:
            inspection = _inspect(runner, kind="volume", name=row.volume_name)
            if inspection is None:
                raise LocalTopologyError(f"validator volume is missing: {row.volume_name}")
            _require_owned(
                inspection,
                kind="volume",
                expected_labels=_owned_labels(
                    transaction_id=transaction,
                    runtime_digest=runtime_digest,
                    row=row,
                ),
            )
        if document.get("valid") is not True:
            raise LocalTopologyError("validator volume attestation is not valid")
        journal["state"] = "removing"
        _write_semantic_document(journal_path, journal)
    recover_validator_volume_transaction(
        plan=plan,
        runtime_root=runtime_root,
        journal_path=journal_path,
        recovery_output_path=recovery_output_path,
        runner=runner,
    )


def recover_validator_volume_transaction(
    *,
    plan: Sequence[ValidatorVolumeBootstrap],
    runtime_root: Path,
    journal_path: Path,
    recovery_output_path: Path,
    runner: DockerRunner = subprocess.run,
) -> dict[str, Any]:
    """Idempotently remove every exact transaction-owned stager and volume."""

    journal = cast(dict[str, Any], json.loads(journal_path.read_text(encoding="utf-8")))
    rows = _validate_journal(document=journal, plan=plan, runtime_root=runtime_root)
    if journal.get("state") == "committed":
        raise LocalTopologyError("committed volumes require full verification before removal")
    cleanup_errors: list[str] = []
    probes = cast(list[dict[str, Any]], journal["probes"])
    for probe in reversed(probes):
        try:
            if probe["remove_intent"] is not True:
                probe["remove_intent"] = True
                _write_semantic_document(journal_path, journal)
            _remove_owned(
                runner,
                kind="container",
                name=cast(str, probe["probe_name"]),
                expected_labels=cast(dict[str, str], probe["probe_labels"]),
            )
            if probe["removed"] is not True:
                probe["removed"] = True
                _write_semantic_document(journal_path, journal)
        except LocalTopologyError as exc:
            cleanup_errors.append(str(exc))
    for row in reversed(rows):
        try:
            if row["stager_remove_intent"] is not True:
                row["stager_remove_intent"] = True
                _write_semantic_document(journal_path, journal)
            _remove_owned(
                runner,
                kind="container",
                name=cast(str, row["stager_name"]),
                expected_labels=cast(dict[str, str], row["stager_labels"]),
            )
            if row["stager_removed"] is not True:
                row["stager_removed"] = True
                _write_semantic_document(journal_path, journal)
        except LocalTopologyError as exc:
            cleanup_errors.append(str(exc))
    for row in reversed(rows):
        try:
            if row["volume_remove_intent"] is not True:
                row["volume_remove_intent"] = True
                _write_semantic_document(journal_path, journal)
            _remove_owned(
                runner,
                kind="volume",
                name=cast(str, row["volume_name"]),
                expected_labels=cast(dict[str, str], row["volume_labels"]),
            )
            if row["volume_removed"] is not True:
                row["volume_removed"] = True
                _write_semantic_document(journal_path, journal)
        except LocalTopologyError as exc:
            cleanup_errors.append(str(exc))
    runtime_digest = _runtime_digest(runtime_root)
    listed = _docker(
        runner,
        [
            "volume",
            "ls",
            "--filter",
            f"label={LABEL_NAMESPACE}={NAMESPACE}",
            "--filter",
            f"label={LABEL_RUNTIME}={runtime_digest}",
            "--format",
            "{{.Name}}",
        ],
    )
    remaining = sorted(filter(None, listed.stdout.splitlines()))
    if remaining:
        cleanup_errors.append(f"transaction-owned volumes remain: {remaining}")
    listed_containers = _docker(
        runner,
        [
            "container",
            "ls",
            "--all",
            "--filter",
            f"label={LABEL_NAMESPACE}={NAMESPACE}",
            "--filter",
            f"label={LABEL_RUNTIME}={runtime_digest}",
            "--filter",
            f"label={LABEL_TRANSACTION}={journal['transaction_id']}",
            "--format",
            "{{.Names}}",
        ],
    )
    remaining_containers = sorted(filter(None, listed_containers.stdout.splitlines()))
    if remaining_containers:
        cleanup_errors.append(f"transaction-owned containers remain: {remaining_containers}")
    journal["state"] = "recovery_incomplete" if cleanup_errors else "recovered"
    journal["cleanup_errors"] = cleanup_errors
    _write_semantic_document(journal_path, journal)
    recovery: dict[str, Any] = {
        "schema_version": RECOVERY_SCHEMA,
        "namespace": NAMESPACE,
        "valid": not cleanup_errors,
        "transaction_id": journal["transaction_id"],
        "journal_sha256": _sha256(journal_path),
        "remaining_volume_names": remaining,
        "remaining_container_names": remaining_containers,
        "cleanup_errors": cleanup_errors,
    }
    _write_semantic_document(recovery_output_path, recovery)
    if cleanup_errors:
        raise LocalTopologyError(
            "validator volume transaction recovery failed: " + "; ".join(cleanup_errors)
        )
    return recovery
