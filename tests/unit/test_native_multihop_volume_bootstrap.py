from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import rfc8785
import yaml

import xir_lab.localnet.multihop_volume_bootstrap as volume_bootstrap
from xir_lab.localnet.compose import render_compose
from xir_lab.localnet.identities import initialize_local_identities
from xir_lab.localnet.multihop_topology import (
    load_multihop_identity_manifest,
    load_multihop_topology,
)
from xir_lab.localnet.multihop_volume_bootstrap import (
    LABEL_NAMESPACE,
    NAMESPACE,
    ValidatorVolumeBootstrap,
    _map_namespace_identifier,
    _probe_host_volume_write,
    _runtime_host_ownership,
    build_validator_volume_plan,
    recover_validator_volume_transaction,
    remove_existing_validator_volumes,
    stage_validator_volumes,
    verify_existing_validator_volumes,
)
from xir_lab.localnet.topology import LocalTopologyError

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / "configs/local/topology-multihop-remote-v1.json"


class FakeDocker:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.volumes: dict[str, dict[str, object]] = {}
        self.containers: dict[str, dict[str, object]] = {}
        self.files: dict[str, dict[str, str]] = {}
        self.fail_first_cp = False
        self.fail_volume_rm = False
        self.inspect_error: str | None = None
        self.create_race = False
        self.container_create_conflict = False
        self.image_uid = 1000
        self.image_gid = 1000
        self.probe_exit_code = 0
        self.logs_exit_code = 0
        self.image_user_attach_stdout: str | None = None
        self.image_user_logs_stdout: str | None = None
        self.stager_exit_code = 0
        self.image_id = "sha256:" + "1" * 64
        self.uid_map = "         0     165536      65536\n"
        self.gid_map = "         0     165536      65536\n"
        self.defer_namespace_sentinel = False
        self.pending_namespace_sentinel: tuple[Path, Path] | None = None
        self.volume_root = Path(tempfile.mkdtemp(prefix="xir-volume-test-"))
        self.journal_path: Path | None = None
        self.mutation_journals: list[tuple[list[str], dict[str, object]]] = []

    @staticmethod
    def _labels(arguments: list[str]) -> dict[str, str]:
        labels: dict[str, str] = {}
        for index, value in enumerate(arguments):
            if value == "--label":
                key, label_value = arguments[index + 1].split("=", 1)
                labels[key] = label_value
        return labels

    def __call__(
        self,
        command: list[str],
        *,
        check: bool,
        text: bool,
        capture_output: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert not check and text and capture_output
        self.commands.append(command)
        arguments = command[1:]
        if self.journal_path is not None and (
            arguments[:2] == ["volume", "create"]
            or (arguments and arguments[0] == "create")
            or arguments[:2] == ["start", "--attach"]
            or arguments[:2] in (["volume", "rm"], ["container", "rm"])
        ):
            assert self.journal_path.is_file()
            self.mutation_journals.append(
                (
                    arguments,
                    json.loads(self.journal_path.read_text(encoding="utf-8")),
                )
            )
        if arguments[:2] == ["volume", "inspect"]:
            name = arguments[2]
            if self.inspect_error:
                return subprocess.CompletedProcess(command, 1, "", self.inspect_error)
            if name not in self.volumes:
                return subprocess.CompletedProcess(command, 1, "", f"Error: No such volume: {name}")
            return subprocess.CompletedProcess(command, 0, json.dumps([self.volumes[name]]), "")
        if arguments[:2] == ["container", "inspect"]:
            name = arguments[2]
            if name not in self.containers:
                return subprocess.CompletedProcess(
                    command, 1, "", f"Error: No such container: {name}"
                )
            return subprocess.CompletedProcess(command, 0, json.dumps([self.containers[name]]), "")
        if arguments[:2] == ["container", "exec"]:
            name = arguments[4]
            probe_name = arguments[-1]
            volume = str(self.containers[name]["volume"])
            mountpoint = Path(str(self.volumes[volume]["Mountpoint"]))
            probe = mountpoint / probe_name
            payload = (
                "xir-uid-map-v1\n"
                + self.uid_map
                + "xir-gid-map-v1\n"
                + self.gid_map
                + "xir-map-complete-v1\n"
            )
            if self.defer_namespace_sentinel:
                temporary = probe.with_name(probe.name + ".tmp")
                temporary.write_text(payload, encoding="ascii")
                temporary.chmod(0o600)
                self.pending_namespace_sentinel = (temporary, probe)
            else:
                probe.write_text(payload, encoding="ascii")
                probe.chmod(0o600)
            return subprocess.CompletedProcess(command, 0, "", "")
        if arguments[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, json.dumps([{"Id": self.image_id}]), "")
        if arguments[:2] == ["volume", "create"]:
            name = arguments[-1]
            labels = self._labels(arguments)
            if self.create_race:
                labels = {LABEL_NAMESPACE: NAMESPACE, "racer": "true"}
                self.create_race = False
            self.volumes.setdefault(name, {"Name": name, "Labels": labels})
            mountpoint = self.volume_root / name
            mountpoint.mkdir(mode=0o700, exist_ok=True)
            self.volumes[name]["Mountpoint"] = str(mountpoint)
            self.files.setdefault(name, {})
            return subprocess.CompletedProcess(command, 0, name + "\n", "")
        if arguments and arguments[0] == "create":
            name = arguments[arguments.index("--name") + 1]
            if self.container_create_conflict:
                self.container_create_conflict = False
                self.containers[name] = {
                    "Name": name,
                    "Config": {"Labels": {"owner": "foreign"}},
                }
                return subprocess.CompletedProcess(
                    command, 1, "", "Conflict. The container name is already in use"
                )
            volume = None
            if "--mount" in arguments:
                mount = arguments[arguments.index("--mount") + 1]
                volume = mount.split("source=", 1)[1].split(",", 1)[0]
            self.containers[name] = {
                "Name": name,
                "Config": {"Labels": self._labels(arguments)},
                "State": {"Running": False, "ExitCode": 0},
                "Logs": "",
                "volume": volume,
            }
            return subprocess.CompletedProcess(command, 0, "container\n", "")
        if arguments and arguments[0] == "cp":
            if self.fail_first_cp:
                self.fail_first_cp = False
                return subprocess.CompletedProcess(command, 1, "", "injected docker cp failure")
            source, target = Path(arguments[1]), arguments[2]
            container, destination = target.split(":", 1)
            volume = str(self.containers[container]["volume"])
            self.files[volume][Path(destination).name] = hashlib.sha256(
                source.read_bytes()
            ).hexdigest()
            mountpoint = Path(str(self.volumes[volume]["Mountpoint"]))
            (mountpoint / Path(destination).name).write_bytes(source.read_bytes())
            return subprocess.CompletedProcess(command, 0, "", "")
        if arguments[:2] == ["start", "--attach"]:
            container = arguments[2]
            document = self.containers[container]
            labels = document["Config"]["Labels"]
            assert isinstance(labels, dict)
            role = labels.get("org.xir.probe-role")
            document["State"] = {
                "Running": False,
                "ExitCode": self.probe_exit_code if role is not None else self.stager_exit_code,
            }
            if role == "image-user":
                document["Logs"] = f"{self.image_uid}:{self.image_gid}\n"
                self.image_user_attach_stdout = ""
                return subprocess.CompletedProcess(
                    command,
                    self.probe_exit_code,
                    "",
                    "injected probe failure" if self.probe_exit_code else "",
                )
            volume = document["volume"]
            assert isinstance(volume, str)
            files = self.files[volume]
            if role == "volume-observe":
                output = "\n".join(
                    [
                        files["genesis"],
                        files["key"],
                        "1000",
                        "1000",
                        "700",
                        "1000",
                        "1000",
                        "700",
                        "1000",
                        "1000",
                        "644",
                        "1000",
                        "1000",
                        "600",
                    ]
                )
                document["Logs"] = output + "\n"
                return subprocess.CompletedProcess(command, 0, "", "")
            if role == "volume-write":
                return subprocess.CompletedProcess(
                    command,
                    self.probe_exit_code,
                    "",
                    "injected probe failure" if self.probe_exit_code else "",
                )
            files["genesis"] = files.pop("genesis.json")
            mountpoint = Path(str(self.volumes[volume]["Mountpoint"]))
            bootstrap = mountpoint / "bootstrap"
            bootstrap.mkdir(mode=0o700)
            (mountpoint / "genesis.json").replace(bootstrap / "genesis.json")
            (mountpoint / "key").replace(bootstrap / "key")
            os.chmod(mountpoint, 0o700)
            os.chmod(bootstrap, 0o700)
            os.chmod(bootstrap / "genesis.json", 0o644)
            os.chmod(bootstrap / "key", 0o600)
            return subprocess.CompletedProcess(
                command,
                self.stager_exit_code,
                "",
                "injected stager failure" if self.stager_exit_code else "",
            )
        if arguments and arguments[0] == "logs":
            document = self.containers[arguments[1]]
            labels = document["Config"]["Labels"]
            if labels.get("org.xir.probe-role") == "image-user":
                self.image_user_logs_stdout = str(document["Logs"])
            return subprocess.CompletedProcess(
                command,
                self.logs_exit_code,
                str(document["Logs"]),
                "injected logs failure" if self.logs_exit_code else "",
            )
        if arguments[:2] == ["container", "rm"]:
            name = arguments[-1]
            self.containers.pop(name, None)
            return subprocess.CompletedProcess(command, 0, "", "")
        if arguments and arguments[0] == "rm":
            name = arguments[-1]
            self.containers.pop(name, None)
            return subprocess.CompletedProcess(command, 0, "", "")
        if arguments[:2] == ["volume", "rm"]:
            name = arguments[2]
            if self.fail_volume_rm:
                return subprocess.CompletedProcess(
                    command, 1, "", "injected volume cleanup failure"
                )
            self.volumes.pop(name, None)
            self.files.pop(name, None)
            shutil.rmtree(self.volume_root / name, ignore_errors=True)
            return subprocess.CompletedProcess(command, 0, "", "")
        if arguments[:2] == ["volume", "ls"]:
            names = "\n".join(sorted(self.volumes))
            return subprocess.CompletedProcess(command, 0, names + ("\n" if names else ""), "")
        if arguments[:2] == ["container", "ls"]:
            selected = self.containers
            filters = [
                arguments[index + 1]
                for index, value in enumerate(arguments)
                if value == "--filter"
            ]
            volume_filters = [value.split("=", 1)[1] for value in filters if value.startswith("volume=")]
            if volume_filters:
                selected = {
                    name: document
                    for name, document in selected.items()
                    if document.get("volume") in volume_filters
                }
            names = "\n".join(sorted(selected))
            return subprocess.CompletedProcess(command, 0, names + ("\n" if names else ""), "")
        raise AssertionError(f"unhandled fake Docker command: {command}")

    def publish_namespace_sentinel(self) -> None:
        assert self.pending_namespace_sentinel is not None
        temporary, probe = self.pending_namespace_sentinel
        os.replace(temporary, probe)
        self.pending_namespace_sentinel = None


def _runtime_container_document(
    docker: FakeDocker,
    *,
    row: ValidatorVolumeBootstrap,
    container_id: str,
) -> dict[str, object]:
    return {
        "Id": container_id,
        "Name": "validator-a-v1",
        "Config": {
            "Image": row.image,
            "Labels": {
                "com.docker.compose.project": row.compose_project,
                "com.docker.compose.service": row.service_name,
                "org.xir.environment": "controlled-local-qbft",
                "org.xir.network-id": row.network_id,
                "org.xir.validator-id": row.validator_id,
            },
            "User": "1000:1000",
        },
        "Image": docker.image_id,
        "Mounts": [
            {
                "Type": "volume",
                "Name": row.volume_name,
                "Destination": "/data",
                "RW": True,
            }
        ],
        "State": {
            "Running": True,
            "Pid": 4242,
            "StartedAt": "2026-08-13T07:37:34.000000000Z",
        },
        "RestartCount": 0,
        "volume": row.volume_name,
    }


def _plan(
    tmp_path: Path,
) -> tuple[Path, tuple[ValidatorVolumeBootstrap, ...]]:
    topology = load_multihop_topology(TOPOLOGY)
    runtime = tmp_path / "runtime"
    manifest_path = initialize_local_identities(
        topology,
        runtime_root=runtime,
        repository_root=ROOT,
        created_at=datetime(2026, 8, 12, tzinfo=UTC),
    )
    manifest = load_multihop_identity_manifest(manifest_path, topology=topology)
    compose, _ = render_compose(topology, manifest)
    compose_path = runtime / "compose.yaml"
    compose_path.write_bytes(compose)
    return runtime, build_validator_volume_plan(
        runtime_root=runtime,
        topology_path=TOPOLOGY,
        identity_manifest_path=manifest_path,
        compose_path=compose_path,
    )


def _stage(
    tmp_path: Path,
) -> tuple[Path, tuple[ValidatorVolumeBootstrap, ...], FakeDocker, Path]:
    runtime, plan = _plan(tmp_path)
    docker = FakeDocker()
    attestation = runtime / "provenance/validator-volume-bootstrap.json"
    journal = runtime / "provenance/validator-volume-transaction.json"
    docker.journal_path = journal
    stage_validator_volumes(
        plan=plan,
        runtime_root=runtime,
        output_path=attestation,
        journal_path=journal,
        failure_output_path=runtime / "provenance/bootstrap-failure.json",
        runner=docker,
        transaction_id="a" * 48,
    )
    return runtime, plan, docker, attestation


def test_exact_twenty_volume_transaction_is_verified_and_resumable(
    tmp_path: Path,
) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path)
    document = verify_existing_validator_volumes(
        plan=plan,
        runtime_root=runtime,
        attestation_path=attestation,
        journal_path=attestation.with_name("validator-volume-transaction.json"),
        runner=docker,
    )
    assert document["validator_volume_count"] == 20
    assert document["runtime_uid"] == 1000
    assert document["runtime_gid"] == 1000
    assert {(row.runtime_uid, row.runtime_gid) for row in plan} == {(1000, 1000)}
    image_probe_create = next(
        command
        for command in docker.commands
        if len(command) > 2
        and command[1] == "create"
        and command[command.index("--name") + 1].endswith("-image-user")
    )
    assert image_probe_create[image_probe_create.index("--user") + 1] == "1000:1000"
    assert any(command[1] == "logs" for command in docker.commands)
    assert docker.image_user_attach_stdout == ""
    assert docker.image_user_logs_stdout == "1000:1000\n"
    write_probe_creates = [
        command
        for command in docker.commands
        if len(command) > 2
        and command[1] == "create"
        and "-write-" in command[command.index("--name") + 1]
    ]
    assert len(write_probe_creates) == 20
    assert {
        command[command.index("--user") + 1] for command in write_probe_creates
    } == {"1000:1000"}
    assert all(row["observed"]["root_mode"] == "700" for row in document["volumes"])
    assert not any(command[1] == "run" for command in docker.commands)
    assert (
        len(
            json.loads(attestation.with_name("validator-volume-transaction.json").read_text())[
                "probes"
            ]
        )
        == 41
    )


def test_runtime_host_ownership_uses_the_live_container_namespace_map(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _runtime, plan = _plan(tmp_path)
    row = plan[0]
    docker = FakeDocker()
    docker.containers["validator-a-v1"] = {
        "Id": "a" * 64,
        "Name": "validator-a-v1",
        "Config": {
            "Image": row.image,
            "Labels": {
                "com.docker.compose.project": row.compose_project,
                "com.docker.compose.service": row.service_name,
                "org.xir.environment": "controlled-local-qbft",
                "org.xir.network-id": row.network_id,
                "org.xir.validator-id": row.validator_id,
            },
            "User": "1000:1000",
        },
        "Image": docker.image_id,
        "Mounts": [
            {
                "Type": "volume",
                "Name": row.volume_name,
                "Destination": "/data",
                "RW": True,
            }
        ],
        "State": {
            "Running": True,
            "Pid": 4242,
            "StartedAt": "2026-08-13T07:37:34.000000000Z",
        },
        "RestartCount": 0,
        "volume": row.volume_name,
    }
    proc = tmp_path / "proc/4242"
    proc.mkdir(parents=True)
    # Field 22 (index 19 after the comm/state prefix) is process starttime.
    (proc / "stat").write_text(
        "4242 (besu) S " + " ".join(["0"] * 18 + ["987654"] + ["0"] * 5) + "\n",
        encoding="ascii",
    )
    (proc / "uid_map").write_text("         0     165536      65536\n", encoding="ascii")
    (proc / "gid_map").write_text("         0     165536      65536\n", encoding="ascii")
    monkeypatch.setattr(
        "xir_lab.localnet.multihop_volume_bootstrap._pidfd_open",
        lambda _pid: os.open("/dev/null", os.O_RDONLY),
    )
    assert _runtime_host_ownership(
        docker,
        row=row,
        uid=1000,
        gid=1000,
        proc_root=tmp_path / "proc",
    ) == (166536, 166536)
    labels = docker.containers["validator-a-v1"]["Config"]["Labels"]
    assert isinstance(labels, dict)
    labels["com.docker.compose.service"] = "foreign-service"
    with pytest.raises(LocalTopologyError, match="container identity is invalid"):
        _runtime_host_ownership(
            docker,
            row=row,
            uid=1000,
            gid=1000,
            proc_root=tmp_path / "proc",
        )


def test_runtime_host_ownership_uses_container_exec_for_external_daemon_pid_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _runtime, plan = _plan(tmp_path)
    row = plan[0]
    docker = FakeDocker()
    volume_root = tmp_path / "external-volume"
    volume_root.mkdir()
    docker.volumes[row.volume_name] = {
        "Name": row.volume_name,
        "Mountpoint": str(volume_root),
    }
    docker.containers["validator-a-v1"] = {
        "Id": "b" * 64,
        "Name": "validator-a-v1",
        "Config": {
            "Image": row.image,
            "Labels": {
                "com.docker.compose.project": row.compose_project,
                "com.docker.compose.service": row.service_name,
                "org.xir.environment": "controlled-local-qbft",
                "org.xir.network-id": row.network_id,
                "org.xir.validator-id": row.validator_id,
            },
            "User": "1000:1000",
        },
        "Image": docker.image_id,
        "Mounts": [
            {
                "Type": "volume",
                "Name": row.volume_name,
                "Destination": "/data",
                "RW": True,
            }
        ],
        "State": {
            "Running": True,
            "Pid": 4242,
            "StartedAt": "2026-08-13T07:37:34.000000000Z",
        },
        "RestartCount": 0,
        "volume": row.volume_name,
    }

    def external_daemon_pid(_pid: int) -> int:
        raise OSError(errno.ESRCH, "external daemon PID namespace")

    monkeypatch.setattr(
        "xir_lab.localnet.multihop_volume_bootstrap._pidfd_open",
        external_daemon_pid,
    )
    assert _runtime_host_ownership(
        docker,
        row=row,
        uid=1000,
        gid=1000,
        proc_root=tmp_path / "absent-proc",
        volume_root=volume_root,
    ) == (166536, 166536)
    exec_commands = [
        command
        for command in docker.commands
        if command[1:3] == ["container", "exec"]
    ]
    assert len(exec_commands) == 1
    assert exec_commands[0][exec_commands[0].index("--user") + 1] == "1000:1000"
    assert exec_commands[0][-1].startswith(".xir-namespace-map-")
    assert not any(volume_root.iterdir())


def test_external_daemon_namespace_proof_waits_for_async_sentinel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _runtime, plan = _plan(tmp_path)
    row = plan[0]
    docker = FakeDocker()
    docker.defer_namespace_sentinel = True
    volume_root = tmp_path / "external-volume"
    volume_root.mkdir()
    docker.volumes[row.volume_name] = {
        "Name": row.volume_name,
        "Mountpoint": str(volume_root),
    }
    docker.containers["validator-a-v1"] = _runtime_container_document(
        docker,
        row=row,
        container_id="d" * 64,
    )

    def external_daemon_pid(_pid: int) -> int:
        raise OSError(errno.ESRCH, "external daemon PID namespace")

    sleep_calls: list[float] = []

    def publish_after_first_miss(seconds: float) -> None:
        sleep_calls.append(seconds)
        assert not any(path.name.endswith(".tmp") is False for path in volume_root.iterdir())
        docker.publish_namespace_sentinel()

    monkeypatch.setattr(
        "xir_lab.localnet.multihop_volume_bootstrap._pidfd_open",
        external_daemon_pid,
    )
    monkeypatch.setattr(volume_bootstrap.time, "sleep", publish_after_first_miss)
    assert _runtime_host_ownership(
        docker,
        row=row,
        uid=1000,
        gid=1000,
        proc_root=tmp_path / "absent-proc",
        volume_root=volume_root,
    ) == (166536, 166536)
    assert sleep_calls == [0.05]
    assert docker.pending_namespace_sentinel is None
    assert not any(volume_root.iterdir())


def test_external_daemon_namespace_proof_timeout_cleans_temporary_sentinel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = FakeDocker()
    docker.defer_namespace_sentinel = True
    volume_root = tmp_path / "external-volume"
    volume_root.mkdir()
    volume_name = "validator-a-v1-data"
    docker.volumes[volume_name] = {
        "Name": volume_name,
        "Mountpoint": str(volume_root),
    }
    docker.containers["validator-a-v1"] = {"volume": volume_name}
    monotonic = iter((0.0, 0.2))
    monkeypatch.setattr(volume_bootstrap.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(volume_bootstrap.time, "sleep", lambda _seconds: None)

    with pytest.raises(LocalTopologyError, match="sentinel timed out"):
        volume_bootstrap._external_daemon_namespace_maps(
            docker,
            name="validator-a-v1",
            volume_root=volume_root,
            uid=1000,
            gid=1000,
            timeout_seconds=0.1,
        )
    assert not any(volume_root.iterdir())


def test_external_daemon_namespace_proof_rejects_container_restart_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _runtime, plan = _plan(tmp_path)
    row = plan[0]
    docker = FakeDocker()
    volume_root = tmp_path / "external-volume"
    volume_root.mkdir()
    docker.volumes[row.volume_name] = {
        "Name": row.volume_name,
        "Mountpoint": str(volume_root),
    }
    document: dict[str, object] = {
        "Id": "c" * 64,
        "Name": "validator-a-v1",
        "Config": {
            "Image": row.image,
            "Labels": {
                "com.docker.compose.project": row.compose_project,
                "com.docker.compose.service": row.service_name,
                "org.xir.environment": "controlled-local-qbft",
                "org.xir.network-id": row.network_id,
                "org.xir.validator-id": row.validator_id,
            },
            "User": "1000:1000",
        },
        "Image": docker.image_id,
        "Mounts": [
            {
                "Type": "volume",
                "Name": row.volume_name,
                "Destination": "/data",
                "RW": True,
            }
        ],
        "State": {
            "Running": True,
            "Pid": 4242,
            "StartedAt": "2026-08-13T07:37:34.000000000Z",
        },
        "RestartCount": 0,
        "volume": row.volume_name,
    }
    docker.containers["validator-a-v1"] = document

    def external_daemon_pid(_pid: int) -> int:
        raise OSError(errno.ESRCH, "external daemon PID namespace")

    monkeypatch.setattr(
        "xir_lab.localnet.multihop_volume_bootstrap._pidfd_open",
        external_daemon_pid,
    )

    def restart_during_proof(
        command: list[str], *, check: bool, text: bool, capture_output: bool
    ) -> subprocess.CompletedProcess[str]:
        result = docker(
            command,
            check=check,
            text=text,
            capture_output=capture_output,
        )
        if command[1:3] == ["container", "exec"]:
            state = document["State"]
            assert isinstance(state, dict)
            state["StartedAt"] = "2026-08-13T07:38:00.000000000Z"
            document["RestartCount"] = 1
        return result

    with pytest.raises(LocalTopologyError, match="changed during namespace proof"):
        _runtime_host_ownership(
            restart_during_proof,
            row=row,
            uid=1000,
            gid=1000,
            proc_root=tmp_path / "absent-proc",
            volume_root=volume_root,
        )
    assert not any(volume_root.iterdir())


def test_namespace_mapping_rejects_missing_or_ambiguous_runtime_ids() -> None:
    assert (
        _map_namespace_identifier("0 165536 65536\n", 1000, label="uid")
        == 166536
    )
    with pytest.raises(LocalTopologyError, match="does not uniquely cover"):
        _map_namespace_identifier("0 165536 1000\n", 1000, label="uid")
    with pytest.raises(LocalTopologyError, match="does not uniquely cover"):
        _map_namespace_identifier(
            "0 165536 65536\n0 231072 65536\n", 1000, label="uid"
        )


def test_host_write_probe_uses_the_mapped_owner_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state: dict[str, object] = {"euid": 0, "egid": 0, "groups": [0, 27]}
    changes: list[tuple[str, object]] = []

    monkeypatch.setattr(os, "geteuid", lambda: state["euid"])
    monkeypatch.setattr(os, "getegid", lambda: state["egid"])
    monkeypatch.setattr(os, "getgroups", lambda: list(state["groups"]))

    def set_euid(value: int) -> None:
        changes.append(("uid", value))
        state["euid"] = value

    def set_egid(value: int) -> None:
        changes.append(("gid", value))
        state["egid"] = value

    def set_groups(values: list[int]) -> None:
        changes.append(("groups", tuple(values)))
        state["groups"] = list(values)

    monkeypatch.setattr(os, "seteuid", set_euid)
    monkeypatch.setattr(os, "setegid", set_egid)
    monkeypatch.setattr(os, "setgroups", set_groups)
    _probe_host_volume_write(
        tmp_path,
        runtime_uid=1000,
        host_uid=166536,
        host_gid=166536,
    )
    assert changes[:3] == [
        ("groups", (166536,)),
        ("gid", 166536),
        ("uid", 166536),
    ]
    assert changes[-3:] == [
        ("uid", 0),
        ("groups", (0, 27)),
        ("gid", 0),
    ]
    assert state == {"euid": 0, "egid": 0, "groups": [0, 27]}
    assert not (tmp_path / ".xir-write-probe").exists()


def test_volume_plan_rejects_compose_runtime_user_drift(tmp_path: Path) -> None:
    runtime, _plan_rows = _plan(tmp_path)
    compose_path = runtime / "compose.yaml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    compose["services"]["local-chain-a-v1"]["user"] = "1001:1001"
    compose_path.write_text(yaml.safe_dump(compose, sort_keys=True), encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="service local-chain-a-v1 is incomplete"):
        build_validator_volume_plan(
            runtime_root=runtime,
            topology_path=TOPOLOGY,
            identity_manifest_path=runtime / "identity-manifest.json",
            compose_path=compose_path,
        )


def test_owned_volumes_are_removed_only_after_full_reverification(tmp_path: Path) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path)
    remove_existing_validator_volumes(
        plan=plan,
        runtime_root=runtime,
        attestation_path=attestation,
        journal_path=attestation.with_name("validator-volume-transaction.json"),
        recovery_output_path=attestation.with_name("validator-volume-recovery.json"),
        runner=docker,
    )
    assert docker.volumes == {}


def test_removal_allows_runtime_data_but_rejects_active_owned_containers(
    tmp_path: Path,
) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path)
    first = docker.volume_root / plan[0].volume_name
    (first / "database").mkdir()
    (first / "database/MANIFEST-000005").write_text("runtime data", encoding="utf-8")
    remove_existing_validator_volumes(
        plan=plan,
        runtime_root=runtime,
        attestation_path=attestation,
        journal_path=attestation.with_name("validator-volume-transaction.json"),
        recovery_output_path=attestation.with_name("validator-volume-recovery.json"),
        runner=docker,
    )
    assert docker.volumes == {}

    runtime, plan, docker, attestation = _stage(tmp_path / "active")
    docker.containers["active-validator"] = {
        "Name": "active-validator",
        "Config": {
            "Labels": {
                "com.docker.compose.project": plan[0].compose_project,
                "com.docker.compose.service": plan[0].service_name,
                "org.xir.environment": "controlled-local-qbft",
                "org.xir.network-id": plan[0].network_id,
                "org.xir.validator-id": plan[0].validator_id,
            }
        },
        "State": {"Running": True, "ExitCode": 0},
        "Logs": "",
        "volume": plan[0].volume_name,
    }
    with pytest.raises(LocalTopologyError, match="validator containers remain"):
        remove_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            attestation_path=attestation,
            journal_path=attestation.with_name("validator-volume-transaction.json"),
            recovery_output_path=attestation.with_name("validator-volume-recovery.json"),
            runner=docker,
        )
    assert set(docker.volumes) == {row.volume_name for row in plan}
    assert json.loads(
        attestation.with_name("validator-volume-transaction.json").read_text(
            encoding="utf-8"
        )
    )["state"] == "committed"
    assert not any(command[1:3] == ["volume", "rm"] for command in docker.commands)


def test_inspect_daemon_error_and_create_race_fail_closed(tmp_path: Path) -> None:
    runtime, plan = _plan(tmp_path)
    for daemon_error, race, match in (
        ("permission denied", False, "inspect failed closed"),
        (None, True, "ownership labels mismatch"),
    ):
        docker = FakeDocker()
        docker.inspect_error = daemon_error
        docker.create_race = race
        with pytest.raises(LocalTopologyError, match=match):
            stage_validator_volumes(
                plan=plan,
                runtime_root=runtime,
                output_path=runtime / f"attestation-{match}.json",
                journal_path=runtime / f"journal-{match}.json",
                failure_output_path=runtime / f"failure-{match}.json",
                runner=docker,
                transaction_id="b" * 48,
            )


def test_copy_failure_rolls_back_only_transaction_owned_resources(
    tmp_path: Path,
) -> None:
    runtime, plan = _plan(tmp_path)
    docker = FakeDocker()
    docker.fail_first_cp = True
    failure = runtime / "provenance/bootstrap-failure.json"
    with pytest.raises(LocalTopologyError, match="injected docker cp failure"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=failure,
            runner=docker,
            transaction_id="c" * 48,
        )
    assert docker.volumes == {}
    assert docker.containers == {}
    assert json.loads(failure.read_text(encoding="utf-8"))["cleanup_complete"] is True


def test_resume_rejects_missing_wrong_label_and_tampered_content(tmp_path: Path) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path)
    first = plan[0]
    original_volume = docker.volumes.pop(first.volume_name)
    with pytest.raises(LocalTopologyError, match="inventory differs"):
        verify_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            attestation_path=attestation,
            journal_path=attestation.with_name("validator-volume-transaction.json"),
            runner=docker,
        )
    docker.volumes[first.volume_name] = original_volume
    labels = docker.volumes[first.volume_name]["Labels"]
    assert isinstance(labels, dict)
    original_transaction = labels["org.xir.bootstrap-transaction"]
    labels["org.xir.bootstrap-transaction"] = "wrong"
    with pytest.raises(LocalTopologyError, match="labels mismatch"):
        verify_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            attestation_path=attestation,
            journal_path=attestation.with_name("validator-volume-transaction.json"),
            runner=docker,
        )
    labels["org.xir.bootstrap-transaction"] = original_transaction
    docker.files[first.volume_name]["genesis"] = "0" * 64
    mountpoint = Path(str(docker.volumes[first.volume_name]["Mountpoint"]))
    (mountpoint / "bootstrap/genesis.json").write_bytes(b"tampered")
    with pytest.raises(LocalTopologyError, match="metadata mismatch"):
        verify_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            attestation_path=attestation,
            journal_path=attestation.with_name("validator-volume-transaction.json"),
            runner=docker,
        )


def test_live_validator_mapping_drift_rejects_before_writer_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path)
    row = plan[0]
    docker.containers["current-validator"] = {
        "Name": "current-validator",
        "Config": {"Labels": {}},
        "State": {"Running": True},
        "volume": row.volume_name,
    }
    monkeypatch.setattr(
        volume_bootstrap,
        "_runtime_host_ownership",
        lambda *_args, **_kwargs: (166537, 166537),
    )
    with pytest.raises(
        LocalTopologyError,
        match="runtime namespace ownership mismatch",
    ):
        verify_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            attestation_path=attestation,
            journal_path=attestation.with_name("validator-volume-transaction.json"),
            runner=docker,
        )


def test_stager_name_conflict_is_never_claimed_or_deleted(tmp_path: Path) -> None:
    runtime, plan = _plan(tmp_path)
    docker = FakeDocker()
    docker.container_create_conflict = True
    with pytest.raises(LocalTopologyError, match="container name is already in use"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=runtime / "provenance/bootstrap-failure.json",
            runner=docker,
            transaction_id="d" * 48,
        )
    assert len(docker.containers) == 1
    assert next(iter(docker.containers.values()))["Config"] == {"Labels": {"owner": "foreign"}}
    assert not any(command[1:3] == ["container", "rm"] for command in docker.commands)


def test_rollback_failure_is_durable_and_never_reported_complete(
    tmp_path: Path,
) -> None:
    runtime, plan = _plan(tmp_path)
    docker = FakeDocker()
    docker.fail_first_cp = True
    docker.fail_volume_rm = True
    failure = runtime / "provenance/bootstrap-failure.json"
    with pytest.raises(LocalTopologyError, match="owned-resource rollback failed"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=failure,
            runner=docker,
            transaction_id="e" * 48,
        )
    document = json.loads(failure.read_text(encoding="utf-8"))
    assert document["cleanup_complete"] is False
    assert document["cleanup_errors"]
    assert len(docker.volumes) == 1


def test_root_image_and_runtime_identity_drift_fail_closed(tmp_path: Path) -> None:
    runtime, plan = _plan(tmp_path)
    root_docker = FakeDocker()
    root_docker.image_uid = 0
    with pytest.raises(LocalTopologyError, match="must not run as root"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=runtime / "provenance/bootstrap-failure.json",
            runner=root_docker,
            transaction_id="f" * 48,
        )

    runtime, plan = _plan(tmp_path / "failed-process")
    failed_docker = FakeDocker()
    failed_docker.probe_exit_code = 127
    with pytest.raises(LocalTopologyError, match="validator probe process failed"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=runtime / "provenance/bootstrap-failure.json",
            runner=failed_docker,
            transaction_id="1" * 48,
        )
    assert failed_docker.containers == {}

    runtime, plan = _plan(tmp_path / "failed-logs")
    failed_logs = FakeDocker()
    failed_logs.logs_exit_code = 1
    with pytest.raises(LocalTopologyError, match="validator probe process failed"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=runtime / "provenance/bootstrap-failure.json",
            runner=failed_logs,
            transaction_id="2" * 48,
        )
    assert failed_logs.containers == {}

    runtime, plan = _plan(tmp_path / "failed-stager")
    failed_stager = FakeDocker()
    failed_stager.stager_exit_code = 2
    with pytest.raises(LocalTopologyError, match="validator stager process failed"):
        stage_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            output_path=runtime / "provenance/attestation.json",
            journal_path=runtime / "provenance/journal.json",
            failure_output_path=runtime / "provenance/bootstrap-failure.json",
            runner=failed_stager,
            transaction_id="2" * 48,
        )
    assert failed_stager.containers == {}
    assert failed_stager.volumes == {}

    runtime, plan, docker, attestation = _stage(tmp_path / "drift")
    docker.image_uid = 1001
    docker.image_id = "sha256:" + "2" * 64
    with pytest.raises(LocalTopologyError, match="runtime identity differs"):
        verify_existing_validator_volumes(
            plan=plan,
            runtime_root=runtime,
            attestation_path=attestation,
            journal_path=attestation.with_name("validator-volume-transaction.json"),
            runner=docker,
        )


def test_every_docker_create_has_a_durable_prior_intent(tmp_path: Path) -> None:
    _runtime, _plan_rows, docker, _attestation = _stage(tmp_path)
    volume_creates = [
        document
        for arguments, document in docker.mutation_journals
        if arguments[:2] == ["volume", "create"]
    ]
    container_creates = [
        (arguments, document)
        for arguments, document in docker.mutation_journals
        if arguments and arguments[0] == "create"
    ]
    assert len(volume_creates) == 20
    assert len(container_creates) == 61
    assert not any(
        arguments and arguments[0] == "run" for arguments, _document in docker.mutation_journals
    )
    for index, document in enumerate(volume_creates):
        assert document["resources"][index]["volume_create_intent"] is True
    for arguments, document in container_creates:
        name = arguments[arguments.index("--name") + 1]
        if "-stager-" in name:
            row = next(item for item in document["resources"] if item["stager_name"] == name)
            assert row["stager_create_intent"] is True
        else:
            probe = next(item for item in document["probes"] if item["probe_name"] == name)
            assert probe["create_intent"] is True
    for arguments, document in docker.mutation_journals:
        if arguments[:2] == ["start", "--attach"] and "-probe-" in arguments[2]:
            probe = next(item for item in document["probes"] if item["probe_name"] == arguments[2])
            assert probe["start_intent"] is True
        if arguments[:2] == ["start", "--attach"] and "-stager-" in arguments[2]:
            resource = next(
                item for item in document["resources"] if item["stager_name"] == arguments[2]
            )
            assert resource["stager_start_intent"] is True
        if arguments[:2] == ["container", "rm"] and "-probe-" in arguments[-1]:
            probe = next(item for item in document["probes"] if item["probe_name"] == arguments[-1])
            assert probe["remove_intent"] is True


def test_journal_recovers_resources_without_attestation_or_failure_record(
    tmp_path: Path,
) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path)
    journal_path = attestation.with_name("validator-volume-transaction.json")
    attestation.unlink()
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["state"] = "prepared"
    journal.pop("attestation_sha256")
    journal.pop("attestation_semantic_sha256")
    journal.pop("semantic_sha256")
    journal["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(journal)).hexdigest()
    journal_path.write_text(json.dumps(journal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    recovery = recover_validator_volume_transaction(
        plan=plan,
        runtime_root=runtime,
        journal_path=journal_path,
        recovery_output_path=runtime / "provenance/validator-volume-recovery.json",
        runner=docker,
    )
    assert recovery["valid"] is True
    assert docker.volumes == {}


@pytest.mark.parametrize(
    ("created", "started", "remove_intent"),
    ((False, False, False), (True, False, False), (True, True, True)),
)
def test_recovery_closes_every_probe_crash_window(
    tmp_path: Path,
    created: bool,
    started: bool,
    remove_intent: bool,
) -> None:
    runtime, plan, docker, attestation = _stage(tmp_path / f"{created}-{started}-{remove_intent}")
    journal_path = attestation.with_name("validator-volume-transaction.json")
    attestation.unlink()
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["state"] = "prepared"
    journal.pop("attestation_sha256")
    journal.pop("attestation_semantic_sha256")
    probe = journal["probes"][1]
    for resource in journal["resources"]:
        resource["volume_remove_intent"] = True
        resource["volume_removed"] = True
    for name in list(docker.volumes):
        shutil.rmtree(Path(str(docker.volumes[name]["Mountpoint"])), ignore_errors=True)
        docker.volumes.pop(name)
        docker.files.pop(name)
    probe.update(
        {
            "created": created,
            "start_intent": created,
            "started": started,
            "remove_intent": remove_intent,
            "removed": False,
        }
    )
    name = probe["probe_name"]
    docker.containers[name] = {
        "Name": name,
        "Config": {"Labels": probe["probe_labels"]},
        "volume": probe["volume_name"],
    }
    journal.pop("semantic_sha256")
    journal["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(journal)).hexdigest()
    journal_path.write_text(json.dumps(journal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    recovery = recover_validator_volume_transaction(
        plan=plan,
        runtime_root=runtime,
        journal_path=journal_path,
        recovery_output_path=runtime / "provenance/probe-recovery.json",
        runner=docker,
    )
    assert recovery["valid"] is True
    assert recovery["remaining_container_names"] == []
    assert docker.containers == {}
