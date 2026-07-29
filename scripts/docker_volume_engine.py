#!/usr/bin/env python3
"""Small Docker CLI adapter for shared daemons that reject Compose volume binds."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

PROJECT = "xir-local-scale"
ENVIRONMENT_LABEL = "controlled-local-qbft"


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("docker", *arguments),
        check=check,
        text=True,
        capture_output=True,
    )


def exists(kind: str, name: str) -> bool:
    return docker(kind, "inspect", name, check=False).returncode == 0


def load_compose(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("name") != PROJECT:
        raise RuntimeError("unexpected Compose project document")
    return value


def ensure_networks(document: dict[str, Any]) -> None:
    for key, network in sorted(document["networks"].items()):
        name = network["name"]
        if exists("network", name):
            continue
        subnet = network["ipam"]["config"][0]["subnet"]
        docker(
            "network",
            "create",
            "--driver",
            "bridge",
            "--subnet",
            subnet,
            "--label",
            f"org.xir.environment={ENVIRONMENT_LABEL}",
            "--label",
            f"com.docker.compose.project={PROJECT}",
            "--label",
            f"com.docker.compose.network={key}",
            name,
        )


def ensure_volumes(document: dict[str, Any]) -> None:
    for key, volume in sorted(document["volumes"].items()):
        name = volume["name"]
        if exists("volume", name):
            continue
        docker(
            "volume",
            "create",
            "--label",
            f"org.xir.environment={ENVIRONMENT_LABEL}",
            "--label",
            f"com.docker.compose.project={PROJECT}",
            "--label",
            f"com.docker.compose.volume={key}",
            name,
        )


def container_name(service_name: str) -> str:
    return f"{PROJECT}-{service_name}-1"


def create_service(
    service_name: str,
    service: dict[str, Any],
    document: dict[str, Any],
) -> str:
    name = container_name(service_name)
    if exists("container", name):
        inspected = json.loads(docker("container", "inspect", name).stdout)[0]
        labels = inspected["Config"]["Labels"]
        if (
            labels.get("org.xir.environment") != ENVIRONMENT_LABEL
            or labels.get("com.docker.compose.service") != service_name
        ):
            raise RuntimeError(f"refusing unrelated existing container: {name}")
        return name

    network_key, network_settings = next(iter(service["networks"].items()))
    network_name = document["networks"][network_key]["name"]
    arguments = [
        "create",
        "--name",
        name,
        "--restart",
        service["restart"],
        "--stop-timeout",
        service["stop_grace_period"].removesuffix("s"),
        "--memory",
        service["mem_limit"],
        "--cpus",
        str(service["cpus"]),
        "--network",
        network_name,
        "--ip",
        network_settings["ipv4_address"],
    ]
    for key, value in sorted(service.get("environment", {}).items()):
        arguments.extend(("--env", f"{key}={value}"))
    labels = dict(service.get("labels", {}))
    labels.update(
        {
            "com.docker.compose.container-number": "1",
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": service_name,
        }
    )
    for key, value in sorted(labels.items()):
        arguments.extend(("--label", f"{key}={value}"))
    for mount in service.get("volumes", []):
        if mount["type"] != "volume" or mount["target"] != "/data":
            raise RuntimeError(f"unsupported shared-daemon mount for {service_name}")
        volume_name = document["volumes"][mount["source"]]["name"]
        arguments.extend(
            (
                "--mount",
                f"type=volume,source={volume_name},target={mount['target']}",
            )
        )
    for port in service.get("ports", []):
        arguments.extend(("--publish", port))
    health = service["healthcheck"]
    if health["test"][0] != "CMD-SHELL":
        raise RuntimeError("only CMD-SHELL health checks are supported")
    arguments.extend(
        (
            "--health-cmd",
            health["test"][1],
            "--health-interval",
            health["interval"],
            "--health-timeout",
            health["timeout"],
            "--health-retries",
            str(health["retries"]),
            "--health-start-period",
            health["start_period"],
            service["image"],
            *service["command"],
        )
    )
    docker(*arguments)
    return name


def up(document: dict[str, Any]) -> None:
    ensure_networks(document)
    ensure_volumes(document)
    names = [
        create_service(name, service, document)
        for name, service in sorted(document["services"].items())
    ]
    docker("start", *names)
    print(json.dumps({"action": "up", "containers": names}, sort_keys=True))


def status(document: dict[str, Any]) -> None:
    rows: list[dict[str, Any]] = []
    for service_name in sorted(document["services"]):
        name = container_name(service_name)
        if not exists("container", name):
            rows.append({"name": name, "status": "absent"})
            continue
        inspected = json.loads(docker("container", "inspect", name).stdout)[0]
        state = inspected["State"]
        rows.append(
            {
                "name": name,
                "running": state["Running"],
                "status": state["Status"],
                "health": state.get("Health", {}).get("Status", "none"),
            }
        )
    print(json.dumps(rows, indent=2, sort_keys=True))


def stop(document: dict[str, Any]) -> None:
    names = [
        container_name(service_name)
        for service_name in sorted(document["services"])
        if exists("container", container_name(service_name))
    ]
    if names:
        docker("stop", "--time", "30", *names)
    print(json.dumps({"action": "stop", "containers": names}, sort_keys=True))


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"up", "status", "stop"}:
        print("usage: docker_volume_engine.py {up|status|stop} COMPOSE", file=sys.stderr)
        return 2
    document = load_compose(Path(sys.argv[2]))
    {"up": up, "status": status, "stop": stop}[sys.argv[1]](document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
