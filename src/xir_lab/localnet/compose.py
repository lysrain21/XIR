"""Deterministic Docker Compose rendering for twelve Besu validators."""

from __future__ import annotations

import hashlib
from typing import Any

import yaml

from xir_lab.localnet.topology import LocalIdentityManifest, LocalTopology


def _memory_megabytes(value: int) -> str:
    return f"{value // (1024 * 1024)}m"


def render_compose(
    topology: LocalTopology,
    manifest: LocalIdentityManifest,
) -> tuple[bytes, str]:
    """Render stable Compose bytes from validated public inputs."""

    services: dict[str, Any] = {}
    networks: dict[str, Any] = {}
    volumes: dict[str, Any] = {}
    identity_map = {item.network_id: item for item in manifest.networks}
    runtime = f"${{{topology.runtime_root_environment_variable}:?set runtime root}}"
    for network_index, network in enumerate(topology.networks, start=1):
        identity = identity_map[network.network_id]
        network_name = network.network_id
        networks[network_name] = {
            "name": f"{topology.project_name}-{network_name}",
            "ipam": {"config": [{"subnet": network.subnet}]},
        }
        for validator_index, validator in enumerate(identity.validators, start=1):
            service_name = f"{network.network_id}-v{validator_index}"
            data_path = f"data/{network.network_id}/v{validator_index}"
            volume_name = f"{network.network_id}-v{validator_index}-data"
            peer_bootnodes = ",".join(
                item.enode
                for item in identity.validators
                if item.validator_id != validator.validator_id
            )
            genesis_file = "/config/genesis.json"
            private_key_file = "/run/xir-validator/key"
            if topology.validator_data_storage == "docker-volume":
                # The remote Docker daemon cannot see the SSH client's GPFS
                # namespace. The lifecycle script stages these two immutable
                # bootstrap files into each validator's private data volume.
                genesis_file = "/data/bootstrap/genesis.json"
                private_key_file = "/data/bootstrap/key"
            command = [
                f"--genesis-file={genesis_file}",
                "--data-path=/data",
                f"--node-private-key-file={private_key_file}",
                f"--network-id={network.chain_id}",
                "--p2p-host=0.0.0.0",
                "--p2p-port=30303",
                f"--bootnodes={peer_bootnodes}",
                "--discovery-enabled=true",
                "--rpc-http-enabled=true",
                "--rpc-http-host=0.0.0.0",
                "--rpc-http-port=8545",
                f"--rpc-http-api={','.join(topology.rpc_http_apis)}",
                "--host-allowlist=localhost,127.0.0.1",
                "--min-gas-price=0",
                "--sync-mode=FULL",
                "--sync-min-peers=3",
                "--data-storage-format=BONSAI",
            ]
            data_mount: str | dict[str, str] = f"{runtime}/{data_path}:/data"
            if topology.validator_data_storage == "docker-volume":
                volumes[volume_name] = {
                    "name": f"{topology.project_name}-{volume_name}"
                }
                # Long syntax is intentional. Some shared Docker wrappers
                # reject the legacy HostConfig.Binds representation of a
                # named volume while allowing the API Mounts representation.
                data_mount = {
                    "type": "volume",
                    "source": volume_name,
                    "target": "/data",
                }
            service_mounts = [
                f"{runtime}/{identity.genesis_path}:/config/genesis.json:ro",
                f"{runtime}/{validator.private_key_path}:/run/xir-validator/key:ro",
                data_mount,
            ]
            if topology.validator_data_storage == "docker-volume":
                service_mounts = [data_mount]
            service: dict[str, Any] = {
                "image": topology.besu_image,
                "command": command,
                "restart": "unless-stopped",
                "stop_grace_period": "30s",
                "mem_limit": _memory_megabytes(
                    topology.resource_policy.validator_memory_bytes
                ),
                "cpus": f"{topology.resource_policy.validator_cpu_limit:.2f}",
                "environment": {
                    "JAVA_OPTS": "-Xms128m -Xmx384m",
                },
                "volumes": service_mounts,
                "networks": {
                    network_name: {
                        "ipv4_address": validator.enode.rsplit("@", 1)[1].split(":", 1)[0]
                    }
                },
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "bash -c 'exec 3<>/dev/tcp/127.0.0.1/8545'",
                    ],
                    "interval": "5s",
                    "timeout": "3s",
                    "retries": 24,
                    "start_period": "20s",
                },
                "labels": {
                    "org.xir.environment": "controlled-local-qbft",
                    "org.xir.network-id": network.network_id,
                    "org.xir.route-role": network.route_role,
                    "org.xir.validator-id": validator.validator_id,
                    "org.xir.topology-sha256": topology.source_sha256,
                    "org.xir.identity-manifest-sha256": manifest.payload_sha256,
                },
            }
            if topology.validator_runtime_user is not None:
                service["user"] = topology.validator_runtime_user
            if validator_index == 1:
                service["ports"] = [
                    f"127.0.0.1:{network.host_rpc_port}:8545"
                ]
            services[service_name] = service
    document = {
        "name": topology.project_name,
        "services": services,
        "networks": networks,
    }
    if volumes:
        document["volumes"] = volumes
    rendered = yaml.safe_dump(
        document,
        sort_keys=True,
        default_flow_style=False,
        allow_unicode=False,
    ).encode("utf-8")
    return rendered, hashlib.sha256(rendered).hexdigest()
