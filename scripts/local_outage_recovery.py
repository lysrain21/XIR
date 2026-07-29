#!/usr/bin/env python3
"""Exercise one-validator QBFT outage and recovery with immutable JSON evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xir_lab.localnet.topology import load_identity_manifest, load_topology


def rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"Content-Type": "application/json", "Host": "localhost"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        document = json.loads(response.read())
    if "result" not in document:
        raise RuntimeError(f"RPC returned no result: {method}")
    return document["result"]


def snapshot(endpoints: dict[str, str]) -> dict[str, Any]:
    heads = {
        validator: int(rpc(url, "eth_blockNumber", []), 16)
        for validator, url in endpoints.items()
    }
    checkpoint = min(heads.values())
    hashes = {
        validator: rpc(url, "eth_getBlockByNumber", [hex(checkpoint), False])["hash"]
        for validator, url in endpoints.items()
    }
    peers = {
        validator: int(rpc(url, "net_peerCount", []), 16)
        for validator, url in endpoints.items()
    }
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "heads": heads,
        "peer_counts": peers,
        "checkpoint_block": checkpoint,
        "checkpoint_hashes": hashes,
        "checkpoint_agreement": len(set(hashes.values())) == 1,
    }


def docker(*arguments: str) -> None:
    subprocess.run(("docker", *arguments), check=True, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--identity-manifest", type=Path, required=True)
    parser.add_argument("--network-id", default="local-source")
    parser.add_argument("--validator-id", default="v4")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    topology = load_topology(arguments.topology)
    manifest = load_identity_manifest(arguments.identity_manifest, topology=topology)
    identity = next(
        item for item in manifest.networks if item.network_id == arguments.network_id
    )
    endpoints = {
        item.validator_id: (
            f"http://{item.enode.rsplit('@', 1)[1].split(':', 1)[0]}:8545"
        )
        for item in identity.validators
    }
    target = (
        f"{topology.project_name}-{arguments.network_id}-{arguments.validator_id}-1"
    )
    before = snapshot(endpoints)
    target_started = True
    try:
        docker("stop", "--time", "30", target)
        target_started = False
        time.sleep(4)
        during_endpoints = {
            key: value
            for key, value in endpoints.items()
            if key != arguments.validator_id
        }
        during = snapshot(during_endpoints)
        docker("start", target)
        target_started = True
        deadline = time.monotonic() + 60
        while True:
            time.sleep(2)
            try:
                after = snapshot(endpoints)
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise
                continue
            recovered = (
                after["heads"][arguments.validator_id]
                >= during["checkpoint_block"]
                and min(after["peer_counts"].values()) >= 3
            )
            if recovered or time.monotonic() >= deadline:
                break
    finally:
        if not target_started:
            docker("start", target)

    eligible = (
        before["checkpoint_agreement"]
        and during["checkpoint_agreement"]
        and during["checkpoint_block"] > before["checkpoint_block"]
        and after["checkpoint_agreement"]
        and after["heads"][arguments.validator_id] >= during["checkpoint_block"]
        and min(after["peer_counts"].values()) >= 3
    )
    document = {
        "schema_version": "xir-lab-local-outage-recovery-v1",
        "environment": "controlled-local-qbft",
        "network_id": arguments.network_id,
        "chain_id": identity.chain_id,
        "stopped_validator": arguments.validator_id,
        "container": target,
        "before": before,
        "during_outage": during,
        "after_recovery": after,
        "eligible": eligible,
        "effects": {
            "public_network_calls": 0,
            "public_broadcasts": 0,
            "validators_stopped": 1,
            "validators_restarted": 1,
        },
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if eligible else 2


if __name__ == "__main__":
    raise SystemExit(main())
