#!/usr/bin/env python3
"""Initialize and render the fresh five-chain QBFT topology."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from xir_lab.localnet.compose import render_compose
from xir_lab.localnet.identities import LocalIdentityError, initialize_local_identities
from xir_lab.localnet.multihop_topology import (
    load_multihop_identity_manifest,
    load_multihop_topology,
)
from xir_lab.localnet.topology import LocalTopology

_IDENTITY_OUTPUTS = (
    Path("private/accounts"),
    Path("private/validators"),
    Path("data"),
    Path("networks"),
    Path("identity-manifest.json"),
)


def _initialize_campaign_runtime(
    *, topology: LocalTopology, runtime_root: Path, repository_root: Path
) -> Path:
    """Stage fresh identities before merging them into an admitted campaign root."""

    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime_root.chmod(0o700)
    staging = runtime_root / f".identity-initialization-{os.getpid()}"
    if staging.exists():
        raise LocalIdentityError("identity initialization staging path already exists")
    for relative in _IDENTITY_OUTPUTS:
        if (runtime_root / relative).exists():
            raise LocalIdentityError(
                f"campaign identity output already exists: {relative.as_posix()}"
            )
    initialize_local_identities(
        topology,
        runtime_root=staging,
        repository_root=repository_root,
    )
    for relative in _IDENTITY_OUTPUTS:
        if not (staging / relative).exists():
            raise LocalIdentityError(
                f"staged identity output is absent: {relative.as_posix()}"
            )
    for relative in _IDENTITY_OUTPUTS:
        destination = runtime_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(staging / relative, destination)
    (staging / "private").rmdir()
    staging.rmdir()
    return runtime_root / "identity-manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--initialize", action="store_true")
    args = parser.parse_args()
    topology = load_multihop_topology(args.topology)
    manifest_path = args.runtime_root / "identity-manifest.json"
    if args.initialize:
        manifest_path = _initialize_campaign_runtime(
            topology=topology,
            runtime_root=args.runtime_root,
            repository_root=args.repository_root,
        )
    manifest = load_multihop_identity_manifest(manifest_path, topology=topology)
    rendered, digest = render_compose(topology, manifest)
    output = args.runtime_root / "compose.yaml"
    output.write_bytes(rendered)
    print(f"compose_sha256={digest}")
    print(f"validator_services={sum(len(network.validators) for network in manifest.networks)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
