from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from xir_lab.localnet.compose import render_compose
from xir_lab.localnet.identities import initialize_local_identities
from xir_lab.localnet.multihop_topology import (
    MULTIHOP_ROUTE_ROLES,
    load_multihop_identity_manifest,
    load_multihop_topology,
)

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / "configs" / "local" / "topology-multihop-remote-v1.json"


def test_five_chain_topology_renders_twenty_isolated_validators(tmp_path: Path) -> None:
    topology = load_multihop_topology(TOPOLOGY)
    assert tuple(network.route_role for network in topology.networks) == MULTIHOP_ROUTE_ROLES
    runtime = tmp_path / "runtime"
    manifest_path = initialize_local_identities(
        topology,
        runtime_root=runtime,
        repository_root=ROOT,
        created_at=datetime(2026, 8, 12, tzinfo=UTC),
    )
    manifest = load_multihop_identity_manifest(manifest_path, topology=topology)
    assert len(manifest.networks) == 5
    assert sum(len(network.validators) for network in manifest.networks) == 20
    first, first_sha = render_compose(topology, manifest)
    second, second_sha = render_compose(topology, manifest)
    assert first == second
    assert first_sha == second_sha
    text = first.decode()
    assert text.count("org.xir.validator-id") == 20
    assert "127.0.0.1:58545:8545" in text
    assert "local-chain-e-v4" in text


def test_campaign_topology_initialization_preserves_admission_and_lease_files(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    provenance = runtime / "provenance"
    private = runtime / "private"
    provenance.mkdir(parents=True)
    private.mkdir()
    review_gate = provenance / "predeployment-review-gate.json"
    lease_token = private / "writer-lease.token"
    profile = runtime / "profile.json"
    review_gate.write_text('{"valid":true}\n', encoding="utf-8")
    lease_token.write_text("lease-token\n", encoding="ascii")
    profile.write_text('{"schema_version":"profile"}\n', encoding="utf-8")

    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(ROOT / "scripts/prepare_native_multihop_topology.py"),
            "--topology",
            str(TOPOLOGY),
            "--runtime-root",
            str(runtime),
            "--repository-root",
            str(ROOT),
            "--initialize",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "validator_services=20" in result.stdout
    assert json.loads(review_gate.read_text(encoding="utf-8")) == {"valid": True}
    assert lease_token.read_text(encoding="ascii") == "lease-token\n"
    assert profile.read_text(encoding="utf-8") == '{"schema_version":"profile"}\n'
    assert (runtime / "identity-manifest.json").is_file()
    assert (runtime / "compose.yaml").is_file()
    assert (runtime / "private/accounts/deployer.key").is_file()
    assert (runtime / "private/validators/local-chain-e/v4/key").is_file()
    assert not list(runtime.glob(".identity-initialization-*"))
