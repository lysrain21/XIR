from __future__ import annotations

import json
from pathlib import Path

import yaml

from xir_lab.native.hyperlane import HyperlanePublicIdentities
from xir_lab.native.multihop_hyperlane import (
    MULTIHOP_HYPERLANE_NAMES,
    materialize_multihop_hyperlane_registry,
    render_multihop_hyperlane_agent_configs,
    render_multihop_hyperlane_deployment_inputs,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs" / "profiles" / "native-multihop-five-chain-v1.json"


def test_multihop_hyperlane_rendering_covers_five_chains(tmp_path: Path) -> None:
    identities = HyperlanePublicIdentities(
        owner_address="0x" + "11" * 20,
        validator_address="0x" + "22" * 20,
        relayer_address="0x" + "33" * 20,
    )
    first = render_multihop_hyperlane_deployment_inputs(
        profile_path=PROFILE, identities=identities, runtime_root=tmp_path
    )
    second = render_multihop_hyperlane_deployment_inputs(
        profile_path=PROFILE, identities=identities, runtime_root=tmp_path
    )
    assert first == second
    assert [row["chain_name"] for row in first["rendered"]] == list(
        MULTIHOP_HYPERLANE_NAMES
    )
    for index, name in enumerate(MULTIHOP_HYPERLANE_NAMES, start=1):
        source = tmp_path / "hyperlane" / "native-deployments" / f"313370{index}.json"
        source.parent.mkdir(parents=True, exist_ok=True)
        contracts = {
            key: "0x" + f"{index:02x}" * 20
            for key in (
                "mailbox", "merkleTreeHook", "validatorAnnounce", "defaultIsm",
                "staticMessageIdMultisigIsmFactory", "protocolFee"
            )
        }
        source.write_text(json.dumps({"contracts": contracts}), encoding="utf-8")
    registry = materialize_multihop_hyperlane_registry(
        profile_path=PROFILE, runtime_root=tmp_path
    )
    assert len(registry["rendered"]) == 5
    agents = render_multihop_hyperlane_agent_configs(
        profile_path=PROFILE, runtime_root=tmp_path
    )
    assert len(agents["rendered"]) == 6
    metadata = yaml.safe_load(
        (tmp_path / "hyperlane" / "registry" / "chains" / "xirlocalchaine" / "metadata.yaml").read_text(encoding="utf-8")
    )
    assert metadata["chainId"] == 3133705
