"""Controlled local multi-network scale-lab support."""

from xir_lab.localnet.compose import render_compose
from xir_lab.localnet.identities import initialize_local_identities
from xir_lab.localnet.preflight import (
    HostSnapshot,
    build_local_preflight,
    collect_node_observations,
)
from xir_lab.localnet.scale import build_local_scale_plan
from xir_lab.localnet.topology import (
    LocalIdentityManifest,
    LocalTopology,
    load_identity_manifest,
    load_topology,
)

__all__ = [
    "HostSnapshot",
    "LocalIdentityManifest",
    "LocalTopology",
    "build_local_preflight",
    "build_local_scale_plan",
    "collect_node_observations",
    "initialize_local_identities",
    "load_identity_manifest",
    "load_topology",
    "render_compose",
]
