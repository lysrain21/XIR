#!/usr/bin/env python3
"""Run one phase of the review-gated native multihop campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import rfc8785
from requests import RequestException
from web3.exceptions import TimeExhausted, Web3RPCError

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_execution import verify_execution_authority
from xir_lab.native.multihop_identity import config_identity
from xir_lab.native.multihop_publication import verify_prior_phase_handoffs
from xir_lab.native.multihop_runner import NativeMultihopRunner
from xir_lab.native.multihop_scalability import load_multihop_config
from xir_lab.native.rpc import is_transient_rpc_error


def _key(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    return value if value.startswith("0x") else "0x" + value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--review-gate", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--lease-token", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--phase-authority-output", type=Path, required=True)
    parser.add_argument("--smoke-handoff", type=Path)
    parser.add_argument("--publication-smoke-handoff", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--runner-key-file", type=Path, required=True)
    parser.add_argument("--root-signer-key-file", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("smoke", "publication_smoke", "scale"), required=True)
    parser.add_argument("--submission-stop-file", type=Path)
    args = parser.parse_args()
    authority = verify_execution_authority(
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        runtime_root=args.runtime_root,
        preregistration_path=args.preregistration,
        review_gate_path=args.review_gate,
        lease_path=args.lease,
        lease_token_path=args.lease_token,
    )
    config, _ = load_multihop_config(args.config)
    predecessor_handoffs = verify_prior_phase_handoffs(
        phase=args.phase,
        smoke_handoff_path=args.smoke_handoff,
        publication_smoke_handoff_path=args.publication_smoke_handoff,
        verify_full_trees=True,
        expected_namespace=config_identity(config).evidence_namespace,
    )
    preflight_document = json.loads(args.preflight.read_text(encoding="utf-8"))
    phase_authority = {
        "schema_version": "xir-lab-native-multihop-phase-authority-v1",
        "namespace": config_identity(config).evidence_namespace,
        "phase": args.phase,
        "prior_phase_handoffs": predecessor_handoffs,
        "review_gate_sha256": authority["review_gate_sha256"],
        "review_closure_sha256": authority["review_closure_sha256"],
        "lease_identity_sha256": authority["lease_identity_sha256"],
        "lease_identity": authority["lease_identity"],
        "preflight_sha256": hashlib.sha256(args.preflight.read_bytes()).hexdigest(),
        "preflight_semantic_sha256": json.loads(args.preflight.read_text(encoding="utf-8"))[
            "semantic_sha256"
        ],
        "validator_volume_attestation_sha256": preflight_document[
            "validator_volume_attestation_sha256"
        ],
        "validator_volume_attestation_semantic_sha256": preflight_document[
            "validator_volume_attestation_semantic_sha256"
        ],
        "validator_volume_journal_sha256": preflight_document["validator_volume_journal_sha256"],
        "validator_volume_journal_semantic_sha256": preflight_document[
            "validator_volume_journal_semantic_sha256"
        ],
        "toolchain_preflight_sha256": preflight_document["toolchain_preflight_sha256"],
        "toolchain_preflight_semantic_sha256": preflight_document[
            "toolchain_preflight_semantic_sha256"
        ],
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "plan_sha256": hashlib.sha256(args.plan.read_bytes()).hexdigest(),
        "deployment_sha256": hashlib.sha256(args.deployment.read_bytes()).hexdigest(),
        "preregistration_sha256": hashlib.sha256(args.preregistration.read_bytes()).hexdigest(),
    }
    phase_authority["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(phase_authority)).hexdigest()
    serialized_authority = json.dumps(phase_authority, indent=2, sort_keys=True) + "\n"
    if args.phase_authority_output.exists():
        if args.phase_authority_output.read_text(encoding="utf-8") != serialized_authority:
            raise RuntimeError("existing phase authority differs from current inputs")
    else:
        args.phase_authority_output.parent.mkdir(parents=True, exist_ok=True)
        args.phase_authority_output.write_text(serialized_authority, encoding="utf-8")
    runner = NativeMultihopRunner(
        repository_root=args.repository_root,
        workspace_root=args.workspace_root,
        runtime_root=args.runtime_root,
        topology_path=args.topology,
        identity_path=args.identity,
        config_path=args.config,
        plan_path=args.plan,
        deployment_path=args.deployment,
        private_key=_key(args.runner_key_file),
        root_signer_private_key=_key(args.root_signer_key_file),
        state_path=args.state,
        raw_root=args.raw_root,
        preflight_path=args.preflight,
        review_gate_path=args.review_gate,
        phase_authority_path=args.phase_authority_output,
        execution_authority=authority,
        preregistration_path=args.preregistration,
        lease_path=args.lease,
        lease_token_path=args.lease_token,
        submission_stop_file=args.submission_stop_file,
    )
    runner.run_phase(args.phase)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LocalTopologyError as exc:
        if "submissions stopped by resource monitor" in str(exc):
            raise SystemExit(75) from exc
        raise
    except TimeExhausted as exc:
        # The signed transaction is durable before receipt polling. Resume must
        # re-check the same hash instead of treating a slow QBFT block as a
        # terminal experiment failure.
        raise SystemExit(75) from exc
    except (RequestException, Web3RPCError) as exc:
        if is_transient_rpc_error(exc):
            raise SystemExit(75) from exc
        raise
