#!/usr/bin/env python3
"""Acquire, heartbeat, verify, or release the exclusive multihop writer lease."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_execution import (
    PRODUCTION_GLOBAL_LEASE_ROOT,
    acquire_writer_lease,
    activate_writer_lease_resume,
    continue_writer_lease,
    heartbeat_writer_lease,
    mark_writer_lease_resume_pending,
    recover_stale_writer_lease,
    release_writer_lease,
    resolve_blocked_writer_lease_after_audited_cleanup,
    retain_writer_lease_after_cleanup_failure,
    verify_writer_lease,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "acquire",
            "continue",
            "heartbeat",
            "mark-resume-pending",
            "activate-resume",
            "verify",
            "release",
            "retain",
            "resolve-blocked-cleanup",
            "recover",
        ),
    )
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--token", type=Path, required=True)
    parser.add_argument("--holder")
    parser.add_argument("--global-lock-root", type=Path)
    parser.add_argument(
        "--test-only-allow-noncanonical-global-lock-root",
        action="store_true",
        help="unit/fault-injection only; such a lease is rejected by writer authority",
    )
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    parser.add_argument("--supervisor-pid", type=int)
    parser.add_argument("--cleanup-evidence", type=Path)
    parser.add_argument("--review-closure", type=Path)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--current-preregistration", type=Path)
    parser.add_argument("--current-review-gate", type=Path)
    parser.add_argument("--acquisition-review-closure", type=Path)
    parser.add_argument("--topology", type=Path)
    parser.add_argument("--identity-manifest", type=Path)
    parser.add_argument("--compose", type=Path)
    parser.add_argument("--validator-volume-attestation", type=Path)
    parser.add_argument("--validator-volume-journal", type=Path)
    parser.add_argument("--validator-volume-recovery", type=Path)
    args = parser.parse_args()
    if args.action == "acquire":
        if not args.holder:
            parser.error("acquire requires --holder")
        if args.global_lock_root is None:
            parser.error("acquire requires --global-lock-root")
        if (
            args.global_lock_root.resolve() != PRODUCTION_GLOBAL_LEASE_ROOT
            and not args.test_only_allow_noncanonical_global_lock_root
        ):
            parser.error(
                "acquire requires canonical production --global-lock-root "
                f"{PRODUCTION_GLOBAL_LEASE_ROOT}"
            )
        if args.supervisor_pid is None:
            parser.error("acquire requires --supervisor-pid")
        expected = args.runtime_root / "provenance/exclusive-writer-lease/lease.json"
        if args.lease.resolve() != expected.resolve():
            parser.error(f"--lease must be {expected}")
        document = acquire_writer_lease(
            runtime_root=args.runtime_root,
            holder=args.holder,
            ttl_seconds=args.ttl_seconds,
            preregistration_path=args.preregistration,
            token_output=args.token,
            global_lock_root=args.global_lock_root,
            supervisor_pid=args.supervisor_pid,
            review_closure_path=args.review_closure,
        )
    elif args.action == "continue":
        if args.supervisor_pid is None:
            parser.error("continue requires --supervisor-pid")
        document = continue_writer_lease(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
            supervisor_pid=args.supervisor_pid,
        )
    elif args.action == "heartbeat":
        document = heartbeat_writer_lease(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
        )
    elif args.action == "mark-resume-pending":
        document = mark_writer_lease_resume_pending(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
        )
    elif args.action == "activate-resume":
        document = activate_writer_lease_resume(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
        )
    elif args.action == "release":
        document = release_writer_lease(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
        )
    elif args.action == "recover":
        document = recover_stale_writer_lease(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
            global_lock_root=args.global_lock_root,
        )
    elif args.action == "retain":
        if args.supervisor_pid is None:
            parser.error("retain requires --supervisor-pid")
        document = retain_writer_lease_after_cleanup_failure(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
            supervisor_pid=args.supervisor_pid,
        )
    elif args.action == "resolve-blocked-cleanup":
        required = {
            "--cleanup-evidence": args.cleanup_evidence,
            "--workspace-root": args.workspace_root,
            "--repository-root": args.repository_root,
            "--current-preregistration": args.current_preregistration,
            "--current-review-gate": args.current_review_gate,
            "--acquisition-review-closure": args.acquisition_review_closure,
            "--topology": args.topology,
            "--identity-manifest": args.identity_manifest,
            "--compose": args.compose,
            "--validator-volume-attestation": args.validator_volume_attestation,
            "--validator-volume-journal": args.validator_volume_journal,
            "--validator-volume-recovery": args.validator_volume_recovery,
        }
        missing = sorted(name for name, value in required.items() if value is None)
        if missing:
            parser.error("resolve-blocked-cleanup requires " + ", ".join(missing))
        document = resolve_blocked_writer_lease_after_audited_cleanup(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            acquisition_preregistration_path=args.preregistration,
            acquisition_review_closure_path=args.acquisition_review_closure,
            workspace_root=args.workspace_root,
            repository_root=args.repository_root,
            current_preregistration_path=args.current_preregistration,
            current_review_gate_path=args.current_review_gate,
            topology_path=args.topology,
            identity_manifest_path=args.identity_manifest,
            compose_path=args.compose,
            validator_volume_attestation_path=args.validator_volume_attestation,
            validator_volume_journal_path=args.validator_volume_journal,
            validator_volume_recovery_path=args.validator_volume_recovery,
            cleanup_evidence_output_path=args.cleanup_evidence,
        )
    else:
        document = verify_writer_lease(
            lease_path=args.lease,
            token_path=args.token,
            runtime_root=args.runtime_root,
            preregistration_path=args.preregistration,
        )
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    mark_writer_lease_resume_pending,
