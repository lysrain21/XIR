#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.security_v1_rebuild import rebuild_security_publication


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild native-security-v2 publication files without RPC access."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--root-audit", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--remote-preflight", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = rebuild_security_publication(
        config_path=args.config,
        deployment_path=args.deployment,
        state_path=args.state,
        runner_state_path=args.runner_state,
        root_audit_path=args.root_audit,
        evidence_root=args.evidence_root,
        output=args.output,
        remote_preflight_path=args.remote_preflight,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["summary"]["valid"] or not result["validation"]["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
