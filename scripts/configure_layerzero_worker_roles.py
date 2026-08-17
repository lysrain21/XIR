#!/usr/bin/env python3
"""Grant the isolated research worker only the official worker ADMIN_ROLE."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

from eth_account import Account
from eth_utils import keccak  # type: ignore[attr-defined]
from hexbytes import HexBytes
from web3 import Web3
from web3.types import TxParams

from xir_lab.native.multihop_execution import verify_multihop_profile_write_authority
from xir_lab.native.rpc import qbft_web3

ADMIN_ROLE = keccak(text="ADMIN_ROLE")
ACCESS_CONTROL_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "role", "type": "bytes32"},
            {"internalType": "address", "name": "account", "type": "address"},
        ],
        "name": "grantRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "role", "type": "bytes32"},
            {"internalType": "address", "name": "account", "type": "address"},
        ],
        "name": "hasRole",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def append(path: Path, document: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(document, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployer-key-file", type=Path, required=True)
    parser.add_argument("--worker-key-file", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--preregistration", type=Path)
    parser.add_argument("--review-gate", type=Path)
    parser.add_argument("--lease", type=Path)
    parser.add_argument("--lease-token", type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    verify_multihop_profile_write_authority(
        profile=profile,
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        runtime_root=args.runtime_root,
        preregistration_path=args.preregistration,
        review_gate_path=args.review_gate,
        lease_path=args.lease,
        lease_token_path=args.lease_token,
    )
    deployer = Account.from_key(
        args.deployer_key_file.read_text(encoding="ascii").strip()
    )
    worker = Account.from_key(
        args.worker_key_file.read_text(encoding="ascii").strip()
    )
    root = args.runtime_root / "layerzero" / "worker-role-configuration"
    receipt_root = root / "receipts"
    signed_root = root / "private-signed-transactions"
    receipt_root.mkdir(parents=True, exist_ok=True)
    signed_root.mkdir(parents=True, exist_ok=True)
    os.chmod(signed_root, 0o700)
    journal = root / "journal.jsonl"
    verified: list[dict[str, Any]] = []
    for chain in profile["chains"]:
        client = qbft_web3(str(chain["rpc_url"]))
        deployment = json.loads(
            (
                args.runtime_root
                / "layerzero"
                / "deployments"
                / f"{chain['chain_id']}.json"
            ).read_text(encoding="utf-8")
        )
        nonce = int(client.eth.get_transaction_count(deployer.address, "pending"))
        for component in ("dvn", "executor"):
            address = Web3.to_checksum_address(
                deployment["contracts"][component]
            )
            contract = client.eth.contract(address=address, abi=ACCESS_CONTROL_ABI)
            if not contract.functions.hasRole(ADMIN_ROLE, worker.address).call():
                built = cast(
                    dict[str, Any],
                    contract.functions.grantRole(
                        ADMIN_ROLE, worker.address
                    ).build_transaction(
                        cast(
                            TxParams,
                            {
                            "from": deployer.address,
                            "chainId": int(chain["chain_id"]),
                            "nonce": nonce,
                            "gas": 250_000,
                            "maxFeePerGas": max(int(client.eth.gas_price) * 2, 1),
                            "maxPriorityFeePerGas": 0,
                            "type": 2,
                            },
                        )
                    ),
                )
                data = HexBytes(built["data"])
                append(
                    journal,
                    {
                        "record": "intent",
                        "chain_id": int(chain["chain_id"]),
                        "component": component,
                        "target": address.lower(),
                        "worker": worker.address.lower(),
                        "role": "0x" + ADMIN_ROLE.hex(),
                        "nonce": nonce,
                        "calldata_sha256": hashlib.sha256(data).hexdigest(),
                    },
                )
                signed = deployer.sign_transaction(cast(TxParams, built))
                raw = bytes(signed.raw_transaction)
                raw_path = signed_root / f"{signed.hash.hex()}.raw"
                raw_path.write_bytes(raw)
                os.chmod(raw_path, 0o600)
                append(
                    journal,
                    {
                        "record": "signed",
                        "transaction_hash": signed.hash.hex(),
                        "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    },
                )
                tx_hash = client.eth.send_raw_transaction(raw)
                append(
                    journal,
                    {"record": "submitted", "transaction_hash": tx_hash.hex()},
                )
                receipt = client.eth.wait_for_transaction_receipt(
                    tx_hash, timeout=180
                )
                receipt_path = receipt_root / f"{tx_hash.hex()}.json"
                receipt_path.write_text(
                    Web3.to_json(cast(dict[Any, Any], receipt)) + "\n",
                    encoding="utf-8",
                )
                if int(receipt["status"]) != 1:
                    raise RuntimeError(
                        f"worker ADMIN_ROLE grant reverted: {component}"
                    )
                append(
                    journal,
                    {
                        "record": "succeeded",
                        "transaction_hash": tx_hash.hex(),
                        "block_number": int(receipt["blockNumber"]),
                        "gas_used": int(receipt["gasUsed"]),
                        "receipt_sha256": hashlib.sha256(
                            receipt_path.read_bytes()
                        ).hexdigest(),
                    },
                )
                nonce += 1
            if not contract.functions.hasRole(ADMIN_ROLE, worker.address).call():
                raise RuntimeError(
                    f"worker ADMIN_ROLE verification failed: {component}"
                )
            verified.append(
                {
                    "chain_id": int(chain["chain_id"]),
                    "component": component,
                    "address": address.lower(),
                    "worker": worker.address.lower(),
                    "admin_role": "0x" + ADMIN_ROLE.hex(),
                    "effective": True,
                }
            )
    manifest = {
        "schema_version": "xir-lab-layerzero-worker-role-configuration-v1",
        "least_privilege_role": "ADMIN_ROLE",
        "worker": worker.address.lower(),
        "verified": verified,
    }
    (root / "verification.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
