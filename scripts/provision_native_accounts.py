#!/usr/bin/env python3
"""Create isolated experiment roles and fund them on all three local chains."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

from eth_account import Account
from hexbytes import HexBytes
from web3 import Web3
from web3.types import Nonce, TxParams, Wei

from xir_lab.native.multihop_execution import verify_multihop_profile_write_authority
from xir_lab.native.rpc import qbft_web3

ROLES = (
    "runner",
    "root-signer",
    "layerzero-worker",
    "hyperlane-validator",
    "hyperlane-relayer",
)
TARGET_BALANCE = Web3.to_wei(1_000, "ether")


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
    account_root = args.runtime_root / "private" / "accounts"
    account_root.mkdir(parents=True, exist_ok=True)
    os.chmod(account_root, 0o700)
    identities = {}
    for role in ROLES:
        path = account_root / f"{role}.key"
        if not path.is_file():
            generated = Account.create(extra_entropy=os.urandom(32))
            path.write_text(generated.key.hex() + "\n", encoding="ascii")
            os.chmod(path, 0o600)
        account = Account.from_key(path.read_text(encoding="ascii").strip())
        identities[role] = account.address
    public_manifest = {
        "schema_version": "xir-lab-native-public-identities-v1",
        "roles": {role: address.lower() for role, address in identities.items()},
        "private_keys_published": False,
    }
    public_path = args.runtime_root / "provenance" / "public-identities.json"
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_text(
        json.dumps(public_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    deployer = Account.from_key(
        args.deployer_key_file.read_text(encoding="ascii").strip()
    )
    journal = args.runtime_root / "provenance" / "account-funding.jsonl"
    receipt_root = args.runtime_root / "provenance" / "account-funding-receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    for chain in profile["chains"]:
        client = qbft_web3(str(chain["rpc_url"]))
        nonce = int(client.eth.get_transaction_count(deployer.address, "pending"))
        for role, address in identities.items():
            balance = int(client.eth.get_balance(address))
            if balance >= TARGET_BALANCE:
                append(
                    journal,
                    {
                        "record": "already_funded",
                        "chain_id": int(chain["chain_id"]),
                        "role": role,
                        "address": address.lower(),
                        "balance": balance,
                    },
                )
                continue
            value = TARGET_BALANCE - balance
            transaction: TxParams = {
                "chainId": int(chain["chain_id"]),
                "nonce": Nonce(nonce),
                "to": address,
                "value": Wei(value),
                "gas": 21_000,
                "maxFeePerGas": Wei(max(int(client.eth.gas_price) * 2, 1)),
                "maxPriorityFeePerGas": Wei(0),
                "type": 2,
            }
            action_id = hashlib.sha256(
                f"{chain['chain_id']}:{role}:{address}:{value}".encode()
            ).hexdigest()
            append(
                journal,
                {
                    "record": "intent",
                    "action_id": action_id,
                    "chain_id": int(chain["chain_id"]),
                    "role": role,
                    "address": address.lower(),
                    "nonce": nonce,
                    "value": value,
                },
            )
            signed = deployer.sign_transaction(transaction)
            raw = bytes(signed.raw_transaction)
            append(
                journal,
                {
                    "record": "signed",
                    "action_id": action_id,
                    "transaction_hash": signed.hash.hex(),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                },
            )
            transaction_hash = client.eth.send_raw_transaction(raw)
            receipt = client.eth.wait_for_transaction_receipt(
                HexBytes(transaction_hash), timeout=120
            )
            receipt_document = json.loads(
                Web3.to_json(cast(dict[Any, Any], receipt))
            )
            receipt_path = receipt_root / (
                f"{chain['chain_id']}-{role}-{transaction_hash.hex()}.json"
            )
            receipt_path.write_text(
                json.dumps(receipt_document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if int(receipt["status"]) != 1:
                raise SystemExit(f"account funding reverted: {role}")
            append(
                journal,
                {
                    "record": "succeeded",
                    "action_id": action_id,
                    "transaction_hash": transaction_hash.hex(),
                    "receipt_sha256": hashlib.sha256(
                        receipt_path.read_bytes()
                    ).hexdigest(),
                },
            )
            nonce += 1


if __name__ == "__main__":
    main()
