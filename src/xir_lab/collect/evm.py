"""Exact-raw and normalized public EVM transaction collection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from xir_lab.evidence.records import stable_id
from xir_lab.evidence.store import EvidenceStore
from xir_lab.faults import CrashInjector, NoCrashInjector

T = TypeVar("T")


class EvmCollectorError(RuntimeError):
    """Raised when public RPC evidence is inconsistent or incomplete."""


@dataclass(frozen=True)
class RawEnvelope(Generic[T]):
    value: T
    raw_bytes: bytes
    provider_id: str


@dataclass(frozen=True)
class PublicTransaction:
    transaction_hash: str
    chain_id: int
    nonce: int
    sender: str
    recipient: str | None
    input_hex: str
    value_wei: int


@dataclass(frozen=True)
class PublicLog:
    log_index: int
    topic0: str | None


@dataclass(frozen=True)
class PublicReceipt:
    transaction_hash: str
    block_number: int
    block_hash: str
    status: int
    gas_used: int
    effective_gas_price_wei: int
    logs: tuple[PublicLog, ...]
    l1_data_fee_wei: int | None
    l1_data_fee_unavailable_reason: str | None
    carrier_payment_wei: int
    funding_attribution: str


@dataclass(frozen=True)
class PublicBlockHeader:
    block_number: int
    block_hash: str
    parent_hash: str
    timestamp: int


@dataclass(frozen=True)
class PublicBalance:
    address: str
    block_number: int
    balance_wei: int


@dataclass(frozen=True)
class CollectedTransaction:
    transaction_id: str
    transaction_hash: str
    chain_id: int
    block_number: int
    gas_used: int
    execution_fee_wei: int
    input_bytes: int
    balance_snapshots: int


class ReadOnlyEvmProvider(Protocol):
    def transaction(
        self, transaction_hash: str
    ) -> RawEnvelope[PublicTransaction] | None:
        """Read a public transaction."""

    def receipt(self, transaction_hash: str) -> RawEnvelope[PublicReceipt] | None:
        """Read a public receipt."""

    def block_header(
        self, block_number: int
    ) -> RawEnvelope[PublicBlockHeader] | None:
        """Read a public block header."""

    def balance(self, address: str, block_number: int) -> RawEnvelope[PublicBalance]:
        """Read one public account balance at a fixed block."""


class EvmCollector:
    """Collect one known transaction without exposing any write RPC method."""

    def __init__(
        self,
        *,
        store: EvidenceStore,
        provider: ReadOnlyEvmProvider,
        crash_injector: CrashInjector | None = None,
    ) -> None:
        self.store = store
        self.provider = provider
        self.crash_injector = crash_injector or NoCrashInjector()

    def collect_transaction(
        self,
        *,
        transaction_id: str,
        balance_accounts: tuple[str, ...] = (),
    ) -> CollectedTransaction:
        with self.store.connect(read_only=True) as connection:
            known = connection.execute(
                """
                SELECT transaction_record.transaction_hash,
                       transaction_record.chain_id, transaction_record.nonce,
                       stage.attempt_id
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
            existing = connection.execute(
                """
                SELECT resource.chain_id, receipt.block_number, receipt.gas_used,
                       resource.execution_fee_wei, resource.input_bytes,
                       transaction_record.transaction_hash
                FROM transaction_resources AS resource
                JOIN transaction_receipts AS receipt
                  ON receipt.transaction_id = resource.transaction_id
                JOIN transactions AS transaction_record
                  ON transaction_record.transaction_id = resource.transaction_id
                WHERE resource.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
        if known is None or known["transaction_hash"] is None:
            raise EvmCollectorError("collector requires a known precomputed transaction hash")
        if existing is not None:
            return CollectedTransaction(
                transaction_id=transaction_id,
                transaction_hash=str(existing["transaction_hash"]),
                chain_id=int(existing["chain_id"]),
                block_number=int(existing["block_number"]),
                gas_used=int(existing["gas_used"]),
                execution_fee_wei=int(existing["execution_fee_wei"]),
                input_bytes=int(existing["input_bytes"]),
                balance_snapshots=self._balance_count(transaction_id),
            )
        transaction_hash = str(known["transaction_hash"])
        try:
            transaction = self.provider.transaction(transaction_hash)
            receipt = self.provider.receipt(transaction_hash)
        except Exception as exc:
            raise EvmCollectorError(
                "public transaction or receipt read failed"
            ) from exc
        if transaction is None:
            raise EvmCollectorError("known transaction is unavailable from archive data")
        if receipt is None:
            raise EvmCollectorError("known transaction receipt is not yet available")
        try:
            block = self.provider.block_header(receipt.value.block_number)
        except Exception as exc:
            raise EvmCollectorError("public block archive read failed") from exc
        if block is None:
            raise EvmCollectorError("receipt block is unavailable from archive data")
        self._validate(
            transaction_hash=transaction_hash,
            expected_chain_id=int(known["chain_id"]),
            expected_nonce=int(known["nonce"]),
            transaction=transaction.value,
            receipt=receipt.value,
            block=block.value,
        )
        self.crash_injector.hit("after_receipt_before_raw_commit")
        transaction_raw = self._put_rpc_raw(
            transaction.raw_bytes, transaction.provider_id, "transaction"
        )
        receipt_raw = self._put_rpc_raw(
            receipt.raw_bytes, receipt.provider_id, "receipt"
        )
        block_raw = self._put_rpc_raw(
            block.raw_bytes, block.provider_id, "block_header"
        )
        balance_rows: list[tuple[str, PublicBalance, str]] = []
        balance_blocks = tuple(
            sorted(
                {
                    max(0, receipt.value.block_number - 1),
                    receipt.value.block_number,
                }
            )
        )
        for address in sorted(set(balance_accounts)):
            if not _address(address):
                raise EvmCollectorError("balance account is not a nonzero EVM address")
            for block_number in balance_blocks:
                envelope = self.provider.balance(address, block_number)
                if (
                    envelope.value.address.lower() != address.lower()
                    or envelope.value.block_number != block_number
                    or envelope.value.balance_wei < 0
                ):
                    raise EvmCollectorError("balance response changed address or block")
                raw_sha256 = self._put_rpc_raw(
                    envelope.raw_bytes,
                    envelope.provider_id,
                    "balance",
                )
                balance_rows.append((address, envelope.value, raw_sha256))
        self.crash_injector.hit("after_raw_commit_before_normalized_commit")
        tx = transaction.value
        observed_receipt = receipt.value
        input_bytes = len(bytes.fromhex(tx.input_hex.removeprefix("0x")))
        execution_fee = (
            observed_receipt.gas_used
            * observed_receipt.effective_gas_price_wei
        )
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO block_headers(
                    chain_id, block_number, block_hash, parent_hash,
                    block_timestamp, raw_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tx.chain_id,
                    block.value.block_number,
                    block.value.block_hash,
                    block.value.parent_hash,
                    block.value.timestamp,
                    block_raw,
                ),
            )
            connection.execute(
                """
                INSERT INTO transaction_receipts(
                    transaction_id, block_number, block_hash, receipt_status,
                    gas_used, effective_gas_price_wei, raw_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id,
                    observed_receipt.block_number,
                    observed_receipt.block_hash,
                    observed_receipt.status,
                    observed_receipt.gas_used,
                    str(observed_receipt.effective_gas_price_wei),
                    receipt_raw,
                ),
            )
            connection.execute(
                """
                INSERT INTO transaction_resources(
                    transaction_id, chain_id, sender, recipient, input_bytes,
                    transaction_value_wei, gas_used, effective_gas_price_wei,
                    execution_fee_wei, l1_data_fee_wei,
                    l1_data_fee_unavailable_reason, carrier_payment_wei,
                    funding_attribution
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id,
                    tx.chain_id,
                    tx.sender,
                    tx.recipient,
                    input_bytes,
                    str(tx.value_wei),
                    observed_receipt.gas_used,
                    str(observed_receipt.effective_gas_price_wei),
                    str(execution_fee),
                    (
                        None
                        if observed_receipt.l1_data_fee_wei is None
                        else str(observed_receipt.l1_data_fee_wei)
                    ),
                    observed_receipt.l1_data_fee_unavailable_reason,
                    str(observed_receipt.carrier_payment_wei),
                    observed_receipt.funding_attribution,
                ),
            )
            for log in observed_receipt.logs:
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, transaction_id, log_index, topic0, raw_sha256
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        stable_id(
                            "observation",
                            "log",
                            transaction_id,
                            log.log_index,
                        ),
                        transaction_id,
                        log.log_index,
                        log.topic0,
                        receipt_raw,
                    ),
                )
            for address, balance, raw_sha256 in balance_rows:
                connection.execute(
                    """
                    INSERT INTO account_snapshots(
                        snapshot_id, attempt_id, chain_id, account,
                        balance_wei, block_number, raw_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        stable_id(
                            "observation",
                            "balance",
                            transaction_id,
                            address.lower(),
                            balance.block_number,
                        ),
                        known["attempt_id"],
                        tx.chain_id,
                        address,
                        str(balance.balance_wei),
                        balance.block_number,
                        raw_sha256,
                    ),
                )
            current = connection.execute(
                "SELECT state FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if current is None:
                raise EvmCollectorError("transaction disappeared during collection")
            if current["state"] not in {"included", "finalized"}:
                connection.execute(
                    """
                    UPDATE transactions SET state = 'included'
                    WHERE transaction_id = ?
                    """,
                    (transaction_id,),
                )
                self.store.append_transition(
                    connection,
                    entity_kind="transaction",
                    entity_id=transaction_id,
                    from_state=str(current["state"]),
                    to_state="included",
                    payload={
                        "transaction_raw_sha256": transaction_raw,
                        "receipt_raw_sha256": receipt_raw,
                    },
                )
        return CollectedTransaction(
            transaction_id=transaction_id,
            transaction_hash=transaction_hash,
            chain_id=tx.chain_id,
            block_number=observed_receipt.block_number,
            gas_used=observed_receipt.gas_used,
            execution_fee_wei=execution_fee,
            input_bytes=input_bytes,
            balance_snapshots=len(balance_rows),
        )

    def _put_rpc_raw(self, data: bytes, provider_id: str, kind: str) -> str:
        return self.store.put_raw(
            data,
            media_type="application/json",
            metadata={
                "source": "public_read_rpc",
                "provider_id": provider_id,
                "kind": kind,
            },
        )

    def _balance_count(self, transaction_id: str) -> int:
        with self.store.connect(read_only=True) as connection:
            return int(
                connection.execute(
                    """
                    SELECT count(*)
                    FROM account_snapshots AS snapshot
                    JOIN stages AS stage
                      ON stage.attempt_id = snapshot.attempt_id
                    JOIN intents AS intent ON intent.stage_id = stage.stage_id
                    JOIN transactions AS transaction_record
                      ON transaction_record.intent_id = intent.intent_id
                    WHERE transaction_record.transaction_id = ?
                    """,
                    (transaction_id,),
                ).fetchone()[0]
            )

    @staticmethod
    def _validate(
        *,
        transaction_hash: str,
        expected_chain_id: int,
        expected_nonce: int,
        transaction: PublicTransaction,
        receipt: PublicReceipt,
        block: PublicBlockHeader,
    ) -> None:
        if (
            transaction.transaction_hash.lower() != transaction_hash.lower()
            or receipt.transaction_hash.lower() != transaction_hash.lower()
        ):
            raise EvmCollectorError("transaction or receipt hash mismatch")
        if (
            transaction.chain_id != expected_chain_id
            or transaction.nonce != expected_nonce
        ):
            raise EvmCollectorError("transaction chain or nonce mismatch")
        if (
            receipt.block_number != block.block_number
            or receipt.block_hash.lower() != block.block_hash.lower()
        ):
            raise EvmCollectorError("receipt and block header mismatch")
        if receipt.status not in {0, 1}:
            raise EvmCollectorError("receipt status is invalid")
        numeric = (
            transaction.value_wei,
            receipt.block_number,
            receipt.gas_used,
            receipt.effective_gas_price_wei,
            receipt.carrier_payment_wei,
            block.timestamp,
        )
        if min(numeric) < 0:
            raise EvmCollectorError("public resource value cannot be negative")
        if receipt.funding_attribution not in {"experiment", "external"}:
            raise EvmCollectorError("funding attribution is invalid")
        if (
            receipt.l1_data_fee_wei is None
            and not receipt.l1_data_fee_unavailable_reason
        ) or (
            receipt.l1_data_fee_wei is not None
            and receipt.l1_data_fee_unavailable_reason is not None
        ):
            raise EvmCollectorError(
                "L1 data fee needs exactly one value or unavailable reason"
            )
        if (
            receipt.l1_data_fee_wei is not None
            and receipt.l1_data_fee_wei < 0
        ):
            raise EvmCollectorError("L1 data fee cannot be negative")
        if len({log.log_index for log in receipt.logs}) != len(receipt.logs):
            raise EvmCollectorError("receipt log indices must be unique")
        try:
            bytes.fromhex(transaction.input_hex.removeprefix("0x"))
        except ValueError as exc:
            raise EvmCollectorError("transaction input is not exact hex bytes") from exc


def _address(value: str) -> bool:
    try:
        return len(value) == 42 and value.startswith("0x") and int(value, 16) != 0
    except ValueError:
        return False
