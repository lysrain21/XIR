"""Explicit fault-injection boundaries used by recovery tests only."""

from __future__ import annotations

from typing import Literal, Protocol

CrashPoint = Literal[
    "before_prepared_intent_commit",
    "after_prepared_intent_commit",
    "after_signer_return",
    "during_spool_temporary_write",
    "after_spool_file_fsync",
    "after_spool_rename_before_directory_fsync",
    "after_spool_directory_fsync_before_database_reference",
    "after_hash_reference_persistence",
    "after_broadcast_before_acknowledgement",
    "after_acknowledgement_before_receipt",
    "after_receipt_before_raw_commit",
    "after_raw_commit_before_normalized_commit",
]


class InjectedCrash(RuntimeError):
    """Raised to emulate abrupt process loss at one durable boundary."""


class CrashInjector(Protocol):
    def hit(self, point: CrashPoint) -> None:
        """Crash at the selected boundary or return immediately."""


class NoCrashInjector:
    def hit(self, point: CrashPoint) -> None:
        del point


class OneShotCrashInjector:
    """Deterministic test injector that fires at most once."""

    def __init__(self, point: CrashPoint) -> None:
        self.point = point
        self.fired = False
        self.visited: list[CrashPoint] = []

    def hit(self, point: CrashPoint) -> None:
        self.visited.append(point)
        if point == self.point and not self.fired:
            self.fired = True
            raise InjectedCrash(point)
