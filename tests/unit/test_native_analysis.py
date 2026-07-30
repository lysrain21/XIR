import sqlite3
from typing import Any, cast

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.analysis import (
    _expected_cumulative_per_route,
    _install_guid_scope,
    _logs,
)


def test_phase_cumulative_denominators_are_explicit() -> None:
    profile = {
        "progression": {
            "smoke_attempts_per_route": 10,
            "rehearsal_attempts_per_route": 250,
            "scale_attempts_per_route": 10_000,
        }
    }
    assert _expected_cumulative_per_route(profile, "smoke") == 10
    assert _expected_cumulative_per_route(profile, "rehearsal") == 260
    assert _expected_cumulative_per_route(profile, "scale") == 10_260


class _FixtureEth:
    block_number = 7

    def __init__(self) -> None:
        self.filters: list[dict[str, Any]] = []

    def get_logs(self, filter_params: dict[str, Any]) -> list[dict[str, Any]]:
        self.filters.append(filter_params)
        return [{"blockNumber": filter_params["fromBlock"]}]


class _FixtureClient:
    def __init__(self) -> None:
        self.eth = _FixtureEth()


def test_logs_queries_frozen_head_in_non_overlapping_chunks() -> None:
    client = _FixtureClient()

    logs = _logs(
        cast(Any, client),
        "0x" + "11" * 20,
        "0x" + "22" * 32,
        0,
        chunk_blocks=3,
    )

    assert [(row["fromBlock"], row["toBlock"]) for row in client.eth.filters] == [
        (0, 2),
        (3, 5),
        (6, 7),
    ]
    assert [row["blockNumber"] for row in logs] == [0, 3, 6]


def test_logs_rejects_non_positive_chunk_size() -> None:
    with pytest.raises(LocalTopologyError, match="chunk size"):
        _logs(
            cast(Any, _FixtureClient()),
            "0x" + "11" * 20,
            "0x" + "22" * 32,
            0,
            chunk_blocks=0,
        )


def test_guid_scope_supports_more_values_than_sql_variable_limit() -> None:
    connection = sqlite3.connect(":memory:")
    guids = [f"0x{number:064x}" for number in range(2_000)]

    _install_guid_scope(connection, guids)

    assert connection.execute(
        "SELECT COUNT(*) FROM native_scoped_guids"
    ).fetchone()[0] == 2_000
