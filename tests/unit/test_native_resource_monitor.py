import json
from pathlib import Path

from xir_lab.native.monitor import (
    capacity_stop_reason,
    write_stop_request,
)


def test_capacity_stop_reason_is_none_above_both_reserves() -> None:
    assert (
        capacity_stop_reason(
            docker_free_bytes=30,
            gpfs_free_bytes=50,
            minimum_docker_free_bytes=8,
            minimum_gpfs_free_bytes=40,
        )
        is None
    )


def test_capacity_stop_reason_records_each_breach() -> None:
    assert capacity_stop_reason(
        docker_free_bytes=7,
        gpfs_free_bytes=39,
        minimum_docker_free_bytes=8,
        minimum_gpfs_free_bytes=40,
    ) == {
        "docker_free_bytes": 7,
        "gpfs_free_bytes": 39,
        "minimum_docker_free_bytes": 8,
        "minimum_gpfs_free_bytes": 40,
    }


def test_stop_request_is_complete_json(tmp_path: Path) -> None:
    path = tmp_path / "submissions.stop"
    write_stop_request(path, {"reason": "fixture"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"reason": "fixture"}
    assert not path.with_suffix(".stop.tmp").exists()
