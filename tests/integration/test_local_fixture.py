from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "local" / "eight-paths-v1.json"


def test_recorded_local_fixture_covers_all_eight_paths() -> None:
    document: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    paths = document["paths"]
    assert len(paths) == 8
    assert {(path["condition"], path["arm"]) for path in paths} == {
        (condition, arm)
        for condition in ("HH", "HL", "LH", "LL")
        for arm in ("baseline", "xir")
    }
    assert document["network_chain_ids"] == [11155420, 421614, 84532]
    assert document["payload_sha256"] == hashlib.sha256(b"fixed-payload").hexdigest()


def test_fixture_keeps_physical_transactions_and_labels_distinct() -> None:
    document: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for path in document["paths"]:
        assert path["physical_transactions"] == 3
        assert path["accounting_buckets"] == ["source", "intermediate", "destination"]
        if path["arm"] == "baseline":
            assert path["logical_label_count"] == 7
            assert path["xir_work_count"] == 0
        else:
            assert path["logical_label_count"] == 10
            assert path["xir_work_count"] == 3
