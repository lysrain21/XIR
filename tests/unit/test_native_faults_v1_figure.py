from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "native-faults-v1-summary.json"


def render(output: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "render_native_faults_v1.py"),
            "--summary",
            str(FIXTURE),
            "--schema-root",
            str(ROOT / "schemas"),
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_recovery_overview_is_byte_deterministic_and_font_self_contained(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    render(first)
    render(second)
    for name in (
        "recovery-overview.pdf",
        "recovery-overview.svg",
        "recovery-overview.csv",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    source = json.loads((first / "recovery-overview-source.json").read_text(encoding="utf-8"))
    layout = source["layout"]
    assert 0.60 <= layout["nominal_content_region_occupancy"] <= 0.63
    assert layout["font_roles"] == 3
    assert layout["line_styles"] <= 3
    assert len(layout["palette"]) == 3
    pdf = (first / "recovery-overview.pdf").read_bytes()
    svg = (first / "recovery-overview.svg").read_text(encoding="utf-8")
    assert b"/FontFile2" in pdf
    assert "<text" not in svg
    assert "DejaVuSans" in svg
    csv_rows = (first / "recovery-overview.csv").read_text(encoding="utf-8").splitlines()
    assert len(csv_rows) == 21
    assert csv_rows[0] == (
        "code,category,route,scenario,boundary,signed_tx_reuse,effect_invariant,validated,planned"
    )
    assert any(",same raw,exactly_one_destination_effect," in row for row in csv_rows[1:])
    assert source["visual_semantics"]["same raw"].endswith("raw signed bytes, hash, and nonce")
