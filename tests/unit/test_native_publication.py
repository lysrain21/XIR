import json
from pathlib import Path

from xir_lab.native.publication import (
    freeze_manifest,
    render_report,
    verify_manifest,
)


def test_native_manifest_binds_sensitive_files_without_publishing_bytes(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    repository = tmp_path / "repository"
    (runtime / "private").mkdir(parents=True)
    repository.mkdir()
    (runtime / "private" / "worker.key").write_text("secret", encoding="utf-8")
    (runtime / "results.json").write_text("{}\n", encoding="utf-8")
    (repository / "source.py").write_text("value = 1\n", encoding="utf-8")
    document = freeze_manifest(
        runtime_root=runtime, repository_root=repository, excluded=set()
    )
    assert verify_manifest(document, runtime) == []
    sensitive = next(
        item
        for item in document["artifacts"]
        if item["path"] == "private/worker.key"
    )
    assert sensitive["classification"] == "sensitive-retained-not-published"
    assert "secret" not in json.dumps(document)


def test_native_report_states_self_hosted_boundary() -> None:
    report = render_report(
        profile={"chains": [{"chain_id": 1}, {"chain_id": 2}, {"chain_id": 3}]},
        provenance={"components": [{"component_id": "p", "commit": "abc"}]},
        deployment={"schema_version": "deployment-v1"},
        reconciliation={
            "valid": True,
            "denominator": {"logical_attempts": 4},
            "observed": {
                "cumulative_effects": 4,
                "cumulative_xir_transitions": 2,
                "protocol_messages": {"hyperlane": 4, "layerzero_v2": 4},
                "physical_transactions": {"cumulative_unique": 12},
                "retries": {
                    "layerzero_raw_rebroadcasts": 1,
                    "runner_raw_replacements": 2,
                    "runner_transient_rpc_retries": 3,
                    "semantic_retry_attempts": 0,
                },
            },
        },
        analysis={
            "phase": "scale",
            "per_route": [
                {
                    "route": route,
                    "logical_attempts": 1,
                    "success_rate": 1.0,
                    "latency_seconds_mean": 1.0,
                    "latency_seconds_p95": 1.0,
                    "coordinator_gas_used": 1,
                    "xir": route in {"HL", "LH"},
                }
                for route in ("HH", "LL", "HL", "LH")
            ],
            "phase_wall_seconds": 4.0,
            "throughput_logical_attempts_per_second": 1.0,
            "resource_samples": 1,
            "resource_sampling_gaps": 0,
            "observed_process_restarts": 0,
            "resource_extrema": {
                "minimum_memory_available_bytes": 1,
                "minimum_gpfs_free_bytes": 2,
                "minimum_docker_free_bytes": 3,
            },
        },
        manifest_sha256="0" * 64,
        evidence_pointer="/runtime",
    )
    assert "self-hosted XIR research worker" in report
    assert "not a LayerZero Labs managed service" in report
    assert "runner raw transaction" in report
    assert "replacements `2`" in report
    assert "transient RPC retries `3`" in report
    assert "semantic attempt retries" in report
    assert "`0`" in report
