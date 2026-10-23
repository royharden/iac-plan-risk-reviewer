"""Fixed development fake/protocol benchmark source; no provider/plugin/live mode.

Do not run during Dirty Mode. Successful plumbing is still NOT_MEASURED/exit 2.
"""
from __future__ import annotations

import argparse
from datetime import date
from decimal import Decimal
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from iac_review.attempts import AttemptJournal, Budget, PriceIdentity  # noqa: E402
from eval.model.experiment import Limits as ModelLimits, canonical, digest  # noqa: E402
from eval.model.transport import FakeTransport, Reply, Usage  # noqa: E402
from eval.runner.benchmark import (BenchmarkConfig, CaseSpec, coordinate, source_build_digest, validate_config)  # noqa: E402
from eval.scanners.runner import SHA256, bounded_read, strict_json  # noqa: E402
from iac_review.contracts.manifest import RunManifest  # noqa: E402


def config_from_json(value: dict) -> BenchmarkConfig:
    required = {"schema_version", "run_id", "edition_id", "build_sha256", "input_scope", "fake_only",
                "synthetic_input_attested", "cases", "budget"}
    if (not isinstance(value, dict) or not required <= set(value)
            or set(value) - required - {"model_limits", "scanner_arms"}
            or value["schema_version"] != "m4-seven-arm-benchmark-config-v1"):
        raise ValueError("closed_fixed_benchmark_configuration_required")
    if not isinstance(value["cases"], list) or not 0 < len(value["cases"]) <= 256:
        raise ValueError("bounded_case_inventory_required")
    cases = []
    for row in value["cases"]:
        case_required = set(CaseSpec.__dataclass_fields__) - {"case_record_sha256"}
        if (not isinstance(row, dict) or not case_required <= set(row)
                or set(row) - set(CaseSpec.__dataclass_fields__)):
            raise ValueError("closed_case_metadata_required")
        if not isinstance(row["plan_path"], str):
            raise ValueError("case_path_string_required")
        cases.append(CaseSpec(**dict(row, plan_path=Path(row["plan_path"]))))
    config = BenchmarkConfig(run_id=value["run_id"], edition_id=value["edition_id"],
        build_sha256=value["build_sha256"], cases=tuple(cases),
        budget=Budget.model_validate_json(json.dumps(value["budget"])),
        model_limits=ModelLimits(**value.get("model_limits", {})),
        scanner_arms_json=json.dumps(value.get("scanner_arms", {}), allow_nan=False),
        input_scope=value["input_scope"], fake_only=value["fake_only"],
        synthetic_input_attested=value["synthetic_input_attested"])
    validate_config(config)
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True, help="external SHA256 of exact configuration file bytes")
    parser.add_argument("--manifest-context", type=Path, help="optional shared typed metadata-only RunManifest context")
    parser.add_argument("--manifest-context-sha256", help="external canonical record digest, not raw file digest")
    parser.add_argument("--out", type=Path, required=True, help="new run directly under product results/")
    parser.add_argument("--fake-scenario", choices=("valid", "unknown-usage", "timeout", "error"), default="valid")
    args = parser.parse_args()
    try:
        raw_config = bounded_read(args.config, 2 * 1024 * 1024)
        if not SHA256.fullmatch(args.config_sha256) or digest(raw_config) != args.config_sha256:
            raise ValueError("external_configuration_file_pin_mismatch")
        value = strict_json(raw_config)
        config = config_from_json(value)  # Scope rejects before any case/output access.
        if (args.manifest_context is None) != (args.manifest_context_sha256 is None):
            raise ValueError("manifest_context_and_external_pin_required_together")
        context = None
        if args.manifest_context is not None:
            context = RunManifest.model_validate_json(json.dumps(strict_json(
                bounded_read(args.manifest_context, 4 * 1024 * 1024))))
            if digest(canonical(context.model_dump(mode="json"))) != args.manifest_context_sha256:
                raise ValueError("external_manifest_context_pin_mismatch")
        if source_build_digest() != config.build_sha256:
            raise ValueError("actual_source_build_mismatch")
        output = args.out.absolute()
        product = Path(__file__).resolve().parents[1]
        if (output.exists() or output.parent.resolve() != (product / "results").resolve()
                or any(parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())
                       for parent in (output, *output.parents))):
            raise ValueError("exclusive_product_results_directory_required")
        transport = FakeTransport() if args.fake_scenario == "valid" else FakeTransport(
            Reply("error") if args.fake_scenario == "unknown-usage" else
            Reply(args.fake_scenario, usage=Usage(0, 0, Decimal(0))))
        identity = transport.identity
        price = PriceIdentity(provider=identity.provider, model=identity.model,
                              price_id="mock-zero-not-provider-price", price_date=date.today().isoformat(),
                              input_usd_per_million=Decimal(0), output_usd_per_million=Decimal(0))
        output.mkdir(parents=True, exist_ok=False)
        (output / "private").mkdir()
        (output / "shareable").mkdir()
        journal_path = output / "private" / "attempts.jsonl"
        journal_path.touch(exist_ok=False)
        with AttemptJournal(journal_path, config.budget, price) as journal:
            result = coordinate(config, journal=journal, transport=transport, manifest_context=context,
                expected_manifest_context_sha256=args.manifest_context_sha256,
                build_verifier=source_build_digest, operator_config_sha256=args.config_sha256)
            files = (("private/provenance.json", result.private_provenance_json),
                     ("private/run-manifest-candidate.json", result.manifest_candidate_json),
                     ("shareable/summary.json", result.public_summary_json))
            for name, text in files:
                payload = (text + "\n").encode("utf-8")
                if len(payload) > 64 * 1024 * 1024:
                    raise ValueError("benchmark_metadata_output_bound")
                with (output / name).open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                if digest(bounded_read(output / name, 64 * 1024 * 1024)) != digest(payload):
                    raise ValueError("written_artifact_digest_mismatch")
            total = 0
            with (output / "private" / "rows.jsonl").open("xb") as stream:
                for row in result.rows:
                    payload = (row.model_dump_json() + "\n").encode("utf-8")
                    total += len(payload)
                    if total > 64 * 1024 * 1024:
                        raise ValueError("benchmark_row_output_bound")
                    stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        print(result.public_summary_json)
        return 2  # No fake/protocol run closes measurement or product acceptance.
    except (ValueError, OSError, TypeError, KeyError, RuntimeError):
        print("benchmark refused or incomplete; preserve any partial private journal for reconciliation", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
