"""Private producer/assessment regression SOURCE only; no runtime validation claim."""
import base64
from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path

import pytest

from eval.model.assessment_capture import build_capture, write_private_capture
from eval.model.experiment import Attempt, Context, FindingLink, Observation, Result, canonical, digest
from eval.model.explanation_artifacts import ExplanationArtifact, digest as artifact_digest
from eval.model.provenance import export_bundle
from eval.runner.scoring import ArmRow
from eval.model.driver import DriverConfig, run_driver
from eval.model.transport import FakeTransport, Reply, Request, Usage

GENERATOR = "7" * 32


def _result(payload: bytes | None, *, status: str = "invalid", complete: bool = True) -> Result:
    context = Context(build_sha256="a" * 64, source_sha256="b" * 64,
                      corpus_sha256="c" * 64, config_sha256="d" * 64)
    baseline = ArmRow(case_id="1" * 32, resource_id="2" * 32, rule_id="R2", arm="D", status="ok",
                      applicability="supported", outcome="introduced_risk", reason_code="public_access_false_to_true",
                      decision_fact_ids=("4" * 32,), source_sha256=context.source_sha256,
                      build_sha256=context.build_sha256, measurement_ref="sha256:" + "0" * 64)
    attempt = Attempt(attempt_id="5" * 32, arm="P", status=status, duration_ms=1,
                      input_tokens=0, output_tokens=0, known_usd="0", unresolved_usd_upper="0",
                      billing_known=status != "timeout", hashes=tuple(sorted({
                          "build": context.build_sha256, "corpus": context.corpus_sha256,
                          "projection": "e" * 64, "prompt": "f" * 64, "input": "0" * 64,
                          "model": "1" * 64, "config": context.config_sha256}.items())),
                      response_sha256=digest(payload) if payload is not None and complete else None,
                      price_sha256="2" * 64, usage_sha256="3" * 64,
                      requires_reconciliation=status == "timeout")
    obs = Observation("P", "3" * 32, status, "synthetic_fixture", attempt,
                      fact_ids=("4" * 32,), required_limitation_ids=("indeterminate",),
                      private_response=payload, private_response_complete=complete)
    return Result(context, (baseline,), digest(canonical([baseline.model_dump(mode="json")])),
                  (FindingLink("3" * 32, baseline.case_id, baseline.resource_id, "R2"),),
                  (obs,), (), "{}")


@pytest.mark.parametrize("status", ["ok", "invalid", "error", "timeout", "cancelled"])
def test_exact_failed_or_withheld_text_uses_actual_D7_wire_without_labels(status: str) -> None:
    """Catches filtering invalid prose, joining claims, invented labels or hash conflation."""
    raw = b'{"claims":["<script>untrusted()</script>","second claim"]}'
    result = _result(raw, status=status)
    capture = build_capture(result, generator_actor_ids=(GENERATOR,))
    assert len(capture.artifacts) == 1
    artifact = capture.artifacts[0]
    assert type(artifact) is ExplanationArtifact
    assert artifact.prose.encode("utf-8") == raw
    assert artifact.prose_sha256 == artifact.response_sha256 == digest(raw)
    assert artifact.raw_input_sha256 == result.context.source_sha256
    assert artifact.projection_sha256 != artifact.raw_input_sha256
    assert artifact.explanation_withheld is True and artifact.live_eligible is False
    assert artifact.fact_ids == ("4" * 32,) and artifact.limitation_ids == ("indeterminate",)
    assert json.loads(capture.outcomes_json)[0]["status"] == status
    assert json.loads(capture.outcomes_json)[0]["artifact_sha256"] == artifact_digest(artifact)


@pytest.mark.parametrize("raw", [b"unsafe\x1b[31mcontrol", b"invalid-utf8-\xff"])
def test_unrepresentable_output_is_lossless_diagnostic_never_fake_prose(raw: bytes) -> None:
    """Catches dropping invalid bytes or relabeling sanitized text as the exact response."""
    capture = build_capture(_result(raw), generator_actor_ids=(GENERATOR,))
    assert capture.artifacts == () and len(capture.diagnostics) == 1
    diagnostic = json.loads(capture.diagnostics[0][1])
    assert base64.b64decode(diagnostic["response_prefix_base64"]) == raw
    assert diagnostic["capture_state"] == "artifact_wire_rejected"
    assert diagnostic["semantic_assessment_complete"] is False


def test_truncated_and_absent_output_stay_explicitly_incomplete() -> None:
    """Catches presenting a retained prefix or absent response as a complete explanation."""
    for result in (_result(b"prefix", complete=False), _result(None)):
        capture = build_capture(result, generator_actor_ids=(GENERATOR,))
        assert capture.artifacts == ()
        assert json.loads(capture.outcomes_json)[0]["semantic_assessment_complete"] is False
        assert len(capture.diagnostics) == 1


def test_default_export_remains_payload_free_and_D_is_unchanged() -> None:
    """Catches private bytes/HTML leaking into all-attempt exports or mutating D."""
    secret = b'{"claims":["synthetic-private-output-canary"]}'
    result = _result(secret)
    before = result.baseline[0].model_dump_json()
    build_capture(result, generator_actor_ids=(GENERATOR,))
    bundle = export_bundle(result)
    assert "synthetic-private-output-canary" not in (bundle.attempts_json + bundle.provenance_json
                                                     + bundle.accounting_json + bundle.observations_json)
    assert bundle.rows[0].model_dump_json() == before
    assert all(row.status == "not_run" for row in bundle.rows if row.arm != "D")


def test_capture_refuses_response_tamper_and_live_promotion() -> None:
    """Catches producer response/hash mismatch or a caller labeling mock capture as live."""
    result = _result(b"original")
    changed = replace(result.observations[0], private_response=b"changed")
    with pytest.raises(ValueError, match="digest_mismatch"):
        build_capture(replace(result, observations=(changed,)), generator_actor_ids=(GENERATOR,))
    with pytest.raises(ValueError, match="no_live_admission"):
        build_capture(result, generator_actor_ids=(GENERATOR,), origin="live")


def test_private_sink_is_fresh_opaque_JSON_data_only(tmp_path: Path) -> None:
    """Catches unsafe filenames, reuse, execution/rendering and silent partial capture success."""
    capture = build_capture(_result(b"<script>private data</script>"), generator_actor_ids=(GENERATOR,))
    out = tmp_path / "private"
    receipt = write_private_capture(capture, out)
    assert receipt["state"] == "WRITTEN" and receipt["live_eligible"] is False
    path = next(out.glob("artifact-*.json"))
    assert b"<script>" not in path.read_bytes()
    artifact = ExplanationArtifact.model_validate_json(path.read_bytes())
    assert artifact.prose == "<script>private data</script>"
    assert not list(out.glob("*.html"))
    with pytest.raises(ValueError, match="fresh_private"):
        write_private_capture(capture, out)


PLAN_CANARY = "synthetic_raw_plan_identity_never_send"
P_CANARY = "PRIVATE_UNTRUSTED_GENERATED_TEXT"


def _driver_config(tmp_path: Path, *, capture: bool) -> DriverConfig:
    source = tmp_path / "synthetic.json"
    source.write_text(json.dumps({
        "format_version": "1.2", "terraform_version": "1.9.0", "complete": True, "errored": False,
        "resource_changes": [{"address": "aws_db_instance." + PLAN_CANARY, "name": PLAN_CANARY,
            "mode": "managed", "provider_name": "registry.terraform.io/hashicorp/aws", "type": "aws_db_instance",
            "change": {"actions": ["update"], "before": {"publicly_accessible": False, "storage_encrypted": True},
                "after": {"publicly_accessible": True, "storage_encrypted": True, "tags": {"private": PLAN_CANARY}},
                "after_sensitive": {"tags": True}, "after_unknown": {}}}],
    }), encoding="utf-8")
    return DriverConfig(source, tmp_path / "run", True, 20, 2_000_000, 200_000, Decimal(0),
                        capture_private_prose=tmp_path / "private" if capture else None,
                        generator_actor_ids=(GENERATOR,) if capture else ())


class PTextFake(FakeTransport):
    def __init__(self, *, status="ok", raw: bytes | None = None) -> None:
        super().__init__()
        self.status = status
        self.raw = raw if raw is not None else (
            '{"claims":["<script>' + P_CANARY + '</script>"]}').encode("utf-8")
        self.requests = []

    def complete(self, request: Request) -> Reply:
        self.requests.append(request)
        if request.arm == "P":
            return Reply(self.status, self.raw, Usage(0, 0, Decimal(0)))
        return super().complete(request)


def test_driver_default_has_no_private_sink_or_generated_payload(tmp_path: Path) -> None:
    """Catches capture becoming default or raw P text leaking through the normal export."""
    config = _driver_config(tmp_path, capture=False)
    output = run_driver(config, transport=PTextFake()).read_text(encoding="utf-8")
    assert P_CANARY not in output and PLAN_CANARY not in output
    assert json.loads(output)["private_capture"] is None
    assert not (tmp_path / "private").exists()
    assert P_CANARY not in (config.out / "attempts.jsonl").read_text(encoding="utf-8")


def test_driver_index_round_trips_to_D7_manual_annotation_without_truth(tmp_path: Path) -> None:
    """Catches duplicate producer wires, invalid artifact joins, auto labels and unsafe rendering."""
    from eval.model.annotation import export_assessments, prepare_sheet, read_wire, render_worksheet
    from eval.model.explanation_artifacts import Rubric, SpanSpec, make_inventory

    config = _driver_config(tmp_path, capture=True)
    fake = PTextFake()
    ordinary = run_driver(config, transport=fake).read_text(encoding="utf-8")
    assert P_CANARY not in ordinary and PLAN_CANARY not in ordinary
    private = config.capture_private_prose
    assert private is not None
    index_bytes = (private / "artifact-index.json").read_bytes()
    index = json.loads(index_bytes)
    state = json.loads((private / "capture-state.json").read_bytes())
    assert state["state"] == "WRITTEN" and state["index_sha256"] == digest(index_bytes)
    assert json.loads(ordinary)["private_capture"]["index_sha256"] == digest(index_bytes)
    row = next(r for r in index["outcomes"] if r["artifact_id"] is not None)
    path = private / ("artifact-" + row["artifact_id"] + ".json")
    assert index["files"][path.name] == digest(path.read_bytes())
    artifact = read_wire(path, ExplanationArtifact)
    assert artifact_digest(artifact) == row["artifact_sha256"]
    assert artifact.prose.encode("utf-8") == fake.raw and PLAN_CANARY not in artifact.prose
    assert all(PLAN_CANARY not in request.payload_json for request in fake.requests)
    # Explicit synthetic HUMAN span input, not production automatic segmentation.
    inventory = make_inventory(artifact, (SpanSpec(start=0, end=len(artifact.prose), kind="claim", withheld=True),),
                               "9" * 32)
    rubric = Rubric(rubric_id="a" * 32, required_fact_ids=(), required_limitation_ids=())
    first = prepare_sheet(artifact, inventory, rubric, "8" * 32, "6" * 32)
    second = prepare_sheet(artifact, inventory, rubric, "6" * 32, "8" * 32)
    assert all(row.label is None for row in first.rows)
    worksheet = render_worksheet(artifact, inventory, rubric, first)
    assert "<script>" not in worksheet and "&lt;script&gt;" in worksheet
    assessment = export_assessments(artifact, inventory, rubric, first, second)
    assert assessment["complete"] is False and assessment["live_eligible"] is False
    assert assessment["metrics"] is None and assessment["generated"] > 0
    assert assessment["withheld_generated"] == assessment["generated"]


@pytest.mark.parametrize("status", ["invalid", "error", "timeout", "cancelled"])
def test_driver_retains_failed_P_text_and_outcomes_without_promoting(tmp_path: Path, status: str) -> None:
    """Catches keeping only successful model text or dropping failures after timeout halts."""
    config = _driver_config(tmp_path, capture=True)
    ordinary = json.loads(run_driver(config, transport=PTextFake(status=status)).read_text(encoding="utf-8"))
    index = json.loads((config.capture_private_prose / "artifact-index.json").read_bytes())
    assert any(row["status"] == status and row["artifact_id"] is not None for row in index["outcomes"])
    assert all(not row["semantic_assessment_complete"] for row in index["outcomes"])
    assert ordinary["accounting"]["requests"] == len(ordinary["attempts"])
    assert all(row["status"] == "not_run" for row in ordinary["rows"] if row["arm"] != "D")


def test_no_attempt_leaves_missing_L_counts_and_capture_outcomes(tmp_path: Path) -> None:
    """Catches fabricated word counts/artifacts when caps prevented all model requests."""
    from eval.model.experiment import Limits

    config = replace(_driver_config(tmp_path, capture=True), limits=Limits(max_input_bytes=1))
    ordinary = json.loads(run_driver(config).read_text(encoding="utf-8"))
    l_rows = [row for row in ordinary["observations"] if row["arm"] == "L"]
    assert l_rows and all(row["baseline_words"] > 0 and row["rendered_words"] is None for row in l_rows)
    index = json.loads((config.capture_private_prose / "artifact-index.json").read_bytes())
    assert index["artifact_count"] == 0
    assert all(row["attempt_id"] is None for row in index["outcomes"])


def test_L_counts_are_actual_finite_render_and_fallback_is_explicit(tmp_path: Path) -> None:
    """Catches made-up utility receipts or a failed selector counted as accepted model prose."""
    config = replace(_driver_config(tmp_path, capture=False), fake_scenario="invalid")
    ordinary = json.loads(run_driver(config).read_text(encoding="utf-8"))
    l_rows = [row for row in ordinary["observations"] if row["arm"] == "L"]
    assert l_rows and all(row["render_source"] == "deterministic_fallback" for row in l_rows)
    assert all(row["baseline_words"] == row["rendered_words"] > 0 for row in l_rows)
    assert all(row["word_counts_available"] and not row["selection_accepted"] for row in l_rows)


def test_driver_refuses_nested_sink_or_missing_generator_before_creating_run(tmp_path: Path) -> None:
    """Catches implicit capture authorization and private prose landing in ordinary exports."""
    config = _driver_config(tmp_path, capture=True)
    with pytest.raises(ValueError, match="separate_private"):
        run_driver(replace(config, capture_private_prose=config.out / "private"))
    with pytest.raises(ValueError, match="generator_ids_invalid"):
        run_driver(replace(config, generator_actor_ids=()))
    assert not config.out.exists() and not config.capture_private_prose.exists()
