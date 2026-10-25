"""Independent public tests for approved R03 pinned evidence transactions.

No hidden oracle or detector-derived expected labels. Object roots remain existence
summaries. A restored change between boundary observations may go undetected; this
suite does not claim continuous monitoring or preserve per-fact observation points.
"""
from time import monotonic

import pytest

from iac_review import evidence
from iac_review.contracts import ValueState
from iac_review.ingest import MAX_SECONDS, InputError, SourceChangedError, load_plan


def batch(plan, refs, *, deadline=None):
    result = evidence.resolve_many(plan, tuple(refs), deadline=deadline)
    assert type(result) is tuple, "A closed batch must not expose a lazy/partial iterator"
    return result


def wire_rows(results):
    return tuple(row.model_dump_json() for row in results)


@pytest.mark.parametrize("after,masks,tokens,state,status", [
    ({"value": False}, {}, ("value",), "known", "resolved"),
    ({"value": None}, {}, ("value",), "null", "resolved"),
    ({}, {}, ("missing",), "absent", "resolved"),
    ({"value": [False, 0, 0.0]}, {}, ("value",), "known", "resolved"),
    ({"value": 7}, {"after_unknown": {"value": True}}, ("value",), "unknown", "unknown"),
    ({"nest": {"value": 7}}, {"after_unknown": {"nest": True}},
     ("nest", "value"), "unknown", "unknown"),
    ({"value": "BATCH_MASK_CANARY"}, {"after_sensitive": {"value": True}},
     ("value",), "unknown", "sensitive"),
    ({"nest": {"value": "BATCH_MASK_CANARY"}}, {"after_sensitive": True},
     ("nest", "value"), "unknown", "sensitive"),
    ({"a/b~c": 17}, {}, ("a/b~c",), "known", "resolved"),
    ({"values": [4, 9, 2]}, {}, ("values", 1), "known", "resolved"),
    ({"object": {"tag": "BATCH_CONTAINER_CANARY"}}, {}, ("object",), "known", "resolved"),
    ({"nested": [{"tag": "BATCH_CONTAINER_CANARY"}]}, {}, ("nested",), "unknown", "unknown"),
])
def test_fixed_source_equivalence_and_privacy(core_change, core_plan_file, after, masks,
                                            tokens, state, status):
    path = core_plan_file([core_change(after=after, change_fields=masks)])
    plan = load_plan(path)
    ref = evidence.make_ref(plan, plan.resources[0], "after", tokens)
    standalone = evidence.resolve(plan, ref)
    result, = batch(plan, [ref])
    assert (result.value.state, result.status) == (state, status)
    assert wire_rows([result]) == wire_rows([standalone])
    assert "BATCH_MASK_CANARY" not in result.model_dump_json()
    assert "BATCH_CONTAINER_CANARY" not in result.model_dump_json()


def test_order_duplicates_and_duplicate_fact_ids_are_not_deduplicated(core_change, core_plan_file):
    plan = load_plan(core_plan_file([core_change(after={"values": [7, 2, 9]})]))
    refs = [evidence.make_ref(plan, plan.resources[0], "after", ("values", i)) for i in (2, 0, 1)]
    refs[2] = refs[2].model_copy(update={"fact_id": refs[0].fact_id, "role": "supporting"})
    ordered = [refs[0], refs[1], refs[0], refs[2]]
    results = batch(plan, ordered)
    assert len(results) == 4
    assert [row.value.value for row in results] == [9, 7, 9, 2]
    assert [row.ref.fact_id for row in results] == [ref.fact_id for ref in ordered]
    assert [row.ref.role for row in results] == [ref.role for ref in ordered]
    assert wire_rows(results) == wire_rows(evidence.resolve(plan, ref) for ref in ordered)


@pytest.mark.parametrize("change", [
    {"plan_sha256": "0" * 64}, {"resource_key": "foreign"}, {"resource_index": 99},
    {"pointer": "/resource_changes/00/change/after/value"},
    {"pointer": "/resource_changes/0/change/before/value"},
    {"expected": ValueState(state="known", value=0)},
    {"expected": ValueState(state="known", value=0.0)},
])
def test_bad_reference_has_same_mismatch_without_contaminating_valid_neighbor(
    core_change, core_plan_file, change,
):
    plan = load_plan(core_plan_file([core_change(after={"value": False})]))
    good = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    bad = good.model_copy(update=change)
    results = batch(plan, [good, bad, good])
    assert [row.status for row in results] == ["resolved", "mismatch", "resolved"]
    assert wire_rows(results) == wire_rows(evidence.resolve(plan, ref) for ref in [good, bad, good])


def test_batch_reads_fresh_pinned_bytes_instead_of_mutable_plan_raw(core_change, core_plan_file):
    plan = load_plan(core_plan_file([core_change(after={"value": False})]))
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    plan.raw["resource_changes"][0]["change"]["after"]["value"] = True
    result, = batch(plan, [ref])
    assert result.status == "resolved" and result.value.value is False


def test_two_boundary_reads_are_invocation_local_and_standalone_still_reopens(
    core_change, core_plan_file, monkeypatch,
):
    source = core_plan_file([core_change(after={"value": False})])
    plan = load_plan(source)
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    safe_reader = evidence.read_source_bytes
    calls = []

    def observed(path, *args, **kwargs):
        calls.append(str(path))
        return safe_reader(path, *args, **kwargs)

    monkeypatch.setattr(evidence, "read_source_bytes", observed)
    assert len(batch(plan, [ref, ref, ref])) == 3
    assert len(calls) == 2
    assert len(batch(plan, [ref])) == 1
    assert len(calls) == 4
    evidence.resolve(plan, ref)
    evidence.resolve(plan, ref)
    assert len(calls) == 6
    source.write_bytes(source.read_bytes() + b" ")
    with pytest.raises(SourceChangedError):
        batch(plan, [ref])


@pytest.mark.parametrize("boundary", ["entry", "exit"])
def test_persistent_mutation_aborts_whole_batch(core_change, core_plan_file, monkeypatch, boundary):
    source = core_plan_file([core_change(after={"value": False})])
    plan = load_plan(source)
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    if boundary == "entry":
        source.write_bytes(source.read_bytes() + b" ")
    else:
        safe_reader = evidence.read_source_bytes
        calls = 0

        def mutate_after_entry(path, *args, **kwargs):
            nonlocal calls
            raw = safe_reader(path, *args, **kwargs)
            calls += 1
            if calls == 1:
                source.write_bytes(raw + b" ")
            return raw

        monkeypatch.setattr(evidence, "read_source_bytes", mutate_after_entry)
    with pytest.raises(SourceChangedError):
        batch(plan, [ref, ref, ref])


@pytest.mark.parametrize("fail_at", [1, 2])
@pytest.mark.parametrize("reason", ["source_link_rejected", "ancestor_junction_rejected",
                                   "source_read_identity_changed", "source_unreadable"])
def test_safe_reader_failure_at_either_boundary_cannot_return_partial_results(
    core_change, core_plan_file, monkeypatch, fail_at, reason,
):
    # Inject the canonical safe reader's rejection, not an actual OS link check.
    # Actual link/junction filesystem admission remains a separately recorded check.
    plan = load_plan(core_plan_file([core_change(after={"value": 7})]))
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    safe_reader = evidence.read_source_bytes
    calls = 0

    def rejecting(path, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise InputError(reason)
        return safe_reader(path, *args, **kwargs)

    monkeypatch.setattr(evidence, "read_source_bytes", rejecting)
    with pytest.raises(InputError, match=reason):
        batch(plan, [ref, ref])


def test_expired_absolute_deadline_refuses_transaction(core_change, core_plan_file):
    plan = load_plan(core_plan_file([core_change(after={"value": 7})]))
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    with pytest.raises(InputError):
        batch(plan, [ref], deadline=monotonic() - 1)


def test_restored_change_between_observations_has_no_continuous_monitoring_claim(
    core_change, core_plan_file, monkeypatch,
):
    source = core_plan_file([core_change(after={"value": False})])
    original = source.read_bytes()
    plan = load_plan(source)
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    safe_reader = evidence.read_source_bytes
    changed = False

    def restored_after_read(path, *args, **kwargs):
        nonlocal changed
        raw = safe_reader(path, *args, **kwargs)
        if not changed:
            source.write_bytes(original + b" ")
            source.write_bytes(original)
            changed = True
        return raw

    monkeypatch.setattr(evidence, "read_source_bytes", restored_after_read)
    try:
        results = batch(plan, [ref])
    except SourceChangedError:
        # Extra observations may reject the transient change; rejection is valid.
        pass
    else:
        assert len(results) == 1 and results[0].status == "resolved"
        assert results[0].value.value is False
    assert changed and source.read_bytes() == original


def test_direct_symlink_source_is_refused_when_platform_supports_it(
    core_change, core_plan_file, tmp_path,
):
    source = core_plan_file([core_change(after={"value": 7})])
    plan = load_plan(source)
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    link = tmp_path / "linked-plan.json"
    try:
        link.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"OS symlink admission not exercised: {type(exc).__name__}")
    linked = plan.model_copy(update={"source_path": str(link)})
    with pytest.raises(InputError):
        batch(linked, [ref])


def test_original_large_cidr_review_meets_unchanged_budget_and_finalizes_safe_bundle(
    core_change, core_plan_file, tmp_path, monkeypatch, record_property,
):
    from time import process_time

    from iac_review.contracts.report_wire import validate_report_pair
    from iac_review.report import build_report, write_report
    from iac_review.rules import evaluate
    from iac_review.source_view import verify_report

    cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(200)]
    shape = {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
             "cidr_blocks": cidrs, "ipv6_cidr_blocks": [],
             "tags": {"note": "BATCH_PUBLIC_PROJECTION_CANARY"}}
    entry = core_change("aws_security_group_rule", actions=("update",), before=shape,
                        after={**shape, "cidr_blocks": [*cidrs, "0.0.0.0/0"]},
                        change_fields={"after_sensitive": {"tags": True}})
    source = core_plan_file([entry])
    safe_reader = evidence.read_source_bytes
    reads = 0

    def counted(path, *args, **kwargs):
        nonlocal reads
        reads += 1
        return safe_reader(path, *args, **kwargs)

    monkeypatch.setattr(evidence, "read_source_bytes", counted)
    started = monotonic()
    cpu_started = process_time()
    plan = load_plan(source)
    report = build_report(plan, evaluate(plan))
    row = next(row for row in report.private["evaluations"] if row["rule_id"] == "R1")
    assert row["outcome"] == "introduced_risk"
    assert len(row["facts"]) > 256
    assert report.exit_code == 1 and report.shareable["summary"]["risk_present"] is True
    validate_report_pair(report.private, report.shareable, exit_code=report.exit_code)
    out = tmp_path / "large-cidr-report"
    write_report(report, out, deadline=started + MAX_SECONDS)
    elapsed = monotonic() - started
    record_property("input_through_export_wall_seconds", elapsed)
    record_property("input_through_export_cpu_seconds", process_time() - cpu_started)
    record_property("evidence_source_reads_through_export", reads)
    record_property("r1_fact_count", len(row["facts"]))
    assert elapsed < MAX_SECONDS  # No larger timeout and no mocked clock.
    assert reads <= 6, "Hundreds of per-fact reopens must not return in report construction"
    verified = verify_report(out, source)
    assert verified["artifacts_verified"] == 5 and verified["run_manifest_bound"] is True
    assert verified["product_acceptance"] is False
    for name in ("private.json", "shareable.json", "private.html", "shareable.html"):
        assert "BATCH_PUBLIC_PROJECTION_CANARY" not in (out / name).read_text(encoding="utf-8")


def test_actual_windows_ancestor_junction_is_refused(core_change, core_plan_file, tmp_path):
    import os
    import subprocess

    if os.name != "nt":
        pytest.skip("Windows junction admission not exercised on this platform")
    source = core_plan_file([core_change(after={"value": 7})])
    plan = load_plan(source)
    ref = evidence.make_ref(plan, plan.resources[0], "after", ("value",))
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "plan.json").write_bytes(source.read_bytes())
    junction = tmp_path / "junction-alias"
    created = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                             capture_output=True, timeout=10, check=False)
    if created.returncode:
        pytest.skip("OS junction creation unavailable; rejection is not runtime-proven")
    linked = plan.model_copy(update={"source_path": str(junction / "plan.json")})
    with pytest.raises(InputError):
        batch(linked, [ref])
