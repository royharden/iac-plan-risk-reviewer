"""Manual private assessment bookkeeping, never automated semantic truth."""
from __future__ import annotations

from html import escape
from hashlib import sha256
import json
import os
from pathlib import Path
import re

from eval.model.explanation_artifacts import (
    AdjudicationSheet, AnnotationRow, AssessorSheet, ClaimInventory, ExplanationArtifact,
    Rubric, Wire, digest, validate_inventory,
)
from eval.model.protocol import ClaimAssessment, prose_metrics


def _claims(artifact, inventory, rubric):
    validate_inventory(artifact, inventory)
    if (not set(rubric.required_fact_ids) <= set(artifact.fact_ids)
            or not set(rubric.required_limitation_ids) <= set(artifact.limitation_ids)):
        raise ValueError("rubric contains foreign fact/limitation IDs")
    return {span.span_id: span for span in inventory.spans if span.kind == "claim"}


def _pins(artifact, inventory, rubric):
    return {"artifact_sha256": digest(artifact), "inventory_sha256": digest(inventory),
            "rubric_sha256": digest(rubric)}


def _actor(actor, artifact, others=()):
    if not re.fullmatch(r"[0-9a-f]{32}", actor) or actor in (*artifact.generator_actor_ids, *others):
        raise ValueError("distinct declared nonauthoring actor required; external authentication still needed")


def prepare_sheet(artifact: ExplanationArtifact, inventory: ClaimInventory, rubric: Rubric,
                  assessor_id: str, other_assessor_id: str) -> AssessorSheet:
    claims = _claims(artifact, inventory, rubric)
    _actor(assessor_id, artifact, (other_assessor_id,))
    _actor(other_assessor_id, artifact, (assessor_id,))
    return AssessorSheet(**_pins(artifact, inventory, rubric), assessor_id=assessor_id,
                         rows=tuple(AnnotationRow(claim_id=key, withheld=span.withheld)
                                    for key, span in claims.items()))


def _validate_rows(rows, claims, artifact, *, exact):
    mapping = {row.claim_id: row for row in rows}
    if len(mapping) != len(rows) or not set(mapping) <= set(claims) or (exact and set(mapping) != set(claims)):
        raise ValueError("dropped, duplicate or foreign claim IDs")
    for key, row in mapping.items():
        if (row.withheld != claims[key].withheld or not set(row.necessary_fact_ids) <= set(artifact.fact_ids)
                or not set(row.limitation_ids) <= set(artifact.limitation_ids)):
            raise ValueError("changed withholding or foreign fact/limitation IDs")
    return mapping


def _pair(artifact, inventory, rubric, first, second):
    claims = _claims(artifact, inventory, rubric)
    pins = _pins(artifact, inventory, rubric)
    _actor(first.assessor_id, artifact, (second.assessor_id,))
    _actor(second.assessor_id, artifact, (first.assessor_id,))
    for sheet in (first, second):
        if any(getattr(sheet, key) != value for key, value in pins.items()):
            raise ValueError("sheet artifact/inventory/rubric pin mismatch")
    return claims, _validate_rows(first.rows, claims, artifact, exact=True), _validate_rows(second.rows, claims, artifact, exact=True)


def _semantic(row):
    return row.label, row.withheld, frozenset(row.necessary_fact_ids), frozenset(row.limitation_ids)


def prepare_adjudication(artifact, inventory, rubric, first, second, adjudicator_id):
    claims, a, b = _pair(artifact, inventory, rubric, first, second)
    _actor(adjudicator_id, artifact, (first.assessor_id, second.assessor_id))
    if any(row.label is None for row in (*a.values(), *b.values())):
        raise ValueError("finish both assessor sheets before adjudication")
    disputes = [key for key in claims if (_semantic(a[key]), a[key].critical_false) != (_semantic(b[key]), b[key].critical_false)]
    return AdjudicationSheet(
        **_pins(artifact, inventory, rubric), first_sheet_sha256=digest(first), second_sheet_sha256=digest(second),
        adjudicator_id=adjudicator_id,
        rows=tuple(AnnotationRow(claim_id=key, withheld=claims[key].withheld) for key in disputes),
    )


def _protocol(row, actor):
    if row.label is None:
        raise ValueError("blank annotation cannot become a semantic assessment")
    return ClaimAssessment(claim_id=row.claim_id, assessor_id=actor, label=row.label,
                           withheld=row.withheld, necessary_fact_ids=row.necessary_fact_ids,
                           limitation_ids=row.limitation_ids)


def export_assessments(artifact, inventory, rubric, first, second, adjudication=None):
    """Export protocol inputs and honest completeness; never product decisions."""
    claims, a, b = _pair(artifact, inventory, rubric, first, second)
    all_labeled = all(row.label is not None for row in (*a.values(), *b.values()))
    semantic_disputes = {key for key in claims if _semantic(a[key]) != _semantic(b[key])} if all_labeled else set()
    disputes = {key for key in claims if (_semantic(a[key]), a[key].critical_false) != (_semantic(b[key]), b[key].critical_false)} if all_labeled else set()
    judged = {}
    if adjudication is not None:
        if not all_labeled:
            raise ValueError("adjudication cannot bypass blank assessor labels")
        _actor(adjudication.adjudicator_id, artifact, (first.assessor_id, second.assessor_id))
        pins = {**_pins(artifact, inventory, rubric), "first_sheet_sha256": digest(first), "second_sheet_sha256": digest(second)}
        if any(getattr(adjudication, key) != value for key, value in pins.items()):
            raise ValueError("adjudication pins differ from assessed edition")
        judged = _validate_rows(adjudication.rows, {key: claims[key] for key in disputes}, artifact, exact=False)
    first_records = tuple(_protocol(a[key], first.assessor_id) for key in claims) if all_labeled else ()
    second_records = tuple(_protocol(b[key], second.assessor_id) for key in claims) if all_labeled else ()
    selected = {key: a[key] if key not in disputes else judged.get(key) for key in claims}
    resolved = {key: row for key, row in selected.items() if row is not None and row.label is not None}
    unresolved = [key for key in claims if key not in resolved] if all_labeled else list(claims)
    # Existing prose_metrics ignores criticality; only semantic disputes belong in
    # its adjudication map. Critical-only disagreements remain explicitly tracked.
    protocol_judged = {key: _protocol(row, adjudication.adjudicator_id)
                       for key, row in judged.items() if key in semantic_disputes and row.label is not None}
    metrics = prose_metrics(tuple(claims), first_records, second_records, set(rubric.required_fact_ids),
                            set(rubric.required_limitation_ids), set(artifact.generator_actor_ids), protocol_judged) if all_labeled else None
    receipts_declared = bool(inventory.curation_receipt_sha256 and rubric.independent_rubric_receipt_sha256
                             and first.review_receipt_sha256 and second.review_receipt_sha256
                             and (not disputes or adjudication is not None and adjudication.review_receipt_sha256))
    return {
        **_pins(artifact, inventory, rubric), "claim_ids": list(claims),
        "first_sheet_sha256": digest(first), "second_sheet_sha256": digest(second),
        "adjudication_sha256": digest(adjudication) if adjudication is not None else None,
        "artifact_id": artifact.artifact_id, "case_id": artifact.case_id,
        "finding_id": artifact.finding_id, "attempt_id": artifact.attempt_id,
        "rule_id": artifact.decision.rule_id, "origin": artifact.origin,
        "raw_input_sha256": artifact.raw_input_sha256,
        "explanation_withheld": artifact.explanation_withheld,
        "generated_claim_inventory_sha256": sha256(json.dumps(list(claims), sort_keys=True,
              separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest(),
        "first": [row.model_dump(mode="json") for row in first_records],
        "second": [row.model_dump(mode="json") for row in second_records],
        "adjudicated": {key: row.model_dump(mode="json") for key, row in protocol_judged.items()},
        "metrics": metrics, "generated": len(claims),
        "withheld_generated": sum(span.withheld for span in claims.values()),
        "disagreement_claim_ids": sorted(disputes), "unresolved_claim_ids": unresolved,
        "critical_false_claim_ids": sorted(key for key, row in resolved.items() if row.critical_false),
        "bookkeeping_complete": bool(claims) and all_labeled and not unresolved and receipts_declared,
        "labels_complete": all_labeled, "declared_review_receipts_present": receipts_declared,
        "complete": False, "live_eligible": False, "identity_authenticated": False,
        "live_provenance_verified": False, "product_prose_enabled": False,
        "limitations": ["Private manual annotations are untrusted until external identity/custody and rubric verification.",
                        "All generated/withheld claims remain in denominators; context classification requires independent curation.",
                        "Hash/actor string agreement is not semantic truth or authentic live provenance.",
                        "Existing prose_metrics recall includes supported withheld claims; visible-retention utility is a separate scorer check."],
    }


def render_worksheet(artifact, inventory, rubric, sheet, *, review_catalogue=None) -> str:
    """Escape untrusted prose; no Markdown, HTML execution, links or scripts."""
    _claims(artifact, inventory, rubric)
    catalogue_html = '<p>No safe reference catalogue attached; independently checked context is still required.</p>'
    if review_catalogue is not None:
        from eval.model.review_catalogue import validate_catalogue
        validate_catalogue(artifact, review_catalogue)
        catalogue_html = '<h2>Safe fact reference</h2><pre>' + escape(review_catalogue.model_dump_json(indent=2)) + '</pre>'
    rows = "".join(f"<tr><td>{escape(span.span_id)}</td><td>{escape(span.kind)}</td>"
                   f"<td>{span.start}:{span.end}</td><td>{str(span.withheld).lower()}</td>"
                   f"<td><pre>{escape(span.text)}</pre></td></tr>" for span in inventory.spans)
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            '<title>PRIVATE untrusted prose assessment</title></head><body>'
            '<h1>PRIVATE — untrusted prose, no automatic labels</h1><p>External identity/custody and evidence required.</p>'
            f'<p>Artifact {escape(digest(artifact))}; inventory {escape(digest(inventory))}; rubric {escape(digest(rubric))}</p>'
            f'<h2>Frozen rubric</h2><pre>{escape(rubric.rubric_text)}</pre>'
            f'{catalogue_html}<pre>{escape(artifact.prose)}</pre><table>{rows}</table>'
            f'<pre>{escape(sheet.model_dump_json(indent=2))}</pre></body></html>')


def read_wire(path: Path, kind):
    path = Path(path).absolute()
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)) or not path.is_file():
        raise ValueError("bounded regular private JSON file required")
    with path.open("rb") as stream:
        data = stream.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise ValueError("private assessment input byte limit")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate assessment JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("nonfinite assessment JSON")

    json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    return kind.model_validate_json(data)


def write_private(out: Path, actor_id: str, payloads: dict[str, bytes]) -> None:
    """Exclusive actor-labelled fresh directory; OS identity/ACLs remain external."""
    if not re.fullmatch(r"[0-9a-f]{32}", actor_id):
        raise ValueError("opaque actor ID required")
    out = Path(out).absolute()
    if (not out.parent.is_dir() or out.exists()
            or any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (out, *out.parents))):
        raise ValueError("fresh actor-owned output with existing parent required")
    allowed = {"artifact.json", "inventory.json", "rubric.json", "sheet.json", "adjudication.json",
               "first-sheet.json", "second-sheet.json", "assessment.json", "worksheet.html",
               "catalogue.json", "catalogue.html"}
    if not set(payloads) <= allowed or any(len(data) > 1024 * 1024 for data in payloads.values()):
        raise ValueError("fixed bounded assessment payloads required")
    out.mkdir(mode=0o700, exist_ok=False)
    documents = {"packet-state.json": b'{"state":"INCOMPLETE"}',
                 "owner.json": json.dumps({"actor_id": actor_id, "private": True,
                 "identity_authenticated": False}).encode("ascii"), **payloads}
    for name, data in documents.items():
        descriptor = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    state = out / ".packet-state.pending"
    with state.open("xb") as stream:
        stream.write(b'{"state":"WRITTEN","semantic_truth_verified":false}')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(state, out / "packet-state.json")
    # No overwrite/reuse is permitted even after a failed/partial write.
