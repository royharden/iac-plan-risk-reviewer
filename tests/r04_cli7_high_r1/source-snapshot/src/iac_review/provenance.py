"""Acyclic private D-only provenance, with no evaluation/provider/Git dependency."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Callable, Literal

from pydantic import Field, model_validator

from iac_review.contracts import PARSER_VERSION, POLICY_VERSION, PlanDocument
from iac_review.contracts.manifest import (
    CaseBinding, ComponentVersion, Digest, InvocationMetadata, ManifestWire, RunManifest,
)

CORE_FILES_V1 = (
    "contracts/__init__.py", "contracts/manifest.py", "ingest/__init__.py",
    "evidence/__init__.py", "rules/__init__.py", "report/__init__.py",
    "provenance.py", "source_view.py", "cli.py",
)
# Profile 2 deliberately adds the canonical report wire and bundle inventory
# (amended in place to include the inventory before any v2 bundle existed).
# Profile 1 descriptors keep verifying against their nine files; no archive is
# upgraded or repinned.
CORE_FILES_V2 = CORE_FILES_V1 + ("contracts/report_wire.py", "contracts/report_inventory.py")
SOURCE_PROFILES = {1: CORE_FILES_V1, 2: CORE_FILES_V2}
SOURCE_PROFILE_VERSIONS = {1: "content-v1", 2: "content-v2"}
CURRENT_PROFILE = 2
CORE_FILES = SOURCE_PROFILES[CURRENT_PROFILE]
REPORT_FILES = frozenset({"private.json", "private.html", "shareable.json", "shareable.html"})
DESCRIPTOR_FILE = "run-manifest.json"
CORE_ARTIFACTS = REPORT_FILES | {DESCRIPTOR_FILE}


class SourceFilePin(ManifestWire):
    path: Literal[
        "contracts/__init__.py", "contracts/manifest.py", "ingest/__init__.py",
        "evidence/__init__.py", "rules/__init__.py", "report/__init__.py",
        "provenance.py", "source_view.py", "cli.py", "contracts/report_wire.py",
        "contracts/report_inventory.py",
    ]
    sha256: Digest


class LocalConfig(ManifestWire):
    schema_version: Literal[1] = 1
    fail_on: int = Field(ge=1, le=4)
    rules: tuple[Literal["R1"], Literal["R2"], Literal["R3"], Literal["R4"]] = ("R1", "R2", "R3", "R4")


class ReportProvenance(ManifestWire):
    # schema_version selects the source profile. The default stays 1 so an
    # unversioned constructor never silently claims the eleven-file profile.
    schema_version: Literal[1, 2] = 1
    kind: Literal["private_deterministic_descriptor"] = "private_deterministic_descriptor"
    run_manifest: RunManifest
    source_files: tuple[SourceFilePin, ...] = Field(min_length=9, max_length=11)
    config: LocalConfig
    producer_authenticated: Literal[False] = False
    benchmark_execution_verified: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self) -> ReportProvenance:
        run = self.run_manifest
        if run.stage != "deterministic":
            raise ValueError("core report descriptor must be deterministic only")
        files = {row.path: row.sha256 for row in self.source_files}
        profile = SOURCE_PROFILES[self.schema_version]
        if set(files) != set(profile) or len(files) != len(self.source_files):
            raise ValueError("source file pin inventory mismatch")
        if run.build_sha256 != content_digest(files):
            raise ValueError("installed core source digest mismatch")
        components = {row.kind: row for row in run.components}
        source = components.get("source")
        if source is None or source.version != SOURCE_PROFILE_VERSIONS[self.schema_version]:
            raise ValueError("source profile version mismatch")
        expected = {
            "source": run.build_sha256, "parser": files["ingest/__init__.py"],
            "rules": files["rules/__init__.py"], "config": content_digest(self.config.model_dump(mode="json")),
        }
        if any(components[kind].sha256 != value for kind, value in expected.items()):
            raise ValueError("local source/parser/rule/config component hash mismatch")
        if (run.policy_sha256 != expected["rules"] or components["parser"].version != PARSER_VERSION
                or components["rules"].version != POLICY_VERSION):
            raise ValueError("local parser/rule version mismatch")
        invocation, case = run.invocations[0], run.cases[0]
        if (invocation.config_component_id != components["config"].component_id
                or invocation.version_component_id != components["rules"].component_id
                or case.configuration_id != expected["config"]
                or case.safe_projection_sha256 is not None):
            raise ValueError("local invocation/config/source binding mismatch")
        return self


def content_digest(value) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return sha256(raw.encode("ascii")).hexdigest()


def descriptor_bytes(descriptor: ReportProvenance) -> bytes:
    return (json.dumps(descriptor.model_dump(mode="json"), ensure_ascii=True, sort_keys=True,
                       indent=2, allow_nan=False) + "\n").encode("utf-8")


def installed_core_pins(check: Callable[[], None],
                        profile: int = CURRENT_PROFILE) -> tuple[SourceFilePin, ...]:
    """Read only a fixed installed core-source inventory, never repo discovery/Git."""
    root = Path(__file__).resolve().parent
    pins = []
    for name in SOURCE_PROFILES[profile]:
        check()
        path = root.joinpath(*name.split("/"))
        if (any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                for p in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 1024 * 1024):
            raise ValueError("installed core source unavailable or unbounded")
        with path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        check()
        if len(raw) > 1024 * 1024:
            raise ValueError("installed source grew beyond bound")
        pins.append(SourceFilePin(path=name, sha256=sha256(raw).hexdigest()))
    return tuple(pins)


def local_descriptor(plan: PlanDocument, run_id: str, case_id: str, fail_on: int,
                     check: Callable[[], None]) -> ReportProvenance:
    pins = installed_core_pins(check, CURRENT_PROFILE)
    files = {row.path: row.sha256 for row in pins}
    config = LocalConfig(fail_on=fail_on)
    config_hash = content_digest(config.model_dump(mode="json"))
    build = content_digest(files)
    components = tuple(ComponentVersion(
        component_id=kind, kind=kind, name=name, version=version, sha256=value)
        for kind, name, version, value in (
            ("source", "installed-core-subset", SOURCE_PROFILE_VERSIONS[CURRENT_PROFILE], build),
            ("parser", "terraform-json-parser", PARSER_VERSION, files["ingest/__init__.py"]),
            ("rules", "declared-aws-predicates", POLICY_VERSION, files["rules/__init__.py"]),
            ("config", "local-review-config", "config-v1", config_hash)))
    run = RunManifest(
        stage="deterministic", run_id=run_id, edition_id="local-" + run_id,
        edition_state="development", split="dev", build_sha256=build,
        policy_sha256=files["rules/__init__.py"], components=components,
        cases=(CaseBinding(case_id=case_id, split="dev", configuration_id=config_hash,
                           family_id="local-" + case_id, mutation_lineage="local-" + case_id,
                           raw_source_sha256=plan.identity.sha256),),
        invocations=(InvocationMetadata(invocation_id=run_id, arm="D", status="ok", kind="executed",
                                        case_ids=(case_id,), config_component_id="config",
                                        version_component_id="rules", attempt_ids=()),),
        attempts=(), artifacts=(), eligibility=())
    return ReportProvenance(schema_version=CURRENT_PROFILE, run_manifest=run,
                            source_files=pins, config=config)


def private_binding(descriptor: ReportProvenance) -> dict:
    return {"descriptor": descriptor.model_dump(mode="json"),
            "descriptor_sha256": sha256(descriptor_bytes(descriptor)).hexdigest()}


def verify_descriptor(private: dict, shareable: dict, raw: bytes,
                      expected_plan_sha256: str, run_id: str) -> ReportProvenance:
    """Validate declared integrity without reading source files or executing anything."""
    if len(raw) > 65_536:
        raise ValueError("descriptor exceeds byte cap")
    descriptor = ReportProvenance.model_validate_json(raw)
    binding = private.get("provenance")
    if type(binding) is not dict or set(binding) != {"descriptor", "descriptor_sha256"}:
        raise ValueError("private descriptor binding missing")
    if (binding["descriptor_sha256"] != sha256(raw).hexdigest()
            or binding["descriptor"] != descriptor.model_dump(mode="json")
            or raw != descriptor_bytes(descriptor)):
        raise ValueError("private descriptor bytes/digest mismatch")
    run = descriptor.run_manifest
    if (run.run_id != run_id or private.get("run_id") != run_id or shareable.get("run_id") != run_id
            or run.cases[0].case_id != private.get("case_id") or private.get("case_id") != shareable.get("case_id")
            or run.cases[0].raw_source_sha256 != expected_plan_sha256
            or private.get("plan", {}).get("sha256") != expected_plan_sha256
            or private.get("summary", {}).get("fail_on") != descriptor.config.fail_on
            or shareable.get("summary", {}).get("fail_on") != descriptor.config.fail_on):
        raise ValueError("report/run/config/raw-source binding mismatch")
    if {"provenance", "plan", "run_manifest", "source_files", "private_map"} & set(shareable):
        raise ValueError("private provenance leaked into shareable projection")
    return descriptor
